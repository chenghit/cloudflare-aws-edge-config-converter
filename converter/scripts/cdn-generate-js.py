#!/usr/bin/env python3
"""CDN JS code generator — deterministic Python replacement for Stage 8 LLM.

Reads all domain IRs from ir/final/<hostname>.json and generates CloudFront
Function JS (viewer_request.js, viewer_response.js) and Lambda@Edge handlers.

Performs content-hash dedup: identical CFF content across domains is shared
via a single CFF resource in terraform/shared/. Per-domain modules reference
shared CFF by name using data sources.

Usage:
    python3 cdn-generate-js.py <output_dir>
    # output_dir is e.g. "cloudflare-to-aws-cdn"
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Add scripts dir to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from cdn_expr_parser import (parse_expression_full, parse_dynamic_expression,
                             CF_FIELD_MAP, iter_condition_children,
                             CACHE_BYPASS_HEADER)

# ── Constants ────────────────────────────────────────────────────────────────

CFF_SIZE_LIMIT = 10240  # 10 KB
MAX_CFF_NAME = 64       # CloudFront Function name limit
MAX_CFF_ASSOCIATIONS = 100  # Max distributions per CFF (fixed, not adjustable)
CFF_PREFIX = "cf-"

# Human-intervention guidance emitted in ---RESULT--- when a viewer CFF exceeds
# the 10 KB limit. The limit is a HARD CloudFront quota (not adjustable via
# Service Quotas / AWS Support), and this tool deliberately does NOT fall back
# to Lambda@Edge for viewer events (L@E adds latency and cost). So the listed
# domains cannot be deployed as-is and need a human decision.
_SIZE_EXCEEDED_GUIDANCE = (
    "CONTEXT: The listed domain(s) have a viewer-request or viewer-response "
    "CloudFront Function exceeding the 10240-byte (10 KB) limit even after "
    "minification. This is a HARD CloudFront quota — it CANNOT be raised via "
    "Service Quotas or AWS Support. These domains are NOT deployable as generated.\n"
    "GUIDANCE: Tell the user, per listed domain, to either (1) simplify the "
    "Cloudflare rules for that host (remove/consolidate redirects, header "
    "transforms, or conditions) so the generated function fits under 10 KB, or "
    "(2) split the logic across behaviors, or (3) accept that some rules can't "
    "convert and drop them. Do NOT hand-migrate viewer logic to Lambda@Edge: "
    "this tool keeps viewer events on CloudFront Functions by design (Lambda@Edge "
    "adds latency and per-request cost). All OTHER domains generated successfully "
    "and can be deployed."
)


def cff_name(san, event_type):
    """Generate CFF name within 64 char limit. Truncates with hash if needed."""
    suffix = "-req" if event_type == "viewer_request" else "-resp"
    base = f"{CFF_PREFIX}{san}{suffix}"
    if len(base) <= MAX_CFF_NAME:
        return base
    name_hash = hashlib.sha256(san.encode()).hexdigest()[:6]
    available = MAX_CFF_NAME - len(CFF_PREFIX) - len(suffix) - 7  # 7 = "-" + 6 chars
    return f"{CFF_PREFIX}{san[:available]}-{name_hash}{suffix}"


def shared_cff_name(content_hash, event_type):
    """Generate shared CFF name: cf-shared-req-{hash6} or cf-shared-resp-{hash6}."""
    suffix = "-req" if event_type == "viewer_request" else "-resp"
    return f"{CFF_PREFIX}shared{suffix}-{content_hash[:6]}"

# Fields always available (no existence check needed)
ALWAYS_AVAILABLE = {
    "uri.path", "uri", "host", "method", "ip.src", "uri.query",
    "uri.path.extension", "full_uri", "response_code",
}

# CFF field → JS accessor mapping (viewer-request)
CFF_ACCESSORS = {
    "uri.path": "request.uri",
    "uri": "request.uri",
    "uri.query": "_qs(request.querystring)",
    "uri.path.extension": "request.uri.split('.').pop()",
    "host": "request.headers.host.value",
    "method": "request.method",
    # http.cookie = the entire Cookie request header as a string (Cloudflare:
    # "session=abc; theme=dark"). CFF does NOT expose the raw Cookie header —
    # cookies arrive PARSED in request.cookies (a Map). `request.headers.cookie`
    # is undefined. So http.cookie is rebuilt from the map via the _cookieStr
    # helper (see _cookie_str_accessor); handled as a special case in
    # _condition_to_js, not via this direct-accessor table.
    "user_agent": ("request.headers['user-agent']", "request.headers['user-agent'].value"),
    "referer": ("request.headers.referer", "request.headers.referer.value"),
    "http_version": ("request.headers['cloudfront-viewer-http-version']", "request.headers['cloudfront-viewer-http-version'].value"),
    "ip.src": "event.viewer.ip",
    "country": ("request.headers['cloudfront-viewer-country']", "request.headers['cloudfront-viewer-country'].value"),
    "city": ("request.headers['cloudfront-viewer-city']", "request.headers['cloudfront-viewer-city'].value"),
    "region": ("request.headers['cloudfront-viewer-country-region-name']", "request.headers['cloudfront-viewer-country-region-name'].value"),
    "region_code": ("request.headers['cloudfront-viewer-country-region']", "request.headers['cloudfront-viewer-country-region'].value"),
    # subdivision_1 (ip.src.subdivision_1_iso_code) = first-level ISO 3166-2
    # region, same CloudFront header as region_code.
    "subdivision_1": ("request.headers['cloudfront-viewer-country-region']", "request.headers['cloudfront-viewer-country-region'].value"),
    "latitude": ("request.headers['cloudfront-viewer-latitude']", "request.headers['cloudfront-viewer-latitude'].value"),
    "longitude": ("request.headers['cloudfront-viewer-longitude']", "request.headers['cloudfront-viewer-longitude'].value"),
    "postal_code": ("request.headers['cloudfront-viewer-postal-code']", "request.headers['cloudfront-viewer-postal-code'].value"),
    "metro_code": ("request.headers['cloudfront-viewer-metro-code']", "request.headers['cloudfront-viewer-metro-code'].value"),
    "timezone": ("request.headers['cloudfront-viewer-time-zone']", "request.headers['cloudfront-viewer-time-zone'].value"),
    "asnum": ("request.headers['cloudfront-viewer-asn']", "request.headers['cloudfront-viewer-asn'].value"),
}

# Lambda@Edge accessor overrides
LAMBDA_ACCESSORS = {
    "ip.src": "request.clientIp",
    # uri.query: Lambda@Edge request.querystring is already a raw string,
    # unlike CFF where it's a parsed object requiring _qs() reconstruction.
    "uri.query": "request.querystring",
    "host": "request.headers.host[0].value",
    "user_agent": ("request.headers['user-agent']", "request.headers['user-agent'][0].value"),
    "country": ("request.headers['cloudfront-viewer-country']", "request.headers['cloudfront-viewer-country'][0].value"),
}

# viewer-response accessor overrides
RESPONSE_ACCESSORS = {
    "response_code": "response.statusCode",
    "uri.path": "event.request.uri",
    "uri": "event.request.uri",
    "host": "event.request.headers.host.value",
    "method": "event.request.method",
    "ip.src": "event.viewer.ip",
}


def js_string(val):
    """Escape a value for JS string literal."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return f"'{s}'"


def js_array(vals):
    """Format a list as JS array literal."""
    return "[" + ", ".join(js_string(v) for v in vals) + "]"


# ── Wildcard → JS ────────────────────────────────────────────────────────────

def _wildcard_pattern_to_regex(pattern):
    """Convert wildcard pattern to anchored regex. * → .* (greedy for conditions)."""
    result = "^"
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            result += "\\*"
            i += 2
        elif ch == "*":
            result += ".*"
            i += 1
        elif ch in r"\.+?^${}()|[]/":
            result += "\\" + ch
            i += 1
        else:
            result += ch
            i += 1
    result += "$"
    return result


def wildcard_to_js(accessor, pattern, strict=False):
    """Convert wildcard condition to optimal JS code."""
    stars = pattern.count("*") - pattern.count("\\*")
    if stars == 0:
        if strict:
            return f"{accessor} === {js_string(pattern)}"
        return f"{accessor}.toLowerCase() === {js_string(pattern.lower())}"
    if pattern == "*":
        return "true"
    if stars == 1:
        if pattern.endswith("*") and "*" not in pattern[:-1]:
            prefix = pattern[:-1]
            if strict:
                return f"{accessor}.startsWith({js_string(prefix)})"
            return f"{accessor}.toLowerCase().startsWith({js_string(prefix.lower())})"
        if pattern.startswith("*") and "*" not in pattern[1:]:
            suffix = pattern[1:]
            if strict:
                return f"{accessor}.endsWith({js_string(suffix)})"
            return f"{accessor}.toLowerCase().endsWith({js_string(suffix.lower())})"
    regex = _wildcard_pattern_to_regex(pattern)
    flags = "" if strict else "i"
    return f"/{regex}/{flags}.test({accessor})"


def _cf_regex_to_js(pattern):
    """Escape / in Cloudflare regex for JS regex literal."""
    return pattern.replace("/", "\\/")


# ── full_uri wildcard splitting ──────────────────────────────────────────────

def _split_full_uri_wildcard(pattern):
    """Split full_uri wildcard into (host_pattern, path_pattern) or None."""
    m = re.match(r"https?://", pattern)
    if not m:
        return None
    rest = pattern[m.end():]
    slash_idx = rest.find("/")
    if slash_idx == -1:
        return rest, "/*"
    return rest[:slash_idx], rest[slash_idx:]


# ── Condition → JS ───────────────────────────────────────────────────────────

# Short field names that have no direct accessor but ARE convertible because
# condition_to_js resolves them via a KVS preamble (see _generate_continent_preamble).
# The value is the exact JS variable the preamble declares — a condition on the
# field must reference that same name (is_eu → isEU, NOT the raw field name).
_PREAMBLE_ACCESSORS = {"continent": "continent", "is_eu": "isEU"}
_PREAMBLE_FIELDS = set(_PREAMBLE_ACCESSORS)


def _field_is_mappable(field, target="cff"):
    """True if a short (already CF_FIELD_MAP-mapped) field name has a real
    CloudFront equivalent — a direct accessor or a preamble-resolved variable.

    Fields with no CloudFront source (cf.bot_management.score, cf.waf.score,
    ip.src.subdivision_1_iso_code, JWT claims, etc.) are NOT mappable and must
    be reported as non-convertible rather than emitted as bare JS identifiers.
    """
    if field in _PREAMBLE_FIELDS:
        # continent / is_eu depend on a KVS preamble that is only generated for
        # the viewer-request and viewer-response handlers. The Lambda@Edge
        # origin-request handler has no such preamble (and no cf.kvs()), so they
        # are NOT mappable there.
        return target != "lambda"
    if target == "lambda" and field in LAMBDA_ACCESSORS:
        return True
    if target == "response" and field in RESPONSE_ACCESSORS:
        return True
    return field in CFF_ACCESSORS


def _get_accessor(field, target="cff"):
    """Get JS accessor for a field. Returns (check_expr, value_expr) or just value_expr."""
    # continent / is_eu are resolved to a preamble-declared variable (isEU, not
    # the raw field name) — same in every target.
    if field in _PREAMBLE_ACCESSORS:
        return _PREAMBLE_ACCESSORS[field]
    if target == "lambda":
        acc = LAMBDA_ACCESSORS.get(field)
        if acc:
            return acc if isinstance(acc, tuple) else acc
    if target == "response":
        acc = RESPONSE_ACCESSORS.get(field)
        if acc:
            return acc
    acc = CFF_ACCESSORS.get(field)
    if acc is None:
        return field  # unknown field, pass through
    return acc


def _needs_check(field):
    return field not in ALWAYS_AVAILABLE


# Structural "never matches" marker. A condition that can't be evaluated at the
# edge (unmappable field, unresolved list, unknown op, malformed node) resolves
# to this VALUE — never a magic string — so boolean combination is done on the
# value, not by inspecting rendered JS (which collides with real output such as
# `/*x/.test(uri) || m === false`). Only the public wrapper renders it, as the
# JS literal `false`.
_NEVER = object()


def _apply_leaf_modifiers(val_expr, cond):
    """Apply the leaf modifiers the parser records so the op runs on the right
    value:
      size_check (len(x))       → compare x.length (value is numeric)
      transform lowercase/upper → .toLowerCase() / .toUpperCase()
    Without this, `len(uri.path) gt 10` renders `request.uri > 10` (string vs
    number → never true) and `lower(host) eq "x"` is silently case-sensitive.
    Applied to EVERY leaf accessor, including full_uri — the full_uri branch
    reconstructs its own accessor and must run this too, or len()/lower() on
    full_uri are silently ignored."""
    if cond.get("size_check"):
        val_expr = f"{val_expr}.length"
    transform = cond.get("transform")
    if transform == "lowercase":
        val_expr = f"{val_expr}.toLowerCase()"
    elif transform == "uppercase":
        val_expr = f"{val_expr}.toUpperCase()"
    return val_expr


def condition_to_js(cond, target="cff", indent=2):
    """Convert a CDN condition tree to a JS expression string.

    Returns None when the condition is unconditional (caller emits the body with
    no `if`), or a JS string otherwise. An un-evaluable condition renders as the
    literal `false` (fail-closed: the guarded op never fires)."""
    r = _condition_to_js(cond, target, indent)
    if r is _NEVER:
        return "false"
    return r  # None (unconditional) or a JS string


def _condition_to_js(cond, target="cff", indent=2):
    """Inner recursion. Returns one of three kinds:
      - None    → unconditional ("always true")
      - _NEVER  → never matches (un-evaluable / fail-closed)
      - str     → a JS boolean expression
    Combining these at the value level (not by string inspection) is what keeps
    a never-match from flipping a sibling/negation to true (fail OPEN) and stops
    real output from being misread as a sentinel."""
    if cond is None or cond.get("always"):
        return None  # unconditional

    if "logic" in cond:
        logic = cond["logic"]
        # _NEVER means "un-evaluable at the edge" — NOT boolean false. Its correct
        # behavior depends on polarity (how many NOTs are above it), so it cannot
        # be soundly dropped from an OR and then negated: `not(A or NEVER)` must
        # NOT become `!(A)` (that fires when the un-evaluable branch would have
        # matched — fail OPEN). The only polarity-sound rule is: _NEVER is
        # CONTAGIOUS — any logic node containing it fails the whole condition
        # closed. (OR branches that are merely unmappable are already pruned
        # upstream by the processor's _prune_unmappable; here _NEVER is a
        # defense-in-depth backstop for what slipped through, e.g. continent in
        # a Lambda@Edge target.)
        #   None = "always true" is the identity for AND / absorbing for OR.
        if logic in ("and", "or"):
            parts = [_condition_to_js(p, target, indent) for p in cond.get("parts", [])]
            if any(p is _NEVER for p in parts):
                return _NEVER
            if logic == "and":
                # AND is a conjunction of constraints; with no parts there is no
                # constraint → unconditional (identity). None parts are dropped.
                live = [p for p in parts if p is not None]
                if not live:
                    return None
                return " && ".join(f"({p})" if " || " in p else p for p in live)
            # or
            if not parts:
                # A disjunction of nothing matches nothing → fail closed (an
                # empty OR returning None would fire the op on every request).
                return _NEVER
            if any(p is None for p in parts):
                return None  # an always-true branch makes the OR unconditional
            return " || ".join(f"({p})" if " && " in p else p for p in parts)
        if logic == "not":
            inner = _condition_to_js(cond.get("item"), target, indent)
            if inner is None or inner is _NEVER:
                return _NEVER  # not(always)=never; not(un-evaluable)=un-evaluable
            return f"!({inner})"
        # Unknown logic operator → fail closed rather than KeyError.
        print(f"  WARN: unknown logic operator, emitting false: {logic}", file=sys.stderr)
        return _NEVER

    field = cond.get("field", "")
    op = cond.get("op", "eq")
    value = cond.get("value")

    # A size_check (len(x)) compares against a NUMBER. Cloudflare may quote the
    # literal (`len(x) eq "5"`), so the parser hands us the string "5"; rendered
    # as `x.length === '5'` that is Number===String → always false (eq/ne don't
    # coerce; gt/lt would, but normalize uniformly). Coerce a digit-string value
    # to int so the comparison is numeric. Use a STRICT integer match (^-?\d+$)
    # — value.lstrip("-").isdigit() accepts "--5" (lstrip removes BOTH dashes),
    # and int("--5") then raises; leave a non-integer literal untouched so it
    # can't crash codegen.
    if cond.get("size_check") and isinstance(value, str) and re.fullmatch(r"-?\d+", value):
        value = int(value)

    # Handle not_ prefix
    negated = False
    base_op = op
    if op.startswith("not_"):
        negated = True
        base_op = op[4:]

    # Special: full_uri wildcard with host/path split
    if field == "full_uri" and base_op in ("wildcard", "strict_wildcard") and "host_pattern" in cond:
        host_js = wildcard_to_js(
            _val_accessor("host", target), cond["host_pattern"], base_op == "strict_wildcard"
        )
        path_js = wildcard_to_js(
            _val_accessor("uri.path", target), cond["path_pattern"], base_op == "strict_wildcard"
        )
        expr = f"({host_js} && {path_js})" if host_js != "true" and path_js != "true" else (host_js if path_js == "true" else path_js)
        return f"!({expr})" if negated else expr

    # Special: full_uri without a host/path split (contains, eq, matches, or a
    # scheme-less wildcard) — reconstruct the absolute URL and match against it.
    if field == "full_uri":
        uri_acc = _apply_leaf_modifiers(_full_uri_accessor(target), cond)
        js_cond = _op_to_js(uri_acc, base_op, value, field)
        if js_cond is _NEVER:
            return _NEVER
        return f"!({js_cond})" if negated else js_cond

    # Special: a named cookie / header / query-string arg
    # (http.request.cookies["n"] / .headers["n"] / .uri.args["n"]). CFF exposes
    # each as a Map keyed by name: request.cookies / request.headers /
    # request.querystring, values `{value, multiValue}`. Two leaf forms:
    #   existence (value is True)      → `map['n'] !== undefined`
    #   scalar value (eq/ne/contains…) → existence-guarded op on `map['n'].value`
    # Header names are lowercased (CFF header keys are ASCII-lowercase); cookie
    # and arg names are used as-is. Handled before the generic accessor path.
    if field in _INDEXED_NAMED_FIELDS:
        base = _indexed_named_base(field, target)
        if base is None:
            print(f"  WARN: {field} unsupported in this target, emitting false", file=sys.stderr)
            return _NEVER
        raw_name = cond.get(_INDEXED_NAMED_FIELDS[field], "")
        name = raw_name.lower() if field == "header_named" else raw_name
        entry = f"{base}[{js_string(name)}]"
        if value is True:  # existence form
            return f"{entry} === undefined" if negated else f"{entry} !== undefined"
        # scalar value comparison: guard existence, then compare .value
        val_expr = _apply_leaf_modifiers(f"{entry}.value", cond)
        js_cond = _op_to_js(val_expr, base_op, value, field)
        if js_cond is _NEVER:
            return _NEVER
        if negated:
            return f"{entry} === undefined || !({js_cond})"
        return f"{entry} !== undefined && {js_cond}"

    # Special: http.cookie = the whole Cookie header string. CFF has no raw
    # Cookie header, so rebuild it from the parsed request.cookies map with the
    # _cookieStr helper and run the op (contains/eq/wildcard/matches) on that
    # reconstruction — faithful to Cloudflare's whole-string semantics (a
    # `contains "foo=bar"` matches across the name=value boundary, unlike a
    # per-cookie check). Only in CFF (the map + helper live there).
    if field == "cookie":
        acc = _cookie_str_accessor(target)
        if acc is None:
            print(f"  WARN: http.cookie unsupported in this target, emitting false", file=sys.stderr)
            return _NEVER
        acc = _apply_leaf_modifiers(acc, cond)
        js_cond = _op_to_js(acc, base_op, value, field)
        if js_cond is _NEVER:
            return _NEVER
        return f"!({js_cond})" if negated else js_cond

    # Special: continent / is_eu handled via preamble (not inline condition)
    # These are handled at the section level, not here.

    # Guard: an unmappable condition field would emit a bare (undefined) JS
    # identifier. Fail closed — never matches, regardless of negation.
    if not _field_is_mappable(field, target):
        print(f"  WARN: unmappable condition field, emitting false: {field}", file=sys.stderr)
        return _NEVER

    # in_kvs / not_in_kvs read kvsHandle, which only the CFF handlers have.
    # The Lambda@Edge origin-request handler has no cf.kvs() (not an L@E API),
    # so fail closed there rather than emit an undefined-kvsHandle ReferenceError.
    # (Mirror of the continent/is_eu lambda guard in _field_is_mappable.)
    if target == "lambda" and base_op == "in_kvs":
        print(f"  WARN: in_kvs condition unsupported in Lambda@Edge, emitting false: {field}", file=sys.stderr)
        return _NEVER

    acc = _get_accessor(field, target)
    needs_check = _needs_check(field)

    if isinstance(acc, tuple):
        check_expr, val_expr = acc
    else:
        check_expr, val_expr = None, acc

    val_expr = _apply_leaf_modifiers(val_expr, cond)

    js_cond = _op_to_js(val_expr, base_op, value, field)

    # An un-evaluable op (unresolved in_list, unknown op) is never-match — do NOT
    # negate it into `true` (fail OPEN).
    if js_cond is _NEVER:
        return _NEVER

    if needs_check and check_expr:
        if negated:
            return f"!{check_expr} || !({js_cond})"
        return f"{check_expr} && {js_cond}"

    if negated:
        return f"!({js_cond})"
    return js_cond


# Synthetic "named indexed field" short names → the leaf key carrying the name.
_INDEXED_NAMED_FIELDS = {
    "cookie_named": "cookie_name",
    "header_named": "header_name",
    "arg_named": "arg_name",
}


def _indexed_named_base(field, target="cff"):
    """The JS Map accessor a named cookie/header/arg indexes into, or None if the
    target can't source it. CFF and viewer-response expose parsed maps
    (request.cookies / request.headers / request.querystring); Lambda@Edge
    origin-request does not (raw headers only), so return None → caller fails
    closed. Cache-bypass runs in the viewer-request CFF, the path that matters."""
    if target == "lambda":
        return None
    prefix = "event.request" if target == "response" else "request"
    suffix = {"cookie_named": "cookies", "header_named": "headers",
              "arg_named": "querystring"}[field]
    return f"{prefix}.{suffix}"


def _cookie_str_accessor(target="cff"):
    """JS accessor that rebuilds the whole Cookie header string (http.cookie)
    from the parsed cookie map, via the _cookieStr helper. None for Lambda@Edge
    (no parsed-cookie map). CFF only — cookie-bypass runs in the viewer-request
    CFF. The helper (see _cookie_str_helper_lines) joins name=value pairs with
    '; ', matching Cloudflare's Cookie string."""
    if target == "lambda":
        return None
    base = "event.request.cookies" if target == "response" else "request.cookies"
    return f"_cookieStr({base})"


def _val_accessor(field, target="cff"):
    """Get just the value accessor (not the check expression)."""
    acc = _get_accessor(field, target)
    if isinstance(acc, tuple):
        return acc[1]
    return acc


def _full_uri_accessor(target="cff"):
    """Reconstruct http.request.full_uri as a JS string expression.

    Cloudflare's full_uri is the absolute URL (scheme://host/path?query, minus
    the #fragment). CloudFront exposes host, path and query separately and does
    NOT surface the scheme in an edge function, so the scheme is assumed to be
    https (see the note emitted into conversion_report.md). The result is
    parenthesized so a following `.includes(...)` / `.startsWith(...)` /
    `=== ...` binds to the whole concatenation, not just the last operand.

    Query string: included for cff (via the always-injected `_qs` helper) and
    lambda (raw string). Viewer-response has neither `_qs` nor `request` in
    scope, so full_uri is reconstructed there without the query string.
    """
    host = _val_accessor("host", target)
    path = _val_accessor("uri.path", target)
    if target == "lambda":
        return f"('https://' + {host} + {path} + (request.querystring ? '?' + request.querystring : ''))"
    if target == "response":
        return f"('https://' + {host} + {path})"
    return (f"('https://' + {host} + {path} + "
            f"(_qs(request.querystring) ? '?' + _qs(request.querystring) : ''))")


def _op_to_js(accessor, op, value, field=""):
    """Convert a single operator to a JS expression, or _NEVER if the op can't
    be evaluated at the edge (unresolved list, unknown op) — a fail-closed
    'never matches' that callers propagate structurally."""
    if op == "eq":
        if value is True:
            return accessor
        return f"{accessor} === {js_string(value)}"
    if op == "ne":
        return f"{accessor} !== {js_string(value)}"
    if op == "gt":
        return f"{accessor} > {js_string(value)}"
    if op == "ge":
        return f"{accessor} >= {js_string(value)}"
    if op == "lt":
        return f"{accessor} < {js_string(value)}"
    if op == "le":
        return f"{accessor} <= {js_string(value)}"
    if op == "contains":
        return f"{accessor}.includes({js_string(value)})"
    if op == "starts_with":
        return f"{accessor}.startsWith({js_string(value)})"
    if op == "ends_with":
        return f"{accessor}.endsWith({js_string(value)})"
    if op == "in":
        if isinstance(value, list):
            return f"{js_array(value)}.includes({accessor})"
        # String set from parser
        return f"{js_array(value)}.includes({accessor})"
    if op == "in_list":
        # An unresolved named list can't be evaluated at the edge → never match.
        print(f"  WARN: unresolved list in condition, emitting false: {value}", file=sys.stderr)
        return _NEVER
    if op == "in_kvs":
        return f"await kvsHandle.exists('ip:{value}:' + {accessor})"
    if op in ("wildcard", "strict_wildcard"):
        return wildcard_to_js(accessor, value, op == "strict_wildcard")
    if op == "matches":
        return f"/{_cf_regex_to_js(value)}/.test({accessor})"
    print(f"  WARN: unknown op in condition, emitting false: {op}", file=sys.stderr)
    return _NEVER


# ── Dynamic expression → JS ──────────────────────────────────────────────────

def _dyn_field_to_js(cf_field, target="cff"):
    """Map a Cloudflare field name to JS accessor in dynamic expressions.

    Non-convertible fields are screened out in the processor, but guard here
    too: never emit a bare unmapped field name (it would be an undefined JS
    variable). Fall back to an empty string with a warning comment.
    """
    mapped = CF_FIELD_MAP.get(cf_field, cf_field)
    # full_uri has no single accessor but IS convertible via reconstruction.
    if mapped == "full_uri":
        return _full_uri_accessor(target)
    if not _field_is_mappable(mapped, target):
        print(f"  WARN: unmappable field in expression, dropping: {cf_field}", file=sys.stderr)
        return f"'' /* WARNING: no CloudFront source for {cf_field} */"
    return _val_accessor(mapped, target)


def _wildcard_replace_glob_to_regex(pattern):
    """Convert wildcard_replace pattern to anchored lazy regex. * → (.*?)"""
    result = "^"
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            result += "\\*"
            i += 2
        elif ch == "*":
            result += "(.*?)"
            i += 1
        elif ch in r"\.+?^${}()|[]/":
            result += "\\" + ch
            i += 1
        else:
            result += ch
            i += 1
    result += "$"
    return result


def _capture_group_cf_to_js(repl):
    """Convert Cloudflare ${N} capture group refs to JS $N."""
    return re.sub(r"\$\{(\d+)\}", r"$\1", repl)


def dyn_expr_to_js(node, target="cff"):
    """Convert a parsed dynamic expression tree to JS code string."""
    if node["type"] == "literal":
        return js_string(node["value"])
    if node["type"] == "field":
        return _dyn_field_to_js(node["value"], target)
    if node["type"] != "func_call":
        return f"/* unknown node type: {node['type']} */"

    func = node["func"]
    args = node["args"]

    if func == "concat":
        parts = [dyn_expr_to_js(a, target) for a in args]
        return " + ".join(parts)

    if func == "regex_replace":
        field_js = dyn_expr_to_js(args[0], target)
        pattern = args[1]["value"]
        replacement = _capture_group_cf_to_js(args[2]["value"])
        return f"{field_js}.replace(/{_cf_regex_to_js(pattern)}/, {js_string(replacement)})"

    if func == "wildcard_replace":
        field_js = dyn_expr_to_js(args[0], target)
        pattern = args[1]["value"]
        replacement = _capture_group_cf_to_js(args[2]["value"])
        flags_val = args[3]["value"] if len(args) > 3 else ""
        regex = _wildcard_replace_glob_to_regex(pattern)
        i_flag = "" if flags_val == "s" else "i"
        return f"{field_js}.replace(/{regex}/{i_flag}, {js_string(replacement)})"

    if func == "lower":
        return f"{dyn_expr_to_js(args[0], target)}.toLowerCase()"
    if func == "upper":
        return f"{dyn_expr_to_js(args[0], target)}.toUpperCase()"
    if func == "to_string":
        return f"String({dyn_expr_to_js(args[0], target)})"
    if func == "substring":
        field_js = dyn_expr_to_js(args[0], target)
        start = dyn_expr_to_js(args[1], target)
        if len(args) > 2:
            end = dyn_expr_to_js(args[2], target)
            return f"{field_js}.substring({start}, {end})"
        return f"{field_js}.substring({start})"
    if func == "len":
        return f"{dyn_expr_to_js(args[0], target)}.length"
    if func == "url_decode":
        field_js = dyn_expr_to_js(args[0], target)
        if len(args) > 1 and "r" in str(args[1].get("value", "")):
            return f"(()=>{{let p='',c={field_js};while(c!==p){{p=c;c=decodeURIComponent(c)}}return c}})()"
        return f"decodeURIComponent({field_js})"

    if func == "encode_base64":
        inner = args[0]
        flags_val = args[1]["value"] if len(args) > 1 else ""
        # Optimize: encode_base64(sha256(...)) → digest('base64')
        if inner["type"] == "func_call" and inner["func"] == "sha256":
            sha_field = dyn_expr_to_js(inner["args"][0], target)
            enc = "base64url" if "u" in flags_val else "base64"
            result = f"crypto.createHash('sha256').update({sha_field}).digest('{enc}')"
            if "p" not in flags_val and "u" not in flags_val:
                result += ".replace(/=+$/, '')"
            return result
        field_js = dyn_expr_to_js(inner, target)
        if "u" in flags_val:
            result = f"Buffer.from({field_js}, 'utf8').toString('base64url')"
            if "p" in flags_val:
                b64_expr = f"Buffer.from({field_js}, 'utf8').toString('base64url')"
                result = f"(()=>{{const b={b64_expr};return b+'='.repeat((4-b.length%4)%4)}})()"
            return result
        if "p" in flags_val:
            return f"Buffer.from({field_js}, 'utf8').toString('base64')"
        return f"Buffer.from({field_js}, 'utf8').toString('base64').replace(/=+$/, '')"

    if func == "decode_base64":
        return f"atob({dyn_expr_to_js(args[0], target)})"

    if func == "sha256":
        field_js = dyn_expr_to_js(args[0], target)
        return f"crypto.createHash('sha256').update({field_js}).digest()"

    if func in ("lookup_json_string", "lookup_json_integer"):
        field_js = dyn_expr_to_js(args[0], target)
        keys = []
        for a in args[1:]:
            if a["type"] == "literal" and isinstance(a["value"], int):
                keys.append(f"[{a['value']}]")
            else:
                keys.append(f"[{js_string(a['value'])}]")
        chain = "".join(keys)
        default = "''" if func == "lookup_json_string" else "0"
        return f"(()=>{{try{{return JSON.parse({field_js}){chain}}}catch(e){{return {default}}}}})()"

    if func == "split":
        field_js = dyn_expr_to_js(args[0], target)
        sep = dyn_expr_to_js(args[1], target)
        if len(args) > 2:
            limit = dyn_expr_to_js(args[2], target)
            return f"{field_js}.split({sep}, {limit})"
        return f"{field_js}.split({sep})"

    if func == "join":
        items_js = dyn_expr_to_js(args[0], target)
        sep = dyn_expr_to_js(args[1], target)
        return f"{items_js}.join({sep})"

    if func == "remove_query_args":
        field_js = dyn_expr_to_js(args[0], target)
        param_names = ", ".join(js_string(a["value"]) for a in args[1:])
        return (f"(()=>{{const qs={field_js};if(!qs)return '';"
                f"const rm=new Set([{param_names}]);"
                f"return qs.split('&').filter(p=>!rm.has(p.split('=')[0])).join('&')}})()")

    if func == "remove_bytes":
        field_js = dyn_expr_to_js(args[0], target)
        bytes_str = args[1]["value"] if len(args) > 1 else ""
        chars = []
        i = 0
        while i < len(bytes_str):
            if bytes_str[i:i+2] == "\\x" and i + 3 < len(bytes_str):
                ch = chr(int(bytes_str[i+2:i+4], 16))
                chars.append(ch)
                i += 4
            else:
                chars.append(bytes_str[i])
                i += 1
        regex_chars = ""
        for ch in chars:
            if ch in r"\]^-./":
                regex_chars += "\\" + ch
            else:
                regex_chars += ch
        return f"{field_js}.replace(/[{regex_chars}]/g, '')"

    if func == "uuidv4":
        return ("(()=>{{return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>"
                "{{const r=Math.random()*16|0;return(c==='x'?r:(r&0x3|0x8)).toString(16)}})"
                "/* WARNING: not cryptographically secure */}})()")

    return f"/* unsupported function: {func} */"


# ── Header value substitution ────────────────────────────────────────────────

def _header_value_to_js(value, target="cff"):
    """Convert header value, handling $viewer_ip substitution."""
    if value == "$viewer_ip":
        return "event.viewer.ip" if target != "lambda" else "request.clientIp"
    if isinstance(value, str) and value.startswith("$"):
        return f"{js_string(value)} /* WARNING: unresolved variable */"
    return js_string(value)


# ── JS file assembly ─────────────────────────────────────────────────────────

def _resolve_static_value(params, key):
    """Resolve a params value that is a plain static string (never an expression)."""
    return js_string(params.get(key, ""))


def _resolve_expression_value(params, key, target="cff"):
    """Resolve a params value that is ALWAYS a Cloudflare dynamic expression.

    Unlike the old function-name heuristic, this parses every expression — so a
    bare field reference like `ip.src` or `http.host` is resolved to its JS
    accessor instead of being emitted as a string literal. Non-convertible
    fields are screened out upstream in the processor (value_expression_unmappable),
    so a parse/translate failure here falls back to an empty string with a
    warning rather than emitting a raw field name.
    """
    val = params.get(key, "")
    if not val:
        return js_string("")
    try:
        tree = parse_dynamic_expression(val)
        return dyn_expr_to_js(tree, target)
    except Exception as e:
        print(f"  WARN: dynamic expression parse failed, dropping value: {val[:60]}... ({e})", file=sys.stderr)
        # Emit an empty string but tag it with the same leak marker the
        # unmappable-field path uses, so cdn-validate-js flags the dropped value
        # instead of it silently shipping as an empty header/redirect/URI.
        return "'' /* WARNING: no CloudFront source for unparsed expression */"


def _protocol_for_port(port):
    """Infer the origin protocol for cf.updateRequestOrigin's customOriginConfig.
    Cloudflare Origin Rules override the destination PORT but carry no scheme
    (Cloudflare's origin scheme comes from the zone SSL/TLS mode, not the rule).
    customOriginConfig requires protocol whenever port is set, so infer it from
    the port: 80/8080 → http, everything else (443/8443/…) → https."""
    return "http" if port in (80, 8080) else "https"


def _generate_op_js(op, target="cff", indent="  "):
    """Generate JS code for a single viewer_request op."""
    lines = []
    op_type = op.get("type", "")
    params = op.get("params", {})
    cond = op.get("condition")
    raw_expr = op.get("raw_expression")
    desc = op.get("description", "")

    # Resolve condition
    if raw_expr and not cond:
        try:
            cond = parse_expression_full(raw_expr)
        except Exception as e:
            # Genuinely unparseable condition — DROP the op (fail closed: never
            # emit its action unconditionally, which would fire on every
            # request). Loudly flagged so it surfaces; the op's action is not
            # applied. (This is rare: the processor defers to raw only when the
            # full parser can't structure the text.)
            print(f"  WARN: NON_CONVERTIBLE op '{op_type}' — condition unparseable, "
                  f"op dropped: {raw_expr[:80]} ({e})", file=sys.stderr)
            lines.append(f"{indent}// NON_CONVERTIBLE: unparseable condition, op dropped: {raw_expr[:80]}")
            return lines

    cond_js = condition_to_js(cond, target)

    if op_type == "redirect":
        if params.get("target_expression"):
            target_url = _resolve_expression_value(params, "target_expression", target)
        else:
            target_url = _resolve_static_value(params, "target_url")
        status = params.get("status_code", 301)
        # preserve_query_string: append the incoming raw query to the target,
        # picking the delimiter (? vs &) based on whether the target already has
        # a query. Cloudflare's flag carries the original request query through.
        if params.get("preserve_query_string"):
            raw_qs = "request.querystring" if target == "lambda" else "_qs(request.querystring)"
            loc_var = "__loc"
            # `let` (block-scoped), not `var` (function-scoped): several redirect
            # ops can land in one handler, and repeated `var __loc`/`var __q`
            # trips the CloudFront console linter ("already defined"). Each op's
            # `let` lives inside its own `if (...) { }` block, so no clash.
            body = (f"let {loc_var} = {target_url}; "
                    f"let __q = {raw_qs}; "
                    f"if (__q) {{ {loc_var} += ({loc_var}.indexOf('?') === -1 ? '?' : '&') + __q; }} "
                    f"return {{statusCode: {status}, headers: {{location: {{value: {loc_var}}}}}}};")
        else:
            body = f"return {{statusCode: {status}, headers: {{location: {{value: {target_url}}}}}}};"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "rewrite":
        stmts = []
        # Path rewrite (only if the rule actually sets a path)
        if params.get("path_expression"):
            stmts.append(f"request.uri = {_resolve_expression_value(params, 'path_expression', target)};")
        elif params.get("path"):
            stmts.append(f"request.uri = {_resolve_static_value(params, 'path')};")
        # Query rewrite. CloudFront Functions accept a raw string assigned to
        # request.querystring (AWS-confirmed), same as Lambda@Edge — so a
        # computed/static query string can be written directly.
        if params.get("query_expression"):
            stmts.append(f"request.querystring = {_resolve_expression_value(params, 'query_expression', target)};")
        elif params.get("new_query") is not None and params.get("new_query") != "":
            stmts.append(f"request.querystring = {_resolve_static_value(params, 'new_query')};")
        body = " ".join(stmts)
        if not body:
            return lines  # nothing to rewrite
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "origin_override":
        # origin_override is CFF-only (viewer events never use Lambda@Edge — see
        # round-14). `Host` is READ-ONLY in a viewer-request CFF (assigning
        # request.headers.host → HTTP 502), so the origin Host is set via
        # updateRequestOrigin's `hostHeader`. Any key omitted from the call is
        # INHERITED from the request's assigned origin, so emit only what the
        # Cloudflare rule actually overrides.
        origin_host = params.get("origin_host", "")
        host_header = params.get("host_header", "")
        port = params.get("origin_port")
        sni = params.get("sni")
        uro_parts = []
        if origin_host:  # a Host-only override leaves this empty — don't blank the origin
            uro_parts.append(f"domainName: {js_string(origin_host)}")
        if port:
            # customOriginConfig requires port + protocol + sslProtocols together
            # (AWS docs). Cloudflare's rule has no scheme, so infer protocol from
            # the port rather than hardcoding https.
            proto = _protocol_for_port(port)
            uro_parts.append(
                f"customOriginConfig: {{port: {port}, protocol: '{proto}', sslProtocols: ['TLSv1.2']}}")
        if sni:
            uro_parts.append(f"sni: {js_string(sni)}")
        if host_header and host_header != origin_host:
            uro_parts.append(f"hostHeader: {js_string(host_header)}")
        if not uro_parts:
            return lines  # no-op override — nothing to emit
        body = f"cf.updateRequestOrigin({{{', '.join(uro_parts)}}});"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "bulk_redirect":
        # Handled as a fixed template block, not per-op
        pass

    elif op_type in ("set_request_header", "set_response_header", "set_header"):
        name = params.get("name", "").lower()
        value = params.get("value", "")
        value_expr = params.get("value_expression")
        if value_expr:
            val_js = _resolve_expression_value(params, "value_expression", target)
        else:
            val_js = _header_value_to_js(value, target)
        header_obj = "response.headers" if "response" in op_type else "request.headers"
        body = f"{header_obj}[{js_string(name)}] = {{value: {val_js}}};"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type in ("add_request_header", "add_response_header", "add_header"):
        name = params.get("name", "").lower()
        value = params.get("value", "")
        value_expr = params.get("value_expression")
        if value_expr:
            val_js = _resolve_expression_value(params, "value_expression", target)
        else:
            val_js = _header_value_to_js(value, target)
        header_obj = "response.headers" if "response" in op_type else "request.headers"
        body = f"if (!{header_obj}[{js_string(name)}]) {{ {header_obj}[{js_string(name)}] = {{value: {val_js}}}; }}"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type in ("remove_request_header", "remove_response_header", "remove_header"):
        name = params.get("name", "").lower()
        header_obj = "response.headers" if "response" in op_type else "request.headers"
        body = f"delete {header_obj}[{js_string(name)}];"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "serve_error_inline":
        kvs_key = params.get("kvs_key", "")
        status = params.get("status_code", 500)
        content_type = params.get("content_type", "text/html")
        body = (f"const body = await kvsHandle.get({js_string(kvs_key)}); "
                f"return {{statusCode: {status}, statusDescription: 'Custom Error', "
                f"headers: {{'content-type': {{value: {js_string(content_type)}}}}}, "
                f"body: {{encoding: 'text', data: body}}}};")
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {body} }}")
        else:
            lines.append(f"{indent}{body}")

    elif op_type == "cache_bypass":
        # Cloudflare "Bypass cache" for matching requests. CloudFront can't skip
        # the cache at request time, so force a guaranteed MISS: inject a header
        # with a per-request-unique value that is part of the cache key (the
        # cache policy whitelists CACHE_BYPASS_HEADER). Every matching request
        # then gets a unique key → always a miss → always fetched from origin.
        #
        # The value is FOUR Math.random() segments joined by '-'. Math.random()
        # in CloudFront Functions is a per-invocation CSPRNG (arc4random); string
        # CONCATENATION preserves each segment's ~52 bits (≈208 bits total), so
        # cross-request collisions are impossible — a collision would let one
        # user's personalized page be served from cache to another (silent data
        # leak). Do NOT add/multiply the randoms: that collapses them back into a
        # single float (≤52 bits) and skews the distribution.
        #
        # The else-branch DELETE is mandatory: without it a client could send the
        # header itself on a NON-matching (e.g. anonymous) request and split /
        # poison the shared cache. Stripping it for non-matching requests keeps
        # them on one clean cache entry. (Both verified live on CloudFront.)
        hdr = js_string(CACHE_BYPASS_HEADER)
        buster = ("''+Math.random()+'-'+Math.random()+'-'"
                  "+Math.random()+'-'+Math.random()")
        set_stmt = f"request.headers[{hdr}] = {{value: {buster}}};"
        del_stmt = f"delete request.headers[{hdr}];"
        if cond_js:
            lines.append(f"{indent}if ({cond_js}) {{ {set_stmt} }} else {{ {del_stmt} }}")
        else:
            # No condition → unconditional bypass is handled as a CachingDisabled
            # policy upstream, never as this op. Emit the set defensively.
            lines.append(f"{indent}{set_stmt}")

    else:
        lines.append(f"{indent}// TODO: unsupported op type: {op_type}")

    return lines


def _ops_need_kvs(ops):
    """Check if a specific handler's op list needs a cf.kvs() handle at runtime.

    Used per-handler so a response-only KVS need (continent in a viewer-response
    rule) doesn't leak `cf.kvs()` into the viewer-request handler that never uses
    it. bulk_redirect and serve_error_inline read KVS via their templates;
    _op_uses_kvs covers continent/is_eu preamble and in_kvs/not_in_kvs."""
    return any(
        op.get("type") in ("bulk_redirect", "serve_error_inline") or _op_uses_kvs(op)
        for op in ops
    )


def _needs_qs_helper(all_ops):
    """_qs is always injected in CFF — 180 bytes, negligible vs 10KB limit.
    Avoids detection gaps (bulk redirect, conditions, dynamic expressions)."""
    return True


def _qs_helper_lines(indent="  "):
    """The `_qs` helper that rebuilds CFF's parsed querystring object into a raw
    string. Shared by the viewer-request and viewer-response handlers (a
    uri.query condition renders `_qs(request.querystring)` in either)."""
    # Inner `for` loop, not `.forEach(function(){})`: a function defined inside
    # the `for (var k in q)` loop that closes over `p`/`k` trips the CloudFront
    # console linter ("functions declared within loops... confusing semantics").
    # A plain nested loop has no closure and no warning.
    return [
        f"{indent}function _qs(q) {{",
        f"{indent}  var p = [];",
        f"{indent}  for (var k in q) {{",
        f"{indent}    if (q[k].multiValue) {{",
        f"{indent}      for (var i = 0; i < q[k].multiValue.length; i++) {{ p.push(k + '=' + q[k].multiValue[i].value); }}",
        f"{indent}    }} else {{",
        f"{indent}      p.push(k + '=' + q[k].value);",
        f"{indent}    }}",
        f"{indent}  }}",
        f"{indent}  return p.join('&');",
        f"{indent}}}",
    ]


def _needs_cookie_str_helper(all_ops):
    """True if any op condition references http.cookie (the whole-Cookie-string
    field), which renders as _cookieStr(request.cookies). Only that field needs
    the helper — cookie_named existence uses a direct map lookup, no helper."""
    return any(_cond_has_field(op.get("condition"), ("cookie",)) for op in all_ops)


def _cookie_str_helper_lines(indent="  "):
    """The `_cookieStr` helper that rebuilds Cloudflare's http.cookie value — the
    whole Cookie header string — from CFF's parsed request.cookies map. CFF does
    not expose the raw Cookie header, so a `http.cookie contains "…"` match is
    run against this reconstruction. Pairs are `name=value` joined by '; ' (the
    Cookie header separator); duplicate-name cookies expand via multiValue."""
    # Inner `for` loop, not `.forEach(function(){})` — same linter reason as _qs.
    return [
        f"{indent}function _cookieStr(c) {{",
        f"{indent}  var p = [];",
        f"{indent}  for (var k in c) {{",
        f"{indent}    if (c[k].multiValue) {{",
        f"{indent}      for (var i = 0; i < c[k].multiValue.length; i++) {{ p.push(k + '=' + c[k].multiValue[i].value); }}",
        f"{indent}    }} else {{",
        f"{indent}      p.push(k + '=' + c[k].value);",
        f"{indent}    }}",
        f"{indent}  }}",
        f"{indent}  return p.join('; ');",
        f"{indent}}}",
    ]


def _cond_uses_query(ops):
    """True if any op condition references uri.query (renders _qs(...))."""
    return any(_cond_has_field(op.get("condition"), ("uri.query",)) for op in ops)


def _needs_crypto(ops):
    """Check if any op in the given list uses sha256/hmac (needs crypto import).

    Scans a single handler's op list (viewer-request OR viewer-response) so each
    generator emits `import crypto` based on its own ops — a response-only
    sha256() must pull the import into the response file, and a request-only one
    must not force it into the response file.
    """
    for op in ops:
        params = op.get("params", {})
        # Only expression-valued keys can carry sha256(...); target_url is a
        # static string and never an expression, so it is not checked here.
        for key in ("value_expression", "target_expression", "path_expression", "query_expression"):
            val = params.get(key, "")
            if val and ("sha256(" in val or "encode_base64(sha256(" in val):
                return True
    return False


def _op_uses_continent_eu(op, which=("continent", "is_eu")):
    """True if an op references continent/is_eu — in its structured condition OR
    in a deferred raw_expression (an OR expression defers to raw text, so a
    structured-only scan would miss it and the preamble would be skipped,
    leaving `continent`/`isEU` undefined in the emitted JS)."""
    cond = op.get("condition")
    if cond and _cond_has_field(cond, which):
        return True
    raw = op.get("raw_expression") or ""
    if "continent" in which and "ip.src.continent" in raw:
        return True
    if "is_eu" in which and "ip.src.is_in_european_union" in raw:
        return True
    return False


def _cond_has_op(cond, ops):
    """True if any leaf in the condition tree uses one of the given ops
    (e.g. in_kvs / not_in_kvs — which call kvsHandle and thus need cf.kvs())."""
    if cond is None:
        return False
    if cond.get("op") in ops:
        return True
    return any(_cond_has_op(c, ops) for c in iter_condition_children(cond))


def _op_uses_kvs(op):
    """True if an op needs a KVS handle at runtime — a continent/is_eu preamble
    lookup, an ip.src in_kvs/not_in_kvs membership test, or an inline error page
    served from KVS (serve_error_inline). Single source of truth for both the
    response-JS `cf.kvs()` emission and the Terraform KVS association."""
    if op.get("type") == "serve_error_inline":
        return True
    return _op_uses_continent_eu(op) or _cond_has_op(op.get("condition"), ("in_kvs", "not_in_kvs"))


def _has_continent_or_eu(ops):
    """Check if any op references continent or is_eu (structured or raw)."""
    return any(_op_uses_continent_eu(op) for op in ops)


def _cond_has_field(cond, fields):
    if cond is None:
        return False
    if cond.get("field") in fields:
        return True
    return any(_cond_has_field(c, fields) for c in iter_condition_children(cond))


def _generate_bulk_redirect_block(indent="  "):
    """Generate the fixed bulk_redirect KVS lookup template."""
    return [
        f"{indent}const host = request.headers.host.value;",
        f"{indent}const uri = request.uri;",
        f"{indent}let kv = null;",
        f"{indent}try {{ kv = await kvsHandle.get('redirect:' + host + uri); }} catch(e) {{}}",
        f"{indent}if (kv === null && host.includes('.')) {{",
        f"{indent}  try {{ kv = await kvsHandle.get('redirect:.' + host + uri); }} catch(e) {{}}",
        f"{indent}}}",
        f"{indent}if (kv !== null) {{",
        f"{indent}  const pts = kv.split('|');",
        f"{indent}  const sc = parseInt(pts[0], 10);",
        f"{indent}  let tgt = pts[2];",
        f"{indent}  if (pts[1] === '1') {{",
        f"{indent}    const qs = _qs(request.querystring);",
        f"{indent}    if (qs) {{ tgt = tgt + (tgt.includes('?') ? '&' : '?') + qs; }}",
        f"{indent}  }}",
        f"{indent}  return {{statusCode: sc, headers: {{location: {{value: tgt}}}}}};",
        f"{indent}}}",
    ]


def _generate_continent_preamble(ops, indent="  "):
    """Generate KVS lookup preamble for continent/is_eu conditions."""
    needs_continent = any(_op_uses_continent_eu(op, ("continent",)) for op in ops)
    needs_eu = any(_op_uses_continent_eu(op, ("is_eu",)) for op in ops)
    if not needs_continent and not needs_eu:
        return []
    lines = [
        f"{indent}const countryHeader = request.headers['cloudfront-viewer-country'];",
        f"{indent}const country = countryHeader ? countryHeader.value : '';",
    ]
    if needs_continent:
        cvar = _PREAMBLE_ACCESSORS["continent"]
        lines.append(f"{indent}let {cvar} = '';")
        lines.append(f"{indent}if (country) {{ try {{ {cvar} = await kvsHandle.get('continent:' + country); }} catch(e) {{}} }}")
    if needs_eu:
        evar = _PREAMBLE_ACCESSORS["is_eu"]
        lines.append(f"{indent}let {evar} = false;")
        lines.append(f"{indent}if (country) {{ try {{ {evar} = await kvsHandle.exists('eu:' + country); }} catch(e) {{}} }}")
    return lines


def generate_viewer_request_js(ir, target="cff"):
    """Generate complete viewer_request.js content."""
    lines = []
    request_ops = [op for beh in ir.get("cache_behaviors", [])
                   for op in beh.get("viewer_request_ops", [])]
    # Compute KVS need from THIS handler's ops (not the domain-wide flag) so a
    # response-only KVS need doesn't emit an unused cf.kvs() here (finding #5).
    needs_kvs_flag = _ops_need_kvs(request_ops)
    needs_crypto_flag = _needs_crypto(request_ops)

    # Imports
    if needs_kvs_flag or any(op.get("type") == "origin_override" for op in request_ops):
        lines.append("import cf from 'cloudfront';")
    if needs_crypto_flag:
        lines.append("import crypto from 'crypto';")

    # KVS init. cf.kvs() takes NO argument — the store is bound to the function
    # via Terraform `key_value_store_associations` (a function has exactly one
    # KVS), so the runtime resolves it with no ID in code.
    if needs_kvs_flag:
        lines.append("const kvsHandle = cf.kvs();")

    lines.append("async function handler(event) {")
    lines.append("  const request = event.request;")

    # Collect all viewer_request_ops across behaviors (already gathered above)
    all_ops = request_ops

    # Inject _qs helper when query string reconstruction is needed (CFF only).
    # CFF request.querystring is a parsed object; _qs rebuilds the raw string.
    # Lambda@Edge request.querystring is already a raw string — no helper needed.
    if target == "cff" and _needs_qs_helper(all_ops):
        lines.extend(_qs_helper_lines())

    # _cookieStr helper — rebuilds http.cookie (whole Cookie string) from the
    # parsed request.cookies map. CFF only (Lambda@Edge has the raw header).
    if target == "cff" and _needs_cookie_str_helper(all_ops):
        lines.extend(_cookie_str_helper_lines())

    # Continent/EU preamble
    if _has_continent_or_eu(all_ops):
        lines.extend(_generate_continent_preamble(all_ops))

    # Group ops by type for section ordering
    redirects = [o for o in all_ops if o.get("type") == "redirect"]
    rewrites = [o for o in all_ops if o.get("type") == "rewrite"]
    origins = [o for o in all_ops if o.get("type") == "origin_override"]
    bulk = [o for o in all_ops if o.get("type") == "bulk_redirect"]
    headers = [o for o in all_ops if o.get("type", "").endswith("_header") or "header" in o.get("type", "")]
    errors = [o for o in all_ops if o.get("type") == "serve_error_inline"]
    bypasses = [o for o in all_ops if o.get("type") == "cache_bypass"]

    for section_ops in [redirects, rewrites, origins]:
        for op in section_ops:
            lines.extend(_generate_op_js(op, target))

    if bulk:
        lines.extend(_generate_bulk_redirect_block())

    # Cache-bypass is emitted BEFORE header transforms: a Cloudflare Cache Rule
    # evaluates against the ORIGINAL viewer request, so the bypass condition
    # (cookie/path/query) must be tested before a request-header-transform rule
    # in the same CFF can mutate a header it might read. This mirrors Cloudflare's
    # phase order (cache rules run before late request-header transforms) and the
    # IR op order (cache rules are processed before header rules).
    for op in bypasses:
        lines.extend(_generate_op_js(op, target))

    for op in headers:
        lines.extend(_generate_op_js(op, target))
    for op in errors:
        lines.extend(_generate_op_js(op, target))

    lines.append("  return request;")
    lines.append("}")
    return "\n".join(lines)


def generate_viewer_response_js(ir):
    """Generate viewer_response.js content. Returns None if not needed."""
    all_ops = []
    for beh in ir.get("cache_behaviors", []):
        all_ops.extend(beh.get("viewer_response_ops", []))
    if not all_ops:
        return None

    lines = []
    needs_kvs = any(_op_uses_kvs(op) for op in all_ops)
    if needs_kvs:
        lines.append("import cf from 'cloudfront';")
        # cf.kvs() takes no argument — bound via Terraform key_value_store_associations.
        lines.append("const kvsHandle = cf.kvs();")
    # crypto import is independent of KVS — a response header value using
    # sha256()/HMAC emits crypto.createHash and would otherwise ReferenceError.
    if _needs_crypto(all_ops):
        lines.append("import crypto from 'crypto';")

    lines.append("async function handler(event) {")
    lines.append("  const response = event.response;")
    # A viewer-response condition may reference the original request (geo
    # headers like cloudfront-viewer-country, full_uri reconstruction, the
    # continent/EU preamble). event.request is populated in viewer-response
    # (AWS-confirmed), so expose it under the same `request` name the accessors
    # and preamble use.
    lines.append("  const request = event.request;")

    # _qs helper — a uri.query condition renders `_qs(request.querystring)` here
    # too; without the helper it's a ReferenceError. (viewer-response is always
    # the CFF target, where querystring is a parsed object.)
    if _cond_uses_query(all_ops):
        lines.extend(_qs_helper_lines())

    # _cookieStr helper — a http.cookie condition on a response op rebuilds the
    # Cookie string from event.request.cookies (viewer-response is CFF).
    if _needs_cookie_str_helper(all_ops):
        lines.extend(_cookie_str_helper_lines())

    # Continent/EU preamble — same KVS-backed country lookup as viewer-request
    # (KVS reads work in viewer-response). Without it, a continent/is_eu
    # condition would reference an undefined variable.
    if _has_continent_or_eu(all_ops):
        lines.extend(_generate_continent_preamble(all_ops))

    for op in all_ops:
        lines.extend(_generate_op_js(op, "response"))

    lines.append("  return response;")
    lines.append("}")
    return "\n".join(lines)




def _generate_origin_response_template(config):
    """Generate Lambda@Edge origin-response handler from config."""
    lines = [
        "'use strict';",
        "",
        "exports.handler = async (event, context, callback) => {",
        "  const response = event.Records[0].cf.response;",
        "  const request = event.Records[0].cf.request;",
    ]
    mappings = config if isinstance(config, list) else config.get("error_mappings", [])
    for m in mappings:
        status = m.get("status_code", 500)
        body = m.get("body", "").replace("'", "\\'").replace("\n", "\\n")
        content_type = m.get("content_type", "text/html")
        lines.append(f"  if (response.status === '{status}') {{")
        lines.append(f"    response.body = '{body}';")
        lines.append(f"    response.headers['content-type'] = [{{key: 'Content-Type', value: '{content_type}'}}];")
        lines.append(f"  }}")
    lines.append("  callback(null, response);")
    lines.append("};")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-generate-js.py <output_dir>", file=sys.stderr)
        sys.exit(2)

    output_dir = sys.argv[1]
    ir_dir = os.path.join(output_dir, "ir", "final")

    if not os.path.isdir(ir_dir):
        print(f"---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: IR directory not found: {ir_dir}")
        sys.exit(2)

    ir_files = sorted(Path(ir_dir).glob("*.json"))
    if not ir_files:
        print(f"---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: No IR files found in {ir_dir}")
        sys.exit(2)

    # ── Phase 1: Generate all JS in memory ───────────────────────────────────

    all_irs = {}
    all_vr = {}   # san → viewer_request JS string
    all_vresp = {}  # san → viewer_response JS string (or None)
    failed = []

    for ir_file in ir_files:
        with open(ir_file) as f:
            ir = json.load(f)
        hostname = ir["metadata"]["hostname"]
        sanitized = ir["metadata"]["sanitized_name"]
        all_irs[sanitized] = ir

        # Generate both viewer handlers. VIEWER EVENTS ARE CFF-ONLY: this tool
        # never falls back to Lambda@Edge for viewer-request/response (L@E adds
        # latency/cost and changes the execution model). If a handler exceeds the
        # 10 KB CFF hard limit even after minification, the domain is reported
        # SIZE_EXCEEDED for human intervention — it is NOT silently escalated to
        # L@E. (origin_override therefore always stays in the CFF as
        # cf.updateRequestOrigin; L@E is used only for genuine ORIGIN events like
        # the default-cache/custom-error origin-response, handled elsewhere.)
        vr_js = generate_viewer_request_js(ir)
        vr_size = len(vr_js.encode("utf-8"))
        if vr_size > CFF_SIZE_LIMIT:
            vr_js = minify_js(vr_js)
            vr_size = len(vr_js.encode("utf-8"))

        vresp_js = generate_viewer_response_js(ir)
        vresp_size = len(vresp_js.encode("utf-8")) if vresp_js else 0
        if vresp_size > CFF_SIZE_LIMIT:
            vresp_js = minify_js(vresp_js)
            vresp_size = len(vresp_js.encode("utf-8"))

        # Either handler over the hard limit fails the whole domain (a CFF can't
        # be partially deployed, and request/response are one logical unit).
        over = []
        if vr_size > CFF_SIZE_LIMIT:
            over.append(f"viewer-request {vr_size}B")
        if vresp_size > CFF_SIZE_LIMIT:
            over.append(f"viewer-response {vresp_size}B")
        if over:
            failed.append((hostname, "SIZE_EXCEEDED",
                           f"{', '.join(over)} > {CFF_SIZE_LIMIT}B hard limit after minify"))
            continue

        all_vr[sanitized] = vr_js
        all_vresp[sanitized] = vresp_js
        print(f"[JS] {hostname}: generated (vr {vr_size}B, vresp {vresp_size}B)", file=sys.stderr)

    if not all_vr:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\nCONTEXT: All domains failed JS generation")
        sys.exit(2)

    # ── Phase 2: Content-hash dedup ──────────────────────────────────────────

    vr_groups = {}  # hash → {"js": str, "domains": [san, ...]}
    for san, js in all_vr.items():
        h = hashlib.sha256(js.encode()).hexdigest()[:12]
        vr_groups.setdefault(h, {"js": js, "domains": []})["domains"].append(san)

    vresp_groups = {}
    for san, js in all_vresp.items():
        if js is None:
            continue
        h = hashlib.sha256(js.encode()).hexdigest()[:12]
        vresp_groups.setdefault(h, {"js": js, "domains": []})["domains"].append(san)

    domain_cff_config = {}
    shared_cffs = []

    for h, group in vr_groups.items():
        if len(group["domains"]) >= 2:
            name = shared_cff_name(h, "viewer_request")
            for ci in range(0, len(group["domains"]), MAX_CFF_ASSOCIATIONS):
                chunk = group["domains"][ci:ci + MAX_CFF_ASSOCIATIONS]
                cn = name if ci == 0 else f"{name}-{ci // MAX_CFF_ASSOCIATIONS + 1}"
                shared_cffs.append({"hash": h, "event_type": "viewer_request",
                                    "name": cn, "js": group["js"], "domains": chunk})
                for san in chunk:
                    domain_cff_config.setdefault(san, {})["viewer_request"] = {"mode": "shared", "name": cn}
        else:
            san = group["domains"][0]
            domain_cff_config.setdefault(san, {})["viewer_request"] = {
                "mode": "independent", "name": cff_name(san, "viewer_request")}

    for h, group in vresp_groups.items():
        if len(group["domains"]) >= 2:
            name = shared_cff_name(h, "viewer_response")
            for ci in range(0, len(group["domains"]), MAX_CFF_ASSOCIATIONS):
                chunk = group["domains"][ci:ci + MAX_CFF_ASSOCIATIONS]
                cn = name if ci == 0 else f"{name}-{ci // MAX_CFF_ASSOCIATIONS + 1}"
                shared_cffs.append({"hash": h, "event_type": "viewer_response",
                                    "name": cn, "js": group["js"], "domains": chunk})
                for san in chunk:
                    domain_cff_config.setdefault(san, {})["viewer_response"] = {"mode": "shared", "name": cn}
        else:
            san = group["domains"][0]
            domain_cff_config.setdefault(san, {})["viewer_response"] = {
                "mode": "independent", "name": cff_name(san, "viewer_response")}

    for san in all_vr:
        cfg = domain_cff_config.setdefault(san, {})
        if "viewer_response" not in cfg:
            cfg["viewer_response"] = {"mode": "none"}

    # ── Phase 3: Write files (atomic) ────────────────────────────────────────

    # KVS dedup: hash ALL kvs-data.json BEFORE cleanup (files get deleted below)
    shared_kvs_groups = []  # list of {"name": str, "domains": [...], "content": str}
    shared_kvs_domains = []  # flat list of all domains using shared KVS
    kvs_hashes = {}
    for san in all_vr:
        kvs_path = os.path.join(output_dir, "terraform", "domains", san, "kvs-data.json")
        if os.path.exists(kvs_path):
            with open(kvs_path, "rb") as f:
                content = f.read()
                kvs_hashes[san] = (hashlib.sha256(content).hexdigest()[:12], content.decode())

    if kvs_hashes:
        kvs_groups = {}
        for san, (h, _) in kvs_hashes.items():
            kvs_groups.setdefault(h, []).append(san)
        for h, domains in kvs_groups.items():
            if len(domains) >= 2:
                name = f"cf-shared-kvs-{h[:6]}"
                content = kvs_hashes[domains[0]][1]
                shared_kvs_groups.append({"name": name, "domains": domains, "content": content})
                shared_kvs_domains.extend(domains)

    # Clean up previous run
    shared_functions_dir = os.path.join(output_dir, "terraform", "shared", "functions")
    if os.path.isdir(shared_functions_dir):
        shutil.rmtree(shared_functions_dir)
    manifest_path = os.path.join(output_dir, "cff_dedup_manifest.json")
    if os.path.exists(manifest_path):
        os.remove(manifest_path)
    for san in all_vr:
        fd = os.path.join(output_dir, "terraform", "domains", san, "functions")
        if os.path.isdir(fd):
            shutil.rmtree(fd)

    # Remove per-domain KVS files for shared KVS domains
    if shared_kvs_domains:
        for san in shared_kvs_domains:
            domain_dir = os.path.join(output_dir, "terraform", "domains", san)
            for fname in ("kvs.tf", "kvs-data.json", "seed-kvs.py"):
                fpath = os.path.join(domain_dir, fname)
                if os.path.exists(fpath):
                    os.remove(fpath)

    # Shared JS files + functions.tf + KVS
    os.makedirs(shared_functions_dir, exist_ok=True)
    written_shared = set()
    shared_tf_lines = []

    # Build domain → shared KVS name mapping
    domain_to_shared_kvs = {}
    for grp in shared_kvs_groups:
        for san in grp["domains"]:
            domain_to_shared_kvs[san] = grp["name"]

    for cff in shared_cffs:
        if cff["name"] in written_shared:
            continue
        written_shared.add(cff["name"])
        with open(os.path.join(shared_functions_dir, f"{cff['name']}.js"), "w") as f:
            f.write(cff["js"])
        tf_id = cff["name"].replace("-", "_")
        comment_domains = ", ".join(cff["domains"][:2])
        if len(cff["domains"]) > 2:
            comment_domains += f", +{len(cff['domains']) - 2} more"
        shared_tf_lines += [
            f'resource "aws_cloudfront_function" "{tf_id}" {{',
            f'  name    = "{cff["name"]}"',
            f'  runtime = "cloudfront-js-2.0"',
            f'  publish = true',
            f'  comment = "Shared by {len(cff["domains"])} domains ({comment_domains})"',
            f'  code    = file("${{path.module}}/functions/{cff["name"]}.js")',
        ]
        # Add KVS association if this shared CFF uses KVS (check JS content for cf.kvs)
        if "cf.kvs(" in cff["js"] and shared_kvs_groups:
            # Safe to use domains[0]: if CFF content is identical, KVS data must also be
            # identical (KVS keys are derived from the same rules). Different KVS content
            # would produce different JS, which wouldn't be in the same CFF dedup group.
            sample_san = cff["domains"][0]
            kvs_name = domain_to_shared_kvs.get(sample_san)
            if kvs_name:
                kvs_tf_id = kvs_name.replace("-", "_")
                shared_tf_lines.append(f'  key_value_store_associations = [aws_cloudfront_key_value_store.{kvs_tf_id}.arn]')
        shared_tf_lines += ['}', '']

    # Add shared KVS resources to shared/functions.tf
    for grp in shared_kvs_groups:
        kvs_tf_id = grp["name"].replace("-", "_")
        shared_tf_lines += [
            f'resource "aws_cloudfront_key_value_store" "{kvs_tf_id}" {{',
            f'  name    = "{grp["name"]}"',
            f'  comment = "Shared KVS for {len(grp["domains"])} domains"',
            '}', '',
            f'output "{kvs_tf_id}_arn" {{',
            f'  value = aws_cloudfront_key_value_store.{kvs_tf_id}.arn',
            '}', '',
        ]
        # Generate per-group seed script and data file
        kvs_tf_id_for_seed = grp["name"].replace("-", "_")
        kvs_data_file = f"kvs-data-{grp['name']}.json" if len(shared_kvs_groups) > 1 else "kvs-data.json"
        seed_file = f"seed-kvs-{grp['name']}.py" if len(shared_kvs_groups) > 1 else "seed-kvs.py"
        shared_seed = f'''#!/usr/bin/env python3
"""Seed shared KVS data for {grp["name"]}. Run after 'cd terraform/shared && terraform apply'."""
import json, subprocess, sys, time

def main():
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        print("ERROR: boto3 required. Install with: pip install boto3", file=sys.stderr)
        sys.exit(1)

    result = subprocess.run(["terraform", "output", "-raw", "{kvs_tf_id_for_seed}_arn"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: terraform output failed. Run 'terraform apply' first.", file=sys.stderr)
        sys.exit(1)
    kvs_arn = result.stdout.strip()

    with open("{kvs_data_file}") as f:
        entries = json.load(f)["data"]
    if not entries:
        print("No KVS data to seed.")
        return

    client = boto3.client("cloudfront-keyvaluestore")
    etag = client.describe_key_value_store(KvsARN=kvs_arn)["ETag"]
    batch_size = 50
    total = len(entries)
    for i in range(0, total, batch_size):
        batch = entries[i:i + batch_size]
        puts = [{{"Key": e["key"], "Value": e["value"]}} for e in batch]
        for attempt in range(5):
            try:
                resp = client.update_keys(KvsARN=kvs_arn, IfMatch=etag, Puts=puts)
                etag = resp["ETag"]
                print(f"  Batch {{i // batch_size + 1}}/{{(total + batch_size - 1) // batch_size}}: {{len(batch)}} keys")
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ConflictException":
                    etag = client.describe_key_value_store(KvsARN=kvs_arn)["ETag"]
                elif code in ("ThrottlingException", "InternalServerException"):
                    time.sleep(2 ** attempt)
                else:
                    raise
        else:
            print(f"ERROR: batch {{i // batch_size + 1}} failed after 5 retries", file=sys.stderr)
            sys.exit(1)
    print(f"Done: {{total}} keys seeded into {grp['name']}")

if __name__ == "__main__":
    main()
'''
        with open(os.path.join(output_dir, "terraform", "shared", seed_file), "w") as f:
            f.write(shared_seed)

        with open(os.path.join(output_dir, "terraform", "shared", kvs_data_file), "w") as f:
            f.write(grp["content"])

    if shared_tf_lines:
        with open(os.path.join(output_dir, "terraform", "shared", "functions.tf"), "w") as f:
            f.write("\n".join(shared_tf_lines))

    # Per-domain files
    for san, config in domain_cff_config.items():
        ir = all_irs[san]
        domain_dir = os.path.join(output_dir, "terraform", "domains", san)
        functions_dir = os.path.join(domain_dir, "functions")

        if config.get("viewer_request", {}).get("mode") == "independent":
            os.makedirs(functions_dir, exist_ok=True)
            with open(os.path.join(functions_dir, f"{san}_viewer_request.js"), "w") as f:
                f.write(all_vr[san])
        if config.get("viewer_response", {}).get("mode") == "independent":
            os.makedirs(functions_dir, exist_ok=True)
            with open(os.path.join(functions_dir, f"{san}_viewer_response.js"), "w") as f:
                f.write(all_vresp[san])

        le_or = ir.get("metadata", {}).get("lambda_edge", {}).get("origin_response")
        if le_or:
            lambda_dir = os.path.join(domain_dir, "lambda")
            os.makedirs(lambda_dir, exist_ok=True)
            with open(os.path.join(lambda_dir, "default_cache_origin_response.js"), "w") as f:
                f.write(_generate_origin_response_template(le_or))

        _write_domain_functions_tf(san, config, ir, domain_dir,
                                   kvs_is_shared=(san in shared_kvs_domains),
                                   shared_kvs_name=domain_to_shared_kvs.get(san))

    # ── Phase 3b: Validate shared module terraform ─────────────────────────────

    shared_dir = os.path.join(output_dir, "terraform", "shared")
    if shared_tf_lines and os.path.isdir(shared_dir):
        init_result = subprocess.run(
            ["terraform", "init", "-backend=false"],
            cwd=shared_dir, capture_output=True, text=True)
        if init_result.returncode == 0:
            val_result = subprocess.run(
                ["terraform", "validate"],
                cwd=shared_dir, capture_output=True, text=True)
            if val_result.returncode != 0:
                print(f"  WARN: shared module terraform validate failed: {val_result.stdout.strip()}", file=sys.stderr)

    # ── Phase 4: Write manifest + append report ──────────────────────────────

    manifest = {"shared_functions": [
        {"name": c["name"], "event_type": c["event_type"], "hash": c["hash"],
         "domains": c["domains"], "file": f"shared/functions/{c['name']}.js"}
        for c in shared_cffs if c["name"] in written_shared
    ], "domain_config": domain_cff_config}
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    indep_count = sum(1 for cfg in domain_cff_config.values()
                      for v in cfg.values() if isinstance(v, dict) and v.get("mode") == "independent")
    actual_count = len(written_shared) + indep_count
    original_count = sum(1 for san in all_vr) + sum(1 for san, js in all_vresp.items() if js)

    report_path = os.path.join(output_dir, "conversion_report.md")
    if os.path.exists(report_path):
        with open(report_path, "a") as f:
            # Resource architecture explanation
            f.write(f"\n## Resource Architecture\n\n")
            f.write("Each domain gets one CloudFront distribution. Within a distribution, the domain shares one "
                    "viewer-request (and, if needed, one viewer-response) CloudFront Function, but the tool attaches it "
                    "**only to the cache behaviors that actually need it** — a CloudFront behavior does not inherit function "
                    "associations, so each is wired explicitly.\n\n")
            f.write("A behavior gets the CFF when:\n"
                    "- it has its own path-specific rule (e.g. a cache rule scoped to a URL pattern), or\n"
                    "- the zone has a **zone-wide** rule (no path condition: redirects, header transforms, bulk redirects, "
                    "a cookie/header-gated cache bypass) — those must run on every behavior to match Cloudflare's zone scope.\n\n"
                    "A behavior created only for a TTL / cache-key setting, with no rule logic of its own and no zone-wide rule, "
                    "is left **without** a CFF association automatically — you no longer need to prune it by hand.\n\n")
            f.write("Lambda@Edge (origin-response), when present, is associated only with the default cache behavior.\n\n")
            f.write("**Cost note**: Where your zone has zone-wide rules (bulk redirects, request header transforms), the CFF "
                    "runs on every request to every behavior — including static assets — because that is what Cloudflare's "
                    "zone-wide scope means. This faithfully replicates Cloudflare; behaviors that need no rule processing and "
                    "aren't covered by a zone-wide rule already carry no CFF.\n\n")

            # Per-domain resource mapping — grouped to avoid repetition
            f.write("### Per-Domain Resource Mapping\n\n")

            # Group domains by their resource profile
            profiles = {}  # (vr_mode, vresp_mode, kvs_label, le_type) → [(hostname, le_name)]
            for san in sorted(all_vr.keys()):
                ir = all_irs[san]
                hostname = ir["metadata"]["hostname"]
                cfg = domain_cff_config.get(san, {})
                vr_cfg = cfg.get("viewer_request", {})
                vresp_cfg = cfg.get("viewer_response", {})

                vr_label = f"shared: {vr_cfg['name']}" if vr_cfg.get("mode") == "shared" else f"`{cff_name(san, 'viewer_request')}` (independent)"
                vresp_label = "—"
                if vresp_cfg.get("mode") == "shared":
                    vresp_label = f"shared: {vresp_cfg['name']}"
                elif vresp_cfg.get("mode") == "independent":
                    vresp_label = f"`{cff_name(san, 'viewer_response')}` (independent)"

                kvs_label = "—"
                if san in shared_kvs_domains:
                    kvs_label = f"shared: {domain_to_shared_kvs.get(san, '?')}"
                elif os.path.exists(os.path.join(output_dir, "terraform", "domains", san, "kvs.tf")):
                    kvs_label = "independent"

                # For grouping, use event type only (actual names are per-domain).
                # Viewer events are CFF-only; the only L@E here is origin-response.
                le_type = "—"
                le_or = ir.get("metadata", {}).get("lambda_edge", {}).get("origin_response")
                if le_or:
                    le_type = "origin-response"

                key = (vr_label, vresp_label, kvs_label, le_type)
                profiles.setdefault(key, []).append(hostname)

            # Write grouped output
            for (vr_label, vresp_label, kvs_label, le_type), hostnames in sorted(profiles.items(), key=lambda x: -len(x[1])):
                if len(hostnames) > 5:
                    shown = ", ".join(hostnames[:3]) + f", ... (+{len(hostnames) - 3} more)"
                else:
                    shown = ", ".join(hostnames)
                f.write(f"**{len(hostnames)} domain(s)**: {shown}\n\n")
                f.write(f"| Resource | Value |\n")
                f.write(f"|----------|-------|\n")
                f.write(f"| CFF viewer-request | {vr_label} |\n")
                f.write(f"| CFF viewer-response | {vresp_label} |\n")
                f.write(f"| KVS | {kvs_label} |\n")
                if le_type != "—":
                    f.write(f"| Lambda@Edge | {le_type} (per-domain, named `cf-<domain>-le-oresp`) |\n\n")
                else:
                    f.write(f"| Lambda@Edge | {le_type} |\n\n")

            f.write(f"\n### Adjusting After Deployment\n\n")
            f.write("- **CFF association is already minimized**: the tool attaches the CFF only to behaviors that need it "
                    "(their own rule, or a zone-wide rule). You can prune further by deleting a behavior's "
                    "`function_associations` block in `main.tf`, but note any zone-wide bulk redirects / header transforms "
                    "will then no longer apply to that path.\n")
            f.write("- **Add path-specific logic to one domain only**: In the shared CFF, wrap the logic in "
                    "`if (event.request.headers.host.value === 'your-domain') { ... }`.\n")
            f.write("- **Move a domain from shared to independent CFF**: Create a new CFF resource in the domain's "
                    "`functions.tf`, update `locals.viewer_request_arn` to point to it, and copy+modify the JS.\n")

            # Dedup stats
            f.write(f"\n## CloudFront Functions Deduplication\n\n")
            f.write(f"- Original (without dedup): {original_count} CFF\n")
            f.write(f"- After dedup: {actual_count} CFF\n")
            f.write(f"- Shared: {len(written_shared)} functions\n")
            f.write(f"- Independent: {indep_count} functions\n")
            f.write(f"\n### Customizing After Migration\n\n")
            f.write(f"- **Modify rules for all domains**: Edit shared CFF in `terraform/shared/functions/`, then `cd terraform/shared && terraform apply`.\n")
            f.write(f"- **Add domain-specific logic**: Add a condition on `event.request.headers.host.value` in the shared CFF.\n")
            f.write(f"- **Add a new domain**: Create a module under `terraform/domains/`, use `data \"aws_cloudfront_function\"` to reference shared CFF by name.\n")
            f.write(f"- **Remove a domain**: `cd terraform/domains/<domain> && terraform destroy`.\n")

    # CFF quota check (post-dedup)
    if actual_count > 100:
        print(f"  WARN: CFF count {actual_count} exceeds default quota 100. "
              f"Contact AWS Support to inquire about increase, or deploy a subset of domains.", file=sys.stderr)
    elif actual_count > 80:
        print(f"  WARN: CFF count {actual_count} approaching default quota 100.", file=sys.stderr)

    # KVS quota check (POST-dedup — the real number of aws_cloudfront_key_value_store
    # resources). = shared groups (each shared by ≥2 domains) + standalone stores
    # (a domain whose KVS content is unique). cdn-finalize can't compute this (dedup
    # happens here), so it must be checked here, NOT counted per-host there.
    kvs_standalone = sum(1 for san in kvs_hashes if san not in shared_kvs_domains)
    kvs_total = len(shared_kvs_groups) + kvs_standalone
    # KVS-stores-per-account (50) is SOFT but raisable ONLY via an AWS Support
    # case — it has no Service Quotas console entry (no L- quota code), same as
    # the CFF-count quota above. Do NOT say "Service Quotas".
    kvs_warn = None
    if kvs_total > 50:
        kvs_warn = (f"{kvs_total} KeyValueStores exceed the default quota 50 (SOFT). "
                    f"Request an increase via an AWS Support case (this quota has no "
                    f"Service Quotas console entry) before deploying.")
    elif kvs_total > 40:
        kvs_warn = f"{kvs_total} KeyValueStores approaching default quota 50 (SOFT)."
    if kvs_warn:
        print(f"  WARN: {kvs_warn}", file=sys.stderr)

    # Augment cdn_summary.json (written by cdn-finalize) with post-dedup CFF/KVS
    # counts + any CFF/KVS quota warning, so the last step (cdn-validate-js) can
    # summarize them in the final ---RESULT---.
    #
    # cdn-finalize ALWAYS writes this file first (Stage 5, before this Stage 8).
    # If it's missing or unreadable here, something is wrong AND blindly starting
    # from {} would erase every warning cdn-finalize recorded — including a
    # QUOTA-REDESIGN hard-limit breach — then write the truncated dict back,
    # silently hiding a deploy blocker. So fail LOUD instead of failing open.
    summary_path = os.path.join(output_dir, "cdn_summary.json")
    try:
        with open(summary_path) as f:
            _summary = json.load(f)
    except Exception as e:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"CONTEXT: cdn_summary.json missing or unreadable ({e}). It is written by "
              f"cdn-finalize (Stage 5); re-run Stage 5 before Stage 8. Refusing to "
              f"continue — starting fresh would erase Stage-5 warnings (incl. any "
              f"deploy-blocking QUOTA-REDESIGN).", file=sys.stderr)
        sys.exit(2)
    _summary["cff_total"] = actual_count
    _summary["cff_dedup"] = f"{original_count} -> {actual_count}"
    _summary["kvs_total"] = kvs_total
    # Tag with QUOTA-RAISE so the final ---RESULT--- carries the same
    # raise-and-proceed signal as cdn-finalize's checks (both are SOFT quotas;
    # the conversion is correct, deploy is only blocked until the quota is
    # raised). BOTH the CFF-count and KVS-stores quotas are raised via an AWS
    # Support case, NOT the Service Quotas console.
    _extra = list(_summary.get("warnings", []))
    if actual_count > 100:
        _extra.append(f"QUOTA-RAISE — CloudFront Functions per account: {actual_count} "
                      f"exceeds the default quota 100 (SOFT). The conversion is correct; "
                      f"request an increase via AWS Support (not Service Quotas), then "
                      f"deploy unchanged. Or deploy a subset of domains. Blocked until raised.")
    if kvs_warn:
        # kvs_warn already describes the SOFT overage; tag it for the agent.
        _extra.append(f"QUOTA-RAISE — {kvs_warn}" if kvs_total > 50 else kvs_warn)
    _summary["warnings"] = _extra
    with open(summary_path, "w") as f:
        json.dump(_summary, f, indent=2, ensure_ascii=False)

    # ── Report ───────────────────────────────────────────────────────────────

    ok_count = len(all_vr)
    fail_count = len(failed)

    if fail_count == 0:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nDOMAINS: {ok_count}\nGENERATED: {ok_count}\n"
              f"CFF_TOTAL: {actual_count}\nCFF_SHARED: {len(written_shared)}\n"
              f"CFF_INDEPENDENT: {indep_count}\nCFF_DEDUP_RATIO: {original_count} -> {actual_count}\n"
              f"KVS_TOTAL: {kvs_total}")
    elif ok_count > 0:
        failed_items = "\n".join(f"  {h}: {s} — {d}" for h, s, d in failed)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: PARTIAL\nSUCCEEDED: {ok_count}\nFAILED: {fail_count}\n"
              f"CFF_TOTAL: {actual_count}\nCFF_SHARED: {len(written_shared)}\n"
              f"CFF_INDEPENDENT: {indep_count}\nCFF_DEDUP_RATIO: {original_count} -> {actual_count}\n"
              f"FAILED_ITEMS:\n{failed_items}\nACTION: FIX\n"
              f"{_SIZE_EXCEEDED_GUIDANCE}")
        sys.exit(3)
    else:
        failed_items = "\n".join(f"  {h}: {s} — {d}" for h, s, d in failed)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nFAILED: {fail_count}\n"
              f"FAILED_ITEMS:\n{failed_items}\nACTION: FIX\n"
              f"{_SIZE_EXCEEDED_GUIDANCE}")
        sys.exit(2)


def _write_domain_functions_tf(san, config, ir, domain_dir, kvs_is_shared=False, shared_kvs_name=None):
    """Write functions.tf — shared data source refs or independent CFF resources.
    Always exports locals: local.viewer_request_arn and local.viewer_response_arn
    so main.tf can reference them uniformly regardless of shared/independent mode."""
    vr_cfg = config.get("viewer_request", {})
    vresp_cfg = config.get("viewer_response", {})
    has_kvs = any(ir["metadata"].get("kvs_requirements", {}).values())
    needs_local_kvs = has_kvs and not kvs_is_shared
    # KVS association is PER-HANDLER, matching the per-handler cf.kvs() emission:
    # only associate a store with the CFF that actually calls cf.kvs(). Otherwise
    # a response-only-KVS domain gets a spurious association on the request CFF
    # (and vice-versa). _ops_need_kvs mirrors generate_viewer_request_js.
    req_uses_kvs = _ops_need_kvs([
        op for beh in ir.get("cache_behaviors", [])
        for op in beh.get("viewer_request_ops", [])
    ])
    resp_uses_kvs = any(
        _op_uses_kvs(op)
        for beh in ir.get("cache_behaviors", [])
        for op in beh.get("viewer_response_ops", [])
    )
    le = ir["metadata"].get("lambda_edge", {})
    has_le_origin_resp = le.get("origin_response") is not None

    lines = []
    w = lines.append

    if vr_cfg.get("mode") == "shared":
        w(f'data "aws_cloudfront_function" "shared_req" {{')
        w(f'  name  = "{vr_cfg["name"]}"')
        w(f'  stage = "LIVE"')
        w('}')
        vr_arn_expr = "data.aws_cloudfront_function.shared_req.arn"
    else:
        w(f'resource "aws_cloudfront_function" "{san}_viewer_request" {{')
        w(f'  name    = "{vr_cfg.get("name", cff_name(san, "viewer_request"))}"')
        w(f'  runtime = "cloudfront-js-2.0"')
        w(f'  publish = true')
        w(f'  code    = file("${{path.module}}/functions/{san}_viewer_request.js")')
        if req_uses_kvs and needs_local_kvs:
            w(f'  key_value_store_associations = [aws_cloudfront_key_value_store.{san}_kvs.arn]')
        elif req_uses_kvs and kvs_is_shared and has_kvs:
            kvs_tf_id = shared_kvs_name.replace("-", "_") if shared_kvs_name else ""
            w(f'  key_value_store_associations = [data.terraform_remote_state.shared.outputs.{kvs_tf_id}_arn]')
        w('}')
        vr_arn_expr = f"aws_cloudfront_function.{san}_viewer_request.arn"

    if vresp_cfg.get("mode") == "shared":
        w('')
        w(f'data "aws_cloudfront_function" "shared_resp" {{')
        w(f'  name  = "{vresp_cfg["name"]}"')
        w(f'  stage = "LIVE"')
        w('}')
        vresp_arn_expr = "data.aws_cloudfront_function.shared_resp.arn"
    elif vresp_cfg.get("mode") == "independent":
        w('')
        w(f'resource "aws_cloudfront_function" "{san}_viewer_response" {{')
        w(f'  name    = "{vresp_cfg.get("name", cff_name(san, "viewer_response"))}"')
        w(f'  runtime = "cloudfront-js-2.0"')
        w(f'  publish = true')
        w(f'  code    = file("${{path.module}}/functions/{san}_viewer_response.js")')
        # A viewer-response CFF that does a continent/is_eu or in_kvs lookup calls
        # cf.kvs(), which throws at init unless a store is associated — mirror the
        # viewer-request association here (a function may have one KVS).
        if resp_uses_kvs and needs_local_kvs:
            w(f'  key_value_store_associations = [aws_cloudfront_key_value_store.{san}_kvs.arn]')
        elif resp_uses_kvs and kvs_is_shared and has_kvs:
            kvs_tf_id = shared_kvs_name.replace("-", "_") if shared_kvs_name else ""
            w(f'  key_value_store_associations = [data.terraform_remote_state.shared.outputs.{kvs_tf_id}_arn]')
        w('}')
        vresp_arn_expr = f"aws_cloudfront_function.{san}_viewer_response.arn"
    else:
        vresp_arn_expr = ""

    # Shared KVS reference (for an independent CFF — request or response — that
    # associates a shared KVS via data.terraform_remote_state.shared).
    req_refs_shared = kvs_is_shared and has_kvs and vr_cfg.get("mode") != "shared"
    resp_refs_shared = kvs_is_shared and has_kvs and resp_uses_kvs and vresp_cfg.get("mode") == "independent"
    if req_refs_shared or resp_refs_shared:
        w('')
        w(f'data "terraform_remote_state" "shared" {{')
        w(f'  backend = "local"')
        w(f'  config = {{ path = "${{path.module}}/../../shared/terraform.tfstate" }}')
        w('}')

    # Locals block — main.tf references local.viewer_request_arn / local.viewer_response_arn
    w('')
    w('locals {')
    w(f'  viewer_request_arn  = {vr_arn_expr}')
    if vresp_arn_expr:
        w(f'  viewer_response_arn = {vresp_arn_expr}')
    w('}')

    if has_le_origin_resp:
        w('')
        role_name = cff_name(san, "viewer_request").replace("-req", "-le-role")
        w(f'resource "aws_iam_role" "{san}_lambda_edge" {{')
        w(f'  name = "{role_name}"')
        w(f'  assume_role_policy = jsonencode({{')
        w(f'    Version = "2012-10-17"')
        w(f'    Statement = [{{')
        w(f'      Action = "sts:AssumeRole"')
        w(f'      Effect = "Allow"')
        w(f'      Principal = {{ Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"] }}')
        w(f'    }}]')
        w(f'  }})')
        w('}')
        w('')
        w(f'resource "aws_iam_role_policy_attachment" "{san}_lambda_edge_basic" {{')
        w(f'  role       = aws_iam_role.{san}_lambda_edge.name')
        w(f'  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"')
        w('}')

    if has_le_origin_resp:
        w('')
        le_resp_name = cff_name(san, "viewer_request").replace("-req", "-le-oresp")
        w(f'data "archive_file" "{san}_origin_response_zip" {{')
        w(f'  type        = "zip"')
        w(f'  source_file = "${{path.module}}/lambda/default_cache_origin_response.js"')
        w(f'  output_path = "${{path.module}}/lambda/default_cache_origin_response.zip"')
        w('}')
        w('')
        w(f'resource "aws_lambda_function" "{san}_origin_response" {{')
        w(f'  provider         = aws.us_east_1')
        w(f'  filename         = data.archive_file.{san}_origin_response_zip.output_path')
        w(f'  source_code_hash = data.archive_file.{san}_origin_response_zip.output_base64sha256')
        w(f'  function_name    = "{le_resp_name}"')
        w(f'  role             = aws_iam_role.{san}_lambda_edge.arn')
        w(f'  handler          = "default_cache_origin_response.handler"')
        w(f'  runtime          = "nodejs20.x"')
        w(f'  publish          = true')
        w('}')

    ft_path = os.path.join(domain_dir, "functions.tf")
    with open(ft_path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
