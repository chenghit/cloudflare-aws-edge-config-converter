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
import copy
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
from cdn_expr_parser import parse_expression_full, parse_dynamic_expression, CF_FIELD_MAP

# ── Constants ────────────────────────────────────────────────────────────────

CFF_SIZE_LIMIT = 10240  # 10 KB
MAX_CFF_NAME = 64       # CloudFront Function name limit
MAX_CFF_ASSOCIATIONS = 100  # Max distributions per CFF (fixed, not adjustable)
CFF_PREFIX = "cf-"


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
_PREAMBLE_FIELDS = {"continent", "is_eu"}


def _field_is_mappable(field, target="cff"):
    """True if a short (already CF_FIELD_MAP-mapped) field name has a real
    CloudFront equivalent — a direct accessor or a preamble-resolved variable.

    Fields with no CloudFront source (cf.bot_management.score, cf.waf.score,
    ip.src.subdivision_1_iso_code, JWT claims, etc.) are NOT mappable and must
    be reported as non-convertible rather than emitted as bare JS identifiers.
    """
    if field in _PREAMBLE_FIELDS:
        return True
    if target == "lambda" and field in LAMBDA_ACCESSORS:
        return True
    if target == "response" and field in RESPONSE_ACCESSORS:
        return True
    return field in CFF_ACCESSORS


def _get_accessor(field, target="cff"):
    """Get JS accessor for a field. Returns (check_expr, value_expr) or just value_expr."""
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


def condition_to_js(cond, target="cff", indent=2):
    """Convert a CDN condition tree to JS expression string."""
    if cond is None or cond.get("always"):
        return None  # unconditional

    if "logic" in cond:
        logic = cond["logic"]
        if logic == "and":
            parts = [condition_to_js(p, target, indent) for p in cond["parts"]]
            return " && ".join(f"({p})" if " || " in p else p for p in parts)
        if logic == "or":
            parts = [condition_to_js(p, target, indent) for p in cond["parts"]]
            return " || ".join(f"({p})" if " && " in p else p for p in parts)
        if logic == "not":
            inner = condition_to_js(cond["item"], target, indent)
            # `false` is the sentinel for an un-evaluable inner (unmappable
            # field, unknown op). It means "never matches" and must stay that
            # way under negation — `!(false)` would be `true` (fail OPEN).
            if inner == "false":
                return "false"
            return f"!({inner})"

    field = cond.get("field", "")
    op = cond.get("op", "eq")
    value = cond.get("value")

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
        uri_acc = _full_uri_accessor(target)
        js_cond = _op_to_js(uri_acc, base_op, value, field)
        return f"!({js_cond})" if negated else js_cond

    # Special: continent / is_eu handled via preamble (not inline condition)
    # These are handled at the section level, not here.

    # Guard: an unmappable condition field would emit a bare (undefined) JS
    # identifier. The processor already marks such ops non-convertible, but
    # fail closed here — emit `false` so the op NEVER fires, regardless of
    # negation. (A negated `!(false)` would be `true` — fail OPEN — so the
    # `false` is returned directly rather than run through the negation below.)
    if not _field_is_mappable(field, target):
        print(f"  WARN: unmappable condition field, emitting false: {field}", file=sys.stderr)
        return "false"

    acc = _get_accessor(field, target)
    needs_check = _needs_check(field)

    if isinstance(acc, tuple):
        check_expr, val_expr = acc
    else:
        check_expr, val_expr = None, acc

    js_cond = _op_to_js(val_expr, base_op, value, field)

    if needs_check and check_expr:
        if negated:
            return f"!{check_expr} || !({js_cond})"
        return f"{check_expr} && {js_cond}"

    if negated:
        return f"!({js_cond})"
    return js_cond


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
    """Convert a single operator to JS expression."""
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
        return f"/* TODO: list {value} not resolved to KVS */ false"
    if op == "in_kvs":
        return f"await kvsHandle.exists('ip:{value}:' + {accessor})"
    if op in ("wildcard", "strict_wildcard"):
        return wildcard_to_js(accessor, value, op == "strict_wildcard")
    if op == "matches":
        return f"/{_cf_regex_to_js(value)}/.test({accessor})"
    return f"/* unknown op: {op} */ false"


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
            print(f"  WARN: condition parse failed: {raw_expr[:60]}... ({e})", file=sys.stderr)
            lines.append(f"{indent}// TODO: could not parse condition: {raw_expr[:80]}")
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
            body = (f"var {loc_var} = {target_url}; "
                    f"var __q = {raw_qs}; "
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
        origin_host = params.get("origin_host", "")
        host_header = params.get("host_header", origin_host)
        port = params.get("origin_port")
        sni = params.get("sni")
        if target == "lambda":
            body_lines = [f"request.origin.custom.domainName = {js_string(origin_host)};"]
            if port:
                body_lines.append(f"request.origin.custom.port = {port};")
                body_lines.append(f"request.origin.custom.protocol = 'https';")
            body_lines.append(f"request.headers.host = [{{key: 'Host', value: {js_string(host_header)}}}];")
            body = " ".join(body_lines)
        else:
            uro_parts = [f"domainName: {js_string(origin_host)}"]
            if port:
                uro_parts.append(f"customOriginConfig: {{port: {port}, protocol: 'https', sslProtocols: ['TLSv1.2']}}")
            if sni:
                uro_parts.append(f"sni: {js_string(sni)}")
            body = f"cf.updateRequestOrigin({{{', '.join(uro_parts)}}});"
            if host_header and host_header != origin_host:
                body += f" request.headers.host = {{value: {js_string(host_header)}}};"
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

    else:
        lines.append(f"{indent}// TODO: unsupported op type: {op_type}")

    return lines


def _needs_kvs(ir):
    """Check if any behavior needs KVS."""
    kvs = ir.get("metadata", {}).get("kvs_requirements", {})
    return any(kvs.values())


def _needs_qs_helper(all_ops):
    """_qs is always injected in CFF — 180 bytes, negligible vs 10KB limit.
    Avoids detection gaps (bulk redirect, conditions, dynamic expressions)."""
    return True


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


def _has_continent_or_eu(ops):
    """Check if any op references continent or is_eu (structured or raw)."""
    return any(_op_uses_continent_eu(op) for op in ops)


def _cond_has_field(cond, fields):
    if cond is None:
        return False
    if cond.get("field") in fields:
        return True
    for p in cond.get("parts", []):
        if _cond_has_field(p, fields):
            return True
    if "item" in cond:
        return _cond_has_field(cond["item"], fields)
    return False


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
        lines.append(f"{indent}let continent = '';")
        lines.append(f"{indent}if (country) {{ try {{ continent = await kvsHandle.get('continent:' + country); }} catch(e) {{}} }}")
    if needs_eu:
        lines.append(f"{indent}let isEU = false;")
        lines.append(f"{indent}if (country) {{ try {{ isEU = await kvsHandle.exists('eu:' + country); }} catch(e) {{}} }}")
    return lines


def generate_viewer_request_js(ir, target="cff"):
    """Generate complete viewer_request.js content."""
    lines = []
    needs_kvs_flag = _needs_kvs(ir)
    request_ops = [op for beh in ir.get("cache_behaviors", [])
                   for op in beh.get("viewer_request_ops", [])]
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
        lines.append("  function _qs(q) {")
        lines.append("    var p = [];")
        lines.append("    for (var k in q) {")
        lines.append("      if (q[k].multiValue) {")
        lines.append("        q[k].multiValue.forEach(function(mv) { p.push(k + '=' + mv.value); });")
        lines.append("      } else {")
        lines.append("        p.push(k + '=' + q[k].value);")
        lines.append("      }")
        lines.append("    }")
        lines.append("    return p.join('&');")
        lines.append("  }")

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

    for section_ops in [redirects, rewrites, origins]:
        for op in section_ops:
            lines.extend(_generate_op_js(op, target))

    if bulk:
        lines.extend(_generate_bulk_redirect_block())

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
    needs_kvs = any(
        _op_uses_continent_eu(op)
        or op.get("type") == "serve_error_inline"
        for op in all_ops
    )
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


def generate_lambda_origin_request_js(ops):
    """Generate Lambda@Edge origin_request_handler.js for escalated origin_override ops."""
    lines = [
        "'use strict';",
        "",
        "exports.handler = async (event, context, callback) => {",
        "  const request = event.Records[0].cf.request;",
        "  const uri = request.uri;",
    ]
    for op in ops:
        lines.extend(_generate_op_js(op, "lambda", "  "))
    lines.append("  callback(null, request);")
    lines.append("};")
    return "\n".join(lines)


# ── Minification ─────────────────────────────────────────────────────────────

def minify_js(js_code):
    """Minify JS by removing comments, whitespace, and empty lines."""
    result = []
    for line in js_code.split("\n"):
        # Remove single-line comments (but not URLs like https://)
        stripped = re.sub(r"(?<!:)//[^'\"]*$", "", line)
        stripped = stripped.strip()
        if stripped:
            result.append(stripped)
    return "\n".join(result)


# ── Main: process all domains ────────────────────────────────────────────────

def process_domain(ir, output_dir):
    """Process a single domain IR → generate JS files. Returns (hostname, status, detail)."""
    hostname = ir["metadata"]["hostname"]
    sanitized = ir["metadata"]["sanitized_name"]
    domain_dir = os.path.join(output_dir, "terraform", "domains", sanitized)
    functions_dir = os.path.join(domain_dir, "functions")
    lambda_dir = os.path.join(domain_dir, "lambda")
    os.makedirs(functions_dir, exist_ok=True)

    # Generate viewer_request.js
    vr_js = generate_viewer_request_js(ir)
    vr_size = len(vr_js.encode("utf-8"))

    # Size check + minification + escalation
    origin_ops = [
        op for beh in ir.get("cache_behaviors", [])
        for op in beh.get("viewer_request_ops", [])
        if op.get("type") == "origin_override"
    ]

    if vr_size > CFF_SIZE_LIMIT:
        vr_js = minify_js(vr_js)
        vr_size = len(vr_js.encode("utf-8"))

    if vr_size > CFF_SIZE_LIMIT and origin_ops:
        # Escalate: move origin_override to Lambda@Edge
        # Regenerate CFF without origin_override using a deep copy
        ir_no_origin = copy.deepcopy(ir)
        for beh in ir_no_origin.get("cache_behaviors", []):
            beh["viewer_request_ops"] = [
                op for op in beh.get("viewer_request_ops", [])
                if op.get("type") != "origin_override"
            ]
        vr_js = generate_viewer_request_js(ir_no_origin)
        vr_size = len(vr_js.encode("utf-8"))
        if vr_size > CFF_SIZE_LIMIT:
            vr_js = minify_js(vr_js)
            vr_size = len(vr_js.encode("utf-8"))

        if vr_size > CFF_SIZE_LIMIT:
            return hostname, "SIZE_EXCEEDED", f"{vr_size} bytes after escalation"

        # Write Lambda@Edge origin_request
        os.makedirs(lambda_dir, exist_ok=True)
        le_js = generate_lambda_origin_request_js(origin_ops)
        with open(os.path.join(lambda_dir, "origin_request_handler.js"), "w") as f:
            f.write(le_js)

        # Update functions.tf
        ft_path = os.path.join(domain_dir, "functions.tf")
        if os.path.exists(ft_path):
            with open(ft_path) as f:
                ft_content = f.read()
            lambda_block = (
                f'\ndata "archive_file" "{sanitized}_origin_request_zip" {{\n'
                f'  type        = "zip"\n'
                f'  source_file = "${{path.module}}/lambda/origin_request_handler.js"\n'
                f'  output_path = "${{path.module}}/lambda/origin_request_handler.js.zip"\n'
                f'}}\n\n'
                f'resource "aws_lambda_function" "{sanitized}_origin_request" {{\n'
                f'  provider         = aws.us_east_1\n'
                f'  filename         = data.archive_file.{sanitized}_origin_request_zip.output_path\n'
                f'  source_code_hash = data.archive_file.{sanitized}_origin_request_zip.output_base64sha256\n'
                f'  function_name    = "cfcdn-{sanitized}-origin-request"\n'
                f'  role             = aws_iam_role.{sanitized}_lambda_edge.arn\n'
                f'  handler          = "origin_request_handler.handler"\n'
                f'  runtime          = "nodejs20.x"\n'
                f'  publish          = true\n'
                f'}}\n'
            )
            ft_content = ft_content.replace("# LAMBDA_EDGE_PLACEHOLDER", lambda_block)
            with open(ft_path, "w") as f:
                f.write(ft_content)

    elif vr_size > CFF_SIZE_LIMIT:
        return hostname, "SIZE_EXCEEDED", f"{vr_size} bytes, no origin_override to escalate"

    # Write viewer_request.js
    with open(os.path.join(functions_dir, f"{sanitized}_viewer_request.js"), "w") as f:
        f.write(vr_js)

    # Generate viewer_response.js
    vresp_js = generate_viewer_response_js(ir)
    if vresp_js:
        with open(os.path.join(functions_dir, f"{sanitized}_viewer_response.js"), "w") as f:
            f.write(vresp_js)

    # Lambda@Edge origin_response (fixed template)
    le_or = ir.get("metadata", {}).get("lambda_edge", {}).get("origin_response")
    if le_or:
        os.makedirs(lambda_dir, exist_ok=True)
        # Copy template and fill in custom error mappings
        template = _generate_origin_response_template(le_or)
        with open(os.path.join(lambda_dir, "default_cache_origin_response.js"), "w") as f:
            f.write(template)

    return hostname, "OK", f"{vr_size} bytes"


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

        # Generate viewer_request
        vr_js = generate_viewer_request_js(ir)
        vr_size = len(vr_js.encode("utf-8"))

        # Size check + minification + escalation
        origin_ops = [
            op for beh in ir.get("cache_behaviors", [])
            for op in beh.get("viewer_request_ops", [])
            if op.get("type") == "origin_override"
        ]

        if vr_size > CFF_SIZE_LIMIT:
            vr_js = minify_js(vr_js)
            vr_size = len(vr_js.encode("utf-8"))

        if vr_size > CFF_SIZE_LIMIT and origin_ops:
            ir_no_origin = copy.deepcopy(ir)
            for beh in ir_no_origin.get("cache_behaviors", []):
                beh["viewer_request_ops"] = [
                    op for op in beh.get("viewer_request_ops", [])
                    if op.get("type") != "origin_override"
                ]
            vr_js = generate_viewer_request_js(ir_no_origin)
            vr_size = len(vr_js.encode("utf-8"))
            if vr_size > CFF_SIZE_LIMIT:
                vr_js = minify_js(vr_js)
                vr_size = len(vr_js.encode("utf-8"))
            if vr_size > CFF_SIZE_LIMIT:
                failed.append((hostname, "SIZE_EXCEEDED", f"{vr_size} bytes after escalation"))
                continue
            ir["_escalated_origin_ops"] = origin_ops
        elif vr_size > CFF_SIZE_LIMIT:
            failed.append((hostname, "SIZE_EXCEEDED", f"{vr_size} bytes, no origin_override to escalate"))
            continue

        all_vr[sanitized] = vr_js
        all_vresp[sanitized] = generate_viewer_response_js(ir)
        print(f"[JS] {hostname}: generated ({vr_size} bytes)", file=sys.stderr)

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

        if ir.get("_escalated_origin_ops"):
            lambda_dir = os.path.join(domain_dir, "lambda")
            os.makedirs(lambda_dir, exist_ok=True)
            with open(os.path.join(lambda_dir, "origin_request_handler.js"), "w") as f:
                f.write(generate_lambda_origin_request_js(ir["_escalated_origin_ops"]))

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
            f.write("Each domain gets one CloudFront distribution. Within a distribution, "
                    "**all cache behaviors share the same CloudFront Functions** (viewer-request and viewer-response). "
                    "This is because Cloudflare rules (redirects, rewrites, header transforms, bulk redirects) apply zone-wide — "
                    "they are not scoped to specific URL paths. To replicate this behavior in CloudFront, "
                    "the CFF must be associated with every cache behavior.\n\n")
            f.write("The CFF internally uses path matching (`request.uri`) to apply path-specific logic "
                    "(e.g., cache rules scoped to certain extensions). Rules without path conditions execute unconditionally.\n\n")
            f.write("Lambda@Edge (origin-response), when present, is associated only with the default cache behavior.\n\n")
            f.write("**Cost note**: Because your Cloudflare zone has zone-wide rules (bulk redirects, request header transforms), "
                    "the CFF executes on every request to every cache behavior — including static assets that don't need rule processing. "
                    "This is not a limitation of the conversion tool; it faithfully replicates Cloudflare's zone-wide rule scope. "
                    "If you want to reduce CFF invocation cost ($0.10/million requests) on specific behaviors after deployment, "
                    "remove the `function_associations` block from those behaviors in `main.tf`. "
                    "Be aware that bulk redirects and unconditional header transforms will no longer apply to those paths.\n\n")

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

                # For grouping, use event type only (actual names are per-domain)
                le_type = "—"
                if ir.get("_escalated_origin_ops"):
                    le_type = "origin-request"
                le_or = ir.get("metadata", {}).get("lambda_edge", {}).get("origin_response")
                if le_or:
                    le_type = "origin-response" if le_type == "—" else f"{le_type}, origin-response"

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
            f.write("- **Remove CFF from a specific cache behavior**: Edit `main.tf`, delete the `function_associations` "
                    "block from that behavior. Note: bulk redirects and unconditional header transforms will no longer "
                    "apply to that path.\n")
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

    # ── Report ───────────────────────────────────────────────────────────────

    ok_count = len(all_vr)
    fail_count = len(failed)

    if fail_count == 0:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nDOMAINS: {ok_count}\nGENERATED: {ok_count}\n"
              f"CFF_TOTAL: {actual_count}\nCFF_SHARED: {len(written_shared)}\n"
              f"CFF_INDEPENDENT: {indep_count}\nCFF_DEDUP_RATIO: {original_count} -> {actual_count}")
    elif ok_count > 0:
        failed_items = "\n".join(f"  {h}: {s} — {d}" for h, s, d in failed)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: PARTIAL\nSUCCEEDED: {ok_count}\nFAILED: {fail_count}\n"
              f"CFF_TOTAL: {actual_count}\nCFF_SHARED: {len(written_shared)}\n"
              f"CFF_INDEPENDENT: {indep_count}\nCFF_DEDUP_RATIO: {original_count} -> {actual_count}\n"
              f"FAILED_ITEMS:\n{failed_items}\nACTION: FIX\n"
              f"CONTEXT: {fail_count} domain(s) exceeded 10KB CFF size limit")
        sys.exit(3)
    else:
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"CONTEXT: All {fail_count} domains failed JS generation")
        sys.exit(2)


def _write_domain_functions_tf(san, config, ir, domain_dir, kvs_is_shared=False, shared_kvs_name=None):
    """Write functions.tf — shared data source refs or independent CFF resources.
    Always exports locals: local.viewer_request_arn and local.viewer_response_arn
    so main.tf can reference them uniformly regardless of shared/independent mode."""
    vr_cfg = config.get("viewer_request", {})
    vresp_cfg = config.get("viewer_response", {})
    has_kvs = any(ir["metadata"].get("kvs_requirements", {}).values())
    needs_local_kvs = has_kvs and not kvs_is_shared
    le = ir["metadata"].get("lambda_edge", {})
    has_le_origin_resp = le.get("origin_response") is not None
    escalated = "_escalated_origin_ops" in ir

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
        if needs_local_kvs:
            w(f'  key_value_store_associations = [aws_cloudfront_key_value_store.{san}_kvs.arn]')
        elif kvs_is_shared and has_kvs:
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
        w('}')
        vresp_arn_expr = f"aws_cloudfront_function.{san}_viewer_response.arn"
    else:
        vresp_arn_expr = ""

    # Shared KVS reference (for independent CFF that uses shared KVS)
    if kvs_is_shared and has_kvs and vr_cfg.get("mode") != "shared":
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

    if escalated:
        w('')
        le_name = cff_name(san, "viewer_request").replace("-req", "-le-origin")
        w(f'data "archive_file" "{san}_origin_request_zip" {{')
        w(f'  type        = "zip"')
        w(f'  source_file = "${{path.module}}/lambda/origin_request_handler.js"')
        w(f'  output_path = "${{path.module}}/lambda/origin_request_handler.js.zip"')
        w('}')
        w('')
        w(f'resource "aws_lambda_function" "{san}_origin_request" {{')
        w(f'  provider         = aws.us_east_1')
        w(f'  filename         = data.archive_file.{san}_origin_request_zip.output_path')
        w(f'  source_code_hash = data.archive_file.{san}_origin_request_zip.output_base64sha256')
        w(f'  function_name    = "{le_name}"')
        w(f'  role             = aws_iam_role.{san}_lambda_edge.arn')
        w(f'  handler          = "origin_request_handler.handler"')
        w(f'  runtime          = "nodejs20.x"')
        w(f'  publish          = true')
        w('}')

    if has_le_origin_resp or escalated:
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

    # Placeholder for origin-request Lambda (filled by escalation logic above)
    if not escalated:
        w('')
        w('# --- LAMBDA_EDGE_PLACEHOLDER ---')
    ft_path = os.path.join(domain_dir, "functions.tf")
    with open(ft_path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
