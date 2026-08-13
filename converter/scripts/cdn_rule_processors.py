"""Rule processors for cdn-preprocess.py — one function per Cloudflare rule type.

Each processor takes a rule dict (from Cloudflare JSON) and returns a list of
viewer_request_ops / viewer_response_ops / non_convertible entries, plus metadata
updates (cache_policy, origin, distribution_settings, etc.).
"""
import re
from cdn_expr_parser import (
    parse_expression, parse_expression_full, extract_orp_headers,
    extract_kvs_triggers, extract_host_filter, CF_FIELD_MAP,
    extract_path_pattern_single, iter_condition_children,
    condition_unmappable_fields, validate_condition_semantics,
    lower_literal_value, lower_dynamic_value, header_name_is_valid,
    header_mutation_capability_reason, HEADER_OPS_ACCEPTED_FOR_VALIDATION_BY_PHASE,
    LOWERED_EMPTY_NONE, LOWERED_EMPTY_DELETE_HEADER, LOWERED_EMPTY_CLEAR_QUERY,
    VIEWER_RESPONSE_GAP_REASON,
    host_leaf_is_routing,
)
from cdn_rhp_capabilities import security_capability, is_static_cors_header

# Every artifact-producing result that reaches cdn-preprocess's generic viewer-op
# placement MUST carry an explicit outcome_status (no implicit EXACT default — status is
# always explicit). Most conversions THIS module emits to that tail are EXACT; a static CORS
# header is LOSSY_WITH_WARNING (viewer-response CFF, error-response gap). String literals to
# avoid a circular import; MUST match cdn-preprocess.OUTCOME_EXACT / OUTCOME_LOSSY.
_OUTCOME_EXACT = "EXACT"
_OUTCOME_LOSSY = "LOSSY_WITH_WARNING"

# Redirect status codes Cloudflare's dynamic redirect supports (and a CFF redirect can emit):
# the standard 3xx redirect set. Anything else → non-convertible (round-25 finding 2).
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# ── Supported CloudFront custom error response status codes ──────────────────
SUPPORTED_ERROR_CODES = {400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504}

# ── Non-convertible Cloudflare-only features ─────────────────────────────────
NON_CONVERTIBLE_CONFIG_SETTINGS = {
    "bic": "Browser Integrity Check is a Cloudflare-specific feature with no CloudFront equivalent",
    "email_obfuscation": "Email Obfuscation is a Cloudflare-specific feature with no CloudFront equivalent",
    "disable_apps": "Cloudflare Apps is a Cloudflare-specific feature",
    "disable_zaraz": "Cloudflare Zaraz is a Cloudflare-specific feature",
    "disable_rum": "Cloudflare RUM is a Cloudflare-specific feature",
    "hotlink_protection": "Hotlink Protection requires Referer-based blocking; implement via CFF viewer-request if needed",
    "mirage": "Mirage is a Cloudflare-specific image optimization feature",
    "polish": "Polish is a Cloudflare-specific image optimization feature",
    "rocket_loader": "Rocket Loader is a Cloudflare-specific JS optimization feature",
    "security_level": "Security Level is a Cloudflare-specific feature; use AWS WAF for equivalent protection",
    "server_side_excludes": "Server Side Excludes is a Cloudflare-specific feature",
    "waf": "WAF toggle is handled by the WAF pipeline, not CDN",
}

# ── ip.src convertibility by rule type ───────────────────────────────────────
# Rule types where ip.src conditions are NOT convertible
IP_SRC_NON_CONVERTIBLE_PHASES = {
    "http_request_cache_settings",   # Cache Rules
    "http_request_compress",         # Compression Rules
}


def _condition_uses_ip_src(condition):
    """Check if a parsed condition references ip.src (direct IP, not geo)."""
    if condition is None:
        return False
    if "logic" in condition:
        return any(_condition_uses_ip_src(c) for c in iter_condition_children(condition))
    return condition.get("field") in ("ip.src",)


# `ip.src` as a direct-IP FIELD reference: the token `ip.src`, not followed by
# `.<subfield>` (a geo field like ip.src.country), AND immediately followed by a
# comparison operator. Requiring an operator avoids a false match on `ip.src`
# inside a string literal (e.g. `http.request.uri contains "ip.src"`), which
# would wrongly reject the rule. The operator set must cover the ALLOWLIST forms
# too — `ip.src not in {...}` (Wireshark-style) and `!=` — or a negated IP
# restriction slips past the cache/compression guard and is silently dropped.
# `not in` / `not eq` / `not ne` are matched via an optional `not` prefix;
# longer C-like operators (`==`, `!=`) as alternatives.
_RE_RAW_IP_SRC = re.compile(
    r"\bip\.src\b(?!\.)\s+(?:(?:not\s+)?(?:in|eq|ne)\b|==|!=)")


def _uses_ip_src(condition, raw_expr=None):
    """Direct-IP (ip.src) check that also covers a deferred raw expression.

    parse_expression now structures OR/AND/NOT, so `condition` is the normal
    case. It only falls back to raw text (condition is None) when the parser
    genuinely can't parse the expression. A structured-only check would then let
    an unparseable `ip.src`-bearing expression slip past the cache/compression
    ip.src guard and silently drop the IP restriction, so scan the raw text too.
    """
    if _condition_uses_ip_src(condition):
        return True
    # Strip quoted string literals first so an `ip.src`-looking token INSIDE a
    # literal (e.g. `uri contains "ip.src eq 1.2.3.4"`) can't false-match and
    # spuriously mark the rule non-convertible. (Only reachable on the rare
    # raw-fallback path, and it already fails safe, but this removes the false
    # positive entirely.)
    if raw_expr and _RE_RAW_IP_SRC.search(_strip_string_literals(raw_expr)):
        return True
    return False


def _strip_string_literals(expr):
    """Blank out "..." and '...' string-literal contents in a raw expression, so
    a field-name scan can't match a token that only appears inside a literal."""
    expr = re.sub(r'"[^"]*"', '""', expr)
    expr = re.sub(r"'[^']*'", "''", expr)
    return expr


def _check_ip_list(list_name, ip_lists):
    """Check an IP list for CIDR. Returns (ips, non_convertible_reason).

    Pure IPs (no CIDR) of any size are accepted — they will be stored in KVS
    and matched via kvsHandle.exists(). CIDR ranges cannot be matched in CFF.
    """
    ips = ip_lists.get(list_name, [])
    if not ips:
        return ips, f"IP list '{list_name}' is empty or not found"
    has_cidr = any("/" in ip for ip in ips)
    if has_cidr:
        return ips, (
            f"IP list '{list_name}' contains CIDR ranges; CFF event.viewer.ip "
            "cannot perform CIDR matching. Use AWS WAF IP set with Count action "
            "+ custom header to pass match result to CloudFront Function. "
            "See 'WAF + Custom Header Pattern' in conversion_report.md"
        )
    return ips, None


def _resolve_ip_list_in_condition(condition, ip_lists):
    """Resolve $list_name references in condition. Returns (condition, non_conv_reason).

    For pure IP lists, replaces in_list with in_kvs op (KVS-based lookup).
    """
    if condition is None:
        return condition, None
    if "logic" in condition:
        # A logic node is either AND/OR (children under "parts") or NOT (single
        # child under "item"). Handle both — assuming "parts" crashes on `not`.
        if "item" in condition:
            ni, reason = _resolve_ip_list_in_condition(condition["item"], ip_lists)
            if reason:
                return None, reason
            return {**condition, "item": ni}, None
        new_parts = []
        for p in condition.get("parts", []):
            np, reason = _resolve_ip_list_in_condition(p, ip_lists)
            if reason:
                return None, reason
            new_parts.append(np)
        return {**condition, "parts": new_parts}, None
    op = condition.get("op")
    if op in ("in_list", "not_in_list"):
        # Only ip.src lists map to the IP KVS lookup. A $list on any other field
        # (http.host in $hosts, ip.src.country in $geo, ip.src.asnum in $asns)
        # has no CloudFront equivalent — resolving it as an IP list would build
        # a bogus `ip:<list>:` lookup that never matches (silently narrowing the
        # rule). Report those as non-convertible instead.
        if condition.get("field") != "ip.src":
            return None, (
                f"'{condition.get('field')} in ${condition['value'].lstrip('$')}' "
                "references a named list with no CloudFront equivalent "
                "(only ip.src IP lists convert to a KVS lookup)")
        list_name = condition["value"].lstrip("$")
        ips, reason = _check_ip_list(list_name, ip_lists)
        if reason:
            return None, reason
        # Use KVS exists() for IP list matching. Preserve the not_ prefix so a
        # negated membership test ("... unless IP in allowlist") stays negated —
        # otherwise it would fall through to the raw op and condition_to_js would
        # emit !(/* TODO */ false) = true, firing the rule on EVERY request.
        new_op = "not_in_kvs" if op == "not_in_list" else "in_kvs"
        return {**condition, "op": new_op, "value": list_name, "kvs_ips": ips}, None
    return condition, None


def _prune_unmappable(condition, target="cff"):
    """Apply the conservative unmappable-field policy to a structured condition.

    Returns (new_condition, non_conv_reason). reason is None when convertible.
      - top-level OR: drop each branch that references an unmappable field,
        keep the rest (this only narrows the match — safe). If every branch is
        dropped, the whole condition is unmappable.
      - AND / NOT / a bare leaf: dropping a branch would WIDEN the match
        (potential over-match / security change), so mark the whole op
        non-convertible for human review.

    ``target`` selects the phase so response-only fields (response_code) are
    flagged in a request-phase condition.
    """
    # Top-level OR: classify each branch exactly once. Drop every branch that
    # references an unmappable field (this only narrows the match — safe), keep
    # the rest. If every branch is dropped, the whole condition is unmappable.
    if "logic" in condition and condition["logic"] == "or":
        kept, first_bad = [], None
        for p in condition.get("parts", []):
            bad = condition_unmappable_fields(p, target)
            if bad:
                first_bad = first_bad or bad[0][1]
            else:
                kept.append(p)
        if first_bad is None:
            return condition, None      # nothing unmappable
        if not kept:
            return None, first_bad      # every branch dropped
        if len(kept) == 1:
            return kept[0], None
        return {**condition, "parts": kept}, None
    # AND / NOT / bare leaf → cannot safely drop; whole op is non-convertible.
    bad = condition_unmappable_fields(condition, target)
    if not bad:
        return condition, None
    return None, bad[0][1]


def _raw_condition_unparseable_reason(raw_expr):
    """If `raw_expr` is a deferred condition the FULL parser also can't structure
    (e.g. a legal Cloudflare array form `headers["x"][0]` / `any(headers["x"][*]…)`,
    or any syntax we don't model), return a non-convertible reason string; else
    None. Shared by _resolve_unmappable_in_condition (the _screen_unmappable path)
    and the processors that DON'T route through it (compression, cloud connector),
    so an unparseable gate is reported the SAME way everywhere instead of being
    silently dropped by the generator's comment-only guard. Single judgement point
    — the generator uses this very parser and would just drop the action, so a raw
    that fails here can never be salvaged downstream."""
    if not raw_expr:
        return None
    try:
        parse_expression_full(raw_expr)
    except Exception:
        return ("condition could not be parsed to a CloudFront-evaluable form: "
                f"{raw_expr}")
    return None


def _resolve_unmappable_in_condition(condition, raw_expr=None, target="cff"):
    """Handle match-condition fields with no CloudFront equivalent.

    Works whether the expression was structured (``condition``) or deferred as
    a raw string (``raw_expr`` — this happens when parse_expression cannot
    structure it, e.g. because it contains an unmapped field). In the raw case
    we parse it with the full parser so the unmappable check can see the fields.

    Returns (condition, raw_expr=None-on-success, non_conv_reason). A CONVERTED op must carry a
    STRUCTURED condition — NEVER a raw_expression (round-27 review-3 finding 1: raw_expression is
    only an NC diagnostic; the generator must not re-parse it). So this ALWAYS resolves the raw
    case to either a structured condition (raw cleared) or a non_convertible; it never leaves a
    converted op holding raw.
    """
    if condition is not None:
        new_cond, reason = _prune_unmappable(condition, target)
        return new_cond, raw_expr, reason
    if raw_expr:
        # A raw the FULL parser can't structure would have its guarded action silently dropped by
        # the generator. Report non-convertible here instead (shared judgement via
        # _raw_condition_unparseable_reason).
        unparse_reason = _raw_condition_unparseable_reason(raw_expr)
        if unparse_reason:
            return condition, raw_expr, unparse_reason
        full = parse_expression_full(raw_expr)  # guaranteed to parse (unparse_reason was None)
        if not condition_unmappable_fields(full, target):
            # Parseable + fully mappable → use the STRUCTURED form and DROP raw (no two-path
            # converted op). Was: "leave deferred" (raw survived onto the converted op) — the last
            # raw-drives-codegen seam, now closed.
            return full, None, None
        new_cond, reason = _prune_unmappable(full, target)
        if reason:
            return None, None, reason
        # OR-prune succeeded → use the structured pruned condition, drop raw.
        return new_cond, None, None
    return condition, raw_expr, None


def _screen_condition_semantics(rule, cond, target="cff"):
    """Shared PROCESSOR-side semantic screen (step-3 item 1): a mappable + parseable condition must
    ALSO be EXECUTABLE at the edge. validate_condition_semantics runs the typed field×operator×value
    contract AND the conversion-policy NON_CONVERTIBLE_CONDITION_FIELDS set; returns a non_convertible
    dict when the condition isn't executable / is policy-NC, else None. This makes such a condition a
    first-class NC at the PROCESSOR instead of a whole-domain LedgerError at _append_viewer_op (the
    viewer-op families) or a silently-produced artifact (compression / cloud-connector, which do NOT
    route through _screen_unmappable). With NON_CONVERTIBLE_CONDITION_FIELDS still empty this only
    turns today's non-executable sink-FATALs (float/string-valued numeric-geo leaves) into clean NCs;
    flipping the authority set later routes numeric-geo NC through here too."""
    if cond is None:
        return None
    sem_reason = validate_condition_semantics(cond, "response" if target == "response" else "request")
    if sem_reason:
        return _make_non_convertible(rule, sem_reason)
    return None


def _screen_unmappable(rule, cond, raw_expr, ip_lists, target="cff"):
    """Resolve IP-list references then screen unmappable condition fields.

    Folds the identical pre-processing that every rule-type processor ran
    inline: resolve `$list` references in the condition, then apply the
    unmappable-field policy (OR-prune / AND-NOT-bare reject). Returns
    ``(cond, raw_expr, non_convertible)`` — when ``non_convertible`` is a dict,
    the caller should return it immediately; otherwise the (possibly rewritten)
    cond/raw_expr are ready to use.

    parse_expression now structures OR/NOT via the full parser, so IP-list
    expressions arrive here already structured and are resolved by
    _resolve_ip_list_in_condition below — no raw force-structuring needed. A
    non-None raw_expr means the expression was genuinely unparseable.
    """
    if cond:
        cond, ip_reason = _resolve_ip_list_in_condition(cond, ip_lists)
        if ip_reason:
            return cond, raw_expr, _make_non_convertible(rule, ip_reason)
    cond, raw_expr, unmap_reason = _resolve_unmappable_in_condition(cond, raw_expr, target)
    if unmap_reason:
        return cond, raw_expr, _make_non_convertible(rule, unmap_reason)
    # SEMANTIC screen (step-3 item 1) via the SHARED helper (also called by the compression /
    # cloud-connector processors, which bypass this function). A non-executable / policy-NC condition
    # becomes a first-class NC here, not a sink LedgerError.
    sem_nc = _screen_condition_semantics(rule, cond, target)
    if sem_nc:
        return cond, raw_expr, sem_nc
    return cond, raw_expr, None


def validate_action_value(container, what, allow_empty_value=False, allowed_extra=()):
    """THE shared value-CONTAINER validator for a redirect target / rewrite path / rewrite
    query (round-24 finding 2 — mirrors validate_header_input for the action-value world).
    `container` is the source dict (e.g. target_url / uri.path / uri.query). Returns an NC
    reason string if malformed, else None. Uses FIELD PRESENCE, never truthiness:
      - EXACTLY ONE of `value` / `expression` must be present (both → contradictory; neither →
        nothing to emit; a truthiness check silently ignored the empty/absent one and let a
        no-op or a value-less op pass as EXACT, mis-accounting the ledger).
      - a static `value` must be a STRING (value: 123 → a numeric Location/URI, NC).
      - an `expression` must be a NON-EMPTY string (its signature/type is then checked by
        _screen_value_expr).
      - a static EMPTY-STRING value is rejected UNLESS `allow_empty_value` (a rewrite QUERY of
        "" is a meaningful "clear the query string"; a redirect target / rewrite path of "" is
        not — round-24 finding 2).
      - the container MUST be a dict, and may carry ONLY `value`/`expression` (+ any keys in
        `allowed_extra`, e.g. a header container's already-validated `operation`) — any OTHER
        sibling leaf (e.g. {"value":"a", "future":"x"}) is rejected so it can't ride into an
        EXACT claim un-converted (round-25 finding 2).
    The dynamic-expression SIGNATURE/type/context proof runs in the caller's lowering step; this
    only validates the container shape + static value.
    """
    if not isinstance(container, dict):
        return (f"{what}: expected an object with a `value` or `expression`, got "
                f"{type(container).__name__}")
    unknown = set(container) - {"value", "expression"} - set(allowed_extra)
    if unknown:
        return (f"{what}: unknown field(s) {sorted(unknown)} — only `value`/`expression` are "
                "converted; an unrecognized leaf can't be silently claimed EXACT")
    has_value = "value" in container
    has_expr = "expression" in container
    if has_value and has_expr:
        return (f"{what}: both a static `value` and a dynamic `expression` are set — "
                "contradictory; use exactly one")
    if not has_value and not has_expr:
        return f"{what}: neither a `value` nor an `expression` is set — nothing to emit"
    if has_value:
        v = container.get("value")
        if not isinstance(v, str):
            return (f"{what}: static value must be a string, got {v!r} ({type(v).__name__})")
        if v == "" and not allow_empty_value:
            return (f"{what}: an empty static value has no faithful source meaning — "
                    "an empty redirect target / rewrite path can't be converted")
    else:
        e = container.get("expression")
        if not (isinstance(e, str) and e != ""):
            return (f"{what}: `expression` must be a non-empty string, got {e!r}")
    return None


def lower_action_container(container, what, context, allow_empty_value=False, allowed_extra=()):
    """Validate a value-container AND LOWER it (round-26): the ONE place a header/redirect/rewrite
    action value becomes a versioned LoweredValue. Returns (lowered, None) or (None, reason). The
    empty_behavior is DERIVED here from the context + value shape (the single policy point):
      - a DYNAMIC header value → delete_header (Cloudflare deletes the header on an empty result);
      - a STATIC empty rewrite query "" → clear_query (clear the query string);
      - everything else → none.
    Stamps context + empty_behavior on the value so the hard gate can re-check the combo. The
    generator renders the returned value and NEVER re-parses."""
    shape = validate_action_value(container, what, allow_empty_value=allow_empty_value,
                                  allowed_extra=allowed_extra)
    if shape:
        return None, shape
    is_header = context in ("request_header", "response_header")
    if "value" in container:
        v = container["value"]
        eb = (LOWERED_EMPTY_CLEAR_QUERY if context == "url_rewrite" and v == ""
              else LOWERED_EMPTY_NONE)
        return lower_literal_value(v, context, eb), None
    eb = LOWERED_EMPTY_DELETE_HEADER if is_header else LOWERED_EMPTY_NONE
    lowered = lower_dynamic_value(container["expression"], context, eb)
    if isinstance(lowered, str):        # NC reason
        return None, f"{what}: {lowered}"
    return lowered, None


def validate_action_object(obj, what, allowed_keys):
    """Validate an OUTER action object (action_parameters / from_value / uri) — round-26 finding
    2. Returns an NC reason if `obj` is not a dict (action_parameters=None → clean NC, not an
    AttributeError) or carries a field outside `allowed_keys` (an unknown sibling like
    from_value.future would otherwise be IGNORED, then falsely claimed EXACT because the
    redirect/rewrite artifact owns the whole rule unit). Else None."""
    if not isinstance(obj, dict):
        return f"{what} must be an object, got {type(obj).__name__}"
    unknown = set(obj) - set(allowed_keys)
    if unknown:
        return (f"{what}: unknown field(s) {sorted(unknown)} — unrecognized action fields can't "
                "be silently claimed EXACT (they'd ride the whole-rule artifact)")
    return None


def validate_header_transform_outer(rule):
    """Validate the OUTER shape of a header-transform rule (round-27 finding 3), returning
    (headers_dict, None) on success or (None, nc_result). BOTH header processors call this so
    their outer-object handling can't crash or silently drop source leaves:
      - action_parameters MUST be a dict carrying ONLY `headers` — a non-dict (None/list/str)
        used to AttributeError on `.get("headers")`, and an unknown sibling (a future action
        field) was ignored, then the rule falsely claimed EXACT via its per-header artifacts.
        Either way → a WHOLE-RULE NC (owned_key_segments=None).
      - `headers` MUST be a non-empty dict — a non-dict crashed `.items()`; an absent/empty
        `headers` is a no-op transform that would otherwise vanish from the ledger. → WHOLE-RULE NC.
    Per-header_config shape (each value a dict) is checked PER-HEADER by the caller, so one
    malformed header can't sink its well-formed siblings' conversions."""
    action_params = rule.get("action_parameters")
    bad = validate_action_object(action_params, "header transform action_parameters", ("headers",))
    if bad:
        return None, _make_non_convertible(rule, bad)
    headers = action_params.get("headers")
    if not isinstance(headers, dict):
        return None, _make_non_convertible(
            rule, f"header transform: `headers` must be an object, got {type(headers).__name__}")
    if not headers:
        return None, _make_non_convertible(
            rule, "header transform: `headers` is empty — no header to transform")
    return headers, None


# (round-26: _screen_value_expr was DELETED. It screened a raw expression string that the
# generator then re-parsed — the double-interpretation seam. Redirect/rewrite/header action
# values now go through lower_action_container(), which parses+screens+contract-checks ONCE and
# stores a LoweredValue the generator renders directly. No raw expression drives codegen.)


def _extract_path_pattern(condition, expression):
    """Extract a CloudFront path pattern from condition for cache behavior matching."""
    if condition is None:
        return "*"
    if condition.get("always"):
        return "*"
    if "logic" in condition:
        # Only positive AND/OR branches yield a usable path prefix. Do NOT descend
        # a NOT node's "item": a negated path ("not uri.path eq /a") is an
        # exclusion, and scoping the behavior to /a would be wrong — fall back to
        # "*". (`.get` also avoids a KeyError on the parts-less NOT node.)
        for p in condition.get("parts", []):
            pp = extract_path_pattern_single(p)
            if pp and pp != "*":
                return pp
        return "*"
    return extract_path_pattern_single(condition)


# ── Rule type processors ────────────────────────────────────────────────────

def process_redirect_rule(rule, ip_lists, phase):
    """Process a Redirect Rule (http_request_dynamic_redirect)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})

    cond, raw_expr = parse_expression(expr)

    # OUTER-object schema (round-26 finding 2): action_parameters must be a dict (None → clean
    # NC, not AttributeError) carrying only `from_value`; from_value only its known fields. An
    # unknown sibling is NC, never silently ignored-then-claimed-EXACT.
    bad = validate_action_object(action_params, "redirect action_parameters", ("from_value",))
    if bad:
        return _make_non_convertible(rule, bad)
    from_value = action_params.get("from_value", {})
    bad = validate_action_object(from_value, "redirect from_value",
                                 ("target_url", "status_code", "preserve_query_string"))
    if bad:
        return _make_non_convertible(rule, bad)

    # round-25 finding 3: the old HTTP→HTTPS shortcut (condition full_uri wildcard "http://*"
    # → distribution viewer_protocol_policy=redirect-to-https) is REMOVED. It bypassed ALL
    # action validation — it fired regardless of the rule's actual target/status/preserve-qs,
    # so a rule redirecting to a FIXED url with status 307 was silently turned into a
    # scheme-only VPP redirect (301, host/path/query preserved) — NOT equivalent. Such a rule
    # now flows through the normal redirect path + full action schema like any other; a genuine
    # scheme-only redirect converts to a CFF redirect faithfully.

    # status_code ∈ supported set; preserve_query_string a bool (round-25 finding 2) — before
    # any conversion, so a bad status (999) / non-bool preserve_qs can't be stamped EXACT.
    # (from_value shape already validated by validate_action_object above.)
    status_code = from_value.get("status_code", 302)
    preserve_qs = from_value.get("preserve_query_string", False)
    if status_code not in _REDIRECT_STATUS_CODES:
        return _make_non_convertible(
            rule, f"redirect status_code {status_code!r} is not a supported redirect status "
            f"(one of {sorted(_REDIRECT_STATUS_CODES)})")
    if not isinstance(preserve_qs, bool):
        return _make_non_convertible(
            rule, f"redirect preserve_query_string must be a boolean, got {preserve_qs!r}")
    target_url = from_value.get("target_url", {})

    # Check ip.src convertibility
    if phase in IP_SRC_NON_CONVERTIBLE_PHASES and _uses_ip_src(cond, raw_expr):
        return _make_non_convertible(rule, "ip.src condition in Cache Rules cannot be converted; CFF cannot control caching decisions")

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    # LOWER the redirect target ONCE (round-26): validate the container + parse/contract-check
    # in the "redirect" context, store a JSON-safe LoweredValue. The generator renders this,
    # never the raw string. NC on any shape/parse/type/context problem.
    lowered, nc_reason = lower_action_container(target_url, "redirect target", "redirect")
    if nc_reason:
        return _make_non_convertible(rule, nc_reason)

    op = {
        "type": "redirect",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "outcome_status": _OUTCOME_EXACT,
        "params": {
            "status_code": status_code,
            "preserve_query_string": preserve_qs,
            "target": lowered,          # LoweredValue — the ONLY thing the generator reads
        },
    }
    return op


def process_rewrite_rule(rule, ip_lists, phase):
    """Process a URL Rewrite Rule (http_request_transform)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    # OUTER-object schema (round-26 finding 2): action_parameters a dict carrying only `uri`;
    # uri a dict carrying only path/query. Unknown sibling / None → clean NC, not AttributeError.
    bad = validate_action_object(action_params, "rewrite action_parameters", ("uri",))
    if bad:
        return _make_non_convertible(rule, bad)
    uri = action_params.get("uri", {})
    bad = validate_action_object(uri, "rewrite uri", ("path", "query"))
    if bad:
        return _make_non_convertible(rule, bad)

    # Presence is by KEY (not truthiness — `path: null` is present-but-malformed, NOT "absent";
    # validate_action_value then rejects the non-dict). `path` rejects empty; `query` of "" is a
    # meaningful clear-query. At least one of path/query must be present.
    has_path = "path" in uri
    has_query = "query" in uri
    if not has_path and not has_query:
        return _make_non_convertible(rule, "rewrite: neither a path nor a query rewrite is set "
                                     "— no-op")

    op = {
        "type": "rewrite",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "outcome_status": _OUTCOME_EXACT,
        "params": {},
    }

    # LOWER each present sub-container ONCE (round-26). `path` rejects empty; `query` allows an
    # empty static value = clear the query (empty_behavior=clear_query — the generator emits
    # request.querystring = {}, the AWS-confirmed CFF idiom, NOT ''). Store JSON-safe
    # LoweredValues; the generator renders these, never re-parses.
    if has_path:
        lowered, nc_reason = lower_action_container(uri["path"], "rewrite path", "url_rewrite")
        if nc_reason:
            return _make_non_convertible(rule, nc_reason)
        op["params"]["path_lowered"] = lowered
    if has_query:
        lowered, nc_reason = lower_action_container(uri["query"], "rewrite query", "url_rewrite",
                                                    allow_empty_value=True)
        if nc_reason:
            return _make_non_convertible(rule, nc_reason)
        # The clear-query vs set-query distinction is carried IN the LoweredValue's
        # empty_behavior (clear_query for a static ""), so the generator branches on that — one
        # param, gate-verifiable.
        op["params"]["query_lowered"] = lowered

    return op


def _config_setting_scope_ok(cond, raw_expr):
    """True if a Configuration Rule condition can be honored by a DISTRIBUTION-level
    setting (ssl / min_tls_version apply to the whole distribution, per connection —
    CloudFront has NO way to vary them per request). That's only sound when the
    condition is unconditional (`true`) or purely HOST-ROUTING (host eq/in/ne/…,
    which the router already consumed → after routing it means "this whole
    distribution"). ANY other scope — a path/header/geo predicate, a live host
    predicate, an unparseable raw, or OR/NOT logic — CANNOT be represented as a
    distribution setting; applying it unconditionally is silent WIDENING (the
    setting leaks to requests the rule never targeted), so those must be reported
    non-convertible instead."""
    if raw_expr:
        return False  # unparseable / deferred → not representable as a dist setting
    if cond is None or cond.get("always"):
        return True
    if "logic" in cond:
        if cond["logic"] == "not":
            return _config_setting_scope_ok(cond.get("item"), None)
        # AND or OR: sound iff EVERY branch is pure host-routing. A pure-host OR
        # (host eq a or host eq b) is fine — the router already dispatched it, so on
        # each distribution it reached it's site-wide (a distribution setting needs
        # site-wide-after-routing, not ONE path). A branch with a path/header/geo
        # leaf still fails (not host-routing), so mixed scopes stay rejected.
        parts = cond.get("parts", [])
        return bool(parts) and all(_config_setting_scope_ok(p, None) for p in parts)
    # a single leaf: OK only if it's a host-ROUTING leaf (consumed by the router)
    return host_leaf_is_routing(cond)


def process_config_rule(rule, ip_lists, phase):
    """Process a Configuration Rule (http_config_settings).

    Most settings are Cloudflare-specific → non_convertible. ssl / min_tls_version
    map to a distribution-level setting, but ONLY when the rule's condition is
    unconditional or pure host-routing — a per-request condition (path/header/geo)
    can't gate a distribution setting, so it's reported non-convertible rather than
    silently widened to the whole distribution.
    """
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})
    _cond, _raw = parse_expression(expr)
    _scope_ok = _config_setting_scope_ok(_cond, _raw)
    results = []

    for setting, value in action_params.items():
        reason = NON_CONVERTIBLE_CONFIG_SETTINGS.get(setting)
        if reason:
            results.append({
                "type": "non_convertible",
                "cf_source_rule": rule.get("id", ""),
                "description": f"{rule.get('description', '')}: {setting}",
                "reason": reason,
                # Provenance hint: this NC outcome owns ONLY this setting's leaves (the
                # config rule partially converts — ssl/min_tls may convert while a
                # sibling setting does not). RAW key segments; the resolver escapes +
                # matches them against the inventory. Ledger-agnostic (no key built here).
                "owned_key_segments": [[setting]],
            })
        elif setting == "ssl":
            # ssl mode → ViewerProtocolPolicy, which is PER-CACHE-BEHAVIOR in
            # CloudFront (required on each, not inherited — verified vs AWS docs).
            # The scaffold applies this one value to the default AND every ordered
            # behavior, so it's a site-wide policy. That's only faithful when the
            # rule is unconditional / pure host-routing (site-wide after routing);
            # a per-request condition (path/header/geo) can't select a subset of
            # behaviors here, so report it rather than apply site-wide (widening).
            if not _scope_ok:
                results.append({
                    "type": "non_convertible",
                    "cf_source_rule": rule.get("id", ""),
                    "description": f"{rule.get('description', '')}: {setting}",
                    "reason": ("ssl mode maps to ViewerProtocolPolicy applied to all "
                               "cache behaviors (site-wide); it can't be gated by a "
                               "per-request condition without widening. "
                               f"Condition: {expr}"),
                    "owned_key_segments": [[setting]],
                })
            else:
                results.append({
                    "type": "distribution_setting",
                    "setting": "viewer_protocol_policy",
                    "value": "redirect-to-https" if value == "full" else "allow-all",
                    "cf_source_rule": rule.get("id", ""),
                    "description": rule.get("description", ""),
                    # This EXACT conversion owns the `ssl` source leaf → _place_result records an EXACT
                    # claim for it (else the leaf is a silent drop the finalize gate flags).
                    "owned_key_segments": [[setting]],
                })
        elif setting == "min_tls_version":
            if not _scope_ok:
                results.append({
                    "type": "non_convertible",
                    "cf_source_rule": rule.get("id", ""),
                    "description": f"{rule.get('description', '')}: {setting}",
                    "reason": ("min_tls_version is a distribution-level setting and "
                               "can't be gated by a per-request condition; applying "
                               f"it unconditionally would widen it. Condition: {expr}"),
                    "owned_key_segments": [[setting]],
                })
            else:
                # CloudFront viewer min TLS is STANDARDIZED to a uniform TLSv1.2_2021 baseline (user
                # policy: never below 1.2). CloudFront's managed viewer security policies can't express
                # an arbitrary minimum (there is no "TLS 1.3 minimum only"), so EVERY source value maps
                # to the 1.2 baseline. This is a directed security override, NOT a LOSSY/NC — the setting
                # IS converted (to 1.2), so it does not affect conversion completeness. But it CAN change
                # runtime behavior, so it is surfaced as a conversion warning (via _place_result →
                # conversion_warnings): a source BELOW 1.2 (Cloudflare's common 1.0 default) is HARDENED
                # (legacy TLS 1.0/1.1 clients rejected); a source of 1.3 is CAPPED (can't be enforced).
                _mtls = {
                    "type": "distribution_setting",
                    "setting": "minimum_protocol_version",
                    "value": "TLSv1.2_2021",
                    "cf_source_rule": rule.get("id", ""),
                    "description": rule.get("description", ""),
                    # This EXACT conversion owns the `min_tls_version` source leaf → _place_result
                    # records an EXACT claim (else it's a silent drop the finalize gate flags).
                    "owned_key_segments": [[setting]],
                }
                if value in ("1.0", "1.1"):
                    _mtls["warning"] = (
                        f"Cloudflare min_tls_version {value} was raised to the CloudFront TLSv1.2_2021 "
                        "baseline; legacy TLS 1.0/1.1 clients may be rejected.")
                elif value == "1.3":
                    _mtls["warning"] = (
                        "Cloudflare min_tls_version 1.3 cannot be enforced as a strict CloudFront viewer "
                        "minimum by this converter; output uses the TLSv1.2_2021 baseline (TLS 1.2 "
                        "clients are still accepted).")
                elif value != "1.2":
                    # Fail closed on an UNRECOGNIZED value: still apply the 1.2 baseline (uniform policy),
                    # but never silently — the source value wasn't one of the known TLS versions.
                    _mtls["warning"] = (
                        f"Cloudflare min_tls_version {value!r} is unrecognized; the CloudFront output "
                        "uses the TLSv1.2_2021 baseline — verify the intended minimum TLS version.")
                results.append(_mtls)
        else:
            results.append({
                "type": "non_convertible",
                "cf_source_rule": rule.get("id", ""),
                "description": f"{rule.get('description', '')}: {setting}",
                "reason": f"Configuration setting '{setting}' has no CloudFront equivalent",
                "owned_key_segments": [[setting]],
            })

    return results if results else [_make_non_convertible(rule, "Empty configuration rule")]


def process_origin_rule(rule, ip_lists, phase):
    """Process an Origin Rule (http_request_origin)."""
    expr = rule.get("expression", "true")

    # OUTER + nested SOURCE schema (round-27 review-2 finding 4). Cloudflare's Origin Rule
    # action_parameters carries only `host_header` (str), `origin` ({host,port}), `sni` ({value}).
    # A malformed source (action_parameters None/list, an unknown sibling, a non-dict origin/sni, a
    # non-string host/host_header, a bad port, an empty action) is bad INPUT → a clean NC, NOT a
    # crash and NOT a spurious EXACT that placement silently drops.
    action_params = rule.get("action_parameters")
    bad = validate_action_object(action_params, "origin rule action_parameters",
                                 ("host_header", "origin", "sni"))
    if bad:
        return _make_non_convertible(rule, bad)

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    params = {}
    # host_header: a non-empty string override, if present.
    if "host_header" in action_params:
        hh = action_params["host_header"]
        if not (isinstance(hh, str) and hh != ""):
            return _make_non_convertible(rule, f"origin rule host_header must be a non-empty "
                                         f"string, got {hh!r}")
        params["host_header"] = hh
    # origin: {host, port}. host a non-empty string; port a valid TCP port (1..65535).
    if "origin" in action_params:
        origin_info = action_params["origin"]
        bad = validate_action_object(origin_info, "origin rule `origin`", ("host", "port"))
        if bad:
            return _make_non_convertible(rule, bad)
        if "host" in origin_info:
            oh = origin_info["host"]
            if not (isinstance(oh, str) and oh != ""):
                return _make_non_convertible(rule, f"origin rule origin.host must be a non-empty "
                                             f"string, got {oh!r}")
            params["origin_host"] = oh
        if "port" in origin_info:
            op_ = origin_info["port"]
            if not (isinstance(op_, int) and not isinstance(op_, bool) and 1 <= op_ <= 65535):
                return _make_non_convertible(rule, f"origin rule origin.port must be a TCP port "
                                             f"1..65535, got {op_!r}")
            params["origin_port"] = op_
    # sni: {value} — a non-empty string SNI override, if present.
    if "sni" in action_params:
        sni_obj = action_params["sni"]
        bad = validate_action_object(sni_obj, "origin rule `sni`", ("value",))
        if bad:
            return _make_non_convertible(rule, bad)
        if "value" in sni_obj:
            sv = sni_obj["value"]
            if not (isinstance(sv, str) and sv != ""):
                return _make_non_convertible(rule, f"origin rule sni.value must be a non-empty "
                                             f"string, got {sv!r}")
            params["sni"] = sv

    # An origin rule with NO real override is a no-op → NC (was EXACT, then silently dropped at
    # placement's no-op check). At least one of host_header/origin_host/origin_port/sni required.
    if not params:
        return _make_non_convertible(rule, "origin rule has no origin/host/port/sni override — "
                                     "nothing to convert")

    return {
        "type": "origin_override",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "outcome_status": _OUTCOME_EXACT,
        "params": params,
    }


def process_cache_rule(rule, ip_lists, phase):
    """Process a Cache Rule (http_request_cache_settings)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})

    cond, raw_expr = parse_expression(expr)

    # ip.src in cache rules → non_convertible (raw_expr too: an OR defers to raw
    # text with cond=None, and dropping the IP restriction silently would change
    # who gets cached)
    if _uses_ip_src(cond, raw_expr):
        return _make_non_convertible(
            rule,
            "ip.src condition in Cache Rules cannot be converted; "
            "CFF cannot control caching decisions"
        )

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    edge_ttl = action_params.get("edge_ttl", {})
    browser_ttl = action_params.get("browser_ttl", {})
    cache_key = action_params.get("cache_key", {})
    custom_key = cache_key.get("custom_key", {})

    result = {
        "type": "cache_setting",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "params": {},
    }

    # Cache eligibility is TRI-STATE: only emit `bypass` when the rule EXPLICITLY
    # sets `cache`. A rule that only tweaks TTL/cache-key leaves `bypass` ABSENT, so
    # it neither disables nor re-enables caching — a prior cache=false rule's
    # setting must survive (Cloudflare: an unspecified setting doesn't reset it).
    # bypass=True → disable; bypass=False → an explicit re-enable (cache=true).
    if "cache" in action_params:
        result["params"]["bypass"] = not action_params["cache"]

    # TTL
    if edge_ttl:
        mode = edge_ttl.get("mode", "respect_origin")
        if mode == "override_origin":
            result["params"]["edge_ttl_override"] = edge_ttl.get("default", 0)
        elif mode == "respect_origin":
            result["params"]["edge_ttl_respect_origin"] = True
        status_code_ttl = edge_ttl.get("status_code_ttl", [])
        if status_code_ttl:
            result["params"]["status_code_ttl"] = status_code_ttl

    if browser_ttl:
        mode = browser_ttl.get("mode", "respect_origin")
        if mode == "override_origin":
            result["params"]["browser_ttl_override"] = browser_ttl.get("default", 0)
        elif mode == "respect_origin":
            # A RESET back to the origin's Cache-Control. Tracked so a later
            # respect_origin can cancel an earlier override at the same scope; the
            # placement layer decides whether a CFF can faithfully restore it.
            result["params"]["browser_ttl_respect_origin"] = True

    # Cache key. Cloudflare's cache_key.custom_key.query_string has TWO documented
    # shapes and we must not chain .get() blindly on either (a wrong assumption
    # crashed preprocess with "'list' object has no attribute 'get'"):
    #   - list form:  {"include": ["*"]}  or  {"include": ["a","b"]}  (["*"] = all)
    #                 {"exclude": ["*"]}                              (["*"] = none)
    #   - object form:{"include": {"all": true}} / {"include": {"list": [...]}} / …
    # `_qs_selector` decodes both to (mode, list) and returns (None, None) for an
    # unrecognized shape so the leaf-inventory reports it NC rather than crashing.
    if custom_key:
        qs = custom_key.get("query_string", {})
        if isinstance(qs, dict):
            mode, qlist, consumed = _qs_selector(qs)
            if mode == "all":
                result["params"]["cache_key_qs"] = "all"
            elif mode == "none":
                result["params"]["cache_key_qs"] = "none"
            elif mode == "whitelist":
                result["params"]["cache_key_qs"] = "whitelist"
                result["params"]["cache_key_qs_list"] = qlist
            elif mode == "allExcept":
                result["params"]["cache_key_qs"] = "allExcept"
                result["params"]["cache_key_qs_exclude"] = qlist
            # The EXACT query_string leaf this selector consumed (["include"] /
            # ["include","all"] / ["include","list"] / exclude-symmetric) — the ledger owns
            # ONLY this leaf so an unknown sibling in the same object stays NC.
            if consumed:
                result["params"]["cache_key_qs_consumed"] = consumed
            # mode None → unrecognized shape: left for the leaf inventory to flag NC.

        headers = custom_key.get("header", {})
        if isinstance(headers, dict):
            if headers.get("include"):
                result["params"]["cache_key_headers"] = headers["include"]
            if headers.get("contains"):
                result["params"]["cache_key_header_contains"] = headers["contains"]

        user = custom_key.get("user", {})
        if user.get("device_type"):
            result["params"]["cache_key_device_type"] = True
        if user.get("geo"):
            result["params"]["cache_key_geo"] = True
        if user.get("lang"):
            result["params"]["cache_key_lang"] = True

    # Other settings
    if "origin_cache_control" in action_params:
        result["params"]["origin_cache_control"] = action_params["origin_cache_control"]
    if "respect_strong_etags" in action_params:
        result["params"]["respect_strong_etags"] = action_params["respect_strong_etags"]

    # SETTING INVENTORY (round-9): record the ORIGINAL top-level action-parameter
    # keys this rule configured. Accounting reads THIS, not the reduced params — so
    # a Cloudflare setting the processor never mapped (cache_reserve, serve_stale,
    # read_timeout, …) is still visible and gets a non-convertible outcome instead
    # of silently vanishing. `browser_ttl.mode` is tracked as a sub-key so its
    # respect_origin/bypass_by_default reset states are accounted (only
    # override_origin produces an effect above).
    # RECURSE to LEAVES (round-10 #2): a top-level inventory treats the whole
    # `cache_key`/`edge_ttl` subtree as mapped, so a nested leaf the processor never
    # consumed (cache_key.custom_key.cookie.include, edge_ttl.mode=bypass_by_default)
    # vanishes. Enumerate every leaf path so accounting can flag the unconsumed ones.
    result["_configured"] = _leaf_paths(action_params)

    return result


def _qs_selector(qs):
    """Decode a Cloudflare cache_key query_string selector to (mode, list, consumed).

    mode ∈ {"all","none","whitelist","allExcept", None}; list is the explicit names
    for whitelist/allExcept else None. `consumed` is the EXACT segment path (relative to
    `query_string`) this selector reads — the ledger owns ONLY that leaf, so an unknown
    sibling in the same object stays NC:
      - list form  {"include":[...]}          → ["include"]
      - object     {"include":{"all":true}}   → ["include","all"]
      - object     {"include":{"list":[...]}}  → ["include","list"]   (and exclude symmetric)
    Handles BOTH documented shapes; returns (None, None, None) for anything unrecognized
    (caller reports it non-convertible rather than crashing). `["*"]` = all (include) /
    none (exclude); `[]` or missing is unrecognized.
    """
    inc = qs.get("include")
    exc = qs.get("exclude")
    # list form: {"include": [...]}, {"exclude": [...]}  (["*"] = all/none)
    if isinstance(inc, list):
        if inc == ["*"]:
            return "all", None, ["include"]
        return ("whitelist", inc, ["include"]) if inc else (None, None, None)
    if isinstance(exc, list):
        if exc == ["*"]:
            return "none", None, ["exclude"]
        return ("allExcept", exc, ["exclude"]) if exc else (None, None, None)
    # object form: {"include": {"all": true}} / {"include": {"list": [...]}} / exclude
    if isinstance(inc, dict):
        if inc.get("all"):
            return "all", None, ["include", "all"]
        if inc.get("list"):
            return "whitelist", inc["list"], ["include", "list"]
    if isinstance(exc, dict):
        if exc.get("all"):
            return "none", None, ["exclude", "all"]
        if exc.get("list"):
            return "allExcept", exc["list"], ["exclude", "list"]
    return None, None, None


def _leaf_paths(obj, prefix=""):
    """Flatten a nested action_parameters dict to dotted leaf paths. A scalar leaf
    becomes `path=value` (so edge_ttl.mode=respect_origin is distinguishable);
    a dict recurses; a non-empty list leaf becomes `path[]`. Empty containers become
    a bare `path` leaf so an empty setting is still visible."""
    leaves = []
    if isinstance(obj, dict):
        if not obj:
            return [prefix] if prefix else []
        for k, v in obj.items():
            leaves += _leaf_paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        leaves.append(f"{prefix}[]" if prefix else "[]")
    else:
        # scalar: keep the value for mode-like discriminators, bool/str/int only
        leaves.append(f"{prefix}={obj}" if isinstance(obj, (str, bool, int)) else prefix)
    return sorted(set(leaves))


def validate_header_input(header_config, phase_label, allowed_operations):
    """THE shared STRUCTURAL validator for one header transform config, used by BOTH the
    request and response processors so their input rules can't drift (round-16/17). Returns an
    NC reason string if the config is structurally malformed, else None (the caller then LOWERS
    the value, which runs the semantic proof). `phase_label` ("request"/"response") shapes the
    message; `allowed_operations` is the tuple of operations THIS phase can convert. Callers pass:
    REQUEST → ("set","remove") (Cloudflare's Request Header Transform has NO `add`);
    RESPONSE → ("set","add","remove") (`add` passes structural validation, then the response
    processor's own block marks it NC because a native RHP can't append). round-18/round-19.

    STRUCTURE-ONLY (round-27 finding 4 — PARSE ONCE): this validates only the config SHAPE, NOT
    the dynamic expression's semantics. The parse + signature/context/result-type/unmappable-field
    proof is done EXACTLY ONCE by lower_action_container → lower_dynamic_value (validate_dynamic_
    tree), which is a strict superset of the old check here and ALWAYS runs right after this. So a
    structurally-valid-but-unfaithful expression (sha256 in a header, a non-string result, an
    unmappable field, `foo(`) still becomes NON_CONVERTIBLE — at the lowering step, not here — and
    the expression is parsed a single time. This function no longer parses.

    OPERATION contract (round-17 — the whole contract, not just the field shape):
      - The `operation` must be a NON-EMPTY STRING in `allowed_operations`. Unknown / None /
        non-string / a value this phase can't do (e.g. `add` on the request) → NC. (Was: an
        unknown op fell through to build a `{op}_..._header` viewer op no ledger channel claims
        → an orphan; and `remove` returned success even WITH a value/expression → ignored
        leaves wrongly claimed EXACT.)
      - The field set is EXACTLY a subset of {operation, value, expression} — ANY other key (a
        future/unknown leaf) → NC (round-27 finding 4). Without this, {operation:remove, future:x}
        produced an EXACT remove op owning the whole /headers/<name> subtree, so `future` was
        falsely claimed converted. `remove` further requires the set to be EXACTLY {operation}.
      - `remove` must carry NEITHER `value` NOR `expression` (nothing to append/replace — a
        value/expression on a remove is a contradiction, and would be an unconverted leaf).
      - `set` / `add` must provide EXACTLY ONE of `value` / `expression`:
          value:      a STRING ("" allowed; a non-string has no defined CFF coercion → NC).
          expression: a NON-EMPTY string (a blank has nothing to convert). Its PARSEABILITY and
                      faithfulness are proven by lowering, not here.
          neither / both → NC.
    """
    # Unknown sibling fields → NC (finding 4): no field outside {operation,value,expression} may
    # ride the header op un-converted. Checked FIRST so a stray leaf can't slip past any branch.
    unknown = set(header_config) - {"operation", "value", "expression"}
    if unknown:
        return (f"{phase_label} header: unknown field(s) {sorted(unknown)} — only "
                "operation/value/expression are converted; an unrecognized leaf can't be "
                "silently claimed EXACT")
    operation = header_config.get("operation", "set")
    if not (isinstance(operation, str) and operation in allowed_operations):
        return (f"{phase_label} header: unsupported operation {operation!r} — this phase "
                f"converts only {', '.join(allowed_operations)}")
    has_value = "value" in header_config
    has_expression = "expression" in header_config
    if operation == "remove":
        if has_value or has_expression:
            return (f"{phase_label} header: a `remove` must not carry a `value` or "
                    "`expression` — there is nothing to append or replace")
        return None
    # set / add: exactly one of value / expression, well-typed.
    if has_value and has_expression:
        return (f"{phase_label} header: both a static `value` and a dynamic `expression` are "
                "set — contradictory; fix the source rule to use exactly one")
    if not has_value and not has_expression:
        return (f"{phase_label} header: a `{operation}` provides neither `value` nor "
                "`expression` — nothing to emit (use an explicit `value: \"\"` for an empty header)")
    if has_value:
        value = header_config.get("value")
        if not isinstance(value, str):
            return (f"{phase_label} header: literal value must be a string, got {value!r} "
                    f"({type(value).__name__}) — CloudFront Functions have no defined coercion "
                    "for a non-string header value")
        return None
    # has_expression: structural check only (non-empty string). Parse + faithfulness = lowering.
    expression = header_config.get("expression")
    if not (isinstance(expression, str) and expression != ""):
        return (f"{phase_label} header: `expression` must be a non-empty string, got "
                f"{expression!r} — a malformed dynamic value can't be converted")
    return None


def process_request_header_transform(rule, ip_lists, phase):
    """Process a Request Header Transform Rule (http_request_late_transform)."""
    expr = rule.get("expression", "true")

    # OUTER-object schema (round-27 finding 3): action_parameters a dict carrying only `headers`;
    # `headers` a non-empty dict. A malformed outer shape is a clean WHOLE-RULE NC, never an
    # AttributeError or a silently-ignored action field.
    headers, nc = validate_header_transform_outer(rule)
    if nc:
        return nc

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    ops = []
    for header_name, header_config in headers.items():
        # Per-header provenance: this rule's `headers` dict maps one op per header, so
        # each op (converted OR non-convertible) owns ONLY its own /headers/<name>
        # subtree. Without this, a single header's NC would claim the WHOLE rule and
        # collide with a sibling header's converted-op claim.
        owned = [["headers", header_name]]

        # Each header_config MUST be a dict — a non-dict (e.g. a bare string value) would
        # AttributeError on .get() below. NC just this header, not its siblings.
        if not isinstance(header_config, dict):
            ops.append(_make_non_convertible(
                rule, f"'{header_name}': header config must be an object, got "
                f"{type(header_config).__name__}", owned_key_segments=owned))
            continue
        # A malformed SOURCE header name (not an RFC-7230 token) is bad input → NC this header,
        # NOT a FATAL. The viewer-op contract's name check is a backstop for internal-producer
        # bugs; a source name reaches here first (round-27 finding 2).
        if not header_name_is_valid(header_name):
            ops.append(_make_non_convertible(
                rule, f"'{header_name}': not a valid HTTP header name", owned_key_segments=owned))
            continue
        # CAPABILITY: a CFF can't set/remove a disallowed/read-only header (Host, Content-Length,
        # Via, … → HTTP 502 at runtime). NC this header at the source (round-27 review-2 finding 2).
        _cap = header_mutation_capability_reason(header_name, "request_header")
        if _cap:
            ops.append(_make_non_convertible(rule, f"'{header_name}': {_cap}",
                                             owned_key_segments=owned))
            continue
        operation = header_config.get("operation", "set")

        # ONE shared input validator (round-16/17/18): validates the OPERATION AND the field
        # shape. Cloudflare's Request Header Transform defines ONLY `set` and `remove` — there
        # is no request `add` (round-18 finding 1), so it is NOT in the allow-list and any
        # `add` (or unknown/None op) is NC, never an orphan {op}_request_header op. `set` needs
        # exactly one of value (string, "" allowed) / expression (non-empty parseable string);
        # `remove` must carry neither.
        _bad = validate_header_input(header_config, "request", HEADER_OPS_ACCEPTED_FOR_VALIDATION_BY_PHASE["request"])
        if _bad:
            ops.append(_make_non_convertible(
                rule, f"'{header_name}': {_bad}", owned_key_segments=owned))
            continue

        op = {
            "type": f"{operation}_request_header",
            "cf_source_rule": rule.get("id", ""),
            "description": rule.get("description", ""),
            "condition": cond,
            "raw_expression": raw_expr,
            "params": {"name": header_name},
            "owned_key_segments": owned,
            "outcome_status": _OUTCOME_EXACT,
        }
        if operation == "remove":
            pass  # no value needed
        else:
            # LOWER the header value ONCE (round-26), request_header context. empty_behavior
            # (delete_header for a dynamic value) is DERIVED and stored ON the LoweredValue.
            lowered, nc_reason = lower_action_container(header_config, f"request header "
                                                        f"'{header_name}'", "request_header",
                                                        allow_empty_value=True,
                                                        allowed_extra=("operation",))
            if nc_reason:
                ops.append(_make_non_convertible(rule, nc_reason, owned_key_segments=owned))
                continue
            op["params"]["value_lowered"] = lowered

        ops.append(op)

    return ops


def process_response_header_transform(rule, ip_lists, phase):
    """Process a Response Header Transform Rule (http_response_headers_transform)."""
    expr = rule.get("expression", "true")

    # OUTER-object schema (round-27 finding 3): same shared gate as the request phase —
    # action_parameters a dict carrying only `headers`; `headers` a non-empty dict. Malformed
    # outer shape → clean WHOLE-RULE NC (no AttributeError, no silently-dropped action field).
    headers, nc = validate_header_transform_outer(rule)
    if nc:
        return nc

    # CORS credentials + wildcard (conversion-policy step-3 decision #2): a STATIC
    # Access-Control-Allow-Origin: * combined with a STATIC Access-Control-Allow-Credentials: true is
    # NON_CONVERTIBLE as a WHOLE rule (case-insensitive header names). The Fetch/CORS standard forbids
    # a wildcard origin with credentials (browsers reject the credentialed response); CloudFront does
    # NOT reject or fix it, and the ~60-TLD wildcard workaround is not a faithful equivalent. NC the
    # WHOLE transform, not one leaf — NC-ing only one would leave the other and change the CORS
    # semantics of the response. (This fires regardless of operation; a non-CORS `add` header still
    # hits the per-header add-NC below.)
    _cors = {k.lower(): v for k, v in headers.items() if isinstance(v, dict)}
    _acao, _acac = _cors.get("access-control-allow-origin", {}), _cors.get("access-control-allow-credentials", {})
    if _acao.get("value") == "*" and str(_acac.get("value", "")).lower() == "true":
        return _make_non_convertible(
            rule, "CORS Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is "
            "non-convertible — the Fetch/CORS standard forbids a wildcard origin with credentials "
            "(browsers reject the credentialed response); CloudFront does not fix it and the "
            "TLD-wildcard workaround is not faithful. Use explicit origins.")

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields. Response phase:
    # response_code IS sourceable here, so screen with target="response".
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists, target="response")
    if nc:
        return nc

    ops = []
    for header_name, header_config in headers.items():
        # Per-header provenance: one op per header, so each owns ONLY its own
        # /headers/<name> subtree (see the request-header processor). Applied to every
        # branch below — converted (RHP / viewer-op) and non-convertible alike.
        owned = [["headers", header_name]]

        # Each header_config MUST be a dict — a non-dict would AttributeError on .get() below.
        # NC just this header, not its siblings.
        if not isinstance(header_config, dict):
            ops.append(_make_non_convertible(
                rule, f"'{header_name}': header config must be an object, got "
                f"{type(header_config).__name__}", owned_key_segments=owned))
            continue
        # A malformed SOURCE header name (not an RFC-7230 token) is bad input → NC this header,
        # NOT a FATAL (round-27 finding 2 — the viewer-op contract name check is the backstop).
        if not header_name_is_valid(header_name):
            ops.append(_make_non_convertible(
                rule, f"'{header_name}': not a valid HTTP header name", owned_key_segments=owned))
            continue
        # CAPABILITY: a viewer-response CFF can't set/remove a disallowed/read-only response header
        # (Via, Warning, … → HTTP 502 at runtime). None of these are RHP-managed security/CORS
        # names, so gating here (before the RHP/CORS branches) is safe (round-27 review-2 finding 2).
        _cap = header_mutation_capability_reason(header_name, "response_header")
        if _cap:
            ops.append(_make_non_convertible(rule, f"'{header_name}': {_cap}",
                                             owned_key_segments=owned))
            continue
        operation = header_config.get("operation", "set")

        # ONE shared input validator (round-16/17): validates the OPERATION and field shape.
        # `add` is ALLOWED through here (structurally it's a set/add with a value) so the
        # detailed phase-specific `add` rejection below keeps its "RHP is set-only" message;
        # every OTHER unknown/None operation is NC here. remove must carry neither field; a
        # set/add needs exactly one of value (string, "" allowed) / expression (non-empty
        # parseable string) — never a value-less EXACT the generator fills with "".
        _bad = validate_header_input(header_config, "response", HEADER_OPS_ACCEPTED_FOR_VALIDATION_BY_PHASE["response"])
        if _bad:
            ops.append(_make_non_convertible(
                rule, f"'{header_name}': {_bad}", owned_key_segments=owned))
            continue
        has_expression = "expression" in header_config   # validated: non-empty parseable str
        has_value = ("value" in header_config) and not has_expression

        # Cloudflare `add` APPENDS a new header, keeping existing same-name headers
        # (verified vs Cloudflare docs: "Add operations append a new header without
        # removing existing headers of the same name"). CloudFront has NO faithful
        # equivalent (confirmed vs AWS docs, dual subagents — memory
        # cdn-response-header-mechanism-facts): a Response Headers Policy is set-only
        # (one value, Override is a winner-switch, never appends); and building a
        # brand-new multiValue header from a single value in a CloudFront Function is
        # undocumented. So a `remove`+`set` render it as a no-op today. PHASE-1: report
        # non-convertible until multiValue creation is verified live, rather than emit
        # a silent no-op.
        if operation == "add":
            ops.append(_make_non_convertible(
                rule, f"response header '{header_name}': Cloudflare `add` appends a "
                "duplicate header (keeps existing values); CloudFront has no faithful "
                "equivalent (RHP is set-only; CFF multiValue-from-single is "
                "undocumented). Set the value at the origin, or use `set` if replacing "
                "is acceptable.", owned_key_segments=owned))
            continue

        # A STATIC security header routes to the native RHP only when the shared capability
        # registry can FAITHFULLY emit its NAME *and* VALUE. A supported security header whose
        # VALUE the RHP can't reproduce (HSTS unknown directive, X-Content-Type-Options !=
        # nosniff, X-Frame-Options not DENY/SAMEORIGIN, X-XSS-Protection != `1; mode=block`,
        # an empty or non-string value) is NON_CONVERTIBLE, not EXACT.
        lower_name = header_name.lower()
        sec_cap = security_capability(header_name)
        is_security = sec_cap is not None

        if is_security and has_value:
            # Static security header set → ALWAYS run parse() (finding 1: an empty/invalid
            # value must reach the parser, not slip past a truthiness gate into a plain CFF
            # EXACT). parse() decides EXACT-vs-NC by value and returns the NORMALIZED value
            # the generator renders VERBATIM (no independent re-parse in the generator).
            # has_value proved "value" is present (round-27: read it where used, not up top).
            value = header_config["value"]
            normalized = sec_cap["parse"](value)
            if normalized is None:
                ops.append(_make_non_convertible(
                    rule, f"response header '{header_name}': value {value!r} has no "
                    "faithful native Response Headers Policy representation (CloudFront "
                    "would emit a different or empty value) — set it at the origin",
                    owned_key_segments=owned))
                continue
            # F1: carry the SCREENED cond/raw_expr (post _screen_unmappable) so placement
            # gates on the authoritative condition and never re-parses the raw rule
            # expression (which would restore an already-pruned unmappable OR branch).
            ops.append({
                "type": "response_headers_policy",
                "cf_source_rule": rule.get("id", ""),
                "description": rule.get("description", ""),
                "condition": cond,
                "raw_expression": raw_expr,
                "params": {
                    "name": header_name,
                    "value": value,
                    "operation": operation,
                    "normalized": normalized,     # the value the generator renders
                },
                "owned_key_segments": owned,
            })
            continue

        if lower_name == "permissions-policy" and has_value:
            # Permissions-Policy has no native RHP field, and it is NOT a CORS header — the
            # CORS→CFF-LOSSY path below does not cover it. Keep it NON_CONVERTIBLE (a
            # viewer-response CFF carries the same error-response gap, but accepting that
            # gap for Permissions-Policy is out of this change's scope).
            ops.append(_make_non_convertible(
                rule, f"response header '{header_name}': no native CloudFront Response "
                "Headers Policy field — set it at the origin", owned_key_segments=owned))
            continue

        # Everything else → a viewer-response CloudFront Function op. This mechanism is
        # UNIFORMLY LOSSY_WITH_WARNING (round-27 finding 5): a viewer-response function does NOT
        # run on CloudFront-generated error responses (origin 4xx/5xx, custom error pages, WAF
        # blocks), so the header (set/dynamic/remove alike) is absent/unmodified there, whereas
        # Cloudflare's response transform still applies. That error-response gap is a property of
        # the MECHANISM, not of CORS — plain custom set, a dynamic set, and remove share it, so
        # they are LOSSY too (previously they were wrongly EXACT). EXACT is reserved for headers
        # a NATIVE Response Headers Policy fully covers (the security-header branch above); a
        # header that can't accept this gap is NC'd upstream (security / Permissions-Policy).
        #   - A STATIC CORS header additionally has the native-cors_config unfaithfulness noted
        #     in its reason; custom_headers_config also rejects CORS names. Empty CORS value is
        #     carried verbatim (still LOSSY), never dropped.
        cors_static = is_static_cors_header(header_name) and has_value
        op = {
            "type": f"{operation}_response_header",
            "cf_source_rule": rule.get("id", ""),
            "description": rule.get("description", ""),
            "condition": cond,
            "raw_expression": raw_expr,
            "params": {"name": header_name},
            "owned_key_segments": owned,
            "outcome_status": _OUTCOME_LOSSY,
        }
        _gap = f"response header '{header_name}' {VIEWER_RESPONSE_GAP_REASON}"
        if cors_static:
            op["outcome_reason"] = (_gap + " (CloudFront's native cors_config is not a faithful "
                "equivalent for a static header set, and custom_headers_config rejects CORS "
                "header names.)")
        else:
            op["outcome_reason"] = _gap
        if operation == "remove":
            pass
        else:
            # LOWER the header value ONCE (round-26). empty_behavior (delete_header for a dynamic
            # value; a static "" is an empty header) is DERIVED + stored ON the LoweredValue.
            lowered, nc_reason = lower_action_container(header_config, f"response header "
                                                        f"'{header_name}'", "response_header",
                                                        allow_empty_value=True,
                                                        allowed_extra=("operation",))
            if nc_reason:
                ops.append(_make_non_convertible(rule, nc_reason, owned_key_segments=owned))
                continue
            op["params"]["value_lowered"] = lowered
        ops.append(op)

    return ops


def process_custom_error_rule(rule, ip_lists, phase):
    """Process a Custom Error Rule (http_custom_errors).

    5 paths per architecture doc:
    1. serve_error + supported code + no inline content → custom_error_response + response_page_path
    2. serve_error + supported code + only status remap → custom_error_response + response_code
    3. serve_error + unsupported code → non_convertible
    4. serve_error + inline content → non_convertible
    5. serve_error + dynamic/conditional → non_convertible
    """
    expr = rule.get("expression", "true")

    # SOURCE SCHEMA (round-27 review-3 finding 2). Validate action_parameters BEFORE reading any
    # field, by PRESENCE not truthiness — a None/list action_parameters used to AttributeError,
    # content=123 crashed len(), an unknown sibling was ignored, and a non-string content_type
    # reached a later FATAL. A malformed source is bad INPUT → a clean NC.
    action_params = rule.get("action_parameters")
    bad = validate_action_object(action_params, "custom error action_parameters",
                                 ("status_code", "content", "content_type"))
    if bad:
        return _make_non_convertible(rule, bad)
    has_status = "status_code" in action_params
    status_code = action_params.get("status_code")
    # status_code, WHEN PRESENT, must be a real HTTP status (100..599) — validate on presence, not
    # after an `or 500` fallback that would rewrite an explicit bad value to 500 (finding 2).
    if has_status and not (isinstance(status_code, int) and not isinstance(status_code, bool)
                           and 100 <= status_code <= 599):
        return _make_non_convertible(
            rule, f"custom error status_code {status_code!r} is not a valid HTTP status (100..599)")
    has_content = "content" in action_params
    content = action_params.get("content")
    # content, WHEN PRESENT, must be a string (inline error body). A non-string has no faithful KVS
    # representation. (An empty "" is a legal empty body — see the inline branch.)
    if has_content and not isinstance(content, str):
        return _make_non_convertible(
            rule, f"custom error content must be a string, got {type(content).__name__}")
    content_type = action_params.get("content_type")
    if "content_type" in action_params and not (isinstance(content_type, str) and content_type != ""):
        return _make_non_convertible(
            rule, f"custom error content_type must be a non-empty string, got {content_type!r}")
    # CROSS-FIELD (round-27 review-4 finding 3): content_type describes the inline body, so it is
    # meaningful ONLY when `content` is present. Without content the rule maps to a native
    # custom_error_response (response_page_path / response_code) that has NO content-type field, so
    # a content_type there would be a SILENTLY DROPPED source leaf. Reject it as NC instead of
    # ignoring it (which would leave the leaf un-accounted / wrongly claimed by the whole unit).
    if "content_type" in action_params and "content" not in action_params:
        return _make_non_convertible(
            rule, "custom error content_type is set without content — a native custom error "
            "response has no content-type field, so it can't be honored (set content for an "
            "inline body, or remove content_type)")

    # Parse expression to check for http.response.code (at any depth, incl.
    # under a NOT node).
    cond, raw_expr = parse_expression(expr)
    # Screen unmappable condition fields like every other processor. Without this a
    # PARSEABLE-but-unmappable condition (cf.bot_management.score, an ip.src $list)
    # slipped past into serve_error_inline and rendered `if (false)` — a silent
    # drop (non_convertible=0, ip list never resolved to KVS). Response-phase, so
    # response.code stays mappable.
    cond, raw_expr, _nc = _screen_unmappable(rule, cond, raw_expr, ip_lists, target="response")
    if _nc:
        return _nc
    response_code = _find_response_code_value(cond)

    # Path 4: inline content → NON_CONVERTIBLE (conversion-policy step-3 decision #1). CloudFront's
    # native custom_error_response has NO inline body — it serves an origin-hosted page by
    # response_page_path. The old CFF+KVS inline path is dropped: its behavior was not equivalent (a
    # viewer-response CFF doesn't run on 4xx+, so an inline error page + response-phase logic can't be
    # reproduced). Keyed on PRESENCE, so an explicit `content: ""` is still inline. The source-schema
    # checks above (non-string content / illegal status / content_type-without-content) fire FIRST, so
    # a malformed rule keeps its specific reason; only a well-formed inline rule reaches this. No
    # serve_error_inline op and no inline error KVS are produced.
    if has_content:
        return _make_non_convertible(
            rule, "custom error rule has inline content — CloudFront's native custom_error_response "
            "has no inline body; host the error page on an origin and reference it via "
            "response_page_path (the inline CFF+KVS path is not a faithful conversion)")

    # The ERROR code (which origin status CloudFront intercepts) comes from the
    # rule's CONDITION (http.response.code eq N), NOT the action's status_code
    # (that is the code RETURNED to the viewer — response_page's response_code).
    # Conflating them made `code eq 500 and host x` + action 404 intercept
    # origin 404s. If the condition doesn't yield a single clean code
    # (compound/OR/negated → response_code is None), we can't know which status
    # to intercept → non-convertible.
    error_code = response_code
    if error_code is None:
        return _make_non_convertible(
            rule,
            "Custom error rule's intercepted status is not a single "
            "http.response.code equality (compound/negated condition), so it "
            "can't map to a CloudFront custom error response. Handle at origin."
        )

    # Path 3: unsupported status code
    if error_code not in SUPPORTED_ERROR_CODES:
        return _make_non_convertible(
            rule,
            f"CloudFront custom error response only supports status codes: "
            f"{', '.join(str(c) for c in sorted(SUPPORTED_ERROR_CODES))}; "
            f"got {error_code}"
        )

    # Path 1/2: supported error code, no inline content. response_code (returned
    # to the viewer) is the action's status_code, if any.
    return {
        "type": "custom_error_response",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "params": {
            "error_code": error_code,
            "response_code": status_code,
        },
        # This EXACT native conversion owns the rule's status_code source leaf → _place_result records
        # an EXACT claim (else it's a silent drop the finalize gate flags).
        "owned_key_segments": [["status_code"]],
    }


def process_compression_rule(rule, ip_lists, phase):
    """Process a Compression Rule (http_request_compress)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})
    algorithms = action_params.get("algorithms", [])

    cond, raw_expr = parse_expression(expr)

    enable_gzip = any(a.get("name") == "gzip" for a in algorithms)
    enable_brotli = any(a.get("name") == "brotli" for a in algorithms)

    # ip.src in compression rules → non_convertible (raw_expr too: OR defers to
    # raw text with cond=None)
    if _uses_ip_src(cond, raw_expr):
        return _make_non_convertible(
            rule,
            "ip.src condition in Compression Rules cannot be converted; "
            "CFF cannot control compression"
        )
    # An unstructurable condition would be silently dropped downstream — report it
    # (this processor doesn't route through _screen_unmappable).
    _unparse = _raw_condition_unparseable_reason(raw_expr)
    if _unparse:
        return _make_non_convertible(rule, _unparse)
    # SHARED semantic screen (step-3 item 1): a non-executable / policy-NC condition (e.g. numeric-geo
    # once the authority set flips) → NC here, not a silently-converted compression_setting.
    _sem_nc = _screen_condition_semantics(rule, cond)
    if _sem_nc:
        return _sem_nc

    return {
        "type": "compression_setting",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "params": {
            "enable_gzip": enable_gzip,
            "enable_brotli": enable_brotli,
        },
    }


def process_cloud_connector(rule, ip_lists, phase):
    """Process a Cloud Connector Rule."""
    expr = rule.get("expression", "true")
    provider = rule.get("provider", "")
    params = rule.get("parameters", {})
    host = params.get("host", "")

    cond, raw_expr = parse_expression(expr)
    # An unstructurable condition would be silently dropped downstream — report it
    # (this processor doesn't route through _screen_unmappable).
    _unparse = _raw_condition_unparseable_reason(raw_expr)
    if _unparse:
        return _make_non_convertible(rule, _unparse)
    # SHARED semantic screen (step-3 item 1): a non-executable / policy-NC condition (e.g. numeric-geo
    # once the authority set flips) → NC here, not a silently-converted cloud_connector artifact.
    _sem_nc = _screen_condition_semantics(rule, cond)
    if _sem_nc:
        return _sem_nc

    return {
        "type": "cloud_connector",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "params": {
            "provider": provider,
            "origin_host": host,
        },
    }


# ── helpers ──────────────────────────────────────────────────────────────────


def _find_response_code_value(cond, negated=False):
    """Return the code named by a SINGLE positive `response_code eq N` leaf.

    A CloudFront custom_error_response maps exactly ONE error code to one
    response, so only an unambiguous single code is convertible:
      - an OR / NOT node → None. An OR of codes can't map to one response
        (returning the first would silently drop the rest); a negated code is
        an EXCLUSION, not the code to serve.
      - an AND is allowed ONLY when it reduces to exactly one `code eq N` leaf
        after dropping redundant per-host ROUTING conjuncts (`host eq/in/ne`).
        The pipeline routes one distribution per host, so `code eq 500 and host
        eq x` is really just `code eq 500` on this host's distribution. But only
        a ROUTING host leaf is redundant — a LIVE host predicate (`host contains
        "internal"`, `len(host) gt 5`) is a real scope the custom error can't
        express per-distribution, so it must block extraction (→ None →
        non-convertible), NOT be silently erased (which would intercept the code
        on every request site-wide). A non-host, non-code conjunct (uri.path,
        geo) likewise → None.
    Returns an int (coerced from a quoted "404") or None.
    """
    if not isinstance(cond, dict):
        return None
    if "logic" in cond:
        if cond["logic"] != "and":
            return None  # OR / NOT can't name a single served code
        code = None
        for part in cond.get("parts", []):
            if not isinstance(part, dict) or "logic" in part:
                return None  # nested logic → can't reduce to one clean code
            if host_leaf_is_routing(part):
                continue  # redundant per-host ROUTING conjunct — drop it
            if part.get("field") == "host":
                return None  # LIVE host predicate (contains/len/…) — real scope
            if part.get("field") == "response_code":
                c = _find_response_code_value(part)
                if c is None or code is not None:
                    return None  # unusable code, or more than one code leaf
                code = c
                continue
            return None  # some other scope (path, geo…) → not representable
        return code
    if cond.get("field") == "response_code":
        op = cond.get("op", "eq")
        if op != "eq":  # not_eq / ne / ranges don't name a single served code
            return None
        val = cond.get("value")
        try:
            return int(val)  # a quoted `eq "404"` parses to str; coerce
        except (TypeError, ValueError):
            return None
    return None


def _make_non_convertible(rule, reason, owned_key_segments=None):
    """Build a non_convertible result. `owned_key_segments` (a list of raw dict-key
    paths, e.g. [["headers", "X-Bad"]]) is a PROVENANCE HINT: when the rule only
    PARTIALLY fails (one header of many), it names the leaves this NC outcome owns so
    placement claims only those, not the whole rule. Omit for a whole-unit failure."""
    r = {
        "type": "non_convertible",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "reason": reason,
    }
    if owned_key_segments is not None:
        r["owned_key_segments"] = owned_key_segments
    return r


