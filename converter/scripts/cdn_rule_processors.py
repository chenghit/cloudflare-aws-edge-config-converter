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
    condition_unmappable_fields, value_expression_unmappable,
    host_leaf_is_routing,
)

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


def _is_ip_src_field(field):
    return field in ("ip.src", "ip.src.in")


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

    Returns (condition, raw_expr, non_conv_reason). On OR-prune the pruned
    condition is returned structured and raw_expr is cleared so the generator
    uses the pruned form.
    """
    if condition is not None:
        new_cond, reason = _prune_unmappable(condition, target)
        return new_cond, raw_expr, reason
    if raw_expr:
        # A raw the FULL parser can't structure would have its guarded action
        # silently dropped by the generator (comment-only, unseen by the validator
        # and the report). Report non-convertible here instead. Shared judgement
        # with the non-_screen_unmappable processors via _raw_condition_unparseable_reason.
        unparse_reason = _raw_condition_unparseable_reason(raw_expr)
        if unparse_reason:
            return condition, raw_expr, unparse_reason
        full = parse_expression_full(raw_expr)  # now guaranteed to parse
        if not condition_unmappable_fields(full, target):
            return condition, raw_expr, None  # nothing unmappable; leave deferred
        new_cond, reason = _prune_unmappable(full, target)
        if reason:
            return None, None, reason
        # OR-prune succeeded → use the structured pruned condition, drop raw.
        return new_cond, None, None
    return condition, raw_expr, None


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
    return cond, raw_expr, None


def _screen_value_expr(rule, expression, what, target="cff"):
    """Screen a dynamic ACTION-value expression (redirect target, rewrite path,
    query) for fields with no CloudFront source.

    Header transforms already screen per-header via value_expression_unmappable;
    this gives redirect/rewrite/query the same treatment so an unmappable action
    value becomes a clean per-rule non_convertible instead of a leaked
    `'' /* WARNING… */` marker inlined into the generated JS. Returns a
    non_convertible dict or None.

    ``target`` is the emit phase — redirect/rewrite/query values are all
    request-phase ("cff"), so a response-only field like http.response.code is
    correctly flagged there.
    """
    if not expression:
        return None
    reason = value_expression_unmappable(expression, target)
    if reason:
        return _make_non_convertible(rule, f"{what}: {reason}")
    return None


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
    from_value = action_params.get("from_value", {})
    target_url = from_value.get("target_url", {})
    status_code = from_value.get("status_code", 302)
    preserve_qs = from_value.get("preserve_query_string", False)

    cond, raw_expr = parse_expression(expr)

    # HTTP→HTTPS redirect detection
    if (cond and cond.get("field") == "full_uri" and
            cond.get("op") == "wildcard" and cond.get("value") == "http://*"):
        return {
            "type": "distribution_setting",
            "setting": "viewer_protocol_policy",
            "value": "redirect-to-https",
            "cf_source_rule": rule.get("id", ""),
            "description": rule.get("description", ""),
        }

    # Check ip.src convertibility
    if phase in IP_SRC_NON_CONVERTIBLE_PHASES and _uses_ip_src(cond, raw_expr):
        return _make_non_convertible(rule, "ip.src condition in Cache Rules cannot be converted; CFF cannot control caching decisions")

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    # Check if target is a dynamic expression
    target_expr = target_url.get("expression")
    target_value = target_url.get("value")

    # Screen the action-value expression too (redirect target).
    nc = _screen_value_expr(rule, target_expr, "redirect target")
    if nc:
        return nc

    op = {
        "type": "redirect",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "params": {
            "status_code": status_code,
            "preserve_query_string": preserve_qs,
        },
    }
    if target_expr:
        # Keep condition as-is — tf-domain uses condition for JS if-check,
        # target_expression for JS redirect target generation
        op["params"]["target_expression"] = target_expr
    elif target_value:
        # Static target: store under target_url (the key the JS generator reads).
        op["params"]["target_url"] = target_value

    return op


def process_rewrite_rule(rule, ip_lists, phase):
    """Process a URL Rewrite Rule (http_request_transform)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})
    uri = action_params.get("uri", {})
    path_info = uri.get("path", {})
    query_info = uri.get("query", {})

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    # Screen the action-value expressions (path / query rewrite targets).
    path_expr = path_info.get("expression")
    path_value = path_info.get("value")
    query_expr = query_info.get("expression")
    query_value = query_info.get("value")
    nc = _screen_value_expr(rule, path_expr, "rewrite path") or \
        _screen_value_expr(rule, query_expr, "rewrite query")
    if nc:
        return nc

    op = {
        "type": "rewrite",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "params": {},
    }

    # Path rewrite
    if path_expr:
        # Keep condition as-is — tf-domain uses condition for JS if-check,
        # path_expression for JS rewrite target generation
        op["params"]["path_expression"] = path_expr
    elif path_value:
        # Static path: store under "path" (the key the JS generator reads).
        op["params"]["path"] = path_value

    # Query rewrite (query_expr / query_value resolved above for screening)
    if query_expr:
        op["params"]["query_expression"] = query_expr
    elif query_value:
        op["params"]["new_query"] = query_value

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
                })
            else:
                results.append({
                    "type": "distribution_setting",
                    "setting": "viewer_protocol_policy",
                    "value": "redirect-to-https" if value == "full" else "allow-all",
                    "cf_source_rule": rule.get("id", ""),
                    "description": rule.get("description", ""),
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
                })
            else:
                tls_map = {"1.0": "TLSv1", "1.1": "TLSv1.1_2016", "1.2": "TLSv1.2_2021", "1.3": "TLSv1.2_2021"}
                results.append({
                    "type": "distribution_setting",
                    "setting": "minimum_protocol_version",
                    "value": tls_map.get(value, "TLSv1.2_2021"),
                    "cf_source_rule": rule.get("id", ""),
                    "description": rule.get("description", ""),
                })
        else:
            results.append({
                "type": "non_convertible",
                "cf_source_rule": rule.get("id", ""),
                "description": f"{rule.get('description', '')}: {setting}",
                "reason": f"Configuration setting '{setting}' has no CloudFront equivalent",
            })

    return results if results else [_make_non_convertible(rule, "Empty configuration rule")]


def process_origin_rule(rule, ip_lists, phase):
    """Process an Origin Rule (http_request_origin)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    host_header = action_params.get("host_header")
    origin_info = action_params.get("origin", {})
    sni = action_params.get("sni", {}).get("value")

    op = {
        "type": "origin_override",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "condition": cond,
        "raw_expression": raw_expr,
        "params": {},
    }
    if host_header:
        op["params"]["host_header"] = host_header
    if origin_info:
        op["params"]["origin_host"] = origin_info.get("host")
        op["params"]["origin_port"] = origin_info.get("port")
    if sni:
        op["params"]["sni"] = sni

    return op


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
            mode, qlist = _qs_selector(qs)
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
    """Decode a Cloudflare cache_key query_string selector to (mode, list).

    mode ∈ {"all","none","whitelist","allExcept", None}; list is the explicit names
    for whitelist/allExcept else None. Handles BOTH documented shapes and returns
    (None, None) for anything unrecognized (caller reports it non-convertible rather
    than crashing). `["*"]` means all (include) / none (exclude); `[]` or missing is
    treated as unrecognized.
    """
    inc = qs.get("include")
    exc = qs.get("exclude")
    # list form: {"include": [...]}, {"exclude": [...]}  (["*"] = all/none)
    if isinstance(inc, list):
        if inc == ["*"]:
            return "all", None
        return ("whitelist", inc) if inc else (None, None)
    if isinstance(exc, list):
        if exc == ["*"]:
            return "none", None
        return ("allExcept", exc) if exc else (None, None)
    # object form: {"include": {"all": true}} / {"include": {"list": [...]}} / exclude
    if isinstance(inc, dict):
        if inc.get("all"):
            return "all", None
        if inc.get("list"):
            return "whitelist", inc["list"]
    if isinstance(exc, dict):
        if exc.get("all"):
            return "none", None
        if exc.get("list"):
            return "allExcept", exc["list"]
    return None, None


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


def process_request_header_transform(rule, ip_lists, phase):
    """Process a Request Header Transform Rule (http_request_late_transform)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})
    headers = action_params.get("headers", {})

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    ops = []
    for header_name, header_config in headers.items():
        operation = header_config.get("operation", "set")
        value = header_config.get("value")
        expression = header_config.get("expression")

        op = {
            "type": f"{operation}_request_header",
            "cf_source_rule": rule.get("id", ""),
            "description": rule.get("description", ""),
            "condition": cond,
            "raw_expression": raw_expr,
            "params": {"name": header_name},
        }
        if operation == "remove":
            pass  # no value needed
        elif expression:
            # Partial convert: if this header's value expression references a
            # field with no CloudFront source, drop THIS header op (record it)
            # but keep the rest of the rule's headers. Request headers are
            # request-phase (cff).
            unmap = value_expression_unmappable(expression, "cff")
            if unmap:
                ops.append(_make_non_convertible(
                    rule, f"request header '{header_name}': {unmap}"))
                continue
            # Keep condition as-is — tf-domain uses condition for JS if-check,
            # value_expression for JS header value generation
            op["params"]["value_expression"] = expression
        elif value:
            op["params"]["value"] = value

        ops.append(op)

    return ops


def process_response_header_transform(rule, ip_lists, phase):
    """Process a Response Header Transform Rule (http_response_headers_transform)."""
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})
    headers = action_params.get("headers", {})

    cond, raw_expr = parse_expression(expr)

    # Resolve IP lists + screen unmappable condition fields. Response phase:
    # response_code IS sourceable here, so screen with target="response".
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists, target="response")
    if nc:
        return nc

    ops = []
    for header_name, header_config in headers.items():
        operation = header_config.get("operation", "set")
        value = header_config.get("value")
        expression = header_config.get("expression")

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
                "is acceptable."))
            continue

        # Check if this is a well-known security/CORS header → RHP
        lower_name = header_name.lower()
        is_cors = lower_name.startswith("access-control-")
        is_security = lower_name in (
            "strict-transport-security", "x-frame-options",
            "x-content-type-options", "x-xss-protection",
            "referrer-policy", "content-security-policy",
            "permissions-policy",
        )

        if (is_cors or is_security) and value and not expression:
            # Static security/CORS header → response_headers_policy (native).
            # F1: carry the SCREENED cond/raw_expr (post _screen_unmappable) on the
            # result so placement gates on the authoritative condition and never
            # re-parses the raw rule expression (which would restore an already
            # pruned unmappable OR branch and render the whole thing `false`).
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
                    "is_cors": is_cors,
                    "is_security": is_security,
                },
            })
        else:
            # Dynamic or conditional → viewer_response_ops
            op = {
                "type": f"{operation}_response_header",
                "cf_source_rule": rule.get("id", ""),
                "description": rule.get("description", ""),
                "condition": cond,
                "raw_expression": raw_expr,
                "params": {"name": header_name},
            }
            if operation == "remove":
                pass
            elif expression:
                # Partial convert: drop this one header if its value expression
                # references a field with no CloudFront source; keep the rest.
                # Response headers are response-phase, where response.code IS
                # sourceable — so screen with target="response".
                unmap = value_expression_unmappable(expression, "response")
                if unmap:
                    ops.append(_make_non_convertible(
                        rule, f"response header '{header_name}': {unmap}"))
                    continue
                # Keep condition as-is — tf-domain uses condition for JS if-check,
                # value_expression for JS header value generation
                op["params"]["value_expression"] = expression
            elif value:
                op["params"]["value"] = value
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
    action_params = rule.get("action_parameters", {})
    status_code = action_params.get("status_code")
    content = action_params.get("content")
    content_type = action_params.get("content_type")

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

    # Path 4: inline content
    if content:
        # 4a: expression uses response-phase fields → non_convertible
        #     (CFF viewer-response does not execute on 4xx+)
        if _expression_uses_response_fields(cond, raw_expr):
            return _make_non_convertible(
                rule,
                "Custom error rule with inline content and response-phase condition "
                "(http.response.code) cannot be converted; CFF viewer-response does not "
                "execute on 4xx+ responses. Deploy error page as static file on origin"
            )
        # 4b: content exceeds KVS 1KB value limit → non_convertible
        if len(content) > 1024:
            return _make_non_convertible(
                rule,
                f"Inline content is {len(content)} characters, exceeds CloudFront KVS "
                "1024-character value limit. Deploy error page as static file on origin "
                "and use custom error response with response_page_path"
            )
        # 4b': an unstructurable condition would gate the serve_error_inline op and
        # then be silently dropped by the generator (comment-only) — report it.
        _unparse = _raw_condition_unparseable_reason(raw_expr)
        if _unparse:
            return _make_non_convertible(rule, _unparse)
        # 4c: request-phase only + content ≤ 1KB → serve via CFF + KVS
        effective_code = response_code or status_code or 500
        kvs_key = f"error:{rule.get('id', '')[:8]}"
        return {
            "type": "serve_error_inline",
            "cf_source_rule": rule.get("id", ""),
            "description": rule.get("description", ""),
            "condition": cond,
            "raw_expression": raw_expr,
            "params": {
                "status_code": effective_code,
                "content": content,
                "content_type": content_type or "text/plain",
                "kvs_key": kvs_key,
            },
        }

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


def process_bulk_redirect_items(redirect_items, list_name):
    """Process bulk redirect list items into KVS entries."""
    kvs_entries = []
    for item in redirect_items:
        rd = item.get("redirect", {})
        source = rd.get("source_url", "")
        target = rd.get("target_url", "")
        status = rd.get("status_code", 301)
        preserve_qs = rd.get("preserve_query_string", False)
        include_subdomains = rd.get("include_subdomains", False)

        kvs_entries.append({
            "source_url": source,
            "target_url": target,
            "status_code": status,
            "preserve_query_string": preserve_qs,
            "include_subdomains": include_subdomains,
            "list_name": list_name,
        })

    return kvs_entries


# ── helpers ──────────────────────────────────────────────────────────────────

def _expression_uses_response_fields(cond, raw_expr):
    """Check if expression references response-phase fields (http.response.code)."""
    if raw_expr and "http.response" in raw_expr:
        return True
    if cond is None:
        return False
    if cond.get("field") == "response_code":
        return True
    if "logic" in cond:
        # Recurse through every child (parts AND a NOT's item), at any depth.
        return any(_expression_uses_response_fields(c, None)
                   for c in iter_condition_children(cond))
    return False


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


def _make_non_convertible(rule, reason):
    return {
        "type": "non_convertible",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "reason": reason,
    }


