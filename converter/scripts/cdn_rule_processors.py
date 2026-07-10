"""Rule processors for cdn-preprocess.py — one function per Cloudflare rule type.

Each processor takes a rule dict (from Cloudflare JSON) and returns a list of
viewer_request_ops / viewer_response_ops / non_convertible entries, plus metadata
updates (cache_policy, origin, distribution_settings, etc.).
"""
import re
from cdn_expr_parser import (
    parse_expression, parse_expression_full, extract_orp_headers,
    extract_kvs_triggers, extract_host_filter, CF_FIELD_MAP,
    extract_path_pattern_single,
    condition_unmappable_fields, value_expression_unmappable,
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
        return any(_condition_uses_ip_src(p) for p in condition.get("parts", []))
    return condition.get("field") in ("ip.src",)


# `ip.src` as a direct-IP field: the token `ip.src` NOT followed by another
# `.<subfield>` (which would be a geo field like ip.src.country / .continent).
_RE_RAW_IP_SRC = re.compile(r"\bip\.src\b(?!\.)")


def _uses_ip_src(condition, raw_expr=None):
    """Direct-IP (ip.src) check that also covers a deferred raw expression.

    An OR expression is deferred as raw text (condition is None), so a
    structured-only check would let `ip.src eq "..." or ip.src eq "..."` slip
    past the cache/compression ip.src guard and silently drop the IP
    restriction. Scan the raw text too.
    """
    if _condition_uses_ip_src(condition):
        return True
    if raw_expr and _RE_RAW_IP_SRC.search(raw_expr):
        return True
    return False


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
        new_parts = []
        for p in condition["parts"]:
            np, reason = _resolve_ip_list_in_condition(p, ip_lists)
            if reason:
                return None, reason
            new_parts.append(np)
        return {**condition, "parts": new_parts}, None
    op = condition.get("op")
    if op in ("in_list", "not_in_list"):
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


def _prune_unmappable(condition):
    """Apply the conservative unmappable-field policy to a structured condition.

    Returns (new_condition, non_conv_reason). reason is None when convertible.
      - top-level OR: drop each branch that references an unmappable field,
        keep the rest (this only narrows the match — safe). If every branch is
        dropped, the whole condition is unmappable.
      - AND / NOT / a bare leaf: dropping a branch would WIDEN the match
        (potential over-match / security change), so mark the whole op
        non-convertible for human review.
    """
    # Top-level OR: classify each branch exactly once. Drop every branch that
    # references an unmappable field (this only narrows the match — safe), keep
    # the rest. If every branch is dropped, the whole condition is unmappable.
    if "logic" in condition and condition["logic"] == "or":
        kept, first_bad = [], None
        for p in condition["parts"]:
            bad = condition_unmappable_fields(p)
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
    bad = condition_unmappable_fields(condition)
    if not bad:
        return condition, None
    return None, bad[0][1]


def _resolve_unmappable_in_condition(condition, raw_expr=None):
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
        new_cond, reason = _prune_unmappable(condition)
        return new_cond, raw_expr, reason
    if raw_expr:
        try:
            full = parse_expression_full(raw_expr)
        except Exception:
            return condition, raw_expr, None  # generator has its own guard
        if not condition_unmappable_fields(full):
            return condition, raw_expr, None  # nothing unmappable; leave deferred
        new_cond, reason = _prune_unmappable(full)
        if reason:
            return None, None, reason
        # OR-prune succeeded → use the structured pruned condition, drop raw.
        return new_cond, None, None
    return condition, raw_expr, None


def _screen_unmappable(rule, cond, raw_expr, ip_lists):
    """Resolve IP-list references then screen unmappable condition fields.

    Folds the identical pre-processing that every rule-type processor ran
    inline: resolve `$list` references in the condition, then apply the
    unmappable-field policy (OR-prune / AND-NOT-bare reject). Returns
    ``(cond, raw_expr, non_convertible)`` — when ``non_convertible`` is a dict,
    the caller should return it immediately; otherwise the (possibly rewritten)
    cond/raw_expr are ready to use.
    """
    if cond:
        cond, ip_reason = _resolve_ip_list_in_condition(cond, ip_lists)
        if ip_reason:
            return cond, raw_expr, _make_non_convertible(rule, ip_reason)
    cond, raw_expr, unmap_reason = _resolve_unmappable_in_condition(cond, raw_expr)
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
        for p in condition["parts"]:
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


def process_config_rule(rule, ip_lists, phase):
    """Process a Configuration Rule (http_config_settings).

    Most settings are Cloudflare-specific → non_convertible.
    """
    expr = rule.get("expression", "true")
    action_params = rule.get("action_parameters", {})
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
            # SSL mode → distribution setting
            results.append({
                "type": "distribution_setting",
                "setting": "viewer_protocol_policy",
                "value": "redirect-to-https" if value == "full" else "allow-all",
                "cf_source_rule": rule.get("id", ""),
                "description": rule.get("description", ""),
            })
        elif setting == "min_tls_version":
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

    cache_enabled = action_params.get("cache", True)
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
        "params": {
            "bypass": not cache_enabled,
        },
    }

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

    # Cache key
    if custom_key:
        qs = custom_key.get("query_string", {})
        if qs.get("exclude", {}).get("all"):
            result["params"]["cache_key_qs"] = "none"
        elif qs.get("include", {}).get("all"):
            result["params"]["cache_key_qs"] = "all"
        elif qs.get("include", {}).get("list"):
            result["params"]["cache_key_qs"] = "whitelist"
            result["params"]["cache_key_qs_list"] = qs["include"]["list"]
        elif qs.get("exclude", {}).get("list"):
            result["params"]["cache_key_qs"] = "allExcept"
            result["params"]["cache_key_qs_exclude"] = qs["exclude"]["list"]

        headers = custom_key.get("header", {})
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

    return result


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

    # Resolve IP lists + screen unmappable condition fields.
    cond, raw_expr, nc = _screen_unmappable(rule, cond, raw_expr, ip_lists)
    if nc:
        return nc

    ops = []
    for header_name, header_config in headers.items():
        operation = header_config.get("operation", "set")
        value = header_config.get("value")
        expression = header_config.get("expression")

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
            # Static security/CORS header → response_headers_policy
            ops.append({
                "type": "response_headers_policy",
                "cf_source_rule": rule.get("id", ""),
                "description": rule.get("description", ""),
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

    # Parse expression to check for http.response.code
    cond, raw_expr = parse_expression(expr)
    response_code = None
    if cond and "logic" in cond:
        for p in cond.get("parts", []):
            if p.get("field") == "response_code":
                response_code = p.get("value")

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

    # Path 3: unsupported status code
    effective_code = response_code or status_code
    if effective_code and effective_code not in SUPPORTED_ERROR_CODES:
        return _make_non_convertible(
            rule,
            f"CloudFront custom error response only supports status codes: "
            f"{', '.join(str(c) for c in sorted(SUPPORTED_ERROR_CODES))}; "
            f"got {effective_code}"
        )

    # Path 1/2: supported code, no inline content
    if effective_code:
        return {
            "type": "custom_error_response",
            "cf_source_rule": rule.get("id", ""),
            "description": rule.get("description", ""),
            "params": {
                "error_code": effective_code,
                "response_code": status_code,
            },
        }

    # Path 5: no clear status code
    return _make_non_convertible(
        rule,
        "Custom error rule without a clear status code cannot be automatically converted"
    )


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
        return any(p.get("field") == "response_code" for p in cond.get("parts", []))
    return False


def _make_non_convertible(rule, reason):
    return {
        "type": "non_convertible",
        "cf_source_rule": rule.get("id", ""),
        "description": rule.get("description", ""),
        "reason": reason,
    }


