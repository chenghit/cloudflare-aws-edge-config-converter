#!/usr/bin/env python3
"""cdn-preprocess.py — Stage 3: Convert Cloudflare CDN rules to IR JSON.

Usage:
    python3 cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]

Exit codes: 0 = all OK, 1 = partial failure, 2 = total failure.
"""
import json, sys, os, re, glob as globmod, copy

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_expr_parser import (
    parse_expression, extract_orp_headers, extract_orp_headers_from_raw,
    extract_kvs_triggers, extract_host_filter, extract_path_pattern_single,
    iter_condition_children, host_filter_applies, host_leaf_is_routing,
    condition_has_path_field, CACHE_BYPASS_HEADER,
)
from cdn_common import emit_result, derive_cert_domain
from cdn_rule_processors import (
    process_redirect_rule, process_rewrite_rule, process_config_rule,
    process_origin_rule, process_cache_rule, process_request_header_transform,
    process_response_header_transform, process_custom_error_rule,
    process_cloud_connector, process_bulk_redirect_items,
    process_compression_rule,
    IP_SRC_NON_CONVERTIBLE_PHASES,
)

# ── file discovery ───────────────────────────────────────────────────────────

RULE_FILES = {
    "redirect": "Redirect-Rules.txt",
    "rewrite": "URL-Rewrite-Rules.txt",
    "config": "Configuration-Rules.txt",
    "origin": "Origin-Rules.txt",
    "cache": "Cache-Rules.txt",
    "request_header": "Request-Header-Transform.txt",
    "response_header": "Response-Header-Transform.txt",
    "custom_error": "Custom-Error-Rules.txt",
    "compression": "Compression-Rules.txt",
    "managed_transforms": "Managed-Transforms.txt",
}

CLOUD_CONNECTOR_FILE = "Cloud-Connector-Rules.txt"

PHASE_MAP = {
    "redirect": "http_request_dynamic_redirect",
    "rewrite": "http_request_transform",
    "config": "http_config_settings",
    "origin": "http_request_origin",
    "cache": "http_request_cache_settings",
    "request_header": "http_request_late_transform",
    "response_header": "http_response_headers_transform",
    "custom_error": "http_custom_errors",
    "compression": "http_request_compress",
}


def find_zone_dir(config_path):
    """Find the zone backup directory (contains DNS.txt).

    followlinks=True so a symlinked per-zone view (see SKILL.md multi-zone
    flow) is walked like the glob-based scripts, which follow symlinks.
    """
    for root, dirs, files in os.walk(config_path, followlinks=True):
        if "DNS.txt" in files and "account" not in root:
            return root
    return None


def load_json_file(path):
    """Load a Cloudflare backup JSON file, handling both ruleset and array formats."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"  WARN: {path} is empty or invalid JSON, skipping", file=sys.stderr)
        return None
    if not data.get("success", True):
        return None
    result = data.get("result")
    if isinstance(result, dict) and "rules" in result:
        return result["rules"]
    if isinstance(result, list):
        return result
    return result


def latest_account_dir(config_path):
    """Newest account/<timestamp>/ dir (user may have backed up more than once)."""
    dirs = sorted(d for d in globmod.glob(os.path.join(config_path, "account", "*"))
                  if os.path.isdir(d))
    if not dirs:
        return None
    if len(dirs) > 1:
        print(f"WARNING: {len(dirs)} account backups found; using newest "
              f"({os.path.basename(dirs[-1])})", file=sys.stderr)
    return dirs[-1]


def load_ip_lists(config_path):
    """Load account-level IP lists → {list_name: [ip1, ip2, ...]}."""
    ip_lists = {}
    account_dir = latest_account_dir(config_path)
    if not account_dir:
        return ip_lists

    for f in globmod.glob(os.path.join(account_dir, "List-Items-ip-*.txt")):
        basename = os.path.basename(f)
        # Extract list name: List-Items-ip-<name>.txt
        m = re.match(r"List-Items-ip-(.+)\.txt$", basename)
        if not m:
            continue
        list_name = m.group(1)
        items = load_json_file(f)
        if items and isinstance(items, list):
            ip_lists[list_name] = [item.get("ip", "") for item in items if item.get("ip")]
    return ip_lists


def load_bulk_redirect_items(config_path):
    """Load account-level bulk redirect list items → {list_name: [items]}."""
    redirects = {}
    account_dir = latest_account_dir(config_path)
    if not account_dir:
        return redirects

    for f in globmod.glob(os.path.join(account_dir, "List-Items-redirect-*.txt")):
        basename = os.path.basename(f)
        m = re.match(r"List-Items-redirect-(.+)\.txt$", basename)
        if not m:
            continue
        list_name = m.group(1)
        items = load_json_file(f)
        if items and isinstance(items, list):
            redirects[list_name] = items
    return redirects


def load_managed_transforms(zone_dir):
    """Load Managed Transforms settings."""
    path = os.path.join(zone_dir, "Managed-Transforms.txt")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"  WARN: {path} is empty or invalid JSON, skipping", file=sys.stderr)
        return {}
    return data.get("result", {})


# An S3 host (REST endpoint `bucket.s3[.region].amazonaws.com` or website
# endpoint `bucket.s3-website[.-]region.amazonaws.com`). Mirrors the S3 patterns
# in cdn-parse-dns.classify_origin; used to spot a redundant S3 origin-override.
_RE_S3_HOST = re.compile(r"\.s3[.-]", re.I)


def _is_s3_host(host):
    return bool(host) and ".amazonaws.com" in host.lower() and bool(_RE_S3_HOST.search(host))


# ── domain matching ──────────────────────────────────────────────────────────

def hostname_matches(hostname, pattern):
    """Check if hostname matches a pattern (supports wildcard *)."""
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return hostname.endswith(suffix) or hostname == pattern[2:]
    return False


def rule_applies_to_domain(host_filter, hostname, apex_domain):
    """Check if a rule with the given host filter applies to this domain.

    The host filter is None (global) or a host-condition tree; it is evaluated
    against this CONCRETE distribution hostname via hostname_matches (which
    handles zone wildcards). See extract_host_filter / host_filter_applies —
    evaluating against real hostnames avoids the unsound wildcard set algebra
    the previous include/exclude representation used.
    """
    return host_filter_applies(host_filter, hostname, hostname_matches)


def _host_leaf_consumed_for_routing(cond):
    """True if this leaf is a host test the router consumed for distribution
    scoping (host eq/in/ne/not_in/wildcard) and is therefore redundant on the
    distribution the rule was routed to — safe to strip. A `host` leaf the
    router does NOT consume is a LIVE predicate that must be KEPT and rendered,
    not dropped: `len(http.host) gt 5` (size_check), `http.host contains "x"`.
    full_uri leaves carry a host_pattern but their PATH part still matters, so
    they are never stripped (host_leaf_is_routing guards on field == "host").
    Single source of truth: cdn_expr_parser.host_leaf_is_routing."""
    return host_leaf_is_routing(cond)


def _strip_host_condition(cond):
    """Remove the now-redundant host test once the rule is routed to a single
    host's distribution.

    The CDN pipeline builds one CloudFront distribution per proxied host, and
    rule_applies_to_domain() has ALREADY decided this rule belongs to this
    distribution (honoring include/exclude host filters). A host leaf the router
    consumed is redundant and always-true for this distribution — a positive
    `host eq x` (we ARE x) and, crucially, a negated `host ne x` / `not_eq x`
    too (an exclude-x rule only reaches a non-x distribution, where `host != x`
    holds). Strip ONLY those (see _host_leaf_consumed_for_routing); a live host
    predicate like `len(host) gt 5` is kept. If stripping empties the condition,
    return {"always": True} (NOT None — the op must keep a condition for
    validate-chunk Check11). Non-host leaves and OR/NOT (whose membership the
    classifier already resolved) are left as-is.
    """
    if cond is None:
        return None
    if "logic" not in cond:
        if _host_leaf_consumed_for_routing(cond):
            return {"always": True}  # router consumed it -> redundant here
        # Non-host leaf, live host predicate, or full_uri (path still matters).
        return cond
    if cond["logic"] == "and":
        kept = [p for p in cond.get("parts", [])
                if not _host_leaf_consumed_for_routing(p)]
        if not kept:
            return {"always": True}  # was only routing-host conjuncts -> unconditional
        if len(kept) == 1:
            return kept[0]
        return {**cond, "parts": kept}
    # OR / NOT: leave as-is (the classifier already resolved membership).
    return cond


def _strip_host_in_result(result):
    """Strip the redundant host test from a processor result's `condition`
    in place (the processor re-parsed the expression into its own condition)."""
    if isinstance(result, dict) and result.get("condition") is not None:
        result["condition"] = _strip_host_condition(result["condition"])


# ── IR assembly ──────────────────────────────────────────────────────────────

def make_empty_ir(domain_config):
    """Create empty IR structure for a domain."""
    hostname = domain_config["hostname"]
    sanitized = hostname.replace(".", "_").replace("-", "_")
    return {
        "metadata": {
            "hostname": hostname,
            "sanitized_name": sanitized,
            "apex_domain": domain_config.get("apex_domain", ""),
            # The same-level wildcard SAN this host needs a cert to cover (see
            # cdn_common.derive_cert_domain). Drives the report's per-coverage
            # cert list and the resolve-certs.py matcher. Fall back to deriving it
            # if an older domain_scope.json predates the field.
            "cert_domain": domain_config.get("cert_domain")
                or derive_cert_domain(hostname),
            "origin_type": domain_config.get("origin_type", "server"),
            "cert_arn_mode": domain_config.get("cert_arn_mode", "resolve"),
            "cert_arn": domain_config.get("cert_arn"),
            "kvs_requirements": {
                "needs_redirects": False,
                "needs_continent": False,
                "needs_eu": False,
                "needs_error_pages": False,
                "needs_ip_lists": False,
            },
            "kvs_data": [],
            "custom_error_responses": [],
            "lambda_edge": {
                "origin_request": None,
                "origin_response": None,
            },
        },
        "cache_behaviors": [],
    }


def make_default_behavior(domain_config, origin_content):
    """Create the default cache behavior."""
    hostname = domain_config["hostname"]
    sanitized = hostname.replace(".", "_").replace("-", "_")
    return {
        "path_pattern": "*",
        "precedence": 0,
        "distribution_settings": {
            "viewer_protocol_policy": "redirect-to-https",
            "minimum_protocol_version": "TLSv1.2_2021",
            "http_version": "http2and3",
            "is_ipv6_enabled": True,
            "price_class": "PriceClass_All",
            "waf_acl_arn": None,
            "geo_restriction_type": "none",
            "geo_restriction_locations": [],
        },
        "origin": {
            "id": f"origin_{sanitized}",
            "domain": origin_content or hostname,
            "protocol": "https",
            "port": 443,
            "host_header": None,
            "custom_origin_headers": [],
            "s3_origin": domain_config.get("origin_type") == "s3",
        },
        "cache_policy": {
            "caching_disabled": False,
            "ttl": {"min": 0, "default": 7200, "max": 86400},
            "cache_key": {"headers": [], "cookies": [], "query_strings": "none",
                         "query_strings_list": [], "query_strings_exclude": []},
            "enable_gzip": True,
            "enable_brotli": True,
        },
        "origin_request_policy": {
            "forward": {
                "headers": "none", "headers_list": [],
                "cookies": "none", "cookies_list": [],
                "query_strings": "none", "query_strings_list": [],
            },
        },
        "response_headers_policy": {
            "security_headers": {},
            "custom_headers": [],
            "cors": None,
            "remove_headers": [],
        },
        "required_orp_headers": [],
        "viewer_request_ops": [],
        "viewer_response_ops": [],
        "non_convertible": [],
    }


def find_or_create_behavior(ir, path_pattern, domain_config, origin_content):
    """Find existing behavior by path_pattern or create new one."""
    for b in ir["cache_behaviors"]:
        if b["path_pattern"] == path_pattern:
            return b
    # Create new
    b = make_default_behavior(domain_config, origin_content)
    b["path_pattern"] = path_pattern
    b["precedence"] = len(ir["cache_behaviors"]) + 1
    ir["cache_behaviors"].append(b)
    return b


# ── main processing ──────────────────────────────────────────────────────────

def process_domain(hostname, domain_config, all_rules, ip_lists,
                   bulk_redirects, managed_transforms):
    """Process all rules for a single domain, producing IR JSON."""
    apex = domain_config.get("apex_domain", "")
    origin_content = domain_config.get("origin_content", "")
    ir = make_empty_ir(domain_config)

    # Ensure default behavior exists
    default_beh = find_or_create_behavior(ir, "*", domain_config, origin_content)

    # Process rules in Cloudflare execution order
    rule_order = [
        ("redirect", process_redirect_rule),
        ("rewrite", process_rewrite_rule),
        ("config", process_config_rule),
        ("origin", process_origin_rule),
        ("cache", process_cache_rule),
        ("request_header", process_request_header_transform),
        ("response_header", process_response_header_transform),
        ("custom_error", process_custom_error_rule),
        ("compression", process_compression_rule),
    ]

    for rule_type, processor in rule_order:
        rules = all_rules.get(rule_type, [])
        phase = PHASE_MAP.get(rule_type, "")
        for rule in rules:
            if not rule.get("enabled", True):
                continue

            expr = rule.get("expression", "true")
            cond, raw_expr = parse_expression(expr)
            hosts = extract_host_filter(cond, raw_expr or expr)

            if not rule_applies_to_domain(hosts, hostname, apex):
                continue

            result = processor(rule, ip_lists, phase)

            # This rule is now scoped to this host's distribution, so the host
            # test is redundant — strip it from both the loop cond and each
            # result's condition (the processor re-parsed the expr into its own
            # `condition`). This is what lets `host eq x AND uri.path eq /api`
            # reduce to the `/api` behavior instead of looking "compound".
            cond = _strip_host_condition(cond)
            # Handle list results (config rules, header transforms)
            if isinstance(result, list):
                for r in result:
                    _strip_host_in_result(r)
                    _place_result(ir, r, domain_config, origin_content, cond, expr)
            else:
                _strip_host_in_result(result)
                _place_result(ir, result, domain_config, origin_content, cond, expr)

    # Process Cloud Connector rules
    for rule in all_rules.get("cloud_connector", []):
        if not rule.get("enabled", True):
            continue
        expr = rule.get("expression", "true")
        cond, raw_expr = parse_expression(expr)
        hosts = extract_host_filter(cond, raw_expr or expr)
        if not rule_applies_to_domain(hosts, hostname, apex):
            continue
        result = process_cloud_connector(rule, ip_lists, "")
        cond = _strip_host_condition(cond)
        _strip_host_in_result(result)
        _place_result(ir, result, domain_config, origin_content, cond, expr)

    # Process bulk redirects
    _process_bulk_redirects(ir, hostname, apex, bulk_redirects, domain_config, origin_content)

    # Process managed transforms
    _process_managed_transforms(ir, managed_transforms, default_beh)

    # Process default cache behavior (Lambda@Edge origin-response)
    if domain_config.get("apply_default_cache_behavior"):
        _process_default_cache_behavior(ir, hostname, domain_config, origin_content, all_rules, apex)

    # Collect ORP headers across all behaviors
    for beh in ir["cache_behaviors"]:
        orp_set = set()
        for op in beh["viewer_request_ops"] + beh["viewer_response_ops"]:
            c = op.get("condition")
            if c:
                for h in extract_orp_headers(c):
                    orp_set.add(h)
            raw = op.get("raw_expression")
            if raw:
                for h in extract_orp_headers_from_raw(raw):
                    orp_set.add(h)
        beh["required_orp_headers"] = sorted(orp_set)

    # Collect KVS requirements. Scan BOTH request and response ops — a
    # continent/is_eu condition on a response-header rule also needs the KVS
    # provisioned + associated + seeded, else the response CFF calls
    # kvsHandle.get('continent:'…) against a store that was never created and
    # cf.kvs() throws at init.
    for beh in ir["cache_behaviors"]:
        for op in beh["viewer_request_ops"] + beh["viewer_response_ops"]:
            c = op.get("condition")
            if c:
                for trigger in extract_kvs_triggers(c):
                    ir["metadata"]["kvs_requirements"][trigger] = True
            raw = op.get("raw_expression")
            if raw:
                # Scan raw expression for KVS triggers
                if "ip.src.continent" in raw:
                    ir["metadata"]["kvs_requirements"]["needs_continent"] = True
                if "ip.src.is_in_european_union" in raw:
                    ir["metadata"]["kvs_requirements"]["needs_eu"] = True

    # Cache-bypass: whitelist the buster header in the cache key. The viewer
    # request CFF is SHARED across all of a domain's behaviors, so a cache_bypass
    # op (even one scoped to a single path) may inject the buster on any behavior
    # the shared CFF runs on. The buster only forces a miss if it's part of that
    # behavior's cache key — so if ANY behavior carries a cache_bypass op, add the
    # header to EVERY behavior's cache-key header whitelist. Harmless where the
    # CFF never injects it (absent header = one shared empty value = normal
    # caching — verified live). Same constant the CFF codegen writes, so the
    # injected header and the cache-key header can't drift (avoids a split-brain).
    if any(op.get("type") == "cache_bypass"
           for beh in ir["cache_behaviors"]
           for op in beh["viewer_request_ops"]):
        for beh in ir["cache_behaviors"]:
            hdrs = beh["cache_policy"]["cache_key"]["headers"]
            if CACHE_BYPASS_HEADER not in hdrs:
                hdrs.append(CACHE_BYPASS_HEADER)

    return ir


def _place_result(ir, result, domain_config, origin_content, cond, expr):
    """Place a processed rule result into the appropriate IR location."""
    if result is None:
        return

    rtype = result.get("type", "")

    if rtype == "non_convertible":
        default_beh = ir["cache_behaviors"][0]
        default_beh["non_convertible"].append({
            "cf_source_rule": result.get("cf_source_rule", ""),
            "description": result.get("description", ""),
            "reason": result.get("reason", ""),
        })
        return

    if rtype == "distribution_setting":
        default_beh = ir["cache_behaviors"][0]
        setting = result.get("setting", "")
        value = result.get("value")
        if setting in default_beh["distribution_settings"]:
            default_beh["distribution_settings"][setting] = value
        return

    if rtype == "custom_error_response":
        ir["metadata"]["custom_error_responses"].append(result["params"])
        return

    if rtype == "compression_setting":
        path = _extract_path_from_result(result, cond, expr)
        beh = find_or_create_behavior(ir, path, domain_config, origin_content)
        params = result.get("params", {})
        beh["cache_policy"]["enable_gzip"] = params.get("enable_gzip", True)
        beh["cache_policy"]["enable_brotli"] = params.get("enable_brotli", True)
        return

    if rtype == "response_headers_policy":
        # Static header → RHP on default behavior
        default_beh = ir["cache_behaviors"][0]
        params = result["params"]
        op = params.get("operation", "set")
        if params.get("is_cors"):
            if default_beh["response_headers_policy"]["cors"] is None:
                default_beh["response_headers_policy"]["cors"] = {}
            default_beh["response_headers_policy"]["cors"][params["name"]] = params["value"]
            # Track if any CORS header uses "add" (origin_override = false).
            # If mixed set/add across multiple rules, we use false (conservative
            # — don't override origin). CloudFront cors_config.origin_override
            # is per-config, not per-header.
            if op == "add":
                default_beh["response_headers_policy"]["cors"]["_origin_override"] = False
        elif params.get("is_security"):
            default_beh["response_headers_policy"]["security_headers"][params["name"]] = {
                "value": params["value"], "operation": op,
            }
        else:
            default_beh["response_headers_policy"]["custom_headers"].append({
                "name": params["name"], "value": params["value"], "operation": params["operation"],
            })
        return

    if rtype == "serve_error_inline":
        # Inline error page served via CFF + KVS
        params = result.get("params", {})
        kvs_key = params.get("kvs_key", "")
        # str()-coerce: a KVS value MUST be a string (AWS models it as required
        # string; a non-str reaches botocore as ParamValidationError at seed
        # time, after the infra exists). Cloudflare types error-page content as a
        # String, but a malformed/hand-edited config could carry a JSON array or
        # object — coerce here at the store point so both kvs-data.json and the
        # size estimate are always valid.
        content = params.get("content", "")
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False)
        ir["metadata"]["kvs_requirements"]["needs_error_pages"] = True
        ir["metadata"]["kvs_data"].append({"key": kvs_key, "value": content})
        # Fall through to viewer_request_ops placement below

    if rtype == "cache_setting":
        # status_code_ttl (per-status-code edge cache duration) has no CloudFront
        # equivalent — record it once, before the rule fans out to behaviors.
        if "status_code_ttl" in result.get("params", {}):
            _mark_status_code_ttl_non_convertible(ir, result)
            result["params"].pop("status_code_ttl", None)

    if rtype == "cache_setting" and result.get("params", {}).get("bypass"):
        # Cache bypass = "don't serve this from cache; always go to origin".
        # CloudFront can't conditionally skip the cache at request time, so:
        #   - UNCONDITIONAL bypass (host-stripped condition is always/None) → the
        #     whole behavior never caches: use the managed CachingDisabled policy.
        #   - CONDITIONAL bypass (a real request-time predicate: cookie, path,
        #     query, …) → a viewer-request CFF forces a guaranteed cache MISS for
        #     matching requests by injecting a unique cache-buster header that is
        #     part of the cache key. Represented as a `cache_bypass` op so it runs
        #     through the normal viewer_request_ops placement + codegen.
        bcond = result.get("condition")
        # An UNPARSEABLE condition (raw_expression, no structured cond) must NOT
        # be treated as unconditional — that would disable caching for the WHOLE
        # behavior when the rule really only meant to bypass a specific subset
        # (e.g. any(uri.args["x"][*]=="v"), which we don't convert). Silent
        # over-bypass. Report it non-convertible instead.
        if result.get("raw_expression") and not bcond:
            _mark_cache_non_convertible(ir, result, expr)
            return
        if bcond is None or bcond.get("always"):
            path = _extract_path_from_result(result, cond, expr)
            beh = find_or_create_behavior(ir, path, domain_config, origin_content)
            beh["cache_policy"]["caching_disabled"] = True
            return
        # Conditional → re-tag as a cache_bypass viewer-request op and fall
        # through to the generic viewer_request_ops placement below.
        result["type"] = "cache_bypass"
        rtype = "cache_bypass"

    if rtype == "cache_setting":
        # OR cache rule: try to split into one behavior per path. OR is now a
        # structured {"logic":"or"} condition (no longer deferred to raw), so
        # read it from the condition. A raw_expression still means genuinely
        # unparseable — route that (and any non-splittable OR) to Lambda@Edge.
        result_cond = result.get("condition")
        if (result_cond and result_cond.get("logic") == "or") or \
           (result.get("raw_expression") and not result_cond):
            or_paths = _try_split_or_cache_paths(result_cond)
            if or_paths:
                for path in or_paths:
                    beh = find_or_create_behavior(ir, path, domain_config, origin_content)
                    _apply_cache_setting(beh, result)
                return
            # Non-splittable OR → can't be expressed as CloudFront path behaviors.
            _mark_cache_non_convertible(ir, result, expr)
            return
        path = _extract_path_from_result(result, cond, expr)
        # Fan out to one *.ext behavior per extension ONLY when the condition is
        # PURELY an extension set. A sibling scope (host eq x and ext in [...])
        # must NOT fan out — that would apply the cache setting to *.pdf on every
        # host, dropping the host scope. In that case fall through to the normal
        # single-path placement below (which keeps the host/path scope).
        result_cond = result.get("condition") or cond
        exts = _extract_extensions_from_condition(result_cond)
        if len(exts) > 1 and _condition_is_pure_extension(result_cond):
            for ext in exts:
                ext_path = f"*.{ext}"
                beh = find_or_create_behavior(ir, ext_path, domain_config, origin_content)
                _apply_cache_setting(beh, result)
            return
        # A cache setting is applied to a specific behavior (not via the shared
        # CFF), so its condition MUST be representable as that behavior's single
        # path pattern. After host-stripping, a still-compound scope (e.g.
        # ip.src.country, a multi-field AND, a NOT) can't be — placing it on
        # `_extract_path_from_result`'s best-effort path (often `*`) would apply
        # the setting site-wide. There is no working Lambda@Edge conditional-cache
        # generator (the origin_response template only emits error pages), so
        # report these as non-convertible instead of silently dropping them.
        if not _cache_cond_is_single_path(result_cond):
            _mark_cache_non_convertible(ir, result, expr)
            return
        beh = find_or_create_behavior(ir, path, domain_config, origin_content)
        _apply_cache_setting(beh, result)
        return

    if rtype == "cloud_connector":
        path = _extract_path_from_result(result, cond, expr)
        beh = find_or_create_behavior(ir, path, domain_config, origin_content)
        params = result.get("params", {})
        beh["origin"]["domain"] = params.get("origin_host", beh["origin"]["domain"])
        beh["origin"]["s3_origin"] = "s3." in params.get("origin_host", "")
        return

    # Drop a redundant S3 origin-override. Cloudflare pointing at an S3 bucket
    # needs an Origin Rule that rewrites the Host header to the bucket name (S3
    # routes by Host). On CloudFront+OAC that handling is UNNECESSARY: OAC signs
    # the request (SigV4) and CloudFront sets Host to the origin (bucket) domain
    # automatically — re-setting it via cf.updateRequestOrigin is at best noise
    # and can interfere with signing. So for an S3 origin, drop an origin_override
    # that only re-points Host/origin at the bucket (no genuinely different,
    # non-S3 origin). A real cross-origin override (to a non-S3 host) is kept.
    if rtype == "origin_override" and domain_config.get("origin_type") == "s3":
        ov_origin = result.get("params", {}).get("origin_host") or ""
        if not ov_origin or _is_s3_host(ov_origin):
            return  # redundant on CloudFront+OAC — drop

    # Drop a no-op origin_override — an Origin Rule with no origin host, port,
    # host_header, or sni has nothing to convert. Keeping it would emit an empty
    # (no-op) CFF statement that then trips validate-js's origin_override
    # coverage check ("missing updateRequestOrigin").
    if rtype == "origin_override":
        p = result.get("params", {})
        if not (p.get("origin_host") or p.get("origin_port") or p.get("host_header") or p.get("sni")):
            return

    # viewer_request_ops or viewer_response_ops
    is_response = "response" in rtype
    path = _extract_path_from_result(result, cond, expr)
    beh = find_or_create_behavior(ir, path, domain_config, origin_content)

    op_entry = {
        "type": rtype,
        "cf_source_rule": result.get("cf_source_rule", ""),
        "description": result.get("description", ""),
        "condition": result.get("condition"),
        "raw_expression": result.get("raw_expression"),
        "params": result.get("params", {}),
        "scope": _op_scope(path, result, cond),
    }

    # Generate KVS entries for in_kvs conditions (IP list lookup)
    _collect_kvs_ip_entries(ir, op_entry.get("condition"))

    if is_response:
        beh["viewer_response_ops"].append(op_entry)
    else:
        beh["viewer_request_ops"].append(op_entry)


def _collect_kvs_ip_entries(ir, condition):
    """Generate KVS entries for in_kvs conditions (IP list → KVS exists())."""
    if condition is None:
        return
    if "logic" in condition:
        for child in iter_condition_children(condition):
            _collect_kvs_ip_entries(ir, child)
        return
    if condition.get("op") in ("in_kvs", "not_in_kvs"):
        list_name = condition["value"]
        ips = condition.pop("kvs_ips", [])
        if not ips:
            return
        # Deduplicate: skip if this list was already collected
        prefix = f"ip:{list_name}:"
        if any(e["key"].startswith(prefix) for e in ir["metadata"]["kvs_data"]):
            return
        ir["metadata"]["kvs_requirements"]["needs_ip_lists"] = True
        for ip in ips:
            ir["metadata"]["kvs_data"].append({
                "key": f"{prefix}{ip}",
                "value": "1",
            })


def _try_split_or_cache_paths(condition):
    """Try to split a top-level OR condition into individual path patterns.

    Takes the STRUCTURED condition (OR is now parsed into {"logic":"or",...} —
    it is no longer deferred to raw text). Returns a list of CloudFront path
    patterns if the condition is an OR whose every branch is a single
    path-based leaf, or None otherwise (caller then routes to Lambda@Edge).
    """
    if not isinstance(condition, dict) or condition.get("logic") != "or":
        return None
    parts = condition.get("parts", [])
    if len(parts) < 2:
        return None
    paths = []
    for part in parts:
        # Each branch must be a single path leaf — a nested logic node or a
        # non-path field can't map to a per-path cache behavior.
        if "logic" in part:
            return None
        pp = extract_path_pattern_single(part)
        if not pp or pp == "*":
            return None  # branch doesn't yield a specific path
        paths.append(pp)
    return paths


def _extract_path_from_result(result, cond, expr):
    """Extract path pattern from a rule result's condition."""
    c = result.get("condition") or cond
    if c is None:
        return "*"
    if c.get("always"):
        return "*"
    if "logic" in c:
        # A top-level OR spans multiple paths — no single pattern represents it,
        # and picking the first branch would create a behavior at only one path
        # (a phantom scope). The shared CFF runs on the default behavior and
        # evaluates the full condition anyway, so use `*`. For AND, a path branch
        # IS the real scope (host eq x AND uri.path eq /a → /a), so keep the
        # first specific path. NOT has no "parts" (→ `*`).
        if c.get("logic") == "or":
            return "*"
        for p in c.get("parts", []):
            pp = extract_path_pattern_single(p)
            if pp and pp != "*":
                return pp
        return "*"
    return extract_path_pattern_single(c)


def _op_scope(path, result, cond):
    """Classify how far a viewer op's effect reaches, so the scaffold can attach
    the shared CFF only to the behaviors that need it (a Cloudflare rule's scope
    = distribution × cache-behavior, decided BEFORE the mechanism). Returns:
      'behavior'     — landed on a specific ordered behavior (path→pattern
                       worked); runs only there.
      'default_only' — landed on the default behavior AND the condition DID scope
                       by path, but the path couldn't reduce to a CloudFront
                       pattern (regex/negated/multi-ext/OR-of-paths). The rule
                       only ever meant those (default-behavior) requests → attach
                       to the default behavior only, NOT the ordered ones.
      'all'          — landed on the default behavior with NO path field at all
                       (zone-wide: matched host and/or header/cookie/qs). Must
                       run on EVERY behavior of the distribution, since any path
                       could match and each behavior has its own function assoc.
    """
    if path != "*":
        return "behavior"
    c = result.get("condition") or cond
    return "default_only" if condition_has_path_field(c) else "all"


def _apply_cache_setting(beh, result):
    """Apply cache rule settings to a behavior.

    Bypass is NOT handled here — _place_result intercepts every bypass cache
    rule before this runs (unconditional → CachingDisabled policy; conditional →
    a cache_bypass viewer-request op), so only TTL / cache-key settings reach it.
    """
    params = result.get("params", {})
    cp = beh["cache_policy"]

    if "edge_ttl_override" in params:
        # override_origin means CloudFront must cache for exactly this long
        # regardless of origin headers — min=default=max is the only way to
        # force a fixed TTL. Leaving min/max at their behavior defaults let a
        # >86400s override exceed max_ttl, which CloudFront's create API rejects.
        ttl = params["edge_ttl_override"]
        cp["ttl"]["min"] = ttl
        cp["ttl"]["default"] = ttl
        cp["ttl"]["max"] = ttl
    if "edge_ttl_respect_origin" in params:
        pass  # default behavior

    # browser_ttl (override_origin): Cloudflare forces the max-age in the
    # Cache-Control header sent to the VIEWER, independent of the edge TTL. A
    # viewer-response CFF replicates this faithfully — response.headers is
    # writable there, the value is forced unconditionally (unlike a
    # response-headers policy in override mode, which only fires when the origin
    # already sent Cache-Control), and the CFF stays scoped to THIS behavior's
    # path. Emitted as a set_response_header op so it reuses the normal codegen.
    # Caveat: viewer-response CFF does not run for 4xx/5xx CloudFront-generated
    # responses, so error responses won't carry the forced max-age — acceptable,
    # browser_ttl is about how long normal content lives in the browser cache.
    if "browser_ttl_override" in params:
        max_age = params["browser_ttl_override"]
        already = any(
            op.get("cf_source_rule") == result.get("cf_source_rule")
            and op.get("params", {}).get("name") == "cache-control"
            for op in beh["viewer_response_ops"]
        )
        if not already:
            # scope drives which behaviors get the CFF (tf-scaffold #123). A
            # zone-wide browser_ttl (no path field) lands on the default behavior
            # and MUST run on every behavior → scope='all'; a path-scoped one
            # runs only on its own behavior.
            beh["viewer_response_ops"].append({
                "type": "set_response_header",
                "cf_source_rule": result.get("cf_source_rule", ""),
                "description": f"{result.get('description', '')}: browser_ttl override",
                "condition": result.get("condition"),
                "raw_expression": result.get("raw_expression"),
                "params": {"name": "cache-control", "value": f"max-age={max_age}"},
                "scope": _op_scope(beh["path_pattern"], result, result.get("condition")),
            })

    if "cache_key_qs" in params:
        cp["cache_key"]["query_strings"] = params["cache_key_qs"]
    if "cache_key_qs_list" in params:
        cp["cache_key"]["query_strings_list"] = params["cache_key_qs_list"]
    if "cache_key_qs_exclude" in params:
        cp["cache_key"]["query_strings_exclude"] = params["cache_key_qs_exclude"]
    if "cache_key_headers" in params:
        cp["cache_key"]["headers"] = params["cache_key_headers"]


def _process_bulk_redirects(ir, hostname, apex, bulk_redirects, domain_config, origin_content):
    """Process bulk redirect items that match this domain."""
    kvs_entries = []
    for list_name, items in bulk_redirects.items():
        for item in items:
            rd = item.get("redirect", {})
            source = rd.get("source_url", "")
            include_subdomains = rd.get("include_subdomains", False)

            # Check if this redirect applies to this domain
            # source_url format: "hostname/path" (no scheme)
            source_host = source.split("/")[0] if "/" in source else source
            applies = False
            if source_host == hostname:
                applies = True
            elif include_subdomains and (
                hostname.endswith("." + source_host) or hostname == source_host
            ):
                applies = True

            if applies:
                kvs_entries.append({
                    "source_url": source,
                    "target_url": rd.get("target_url", ""),
                    "status_code": rd.get("status_code", 301),
                    "preserve_query_string": rd.get("preserve_query_string", False),
                    "include_subdomains": include_subdomains,
                    "list_name": list_name,
                })

    if kvs_entries:
        ir["metadata"]["kvs_requirements"]["needs_redirects"] = True
        # Convert to KVS key-value format: value="{status}|{preserve_qs}|{target}".
        # Key convention (must match the CFF lookup in cdn-generate-js):
        #   - exact:  "redirect:{source}"       matches only that exact host+path
        #   - wildcard: "redirect:.{source}"    (leading dot) matches that host
        #     AND any subdomain of it — written ONLY when include_subdomains=true.
        # The dot prefix is the include_subdomains marker: the CFF walks the
        # request host's parent suffixes against dotted keys, so a subdomain
        # request finds the ancestor's wildcard entry. Without this the flag was
        # silently dropped (key stored under the bare apex, never matched for a
        # subdomain request).
        for entry in kvs_entries:
            src = entry["source_url"]
            tgt = entry["target_url"]
            status = entry["status_code"]
            pqs = "1" if entry["preserve_query_string"] else "0"
            value = f"{status}|{pqs}|{tgt}"
            ir["metadata"]["kvs_data"].append({
                "key": f"redirect:{src}",
                "value": value,
            })
            if entry["include_subdomains"]:
                ir["metadata"]["kvs_data"].append({
                    "key": f"redirect:.{src}",
                    "value": value,
                })
        # Add bulk_redirect op after redirect/rewrite/origin ops (Cloudflare execution order)
        default_beh = ir["cache_behaviors"][0]
        # Find insertion point: after last redirect/rewrite/origin_override op
        insert_idx = 0
        for i, op in enumerate(default_beh["viewer_request_ops"]):
            if op["type"] in ("redirect", "rewrite", "origin_override"):
                insert_idx = i + 1
        default_beh["viewer_request_ops"].insert(insert_idx, {
            "type": "bulk_redirect",
            "cf_source_rule": "bulk_redirects",
            "description": f"Bulk redirects ({len(kvs_entries)} entries)",
            "condition": {"always": True},
            "raw_expression": None,
            "params": {"entry_count": len(kvs_entries)},
            "scope": "all",  # unconditional zone-wide → runs on every behavior
        })


def _process_managed_transforms(ir, managed_transforms, default_beh):
    """Process Managed Transforms (True-Client-IP, security headers)."""
    req_headers = managed_transforms.get("managed_request_headers", [])
    resp_headers = managed_transforms.get("managed_response_headers", [])

    for h in req_headers:
        if h.get("enabled") and h.get("id") == "add_true_client_ip_headers":
            default_beh["viewer_request_ops"].append({
                "type": "set_request_header",
                "cf_source_rule": "managed_transform_true_client_ip",
                "description": "Managed Transform: True-Client-IP",
                "condition": {"always": True},
                "raw_expression": None,
                "params": {"name": "True-Client-IP", "value": "$viewer_ip"},
                "scope": "all",  # unconditional zone-wide → runs on every behavior
            })

    for h in resp_headers:
        if h.get("enabled") and h.get("id") == "add_security_headers":
            default_beh["response_headers_policy"]["security_headers"].setdefault(
                "X-Content-Type-Options", {"value": "nosniff", "operation": "add"}
            )
            default_beh["response_headers_policy"]["security_headers"].setdefault(
                "X-Frame-Options", {"value": "SAMEORIGIN", "operation": "add"}
            )


def _mark_cache_non_convertible(ir, result, expr=None):
    """Record a cache rule whose scope can't be expressed as a CloudFront path
    behavior (after host-stripping) as non-convertible, on the default behavior.

    CloudFront cache settings attach to a path-matched cache behavior; a scope
    like ip.src.country, a multi-field AND, or a NOT has no single path pattern.
    There is no working Lambda@Edge conditional-cache generator (the
    origin_response template only emits error pages), so we surface the rule in
    the conversion report instead of silently dropping it or mis-applying it
    site-wide.
    """
    ir["cache_behaviors"][0]["non_convertible"].append({
        "cf_source_rule": result.get("cf_source_rule", ""),
        "description": result.get("description", ""),
        "reason": ("Cache rule condition cannot be expressed as a CloudFront "
                   "cache behavior (path-only). Scope: "
                   f"{result.get('raw_expression') or expr or '(complex)'}. "
                   "Apply the cache policy manually to the matching behavior, "
                   "or handle at the origin."),
    })


def _mark_status_code_ttl_non_convertible(ir, result):
    """Record status_code_ttl (per-status-code edge cache duration) as
    non-convertible. Recorded ONCE per rule on the default behavior.

    Cloudflare's edge_ttl.status_code_ttl sets different EDGE cache TTLs per HTTP
    status code / range (e.g. 200→1h, 404→1s, 5xx→0s). CloudFront can't:
    - a cache policy's min/default/max TTL is status-code-agnostic;
    - Custom Error Responses cover only 4xx/5xx, with a MINIMUM (not exact) TTL,
      and never 2xx.
    CFF can't help either — it controls response headers, not CloudFront's edge
    caching decision. So this is genuinely non-convertible.
    """
    ir["cache_behaviors"][0]["non_convertible"].append({
        "cf_source_rule": result.get("cf_source_rule", ""),
        "description": f"{result.get('description', '')}: status_code_ttl",
        "reason": ("Cloudflare sets different edge cache TTLs per response status "
                   "code. CloudFront cache-policy TTL is status-code-agnostic, and "
                   "Custom Error Responses only cover 4xx/5xx with a minimum-TTL "
                   "(not exact, not 2xx). Handle per-status caching at the origin "
                   "via Cache-Control."),
    })


# Cloudflare default cached extensions (~70 types)
# Source: https://developers.cloudflare.com/cache/concepts/default-cache-behavior/
CLOUDFLARE_DEFAULT_CACHED_EXTENSIONS = {
    "7z", "csv", "gif", "midi", "png", "tif", "zip",
    "avi", "doc", "gz", "mkv", "ppt", "tiff", "zst",
    "avif", "docx", "ico", "mp3", "pptx", "ttf",
    "apk", "dmg", "iso", "mp4", "ps", "webm",
    "bin", "ejs", "jar", "ogg", "rar", "webp",
    "bmp", "eot", "jpg", "otf", "svg", "woff",
    "bz2", "eps", "jpeg", "pdf", "svgz", "woff2",
    "class", "exe", "js", "pict", "swf", "xls",
    "css", "flac", "mid", "pls", "tar", "xlsx",
}


def _process_default_cache_behavior(ir, hostname, domain_config, origin_content, all_rules, apex):
    """Implement Cloudflare's implicit default cache behavior via Lambda@Edge origin-response.

    Three paths based on how many extensions have custom TTLs:
    - 0 custom TTL extensions → L@E with empty custom_ttl_map (uses default 7200s)
    - ≤20 custom TTL extensions → individual cache behaviors per extension + L@E (empty map)
    - >20 custom TTL extensions → L@E with custom_ttl_map (consolidated)
    """
    # Collect extension-based cache rules that apply to this domain
    custom_ttl_map = {}  # extension → ttl_seconds
    bypass_extensions = set()

    for rule in all_rules.get("cache", []):
        if not rule.get("enabled", True):
            continue
        expr = rule.get("expression", "true")
        cond, raw_expr = parse_expression(expr)
        hosts = extract_host_filter(cond, raw_expr or expr)
        if not rule_applies_to_domain(hosts, hostname, apex):
            continue

        # Only look at extension-based rules
        extensions = _extract_extensions_from_condition(cond)
        if not extensions:
            continue

        ap = rule.get("action_parameters", {})
        if not ap.get("cache", True):
            # Bypass cache for these extensions — they override default caching
            bypass_extensions.update(ext.lower() for ext in extensions)
            continue

        edge_ttl = ap.get("edge_ttl", {})
        if edge_ttl.get("mode") == "override_origin":
            ttl = edge_ttl.get("default", 7200)
            for ext in extensions:
                custom_ttl_map[ext.lower()] = ttl

    # Remove bypassed extensions from custom_ttl_map
    for ext in bypass_extensions:
        custom_ttl_map.pop(ext, None)

    # Determine path
    custom_count = len(custom_ttl_map)

    if custom_count <= 20:
        # Path 1 (0 custom) or Path 2 (≤20 custom):
        # Create individual cache behaviors for custom TTL extensions
        for ext, ttl in sorted(custom_ttl_map.items()):
            ext_path = f"*.{ext}"
            beh = find_or_create_behavior(ir, ext_path, domain_config, origin_content)
            # override_origin forces this exact TTL — min=default=max, same
            # reasoning as _apply_cache_setting (a >86400s value would otherwise
            # exceed the behavior's default max_ttl and fail CloudFront's API).
            beh["cache_policy"]["ttl"]["min"] = ttl
            beh["cache_policy"]["ttl"]["default"] = ttl
            beh["cache_policy"]["ttl"]["max"] = ttl

        # L@E with empty map — handles remaining ~70 extensions at default 7200s
        ir["metadata"]["lambda_edge"]["origin_response"] = {
            "type": "default_cache",
            "custom_ttl_map": {},
        }
    else:
        # Path 3 (>20 custom): consolidate into L@E custom_ttl_map
        ir["metadata"]["lambda_edge"]["origin_response"] = {
            "type": "default_cache",
            "custom_ttl_map": custom_ttl_map,
        }


def _extract_extensions_from_condition(condition):
    """Extract the file extensions a rule POSITIVELY matches, if extension-based.

    Collects from ALL positive branches — an `ext in {pdf} or ext in {jpg}` rule
    covers BOTH pdf and jpg, so returning only the first branch's `[pdf]` would
    drop jpg from the custom-TTL map. But a NEGATED set (`not (ext in {pdf})`,
    `ext not_in {pdf}`) matches everything EXCEPT those, so its extensions must
    NOT be collected — doing so would apply the TTL/bypass to exactly the
    extensions the rule excludes (a full inversion). So descend AND/OR `parts`
    only; do NOT descend a NOT node's `item`, and skip negated leaf ops.
    """
    if condition is None:
        return []
    if "logic" in condition:
        if condition["logic"] == "not":
            return []  # negated: matched set is the complement, not these exts
        exts = []
        for child in condition.get("parts", []):
            for e in _extract_extensions_from_condition(child):
                if e not in exts:
                    exts.append(e)
        return exts
    if condition.get("field") == "uri.path.extension":
        if condition.get("op") == "in":
            return list(condition.get("value", []))
        if condition.get("op") == "eq" and isinstance(condition.get("value"), str):
            return [condition["value"]]
    return []


def _cache_cond_is_single_path(condition):
    """True if a cache-rule condition can be represented by ONE specific
    CloudFront path pattern (so applying the setting to one behavior is faithful).

    Unconditional (→ default `*` behavior) is fine. Otherwise the leaf must
    actually yield a SPECIFIC path pattern — verified by asking
    extract_path_pattern_single and rejecting `*`. This catches leaves that are
    "path-ish" but don't reduce to a concrete pattern, e.g.
    `uri.path.extension eq "pdf"` (only `in [one]` yields `*.pdf`; `eq` → `*`),
    which would otherwise be mis-applied site-wide. A logic node (AND/OR/NOT) or
    a non-path field is never single-path.
    """
    if condition is None or condition.get("always"):
        return True
    if "logic" in condition:
        return False
    # full_uri is included: a `full_uri wildcard "https://host/files/*"` leaf
    # reduces to the path pattern /files/* (extract_path_pattern_single reads its
    # path_pattern), so it IS a single-path scope for this host's distribution.
    if condition.get("field") not in ("uri.path", "uri", "uri.path.extension", "full_uri"):
        return False
    return extract_path_pattern_single(condition) != "*"


def _condition_is_pure_extension(condition):
    """True if the condition is ONLY a uri.path.extension test (a single leaf,
    or an OR of extension leaves) — with no sibling scope such as a host or path.

    Per-extension fan-out (one *.ext behavior each) is only safe when the whole
    condition is the extension set. If a host/path scope sits alongside it (an
    AND), fanning out would drop that scope and apply the setting site-wide.
    """
    if not isinstance(condition, dict):
        return False
    if "logic" in condition:
        # Only an OR of pure-extension branches stays pure; an AND has a sibling.
        if condition.get("logic") != "or":
            return False
        parts = condition.get("parts", [])
        return bool(parts) and all(_condition_is_pure_extension(p) for p in parts)
    return condition.get("field") == "uri.path.extension"


# ── main ─────────────────────────────────────────────────────────────────────

def _result(status, code, **fields):
    """Emit a ---RESULT--- via the shared cdn_common.emit_result, then exit.

    Keeps the positional `code` because this stage's PARTIAL maps to exit 1
    (retry-failed-domains), NOT the standard 3 — so the exit code is passed
    explicitly rather than derived from STATUS. Multi-line values (FAILED_ITEMS)
    are passed as a plain list; emit_result owns the indentation.
    """
    emit_result(status, exit_code=code, **fields)


def main():
    if len(sys.argv) < 3:
        print("Usage: cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]",
              file=sys.stderr)
        _result("FATAL", 2, ACTION="FIX",
                CONTEXT="Usage: cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]")

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])
    single_domain = None
    if "--domain" in sys.argv:
        idx = sys.argv.index("--domain")
        if idx + 1 < len(sys.argv):
            single_domain = sys.argv[idx + 1]

    # Load domain_scope.json
    scope_path = os.path.join(output_dir, "domain_scope.json")
    if not os.path.exists(scope_path):
        print(f"ERROR: {scope_path} not found", file=sys.stderr)
        _result("FATAL", 2, ACTION="FIX",
                CONTEXT=f"domain_scope.json not found at {scope_path}. Run Stage 1 "
                        "(cdn-parse-dns.py) first.")
    with open(scope_path) as f:
        domain_scope = json.load(f)

    domains = domain_scope.get("domains", [])
    if single_domain:
        domains = [d for d in domains if d["hostname"] == single_domain]
        if not domains:
            print(f"ERROR: domain {single_domain} not found in domain_scope.json",
                  file=sys.stderr)
            _result("FATAL", 2, ACTION="FIX",
                    CONTEXT=f"--domain {single_domain} is not in domain_scope.json")

    # Find zone directory
    zone_dir = find_zone_dir(config_path)
    if not zone_dir:
        print(f"ERROR: no zone directory with DNS.txt found under {config_path}",
              file=sys.stderr)
        _result("FATAL", 2, ACTION="FIX",
                CONTEXT=f"No zone directory with DNS.txt found under {config_path}")

    # Load all rule files (once)
    all_rules = {}
    for rule_type, filename in RULE_FILES.items():
        if rule_type == "managed_transforms":
            continue
        path = os.path.join(zone_dir, filename)
        rules = load_json_file(path)
        if rules and isinstance(rules, list):
            all_rules[rule_type] = rules
        else:
            all_rules[rule_type] = []

    # Cloud Connector (different JSON format)
    cc_path = os.path.join(zone_dir, CLOUD_CONNECTOR_FILE)
    cc_rules = load_json_file(cc_path)
    all_rules["cloud_connector"] = cc_rules if isinstance(cc_rules, list) else []

    # Load account-level data
    ip_lists = load_ip_lists(config_path)
    bulk_redirects = load_bulk_redirect_items(config_path)
    managed_transforms = load_managed_transforms(zone_dir)

    # Process each domain
    acc_dir = os.path.join(output_dir, "ir", "accumulator")
    os.makedirs(acc_dir, exist_ok=True)

    success = 0
    failed = []
    for domain_config in domains:
        hostname = domain_config["hostname"]
        try:
            ir = process_domain(
                hostname, domain_config, all_rules, ip_lists,
                bulk_redirects, managed_transforms,
            )
            out_path = os.path.join(acc_dir, f"{hostname}.json")
            with open(out_path, "w") as f:
                json.dump(ir, f, indent=2, ensure_ascii=False)
            beh_count = len(ir["cache_behaviors"])
            ops_count = sum(
                len(b["viewer_request_ops"]) + len(b["viewer_response_ops"])
                for b in ir["cache_behaviors"]
            )
            nc_count = sum(len(b["non_convertible"]) for b in ir["cache_behaviors"])
            print(f"OK: {hostname} → {beh_count} behaviors, {ops_count} ops, {nc_count} non-convertible")
            success += 1
        except Exception as e:
            err_path = os.path.join(acc_dir, f"{hostname}.error.json")
            with open(err_path, "w") as f:
                json.dump({"hostname": hostname, "error": str(e)}, f, indent=2)
            print(f"FAIL: {hostname} → {e}", file=sys.stderr)
            failed.append(hostname)

    # Summary
    total = len(domains)
    print(f"\n{'='*60}")
    print(f"Processed {success}/{total} domains successfully")
    if failed:
        print(f"Failed domains: {', '.join(failed)}")

    # FAILED_ITEMS is a list — emit_result indents each line (no hand "\n  ").
    failed_items = [f"{h}: see {h}.error.json" for h in failed]
    if success == 0:
        # Nothing converted — every domain raised. Each has a
        # {hostname}.error.json in the accumulator with the traceback.
        _result("FATAL", 2, ACTION="FIX", FAILED=len(failed),
                FAILED_ITEMS=failed_items,
                CONTEXT=f"All {total} domains failed preprocessing — likely a bad "
                        "config path or a pipeline bug, not a per-domain issue.")
    elif failed:
        # Retry command mirrors SKILL.md Stage 3: re-run with --domain for the
        # failed subset; if retry also fails, mark those SKIPPED and continue.
        retry_domains = ",".join(failed)
        _result("PARTIAL", 1, SUCCEEDED=success, FAILED=len(failed),
                FAILED_ITEMS=failed_items,
                ACTION="RETRY_FAILED",
                COMMAND=f'python3 cdn-preprocess.py "{config_path}" "{output_dir}" '
                        f'--domain {retry_domains}')
    else:
        _result("OK", 0, DOMAINS=total, PROCESSED=success,
                OUTPUT_DIR=acc_dir)


if __name__ == "__main__":
    main()
