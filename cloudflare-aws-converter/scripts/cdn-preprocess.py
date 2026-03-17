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
)
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
    """Find the zone backup directory (contains DNS.txt)."""
    for root, dirs, files in os.walk(config_path):
        if "DNS.txt" in files and "account" not in root:
            return root
    return None


def load_json_file(path):
    """Load a Cloudflare backup JSON file, handling both ruleset and array formats."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    if not data.get("success", True):
        return None
    result = data.get("result")
    if isinstance(result, dict) and "rules" in result:
        return result["rules"]
    if isinstance(result, list):
        return result
    return result


def load_ip_lists(config_path):
    """Load account-level IP lists → {list_name: [ip1, ip2, ...]}."""
    ip_lists = {}
    # Find account directory
    account_dir = None
    for d in globmod.glob(os.path.join(config_path, "account", "*")):
        if os.path.isdir(d):
            account_dir = d
            break
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
    account_dir = None
    for d in globmod.glob(os.path.join(config_path, "account", "*")):
        if os.path.isdir(d):
            account_dir = d
            break
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
    with open(path) as f:
        data = json.load(f)
    return data.get("result", {})


# ── domain matching ──────────────────────────────────────────────────────────

def hostname_matches(hostname, pattern):
    """Check if hostname matches a pattern (supports wildcard *)."""
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return hostname.endswith(suffix) or hostname == pattern[2:]
    return False


def rule_applies_to_domain(hosts, hostname, apex_domain):
    """Check if a rule with given host filter applies to this domain."""
    if hosts is None:
        return True  # global rule
    for h in hosts:
        if hostname_matches(hostname, h):
            return True
    return False


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
            "origin_type": domain_config.get("origin_type", "server"),
            "cert_arn_mode": domain_config.get("cert_arn_mode", "data_source"),
            "cert_arn": domain_config.get("cert_arn"),
            "kvs_requirements": {
                "needs_redirects": False,
                "needs_continent": False,
                "needs_eu": False,
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
            "bypass": False,
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

            # Handle list results (config rules, header transforms)
            if isinstance(result, list):
                for r in result:
                    _place_result(ir, r, domain_config, origin_content, cond, expr)
            else:
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

    # Collect KVS requirements
    for beh in ir["cache_behaviors"]:
        for op in beh["viewer_request_ops"]:
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
        if params.get("is_cors"):
            if default_beh["response_headers_policy"]["cors"] is None:
                default_beh["response_headers_policy"]["cors"] = {}
            default_beh["response_headers_policy"]["cors"][params["name"]] = params["value"]
        elif params.get("is_security"):
            default_beh["response_headers_policy"]["security_headers"][params["name"]] = params["value"]
        else:
            default_beh["response_headers_policy"]["custom_headers"].append({
                "name": params["name"], "value": params["value"], "operation": params["operation"],
            })
        return

    if rtype == "cache_setting":
        # Cache rules with raw_expression can't determine path pattern →
        # mark as non_convertible (CFF can't control caching conditionally)
        if result.get("raw_expression") and not result.get("condition"):
            default_beh = ir["cache_behaviors"][0]
            default_beh["non_convertible"].append({
                "cf_source_rule": result.get("cf_source_rule", ""),
                "description": result.get("description", ""),
                "reason": "Cache rule expression too complex to determine path pattern; "
                          "CloudFront cache behaviors require explicit path patterns. "
                          "Consider splitting into simpler rules or configuring manually",
            })
            return
        path = _extract_path_from_result(result, cond, expr)
        # For extension-based cache rules with multiple extensions,
        # create individual behaviors per extension
        result_cond = result.get("condition") or cond
        if result_cond and "logic" in result_cond:
            for p in result_cond.get("parts", []):
                if (p.get("field") == "uri.path.extension" and
                        p.get("op") == "in" and isinstance(p.get("value"), list) and
                        len(p["value"]) > 1):
                    for ext in p["value"]:
                        ext_path = f"*.{ext}"
                        beh = find_or_create_behavior(ir, ext_path, domain_config, origin_content)
                        _apply_cache_setting(beh, result)
                    return
        elif result_cond and result_cond.get("field") == "uri.path.extension":
            if (result_cond.get("op") == "in" and
                    isinstance(result_cond.get("value"), list) and
                    len(result_cond["value"]) > 1):
                for ext in result_cond["value"]:
                    ext_path = f"*.{ext}"
                    beh = find_or_create_behavior(ir, ext_path, domain_config, origin_content)
                    _apply_cache_setting(beh, result)
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
    }

    if is_response:
        beh["viewer_response_ops"].append(op_entry)
    else:
        beh["viewer_request_ops"].append(op_entry)


def _extract_path_from_result(result, cond, expr):
    """Extract path pattern from a rule result's condition."""
    c = result.get("condition") or cond
    if c is None:
        return "*"
    if c.get("always"):
        return "*"
    if "logic" in c:
        for p in c["parts"]:
            pp = extract_path_pattern_single(p)
            if pp and pp != "*":
                return pp
        return "*"
    return extract_path_pattern_single(c)


def _apply_cache_setting(beh, result):
    """Apply cache rule settings to a behavior."""
    params = result.get("params", {})
    cp = beh["cache_policy"]

    if params.get("bypass"):
        cp["bypass"] = True
        return

    if "edge_ttl_override" in params:
        cp["ttl"]["default"] = params["edge_ttl_override"]
    if "edge_ttl_respect_origin" in params:
        pass  # default behavior

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
        # Convert to KVS key-value format: key="redirect:{source}", value="{status}|{preserve_qs}|{target}"
        for entry in kvs_entries:
            src = entry["source_url"]
            tgt = entry["target_url"]
            status = entry["status_code"]
            pqs = "1" if entry["preserve_query_string"] else "0"
            ir["metadata"]["kvs_data"].append({
                "key": f"redirect:{src}",
                "value": f"{status}|{pqs}|{tgt}",
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
            })

    for h in resp_headers:
        if h.get("enabled") and h.get("id") == "add_security_headers":
            default_beh["response_headers_policy"]["security_headers"].setdefault(
                "X-Content-Type-Options", "nosniff"
            )
            default_beh["response_headers_policy"]["security_headers"].setdefault(
                "X-Frame-Options", "SAMEORIGIN"
            )


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
            beh["cache_policy"]["ttl"]["default"] = ttl

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
    """Extract file extensions from a parsed condition if it's extension-based."""
    if condition is None:
        return []
    if "logic" in condition:
        for p in condition.get("parts", []):
            exts = _extract_extensions_from_condition(p)
            if exts:
                return exts
        return []
    if condition.get("field") == "uri.path.extension":
        if condition.get("op") == "in":
            return condition.get("value", [])
        if condition.get("op") == "eq" and isinstance(condition.get("value"), str):
            return [condition["value"]]
    return []


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: cdn-preprocess.py <config_path> <output_dir> [--domain DOMAIN]",
              file=sys.stderr)
        sys.exit(2)

    config_path = sys.argv[1]
    output_dir = sys.argv[2]
    single_domain = None
    if "--domain" in sys.argv:
        idx = sys.argv.index("--domain")
        if idx + 1 < len(sys.argv):
            single_domain = sys.argv[idx + 1]

    # Load domain_scope.json
    scope_path = os.path.join(output_dir, "domain_scope.json")
    if not os.path.exists(scope_path):
        print(f"ERROR: {scope_path} not found", file=sys.stderr)
        sys.exit(2)
    with open(scope_path) as f:
        domain_scope = json.load(f)

    domains = domain_scope.get("domains", [])
    if single_domain:
        domains = [d for d in domains if d["hostname"] == single_domain]
        if not domains:
            print(f"ERROR: domain {single_domain} not found in domain_scope.json",
                  file=sys.stderr)
            sys.exit(2)

    # Find zone directory
    zone_dir = find_zone_dir(config_path)
    if not zone_dir:
        print(f"ERROR: no zone directory with DNS.txt found under {config_path}",
              file=sys.stderr)
        sys.exit(2)

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

    if success == 0:
        sys.exit(2)
    elif failed:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
