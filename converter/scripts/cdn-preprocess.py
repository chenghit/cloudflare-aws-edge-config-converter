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
    CACHE_BYPASS_HEADER,
)
from cdn_common import (emit_result, derive_cert_domain,
                        pattern_contains, patterns_overlap)
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
                or derive_cert_domain(hostname, domain_config.get("apex_domain", "")),
            "origin_type": domain_config.get("origin_type", "server"),
            "kvs_requirements": {
                "needs_redirects": False,
                "needs_continent": False,
                "needs_eu": False,
                "needs_error_pages": False,
                "needs_ip_lists": False,
            },
            "kvs_data": [],
            "custom_error_responses": [],
            # Non-fatal conversion warnings surfaced in the report (e.g. a native
            # path behavior from a case-INSENSITIVE Cloudflare wildcard — CloudFront
            # PathPattern is case-sensitive, so case variants won't match).
            "conversion_warnings": [],
            "lambda_edge": {
                "origin_request": None,
                "origin_response": None,
            },
        },
        "cache_behaviors": [],
        # Ordered log of NATIVE effects (TTL/cache-key/compression/caching-disabled/
        # response-headers/origin) in SOURCE-RULE order. Native settings are NOT
        # written onto behaviors during the rule loop; they are recorded here and
        # replayed per behavior afterward (see _replay_native_effects). This is what
        # makes Cloudflare's rule-stacking correct on CloudFront: a behavior's
        # effective value = the LAST source-order rule whose scope CONTAINS that
        # behavior's path pattern (default `*` inherits nothing — every behavior is
        # computed independently). Dropped from the IR before it is written out.
        "_native_effects": [],
        # Rule-accounting sets for the every-rule-has-an-output invariant (both
        # internal, stripped before write): IDs that entered processing (passed the
        # host filter) vs IDs that produced any output.
        "_entered_rule_ids": set(),
        "_accounted_rule_ids": set(),
        # Monotonic source-order counter. Every viewer op and native effect is
        # stamped with `seq` in the order rules are PROCESSED (Cloudflare phase
        # order × in-phase file order). The JS generator emits ops sorted by seq —
        # NOT by cache-behavior order — so first-match redirects and last-wins
        # header transforms keep their true Cloudflare precedence regardless of how
        # behaviors are later sorted for CloudFront routing.
        "_seq": 0,
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

            if rule.get("id"):
                ir["_entered_rule_ids"].add(rule["id"])
            ir["_seq"] += 1  # source-processing order for this rule
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
        if rule.get("id"):
            ir["_entered_rule_ids"].add(rule["id"])
        ir["_seq"] += 1
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

    # Before replay: if a header name is handled by BOTH the RHP and the CFF, move
    # its RHP effects into the CFF so AWS's fixed RHP-then-CFF order can't reverse
    # the source (Cloudflare) order for that header.
    _reconcile_mixed_op_headers(ir, domain_config, origin_content)

    # Replay recorded NATIVE effects onto every behavior in source-rule order (F2).
    # MUST run after ALL effects are recorded (rules + cloud connector + managed
    # transforms) and after the behavior set is materialized, but BEFORE the ORP /
    # KVS scans below (they read the finished behaviors). This is what makes
    # Cloudflare rule-stacking correct on CloudFront's no-inheritance behaviors.
    _replay_native_effects(ir, domain_config, origin_content)

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

    # INVARIANT (reviewer's "every enabled rule must have an output"): every rule
    # that entered processing must leave a trace — a native effect, a viewer op, a
    # distribution setting, a custom-error entry, KVS data, or a non_convertible
    # record. A rule ID that produced NOTHING was silently dropped (the whole class
    # of bug this refactor targets). Surface any such orphan as non_convertible so
    # it lands in the report rather than vanishing. `_accounted_rule_ids` is
    # populated as outputs are produced; `_entered_rule_ids` as rules pass the host
    # filter. (Both internal, stripped below with _native_effects.)
    _enforce_every_rule_accounted(ir)

    # Internal bookkeeping — drop from the emitted IR. (`seq` stays ON each op —
    # the JS generator sorts by it; it's harmless metadata on the persisted op.)
    for k in ("_native_effects", "_entered_rule_ids", "_accounted_rule_ids", "_seq"):
        ir.pop(k, None)
    return ir


def _mark_result_non_convertible(ir, result, reason, expr=None):
    """Record a native-mechanism result as non-convertible on the default behavior
    (the single sink the report reads). Used when native_placement() rejects a
    condition — so the rule lands in conversion_report.md instead of being
    silently applied to `*` (widening) or dropped."""
    ir["cache_behaviors"][0]["non_convertible"].append({
        "cf_source_rule": result.get("cf_source_rule", ""),
        "description": result.get("description", ""),
        "reason": f"{reason}. Scope: {result.get('raw_expression') or expr or '(complex)'}",
    })


# ── Native-effect engine (F2: replay in source-rule order per behavior) ────────
# A NATIVE effect is a CloudFront setting that lives ON a cache behavior (not in the
# shared viewer CFF): edge TTL, cache-key, compression, caching-disabled, response-
# headers policy entries, and the behavior's origin. Cloudflare rules STACK — a
# later same-phase rule overrides an earlier one for requests both match — but
# CloudFront picks ONE behavior per request and it inherits nothing from the
# default. So we can't write these settings as we see each rule; we record them in
# source order and, once the full behavior set is known, replay onto each behavior
# every effect whose SCOPE PATTERN contains that behavior's path (last write wins).


def _resolved_vpp(ir):
    """The distribution's resolved ViewerProtocolPolicy (from the default behavior).
    Config rules (phase 3) set it before cache rules (phase 5) are placed, so at
    placement time this is the effective value for the full_uri https-scheme check."""
    return ir["cache_behaviors"][0]["distribution_settings"].get(
        "viewer_protocol_policy", "redirect-to-https")


def _warn_case_insensitive_native(ir, condition, pattern, source):
    """Emit a non-fatal case-difference warning when a NATIVE path pattern is
    derived from a case-INSENSITIVE Cloudflare wildcard (per user's decision: still
    convert natively, but surface the divergence — CloudFront PathPattern is
    case-sensitive, so `/Admin/*` won't match a `/admin/x` request Cloudflare would).
    De-duplicated per (rule, pattern)."""
    if not isinstance(condition, dict) or "logic" in condition:
        return
    if not _pattern_case_insensitive_letters(condition, pattern):
        return
    rid = source.get("cf_source_rule", "")
    msg = (f"Rule {rid or '(cache)'}: path pattern '{pattern}' comes from a "
           f"case-INSENSITIVE Cloudflare `wildcard`, but the CloudFront cache "
           f"behavior is CASE-SENSITIVE — requests with different capitalization "
           f"(e.g. '{pattern.upper()}') that Cloudflare matched will NOT match this "
           f"behavior. If your paths can vary in case, switch the source rule to "
           f"`strict wildcard` or normalize case at the origin.")
    warns = ir["metadata"].setdefault("conversion_warnings", [])
    if msg not in warns:
        warns.append(msg)


def _record_native_effect(ir, scope_pattern, kind, params, source):
    """Append a native effect to the ordered replay log. `scope_pattern` is the
    CloudFront path pattern the effect applies to (`*` = whole distribution).
    `kind` selects the applier branch in _apply_native_effect; `source` carries
    cf_source_rule/description for non-convertible reporting."""
    ir["_native_effects"].append({
        "scope": scope_pattern, "kind": kind, "params": params,
        "cf_source_rule": source.get("cf_source_rule", ""),
        "description": source.get("description", ""),
        "seq": ir.get("_seq", 0),   # source order (replay is order-sensitive: last wins)
    })


def _apply_native_effect(beh, kind, params):
    """Apply one native effect onto one behavior. Pure w.r.t. the behavior dict —
    the replay pass decides WHICH behaviors this runs on. Last-writer-wins is a
    property of replay ORDER, so each branch just overwrites."""
    cp = beh["cache_policy"]
    if kind == "ttl_override":
        # override_origin forces a fixed TTL — min=default=max is the only way
        # (a >max value would otherwise fail CloudFront's create API).
        ttl = params["ttl"]
        cp["ttl"]["min"] = cp["ttl"]["default"] = cp["ttl"]["max"] = ttl
    elif kind == "ttl_respect_origin":
        # RESET to factory TTL (CachingOptimized-like defaults) — undoes a prior
        # override at this scope. Must match make_default_behavior's ttl.
        cp["ttl"]["min"], cp["ttl"]["default"], cp["ttl"]["max"] = 0, 7200, 86400
    elif kind == "caching_enabled":
        cp["caching_disabled"] = False       # RESET: undoes a prior cache=false
    elif kind == "cache_key":
        for k in ("query_strings", "query_strings_list", "query_strings_exclude", "headers"):
            if k in params:
                cp["cache_key"][k] = params[k]
    elif kind == "caching_disabled":
        cp["caching_disabled"] = True
    elif kind == "compression":
        cp["enable_gzip"] = params.get("enable_gzip", True)
        cp["enable_brotli"] = params.get("enable_brotli", True)
    elif kind == "rhp_security":
        sh = beh["response_headers_policy"]["security_headers"]
        entry = {"value": params["value"], "operation": params.get("operation", "set")}
        if params.get("_managed"):
            sh.setdefault(params["name"], entry)   # managed default: explicit rule wins
        else:
            sh[params["name"]] = entry
    elif kind == "rhp_cors":
        rhp = beh["response_headers_policy"]
        if rhp["cors"] is None:
            rhp["cors"] = {}
        rhp["cors"][params["name"]] = params["value"]
        # cors_config.origin_override is ONE flag for the whole CORS config, not per
        # header — so it can't track per-header/per-rule set-vs-add precedence. Any
        # `add` anywhere makes it False (conservative: don't override the origin's
        # CORS headers). A later `set` does NOT flip it back True, because that would
        # also change behavior for the OTHER headers sharing this flag. When set/add
        # are genuinely mixed the faithful answer isn't representable in one flag;
        # False is the safe choice (deferring to origin). Documented limitation.
        if params.get("operation") == "add":
            rhp["cors"]["_origin_override"] = False
    elif kind == "rhp_custom":
        beh["response_headers_policy"]["custom_headers"].append({
            "name": params["name"], "value": params["value"],
            "operation": params.get("operation", "set"),
        })
    elif kind == "origin":
        beh["origin"]["domain"] = params.get("origin_host", beh["origin"]["domain"])
        beh["origin"]["s3_origin"] = "s3." in (params.get("origin_host") or "")


def _replay_native_effects(ir, domain_config, origin_content):
    """Compute each behavior's EFFECTIVE native config by replaying every recorded
    effect, in source-rule order (last write wins — Cloudflare rule stacking), onto
    the behaviors it applies to. Effects that name a concrete path first MATERIALIZE
    that behavior, so `TTL on /files/*` creates the /files/* behavior.

    For each (effect scope S, behavior pattern B), exactly one of:
      - pattern_contains(S, B): every request routed to B matches S → APPLY.
      - pattern_contains(B, S) (B strictly broader): S is a sub-region of B that is
        served by ITS OWN (more-specific) behavior, so B never actually serves an
        S request → the effect does NOT apply to B and is NOT a conflict. (This is
        why an ordered `/img` effect doesn't touch — or flag — the default `*`.)
      - otherwise, if they still OVERLAP: a genuine cross-overlap (e.g. `*.js` vs
        `/api/*`) — some requests match both, route to whichever behavior is listed
        first, and the effect can't be scoped to just them. CloudFront can't express
        a native setting on part of a behavior's traffic → report non-convertible
        rather than widen or drop.
      - disjoint: nothing to do.
    """
    effects = ir.get("_native_effects", [])
    for e in effects:
        if e["scope"] != "*":
            find_or_create_behavior(ir, e["scope"], domain_config, origin_content)

    for beh in ir["cache_behaviors"]:
        bp = beh["path_pattern"]
        for e in effects:
            scope = e["scope"]
            if pattern_contains(scope, bp):
                _apply_native_effect(beh, e["kind"], e["params"])
            elif pattern_contains(bp, scope):
                continue                     # S is a narrower sibling behavior's job
            elif patterns_overlap(scope, bp):
                beh["non_convertible"].append({
                    "cf_source_rule": e["cf_source_rule"],
                    "description": e["description"],
                    "reason": (f"native {e['kind']} scoped to '{scope}' cross-overlaps "
                               f"behavior '{bp}' (neither contains the other) — "
                               "CloudFront can't apply a native setting to only part "
                               "of a behavior's traffic; scope them so one path "
                               "contains the other, or apply it at the origin"),
                })


def _reconcile_mixed_op_headers(ir, domain_config, origin_content):
    """AWS executes a Response Headers Policy BEFORE the viewer-response function.
    So if the SAME header name is set via the RHP (native) but ALSO removed/changed
    via a CFF op (e.g. `remove` isn't RHP-expressible), the two mechanisms run in
    RHP-then-CFF order — which REVERSES Cloudflare's source order when the CFF op
    came from an EARLIER rule. Fix: when a header name has both an RHP effect and a
    CFF response-header op, move ALL of that header's RHP effects into the CFF too,
    so every op for the header lives in one mechanism and emits in `seq` order
    (last-wins preserved). Runs before replay, so the moved effects never reach the
    RHP."""
    # header names (lowercased) that already have a CFF response-header op
    cff_hdr_names = set()
    for beh in ir["cache_behaviors"]:
        for op in beh.get("viewer_response_ops", []):
            if op.get("type", "").endswith("_response_header"):
                nm = op.get("params", {}).get("name")
                if nm:
                    cff_hdr_names.add(nm.lower())
    if not cff_hdr_names:
        return
    kept = []
    for e in ir.get("_native_effects", []):
        if e["kind"] in ("rhp_security", "rhp_cors") and not e["params"].get("_managed") \
                and e["params"].get("name", "").lower() in cff_hdr_names:
            # Move this header's native set/add into the CFF as a source-ordered op.
            op_type = "add_response_header" if e["params"].get("operation") == "add" \
                else "set_response_header"
            beh = find_or_create_behavior(ir, e["scope"], domain_config, origin_content)
            beh["viewer_response_ops"].append({
                "type": op_type,
                "cf_source_rule": e.get("cf_source_rule", ""),
                "description": e.get("description", ""),
                "condition": {"always": True},
                "raw_expression": None,
                "params": {"name": e["params"]["name"], "value": e["params"]["value"]},
                "scope_pattern": e["scope"],
                "seq": e.get("seq", 0),
            })
        else:
            kept.append(e)
    ir["_native_effects"] = kept


def _enforce_every_rule_accounted(ir):
    """Every rule that entered processing (passed the host filter) must leave a
    trace: a native effect, a viewer op, a distribution/custom-error/KVS output, or
    a non_convertible record. A rule ID with NO trace was silently dropped — the
    exact failure class this refactor targets — so record it as non_convertible
    rather than letting it vanish. Scans all output sinks for cf_source_rule."""
    accounted = set(ir.get("_accounted_rule_ids", set()))
    for e in ir.get("_native_effects", []):
        accounted.add(e.get("cf_source_rule"))
    for beh in ir["cache_behaviors"]:
        for nc in beh.get("non_convertible", []):
            accounted.add(nc.get("cf_source_rule"))
        for op in beh.get("viewer_request_ops", []) + beh.get("viewer_response_ops", []):
            accounted.add(op.get("cf_source_rule"))
    # metadata sinks (custom errors, kvs data carry the source in their own ids;
    # distribution settings are recorded in _accounted_rule_ids at placement time).
    orphans = ir.get("_entered_rule_ids", set()) - accounted
    for rid in sorted(orphans):
        ir["cache_behaviors"][0]["non_convertible"].append({
            "cf_source_rule": rid,
            "description": "(rule produced no output)",
            "reason": ("INTERNAL: this enabled rule matched the domain but produced "
                       "no CloudFront output (native setting, function op, or "
                       "non-convertible record) — a silent drop. Reported so it is "
                       "never lost; please file it as a converter bug."),
        })


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
        if result.get("cf_source_rule"):
            ir.setdefault("_accounted_rule_ids", set()).add(result["cf_source_rule"])
        return

    if rtype == "custom_error_response":
        ir["metadata"]["custom_error_responses"].append(result["params"])
        if result.get("cf_source_rule"):
            ir.setdefault("_accounted_rule_ids", set()).add(result["cf_source_rule"])
        return

    if rtype == "compression_setting":
        # Compression is a cache-policy attribute (native). Record it as an ordered
        # native effect scoped to its path; the replay pass applies it to every
        # behavior that path contains (and reports a cross-overlap). A scope that
        # isn't a single pattern (raw / multi-path OR) can't be honored → report.
        scope, reason = native_placement(result.get("condition") or cond, _resolved_vpp(ir))
        if reason:
            _mark_result_non_convertible(ir, result, reason, expr)
            return
        _warn_case_insensitive_native(ir, result.get("condition") or cond, scope, result)
        _record_native_effect(ir, scope, "compression", result.get("params", {}), result)
        return

    if rtype == "response_headers_policy":
        # A response-headers policy is native (per behavior). Record it as an
        # ordered native effect; replay attaches it to every behavior its scope
        # contains. F1: gate on the RESULT's own screened condition, never the
        # outer re-parsed cond.
        scope, reason = native_placement(result.get("condition"), _resolved_vpp(ir))
        if reason:
            _mark_result_non_convertible(ir, result, reason, expr)
            return
        _warn_case_insensitive_native(ir, result.get("condition"), scope, result)
        params = result["params"]
        if params.get("is_cors"):
            kind = "rhp_cors"
        elif params.get("is_security"):
            kind = "rhp_security"
        else:
            kind = "rhp_custom"
        _record_native_effect(ir, scope, kind, params, result)
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
            # Unconditional (after host-strip) → CachingDisabled on the scoped
            # behavior. Record as a native effect so it stacks in source order and
            # covers every behavior its path contains (a site-wide `*` bypass turns
            # caching off on every ordered behavior too — none inherit the default).
            path = _extract_path_from_result(result, cond, expr)
            _record_native_effect(ir, path, "caching_disabled", {}, result)
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
                # One native effect per path branch (each a single pattern); replay
                # stacks them in source order like any other cache effect.
                for path in or_paths:
                    _record_cache_effects(ir, path, result, domain_config, origin_content)
                return
            # Non-splittable OR → can't be expressed as CloudFront path behaviors.
            _mark_cache_non_convertible(ir, result, expr)
            return
        # Fan out to one *.ext effect per extension ONLY when the condition is
        # PURELY an extension set. A sibling scope (host eq x and ext in [...])
        # must NOT fan out — that would apply the cache setting to *.pdf on every
        # host, dropping the host scope. In that case fall through to the normal
        # single-path placement below (which keeps the host/path scope).
        result_cond = result.get("condition") or cond
        exts = _extract_extensions_from_condition(result_cond)
        if len(exts) > 1 and _condition_is_pure_extension(result_cond):
            for ext in exts:
                _record_cache_effects(ir, f"*.{ext}", result, domain_config, origin_content)
            return
        # A cache setting is native (per behavior), so its condition MUST be
        # representable as a single path pattern. After host-stripping, a still-
        # compound scope (ip.src.country, a multi-field AND, a NOT) can't be —
        # applying it to `_extract_path_from_result`'s best-effort `*` would widen
        # it site-wide. Report non-convertible instead of silently dropping.
        if not _cache_cond_is_single_path(result_cond, _resolved_vpp(ir)):
            _mark_cache_non_convertible(ir, result, expr)
            return
        path = _extract_path_from_result(result, cond, expr)
        _warn_case_insensitive_native(ir, result_cond, path, result)
        _record_cache_effects(ir, path, result, domain_config, origin_content)
        return

    if rtype == "cloud_connector":
        # A cloud connector switches the ORIGIN of a cache behavior (native).
        # Record as an ordered origin effect; replay re-points every behavior its
        # scope contains. A non-single-pattern scope → report (would re-point the
        # whole distribution or drop).
        scope, reason = native_placement(result.get("condition") or cond, _resolved_vpp(ir))
        if reason:
            _mark_result_non_convertible(ir, result, reason, expr)
            return
        _warn_case_insensitive_native(ir, result.get("condition") or cond, scope, result)
        _record_native_effect(ir, scope, "origin", result.get("params", {}), result)
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
        "scope_pattern": _op_scope_pattern(path),
        "seq": ir.get("_seq", 0),   # source-processing order (see make_empty_ir)
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


def _op_scope_pattern(path):
    """The CloudFront path pattern a viewer op's effect COULD reach, so the scaffold
    attaches the shared CFF to every behavior that OVERLAPS it (a shared CFF that
    isn't attached to the behavior serving a matching request silently drops the
    op — CloudFront function associations are strictly per-behavior, no inheritance).

    `path` is _extract_path_from_result's best-effort pattern:
      - a concrete pattern (e.g. `/api/*`) when the op reduced to one path → it can
        only match there;
      - `"*"` otherwise. That covers BOTH the old 'all' (zone-wide: host/header/
        cookie, no path field) AND the old 'default_only' (a path field that
        couldn't reduce to a CloudFront pattern — regex/negated/multi-ext/OR-of-
        paths — so it can still match requests served by ORDERED behaviors). The old
        model attached default_only to the default behavior ONLY, which was UNSOUND:
        a request routed to an ordered behavior would never run the op. `*` overlaps
        every behavior — over-attaching is only cost, a miss is a silent drop.
    So this is just `path` today, but named to document the scope-not-placement
    intent (the value feeds overlap-based CFF attachment, not where the op lives)."""
    return path


def _record_cache_effects(ir, scope, result, domain_config, origin_content):
    """Record a cache rule's NATIVE effects (edge TTL, cache-key) as ordered
    effects at `scope`, and emit its browser_ttl (a viewer-response op) directly.

    Bypass is NOT handled here — _place_result intercepts every bypass cache rule
    (unconditional → caching_disabled effect; conditional → cache_bypass op), so
    only TTL / cache-key / browser_ttl reach here.
    """
    params = result.get("params", {})

    if "edge_ttl_override" in params:
        _record_native_effect(ir, scope, "ttl_override",
                              {"ttl": params["edge_ttl_override"]}, result)
    elif params.get("edge_ttl_respect_origin"):
        # respect_origin is a RESET back to factory TTL. It must be a real effect so
        # a LATER respect_origin rule overrides an EARLIER override_origin at the
        # same scope (Cloudflare last-match). Without this the earlier fixed TTL
        # would silently persist (reviewer F2).
        _record_native_effect(ir, scope, "ttl_respect_origin", {}, result)

    # cache=true is a RESET of a prior cache=false at the same scope. bypass=True is
    # intercepted earlier (caching_disabled effect / cache_bypass op); an explicit
    # bypass=False here re-enables caching so a later cache=true beats an earlier
    # cache=false (reviewer F2 — was silently stuck disabled).
    if params.get("bypass") is False:
        _record_native_effect(ir, scope, "caching_enabled", {}, result)

    ck = {}
    for src, dst in (("cache_key_qs", "query_strings"),
                     ("cache_key_qs_list", "query_strings_list"),
                     ("cache_key_qs_exclude", "query_strings_exclude"),
                     ("cache_key_headers", "headers")):
        if src in params:
            ck[dst] = params[src]
    if ck:
        _record_native_effect(ir, scope, "cache_key", ck, result)

    # browser_ttl (override_origin): Cloudflare forces the max-age in the
    # Cache-Control header sent to the VIEWER, independent of the edge TTL. A
    # viewer-response CFF replicates this faithfully — response.headers is
    # writable there, the value is forced unconditionally, and it self-gates on
    # the rule condition. Emitted as a set_response_header op (scope_pattern drives
    # which behaviors the shared CFF attaches to). Caveat: viewer-response CFF does
    # not run for CloudFront-generated 4xx/5xx, acceptable for browser_ttl.
    if "browser_ttl_override" in params:
        beh = find_or_create_behavior(ir, scope, domain_config, origin_content)
        max_age = params["browser_ttl_override"]
        already = any(
            op.get("cf_source_rule") == result.get("cf_source_rule")
            and op.get("params", {}).get("name") == "cache-control"
            for op in beh["viewer_response_ops"]
        )
        if not already:
            beh["viewer_response_ops"].append({
                "type": "set_response_header",
                "cf_source_rule": result.get("cf_source_rule", ""),
                "description": f"{result.get('description', '')}: browser_ttl override",
                "condition": result.get("condition"),
                "raw_expression": result.get("raw_expression"),
                "params": {"name": "cache-control", "value": f"max-age={max_age}"},
                "scope_pattern": scope,
                "seq": ir.get("_seq", 0),
            })


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
            "scope_pattern": "*",  # unconditional zone-wide → overlaps every behavior
            "seq": ir.get("_seq", 0) + 1,  # after all rules (Cloudflare runs bulk late)
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
                "scope_pattern": "*",  # unconditional zone-wide → overlaps every behavior
                "seq": ir.get("_seq", 0) + 1,
            })

    for h in resp_headers:
        if h.get("enabled") and h.get("id") == "add_security_headers":
            # Zone-wide managed security headers — record as `*`-scoped native
            # effects so replay applies them to EVERY behavior (ordered behaviors
            # don't inherit the default's RHP). Recorded at the head of the effect
            # log with operation="add" (setdefault semantics: a later explicit rule
            # for the same header still wins on replay order).
            src = {"cf_source_rule": "managed_transform_security_headers",
                   "description": "Managed Transform: security headers"}
            _record_native_effect(ir, "*", "rhp_security",
                                  {"name": "X-Content-Type-Options", "value": "nosniff",
                                   "operation": "add", "_managed": True}, src)
            _record_native_effect(ir, "*", "rhp_security",
                                  {"name": "X-Frame-Options", "value": "SAMEORIGIN",
                                   "operation": "add", "_managed": True}, src)


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


def _cache_cond_is_single_path(condition, vpp=None):
    """True if a cache-rule condition can be represented by ONE specific
    CloudFront path pattern (so applying the setting to one behavior is faithful).
    `vpp` is the resolved viewer_protocol_policy for the scope (used only for the
    full_uri https-scheme check — see below); None = assume redirect-to-https.

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
    pattern = extract_path_pattern_single(condition)
    if pattern == "*":
        return False
    # A CloudFront path pattern matches ONLY the URI path — never the query string.
    # A full_uri that pins a query (`?`) can't be reduced to a path pattern (the `?`
    # would be a literal/path wildcard char, silently mis-matching), so reject it.
    # SCHEME (confirmed vs AWS docs by dual subagents): redirect-to-https (the
    # default VPP) issues the 301 BEFORE cache-behavior/function execution, so every
    # request a behavior actually serves is HTTPS. Thus an `https://`-pinned full_uri
    # reduces faithfully to a path pattern (the scheme is already guaranteed —
    # redundant), while an `http://`-pinned rule matches ~no served traffic (http is
    # redirected before routing) and scheme is never a CloudFront routing key → a
    # path pattern can't express it, reject as non-single-path. (Caveat: under
    # allow-all VPP an https rule mapped to path-only would widen to http too; the
    # default VPP is redirect-to-https, where accept-https is exact.)
    if condition.get("field") == "full_uri":
        scheme = condition.get("scheme")
        # http-only is never a CloudFront path (scheme isn't a routing key; under
        # redirect-to-https http is redirected before routing).
        if scheme == "http":
            return False
        # https-only is faithful ONLY when the effective VPP redirects/forces https
        # (then all served traffic is https — scheme redundant). Under allow-all,
        # http is served too, so dropping the scheme to a path would WIDEN the rule
        # to http traffic (reviewer F5). `vpp` is the resolved viewer_protocol_policy
        # for this scope; None means "not yet known" → assume the default
        # redirect-to-https (safe/common) rather than reject.
        if scheme == "https" and vpp == "allow-all":
            return False
        if "?" in (condition.get("path_pattern") or ""):
            return False
    if "?" in pattern:
        return False
    return True


def _pattern_case_insensitive_letters(condition, pattern):
    """True if this native path pattern comes from a CASE-INSENSITIVE Cloudflare
    match (`wildcard`, incl. full_uri wildcard) AND contains cased letters — so the
    case-SENSITIVE CloudFront behavior would miss case variants Cloudflare matched.
    Per Cloudflare docs `eq`/`starts_with`/`ends_with`/`strict wildcard` are already
    case-sensitive (faithful); only plain `wildcard` is case-insensitive. Used to
    emit a NON-fatal case-difference warning — the rule is still converted natively
    (user's call), the divergence is surfaced in the report, not silently dropped."""
    if condition.get("op") != "wildcard":
        return False
    return any(c.isalpha() for c in pattern or "")


def _is_pure_host_routing(condition):
    """True if `condition` is ENTIRELY host-routing leaves the router consumed —
    including an OR of them (`host eq a or host eq b`), which _strip_host_condition
    deliberately leaves intact (the classifier already routed it). After routing,
    such a condition is unconditional on each distribution it reached, so a native
    mechanism can honor it globally on that distribution. A full_uri leaf is NOT
    pure host-routing (its path part still matters). Fixes the pure-host-OR
    false-negative."""
    if condition is None or condition.get("always"):
        return True
    if "logic" in condition:
        if condition["logic"] == "not":
            return _is_pure_host_routing(condition.get("item"))
        parts = condition.get("parts", [])
        return bool(parts) and all(_is_pure_host_routing(p) for p in parts)
    return host_leaf_is_routing(condition)


def native_placement(condition, vpp=None):
    """The placement decision for a rule mapped to a NATIVE CloudFront mechanism
    (distribution setting / cache-behavior setting / response-headers policy /
    compression / cloud-connector origin) — mechanisms that can only be scoped by
    a single path pattern, NOT by a per-request predicate (header/cookie/geo/…).

    THE INVARIANT (was enforced only in the cache_setting branch; this generalizes
    it to every native mechanism): after host-routing is consumed, the condition
    must reduce to ONE CloudFront path pattern, else the mechanism can't carry it
    faithfully and it must be reported non-convertible — never silently placed on
    `*` (which widens a scoped setting site-wide) or dropped.

    Returns (path, None) when placeable — `path` is the pattern to attach to
    (`*` for unconditional / pure-host-routing) — or (None, reason) when the
    condition can't be represented, so the caller marks it non-convertible.
    `condition` must already be host-stripped (the caller strips before placing).
    `vpp` is the resolved viewer_protocol_policy (for the full_uri https check)."""
    if _is_pure_host_routing(condition):
        return "*", None
    if _cache_cond_is_single_path(condition, vpp):
        return extract_path_pattern_single(condition), None
    return None, ("condition cannot be scoped to a single CloudFront path pattern "
                  "(a native cache/behavior/header/compression/origin setting can't "
                  "be gated per-request on headers/cookies/geo or a multi-path OR)")


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
