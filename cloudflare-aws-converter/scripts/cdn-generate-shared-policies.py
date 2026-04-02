#!/usr/bin/env python3
"""cdn-generate-shared-policies.py — Stage 7: Generate shared policies.tf.

Replaces cf-cdn-tf-shared-policies LLM subagent. Reads dedup_manifest.json
and generates Terraform resources for all deduplicated CloudFront policies.

Usage:
    python3 cdn-generate-shared-policies.py <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os


def hcl_id(pid):
    return pid.replace("-", "_")


def hcl_list(items):
    if not items:
        return "[]"
    sorted_items = sorted(items)
    return "[" + ", ".join(f'"{i}"' for i in sorted_items) + "]"


# ── Cache policy ─────────────────────────────────────────────────────────────

def gen_cache_policy(pid, config):
    lines = []
    w = lines.append
    bypass = config.get("bypass", False)

    if bypass:
        w(f'resource "aws_cloudfront_cache_policy" "{hcl_id(pid)}" {{')
        w(f'  name        = "cfcdn-cache-bypass-{pid}"')
        w(f'  min_ttl     = 0')
        w(f'  default_ttl = 0')
        w(f'  max_ttl     = 0')
        w('')
        w('  parameters_in_cache_key_and_forwarded_to_origin {')
        w('    cookies_config { cookie_behavior = "none" }')
        w('    headers_config { header_behavior = "none" }')
        w('    query_strings_config { query_string_behavior = "none" }')
        w('  }')
        w('}')
        return "\n".join(lines)

    ttl = config.get("ttl", {})
    ck = config.get("cache_key", {})

    w(f'resource "aws_cloudfront_cache_policy" "{hcl_id(pid)}" {{')
    w(f'  name        = "cfcdn-cache-policy-{pid}"')
    w(f'  min_ttl     = {ttl.get("min", 0)}')
    w(f'  default_ttl = {ttl.get("default", 86400)}')
    w(f'  max_ttl     = {ttl.get("max", 31536000)}')
    w('')
    w('  parameters_in_cache_key_and_forwarded_to_origin {')

    # Cookies
    cookies = ck.get("cookies", [])
    cookie_beh = "whitelist" if cookies else "none"
    w(f'    cookies_config {{')
    w(f'      cookie_behavior = "{cookie_beh}"')
    if cookies:
        w(f'      cookies {{ items = {hcl_list(cookies)} }}')
    w(f'    }}')

    # Headers
    headers = ck.get("headers", [])
    header_beh = "whitelist" if headers else "none"
    w(f'    headers_config {{')
    w(f'      header_behavior = "{header_beh}"')
    if headers:
        w(f'      headers {{ items = {hcl_list(headers)} }}')
    w(f'    }}')

    # Query strings
    qs = ck.get("query_strings", "none")
    qs_list = ck.get("query_strings_list", [])
    qs_exclude = ck.get("query_strings_exclude", [])
    if qs == "whitelist" and qs_list:
        qs_beh = "whitelist"
    elif qs == "allExcept" and qs_exclude:
        qs_beh = "allExcept"
    elif qs == "all":
        qs_beh = "all"
    else:
        qs_beh = "none"

    w(f'    query_strings_config {{')
    w(f'      query_string_behavior = "{qs_beh}"')
    if qs_beh == "whitelist" and qs_list:
        w(f'      query_strings {{ items = {hcl_list(qs_list)} }}')
    elif qs_beh == "allExcept" and qs_exclude:
        w(f'      query_strings {{ items = {hcl_list(qs_exclude)} }}')
    w(f'    }}')

    gzip = config.get("enable_gzip", True)
    brotli = config.get("enable_brotli", True)
    w(f'    enable_accept_encoding_gzip   = {"true" if gzip else "false"}')
    w(f'    enable_accept_encoding_brotli = {"true" if brotli else "false"}')
    w('  }')
    w('}')
    return "\n".join(lines)


# ── Origin request policy ────────────────────────────────────────────────────

def gen_orp(pid, config):
    lines = []
    w = lines.append
    fwd = config.get("forward", {})

    w(f'resource "aws_cloudfront_origin_request_policy" "{hcl_id(pid)}" {{')
    w(f'  name = "cfcdn-orp-{pid}"')
    w('')

    # Cookies
    c_beh = fwd.get("cookies", "none")
    c_list = fwd.get("cookies_list", [])
    w(f'  cookies_config {{')
    w(f'    cookie_behavior = "{c_beh}"')
    if c_beh in ("whitelist", "allExcept") and c_list:
        w(f'    cookies {{ items = {hcl_list(c_list)} }}')
    w(f'  }}')

    # Headers
    h_beh = fwd.get("headers", "none")
    h_list = fwd.get("headers_list", [])
    w(f'  headers_config {{')
    w(f'    header_behavior = "{h_beh}"')
    if h_beh in ("whitelist", "allViewerAndWhitelistCloudFront", "allExcept") and h_list:
        w(f'    headers {{ items = {hcl_list(h_list)} }}')
    w(f'  }}')

    # Query strings
    q_beh = fwd.get("query_strings", "none")
    q_list = fwd.get("query_strings_list", [])
    w(f'  query_strings_config {{')
    w(f'    query_string_behavior = "{q_beh}"')
    if q_beh in ("whitelist", "allExcept") and q_list:
        w(f'    query_strings {{ items = {hcl_list(q_list)} }}')
    w(f'  }}')

    w('}')
    return "\n".join(lines)


# Default TLD wildcard list for CORS credentials=true + origin=* workaround.
# CloudFront rejects literal "*" with credentials=true. Instead, we use TLD
# wildcard patterns (e.g., "*.com") which CloudFront matches against the
# request Origin header and echoes back the exact origin value.
# Scheme-agnostic: "*.com" matches both http:// and https:// origins.
# Limitation: does not match origins with non-standard ports (e.g., :8080).
# Users can add/remove TLDs in the generated policies.tf as needed.
CORS_WILDCARD_TLDS = [
    # Generic TLDs
    "*.com", "*.net", "*.org", "*.info", "*.biz", "*.xyz", "*.top",
    "*.site", "*.online", "*.store", "*.app", "*.dev", "*.io", "*.ai",
    "*.co", "*.me", "*.cc", "*.tv", "*.link", "*.cloud",
    # Country/region TLDs
    "*.cn", "*.uk", "*.de", "*.jp", "*.fr", "*.au", "*.ca", "*.br",
    "*.in", "*.kr", "*.ru", "*.it", "*.es", "*.nl", "*.eu", "*.tw",
    "*.hk", "*.sg", "*.se", "*.ch", "*.pl", "*.be", "*.at", "*.dk",
    "*.fi", "*.no", "*.nz", "*.za", "*.mx", "*.ar", "*.th", "*.vn",
    "*.id", "*.ph", "*.my", "*.pt", "*.ie", "*.cz", "*.il", "*.us",
]


def gen_rhp(pid, config, zone_tld=None):
    sec = config.get("security_headers", {})
    custom = config.get("custom_headers", [])
    cors = config.get("cors")
    remove = config.get("remove_headers", [])

    # Skip empty RHP — Terraform requires at least one config block
    if not sec and not custom and not cors and not remove:
        return None

    lines = []
    w = lines.append

    w(f'resource "aws_cloudfront_response_headers_policy" "{hcl_id(pid)}" {{')
    w(f'  name = "cfcdn-rhp-{pid}"')

    # CORS
    if cors and isinstance(cors, dict):
        allow_creds = cors.get("Access-Control-Allow-Credentials") == "true"
        # Determine origin_override from Cloudflare operation (set=true, add=false)
        origin_override = cors.get("_origin_override", True)  # default true (set)
        w('')
        w('  cors_config {')
        w(f'    access_control_allow_credentials = {"true" if allow_creds else "false"}')

        origins = cors.get("Access-Control-Allow-Origin", "*")
        origin_list = [o.strip() for o in origins.split(",")]

        if allow_creds and "*" in origin_list:
            # Workaround: replace "*" with TLD wildcard patterns
            # CloudFront echoes back the exact request Origin when a pattern matches
            tld_list = list(CORS_WILDCARD_TLDS)
            # Ensure the zone's own TLD is included
            if zone_tld:
                zone_pattern = f"*.{zone_tld}"
                if zone_pattern not in tld_list:
                    tld_list.append(zone_pattern)
            # Keep any non-wildcard origins from the original list
            explicit_origins = [o for o in origin_list if o != "*"]
            origin_list = sorted(set(tld_list + explicit_origins))
            w('    # Cloudflare allowed credentials=true with wildcard origin (*), but')
            w('    # CloudFront requires explicit origins per CORS spec. Using TLD wildcard')
            w('    # patterns as workaround — CloudFront echoes back the exact request Origin.')
            w('    # Add or remove TLD patterns as needed for your use case.')
            w('    # NOTE: Does not match origins with non-standard ports (e.g., :8080).')
            if not origin_override:
                w('    # Cloudflare operation was "add" (not "set"): when the request has no')
                w('    # Origin header, CloudFront will not return CORS headers. This differs')
                w('    # from Cloudflare which adds CORS headers unconditionally. This only')
                w('    # affects non-browser clients (curl, SDKs) — browsers always send Origin')
                w('    # for cross-origin requests.')
        elif not allow_creds and "*" in origin_list:
            # credentials=false with * is fine — CloudFront allows it
            pass
        elif allow_creds and "*" not in origin_list:
            # Explicit origins with credentials — no workaround needed
            pass

        w(f'    access_control_allow_origins {{ items = {hcl_list(origin_list)} }}')

        methods = cors.get("Access-Control-Allow-Methods", "GET, HEAD")
        method_list = [m.strip() for m in methods.split(",")]
        if "*" in method_list:
            method_list = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
        w(f'    access_control_allow_methods {{ items = {hcl_list(method_list)} }}')

        allow_headers = cors.get("Access-Control-Allow-Headers", "*")
        header_list = [h.strip() for h in allow_headers.split(",")]
        if allow_creds and "*" in header_list:
            header_list = [h for h in header_list if h != "*"] or ["Authorization", "Content-Type", "Origin", "Accept", "X-Requested-With"]
            w('    # NOTE: Wildcard headers replaced with common set (credentials=true).')
            w('    # Add any additional headers your application requires.')
        w(f'    access_control_allow_headers {{ items = {hcl_list(header_list)} }}')
        w(f'    origin_override = {"true" if origin_override else "false"}')
        w('  }')

    # Security headers
    if sec:
        w('')
        w('  security_headers_config {')
        # Extract value — support both old format (string) and new format ({value, operation})
        def _sec_val(key):
            v = sec.get(key)
            if v is None:
                return None, True
            if isinstance(v, dict):
                return v.get("value", ""), v.get("operation", "set") == "set"
            return v, True  # legacy string format → default override=true

        val, override = _sec_val("X-Content-Type-Options")
        if val is not None:
            w(f'    content_type_options {{ override = {"true" if override else "false"} }}')

        val, override = _sec_val("X-Frame-Options")
        if val is not None:
            w(f'    frame_options {{')
            w(f'      frame_option = "{val.upper()}"')
            w(f'      override     = {"true" if override else "false"}')
            w(f'    }}')

        val, override = _sec_val("Strict-Transport-Security")
        if val is not None:
            w('    strict_transport_security {')
            w('      access_control_max_age_sec = 31536000')
            w('      include_subdomains         = true')
            w('      preload                    = false')
            w(f'      override                   = {"true" if override else "false"}')
            w('    }')

        val, override = _sec_val("Referrer-Policy")
        if val is not None:
            w(f'    referrer_policy {{')
            w(f'      referrer_policy = "{val}"')
            w(f'      override        = {"true" if override else "false"}')
            w(f'    }}')

        val, override = _sec_val("X-XSS-Protection")
        if val is not None:
            w('    xss_protection {')
            w('      mode_block  = true')
            w(f'      override    = {"true" if override else "false"}')
            w('      protection  = true')
            w('    }')

        val, override = _sec_val("Content-Security-Policy")
        if val is not None:
            w(f'    content_security_policy {{')
            w(f'      content_security_policy = "{val}"')
            w(f'      override                = {"true" if override else "false"}')
            w(f'    }}')
        w('  }')

    # Custom headers
    if custom:
        w('')
        w('  custom_headers_config {')
        for ch in custom:
            op = ch.get("operation", "set")
            w(f'    items {{')
            w(f'      header   = "{ch["name"]}"')
            w(f'      value    = "{ch.get("value", "")}"')
            w(f'      override = {"true" if op == "set" else "false"}')
            w(f'    }}')
        w('  }')

    # Remove headers
    if remove:
        w('')
        w('  remove_headers_config {')
        for rh in remove:
            name = rh if isinstance(rh, str) else rh.get("name", "")
            w(f'    items {{ header = "{name}" }}')
        w('  }')

    w('}')
    return "\n".join(lines)


# ── Outputs ──────────────────────────────────────────────────────────────────

def gen_outputs(policies, skipped_pids=None):
    if skipped_pids is None:
        skipped_pids = set()
    lines = []
    w = lines.append

    cache = {pid: v for pid, v in policies.items() if v["type"] == "cache_policy"}
    orp = {pid: v for pid, v in policies.items() if v["type"] == "origin_request_policy"}
    rhp = {pid: v for pid, v in policies.items() if v["type"] == "response_headers_policy" and pid not in skipped_pids}

    w('output "cache_policy_ids" {')
    w('  value = {')
    for pid in sorted(cache):
        w(f'    "{pid}" = aws_cloudfront_cache_policy.{hcl_id(pid)}.id')
    w('  }')
    w('}')
    w('')
    w('output "origin_request_policy_ids" {')
    w('  value = {')
    for pid in sorted(orp):
        w(f'    "{pid}" = aws_cloudfront_origin_request_policy.{hcl_id(pid)}.id')
    w('  }')
    w('}')
    w('')
    w('output "response_headers_policy_ids" {')
    w('  value = {')
    for pid in sorted(rhp):
        w(f'    "{pid}" = aws_cloudfront_response_headers_policy.{hcl_id(pid)}.id')
    w('  }')
    w('}')

    return "\n".join(lines)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-generate-shared-policies.py <output_dir>", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
    manifest_path = os.path.join(output_dir, "shared", "dedup_manifest.json")
    out_path = os.path.join(output_dir, "terraform", "shared", "policies.tf")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    if not os.path.exists(manifest_path):
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    # Extract zone TLD from domain_scope.json for CORS wildcard workaround
    zone_tld = None
    scope_path = os.path.join(output_dir, "domain_scope.json")
    if os.path.exists(scope_path):
        try:
            with open(scope_path) as f:
                scope = json.load(f)
            zone_name = scope.get("zone_name", "")
            if "." in zone_name:
                zone_tld = zone_name.rsplit(".", 1)[-1]
        except (json.JSONDecodeError, KeyError):
            pass

    policies = manifest.get("policies", {})
    if not policies:
        with open(out_path, "w") as f:
            f.write("# No shared policies — all domains use AWS managed policies.\n")
        print("OK: no policies to generate")
        return

    sections = []

    # Header
    sections.append(
        'terraform {\n  required_providers {\n    aws = {\n'
        '      source  = "hashicorp/aws"\n      version = ">= 6.0"\n'
        '    }\n  }\n}'
    )

    counts = {"cache_policy": 0, "origin_request_policy": 0, "response_headers_policy": 0}
    skipped_pids = set()

    for pid in sorted(policies):
        entry = policies[pid]
        ptype = entry["type"]
        config = entry["config"]
        counts[ptype] = counts.get(ptype, 0) + 1

        if ptype == "cache_policy":
            sections.append(gen_cache_policy(pid, config))
        elif ptype == "origin_request_policy":
            sections.append(gen_orp(pid, config))
        elif ptype == "response_headers_policy":
            result = gen_rhp(pid, config, zone_tld=zone_tld)
            if result:
                sections.append(result)
            else:
                skipped_pids.add(pid)

    sections.append(gen_outputs(policies, skipped_pids))

    with open(out_path, "w") as f:
        f.write("\n\n".join(sections) + "\n")

    total = sum(counts.values())
    print(f"OK: {out_path} → {total} resources "
          f"({counts['cache_policy']} cache, {counts['origin_request_policy']} ORP, "
          f"{counts['response_headers_policy']} RHP)")


if __name__ == "__main__":
    main()
