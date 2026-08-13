#!/usr/bin/env python3
"""cdn-generate-shared-policies.py — Stage 7: Generate shared policies.tf.

Reads dedup_manifest.json
and generates Terraform resources for all deduplicated CloudFront policies.

Usage:
    python3 cdn-generate-shared-policies.py <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_expr_parser import custom_orp_hash, orp_header_union
from cdn_rhp_capabilities import SECURITY_CAPABILITIES


def hcl_id(pid):
    return pid.replace("-", "_")


def hcl_list(items):
    if not items:
        return "[]"
    sorted_items = sorted(items)
    return "[" + ", ".join(f'"{i}"' for i in sorted_items) + "]"


def _orp_desc(headers):
    """Human comment for a custom ORP, from the header set."""
    geo = any(k in h for h in headers
              for k in ("Country", "City", "Latitude", "Longitude", "Region", "Postal", "Metro"))
    dev = any(k in h for h in headers
              for k in ("Mobile", "Desktop", "Tablet", "SmartTV", "IOS", "Android"))
    parts = [p for p, on in (("geo", geo), ("device", dev)) if on] or ["CloudFront"]
    return " + ".join(parts) + " headers"


def gen_custom_orp(headers):
    """Generate ONE shared custom origin request policy for a header set.

    Custom ORPs forward native CloudFront-* headers (e.g. CloudFront-Viewer-
    Country) that a cache policy can't carry. They were previously emitted
    per-domain in tf-scaffold — 54 identical copies blew the account's 20
    custom-ORP quota. Deduped here by header-set content: distributions sharing
    a header set reference one shared ORP (quota: 1 of 20, and up to 100
    distributions may reference the same ORP)."""
    h = custom_orp_hash(headers)
    lines = []
    w = lines.append
    w(f'resource "aws_cloudfront_origin_request_policy" "custom_orp_{h}" {{')
    w(f'  name    = "cfcdn-orp-custom-{h}"')
    w(f'  comment = "Shared custom ORP — forwards {_orp_desc(headers)} to origin"')
    w('')
    w('  headers_config {')
    w('    header_behavior = "allViewerAndWhitelistCloudFront"')
    w('    headers {')
    w(f'      items = {hcl_list(headers)}')
    w('    }')
    w('  }')
    w('')
    # Cloudflare is a reverse proxy — forwards the full request to origin by
    # default. Match that: forward all cookies + query strings (independent of
    # the cache KEY, which the cache policy controls).
    w('  cookies_config {')
    w('    cookie_behavior = "all"')
    w('  }')
    w('')
    w('  query_strings_config {')
    w('    query_string_behavior = "all"')
    w('  }')
    w('}')
    return "\n".join(lines)


def collect_custom_orp_headersets(output_dir):
    """Scan all final IRs for distinct custom-ORP header sets. Returns a dict
    {hash8: sorted_headers_list}, one entry per unique non-empty header set. Uses
    the shared orp_header_union / custom_orp_hash so the resource name generated
    here matches the data-source name cdn-generate-tf-scaffold emits."""
    final_dir = os.path.join(output_dir, "ir", "final")
    sets = {}
    for jf in glob.glob(os.path.join(final_dir, "*.json")):
        with open(jf) as f:
            ir = json.load(f)
        headers = orp_header_union(ir)
        if headers:
            sets[custom_orp_hash(headers)] = headers
    return sets


# ── Cache policy ─────────────────────────────────────────────────────────────

def gen_cache_policy(pid, config):
    lines = []
    w = lines.append
    caching_disabled = config.get("caching_disabled", False)

    if caching_disabled:
        # Unconditional cache bypass — the whole behavior never caches. Same
        # semantics as the AWS-managed CachingDisabled policy (all TTLs 0, no
        # cache-key inputs), emitted as a custom resource for uniform wiring.
        w(f'resource "aws_cloudfront_cache_policy" "{hcl_id(pid)}" {{')
        w(f'  name        = "cfcdn-caching-disabled-{pid}"')
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

    # Headers. These come from a Cloudflare cache-key custom_key.header.include
    # list (real request headers the user named) — NOT from geo/viewer fields.
    # That matters because CloudFront-Viewer-Address / -ASN and the TLS/JA3/JA4
    # headers are ORP-ONLY (they cannot appear in a cache policy); geo fields are
    # forwarded via the origin request policy, never here, so this list can't
    # contain them.
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


def gen_rhp(pid, config):
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
            # DORMANT + FAIL-LOUD (Step 5): the Access-Control-Allow-Origin "*" +
            # Access-Control-Allow-Credentials=true combo is NON_CONVERTIBLE (the Fetch/CORS
            # standard forbids it and CloudFront rejects a literal "*" with credentials) — it is
            # NC'd at the processor (process_response_header_transform, FINDING-61) and must never
            # reach a native cors_config. No producer populates `cors` today (the native path is
            # dormant), so this is unreachable; if someone re-enables native CORS, this combo MUST
            # go through a group-level semantic check first. Fail loud rather than silently emit a
            # literal "*" (an invalid, policy-violating RHP) or resurrect the old TLD-wildcard hack.
            raise ValueError(
                f"RHP {pid}: CORS Access-Control-Allow-Origin '*' with "
                "Access-Control-Allow-Credentials=true is non-convertible (Fetch/CORS forbids it; "
                "CloudFront rejects a literal '*' with credentials) — it must be NC'd at the "
                "processor, never emitted to a native cors_config")
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

    # Security headers — render from the NORMALIZED value the processor's capability.parse()
    # accepted, via the SAME capability's render() (shared cdn_rhp_capabilities registry).
    # The generator MUST NOT re-parse the raw header value: parse() already decided EXACT-vs-NC
    # and produced the exact fields render() reproduces (no more hardcoded HSTS max-age=31536000
    # / forced nosniff). Iterate the registry so ordering is deterministic and adding a header
    # can't drift the two sides. `operation == "set"` → override=true (Cloudflare set replaces).
    if sec:
        block = []
        for cap in SECURITY_CAPABILITIES:
            entry = sec.get(cap["canonical_name"])
            if not isinstance(entry, dict):
                continue
            normalized = entry.get("normalized")
            if normalized is None:
                # A security header reaches the RHP only after parse() accepted it, so its
                # normalized value is always present. Absent → don't guess/emit a wrong value.
                continue
            override = entry.get("operation", "set") == "set"
            block.extend(cap["render"](normalized, override))
        if block:
            w('')
            w('  security_headers_config {')
            for ln in block:
                w(ln)
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

    policies = manifest.get("policies", {})
    # Shared custom ORPs (native CloudFront-* header forwarding), deduped by
    # header-set content — separate from the manifest's forward-config ORPs.
    custom_orps = collect_custom_orp_headersets(output_dir)

    if not policies and not custom_orps:
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
            result = gen_rhp(pid, config)
            if result:
                sections.append(result)
            else:
                skipped_pids.add(pid)

    # Shared custom ORPs (one per distinct header set)
    for h in sorted(custom_orps):
        sections.append(gen_custom_orp(custom_orps[h]))

    sections.append(gen_outputs(policies, skipped_pids))

    with open(out_path, "w") as f:
        f.write("\n\n".join(sections) + "\n")

    total = sum(counts.values())
    print(f"OK: {out_path} → {total} resources "
          f"({counts['cache_policy']} cache, {counts['origin_request_policy']} ORP, "
          f"{counts['response_headers_policy']} RHP) + {len(custom_orps)} shared custom ORP")


if __name__ == "__main__":
    main()
