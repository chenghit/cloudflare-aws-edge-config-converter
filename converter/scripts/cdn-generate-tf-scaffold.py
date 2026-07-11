#!/usr/bin/env python3
"""cdn-generate-tf-scaffold.py — Stage 7.5: Generate Terraform scaffold files.

Generates all deterministic Terraform files from finalized IR JSON.
tf-domain (Stage 8) only needs to generate JS files afterward.

Usage:
    python3 cdn-generate-tf-scaffold.py <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os


def load_ir(final_dir, hostname):
    path = os.path.join(final_dir, f"{hostname}.json")
    with open(path) as f:
        return json.load(f)


def load_manifest(shared_dir):
    path = os.path.join(shared_dir, "dedup_manifest.json")
    with open(path) as f:
        return json.load(f)


# ── Origin deduplication ─────────────────────────────────────────────────────

def collect_origins(ir):
    """Collect unique origins from all cache behaviors. Returns list of origin dicts."""
    seen = {}  # domain → origin dict with unique id
    sanitized = ir["metadata"]["sanitized_name"]
    for b in ir["cache_behaviors"]:
        o = b["origin"]
        domain = o["domain"]
        if domain not in seen:
            idx = len(seen)
            oid = f"origin_{sanitized}" if idx == 0 else f"origin_{sanitized}_{idx}"
            seen[domain] = {
                "origin_id": oid,
                "domain": domain,
                "protocol": o.get("protocol", "https"),
                "port": o.get("port", 443),
                "host_header": o.get("host_header"),
                "custom_origin_headers": o.get("custom_origin_headers", []),
                "s3_origin": o.get("s3_origin", False),
            }
    return list(seen.values()), {d: v["origin_id"] for d, v in seen.items()}


def has_viewer_response_ops(ir):
    return any(len(b.get("viewer_response_ops", [])) > 0 for b in ir["cache_behaviors"])


def _default_beh(ir):
    return next(b for b in ir["cache_behaviors"] if b["path_pattern"] == "*")


def _has_zonewide_op(ir, ops_key):
    """True if the DEFAULT behavior carries a scope='all' op — a zone-wide rule
    (no path field) that must run on EVERY behavior, since CloudFront behaviors
    don't inherit function associations. A scope='default_only' op (had a path
    that couldn't reduce to a pattern) does NOT count — it belongs to the
    default behavior alone."""
    return any(op.get("scope") == "all" for op in _default_beh(ir).get(ops_key, []))


def _behavior_needs_cff(ir, beh, ops_key):
    """Whether a behavior needs the shared viewer CFF for a given event
    (viewer_request_ops / viewer_response_ops). This is the #123 automation:
    stop attaching the shared CFF to behaviors that would only ever run it as a
    no-op. A behavior needs the CFF iff it has its OWN ops for that event, OR the
    default behavior has a zone-wide (scope='all') op that must run everywhere.
    The default behavior itself needs it iff it has ANY op for that event."""
    if beh["path_pattern"] == "*":
        return len(beh.get(ops_key, [])) > 0
    return len(beh.get(ops_key, [])) > 0 or _has_zonewide_op(ir, ops_key)


def collect_orp_headers(ir):
    """Collect all required_orp_headers across all behaviors, deduplicated."""
    headers = set()
    for b in ir["cache_behaviors"]:
        headers.update(b.get("required_orp_headers", []))
    return sorted(headers)


# ── HCL generation helpers ───────────────────────────────────────────────────

def hcl_string(val):
    if val is None:
        return "null"
    return f'"{val}"'


def hcl_bool(val):
    return "true" if val else "false"


def hcl_list_strings(items):
    if not items:
        return "[]"
    inner = ", ".join(f'"{i}"' for i in items)
    return f"[{inner}]"


def hcl_id(pid):
    """Convert policy ID to valid HCL identifier (replace hyphens)."""
    return pid.replace("-", "_")


# AWS-managed origin request policy ID (fixed, well-known constant).
#   AllViewer — all viewer headers (incl. Host) + all cookies + all query
#               strings; NO CloudFront-generated headers. Forwarding the viewer
#               Host is always safe even when a behavior overrides the origin
#               Host: the CFF's cf.updateRequestOrigin({hostHeader}) takes
#               precedence over the ORP-forwarded Host (documented fallback
#               chain — an explicit hostHeader outranks the viewer Host —
#               verified live on a real distribution), so AllViewer never leaks
#               the wrong Host to the origin.
_MANAGED_ORP_ALL_VIEWER = "216adef6-5c7f-47e4-b989-5492eafa07d3"


def _orp_reference(beh, orp_headers, san):
    """The ORP resource reference (HCL RHS) for a behavior, or None for no ORP.
    Cloudflare is a reverse proxy — it forwards the FULL request (all headers
    incl. Host, all cookies, all query strings) to origin by default — so a
    behavior fronting a normal server origin gets a forward-all ORP (CloudFront
    strips everything not in the cache key without one). Selection:
      - S3 + OAC origin → NO ORP (None). OAC signs the request with SigV4;
        forwarding the viewer Host (or arbitrary headers) breaks the signature
        → S3 returns SignatureDoesNotMatch / 403. S3 needs none of the viewer
        Host/cookies/query, and CloudFront sets Host to the bucket domain itself.
      - native CloudFront-* headers needed → custom_orp_{san}
        (header_behavior allViewerAndWhitelistCloudFront + cookie/query all).
      - otherwise → AllViewer (forward the original viewer Host, matching the
        Cloudflare default). A Host override — conditional OR unconditional —
        also uses AllViewer: the CFF's updateRequestOrigin({hostHeader}) wins
        over the forwarded Host for matching requests, and non-matching requests
        correctly keep the viewer Host. (No AllViewerExceptHostHeader — it would
        strand non-matching requests with no Host replacement, and buys nothing
        for matching ones since hostHeader already wins — proven live.)
    Shared by the default and ordered-behavior emitters so their ORP wiring
    can't diverge.
    """
    if beh.get("origin", {}).get("s3_origin"):
        return None  # S3+OAC: no ORP (Host/header forwarding breaks SigV4)
    if orp_headers:
        # custom_orp forwards all viewer headers (incl. Host) + CloudFront-*
        # headers + all cookies/query strings. A Host override still works: the
        # CFF updateRequestOrigin(hostHeader=…) sets the origin Host regardless.
        # A resource reference (unquoted HCL).
        return f"aws_cloudfront_origin_request_policy.custom_orp_{san}.id"
    # Managed policy referenced by its fixed ID as a STRING literal (quoted) —
    # not a resource/data reference.
    return f'"{_MANAGED_ORP_ALL_VIEWER}"'


# ── main.tf generation ───────────────────────────────────────────────────────

def generate_main_tf(ir, manifest, domain_to_origin_id, origins):
    meta = ir["metadata"]
    san = meta["sanitized_name"]
    hostname = meta["hostname"]
    apex = meta["apex_domain"]
    behaviors = ir["cache_behaviors"]
    default_beh = next(b for b in behaviors if b["path_pattern"] == "*")
    ordered_behs = [b for b in behaviors if b["path_pattern"] != "*"]
    ds = default_beh["distribution_settings"]
    has_s3 = any(o["s3_origin"] for o in origins)
    orp_headers = collect_orp_headers(ir)
    le = meta.get("lambda_edge", {})
    has_le_origin_resp = le.get("origin_response") is not None
    kvs_req = meta.get("kvs_requirements", {})
    has_kvs = any(kvs_req.values())
    custom_errors = meta.get("custom_error_responses", [])

    lines = []
    w = lines.append

    # Header
    w('terraform {')
    w('  required_providers {')
    w('    aws = {')
    w('      source  = "hashicorp/aws"')
    w('      version = ">= 6.0"')
    w('    }')
    if has_le_origin_resp:
        w('    archive = {')
        w('      source  = "hashicorp/archive"')
        w('      version = ">= 2.0"')
        w('    }')
    w('  }')
    w('}')
    w('')
    w('provider "aws" {')
    w('  alias  = "us_east_1"')
    w('  region = "us-east-1"')
    w('}')
    w('')

    # ACM certificate
    if meta["cert_arn_mode"] == "explicit" and meta.get("cert_arn"):
        w(f'locals {{')
        w(f'  cert_arn_{san} = "{meta["cert_arn"]}"')
        w('}')
        cert_ref = f"local.cert_arn_{san}"
    else:
        w(f'data "aws_acm_certificate" "{san}" {{')
        w(f'  provider    = aws.us_east_1')
        w(f'  domain      = "*.{apex}"')
        w(f'  statuses    = ["ISSUED"]')
        w(f'  most_recent = true')
        w('}')
        cert_ref = f"data.aws_acm_certificate.{san}.arn"
    w('')

    # Policy data sources
    policy_ids = _collect_policy_ids(behaviors)
    for pid in sorted(policy_ids):
        pinfo = manifest["policies"].get(pid, {})
        ptype = pinfo.get("type", "")
        if ptype == "cache_policy":
            caching_disabled = pinfo.get("config", {}).get("caching_disabled", False)
            prefix = "cfcdn-caching-disabled" if caching_disabled else "cfcdn-cache-policy"
            w(f'data "aws_cloudfront_cache_policy" "{hcl_id(pid)}" {{')
            w(f'  name = "{prefix}-{pid}"')
            w('}')
        elif ptype == "origin_request_policy":
            w(f'data "aws_cloudfront_origin_request_policy" "{hcl_id(pid)}" {{')
            w(f'  name = "cfcdn-orp-{pid}"')
            w('}')
        elif ptype == "response_headers_policy":
            w(f'data "aws_cloudfront_response_headers_policy" "{hcl_id(pid)}" {{')
            w(f'  name = "cfcdn-rhp-{pid}"')
            w('}')
        w('')

    # S3 OAC
    if has_s3:
        w(f'resource "aws_cloudfront_origin_access_control" "s3_oac" {{')
        w(f'  name                              = "cfcdn-s3-oac-{san}"')
        w(f'  description                       = "OAC for S3 origins ({hostname})"')
        w(f'  origin_access_control_origin_type = "s3"')
        w(f'  signing_behavior                  = "always"')
        w(f'  signing_protocol                  = "sigv4"')
        w('}')
        w('')

    # Custom ORP for geo/device headers
    if orp_headers:
        desc_parts = []
        geo_h = [h for h in orp_headers if 'Country' in h or 'City' in h or 'Latitude' in h or 'Longitude' in h or 'Region' in h or 'Postal' in h or 'Metro' in h]
        dev_h = [h for h in orp_headers if 'Mobile' in h or 'Desktop' in h or 'Tablet' in h or 'SmartTV' in h or 'IOS' in h or 'Android' in h]
        if geo_h:
            desc_parts.append('geo')
        if dev_h:
            desc_parts.append('device')
        if not desc_parts:
            desc_parts.append('CloudFront')
        desc = ' + '.join(desc_parts) + ' headers'
        w(f'resource "aws_cloudfront_origin_request_policy" "custom_orp_{san}" {{')
        w(f'  name    = "cfcdn-orp-custom-{san}"')
        w(f'  comment = "Custom ORP for {hostname} - forwards {desc} to origin"')
        w('')
        w('  headers_config {')
        w('    header_behavior = "allViewerAndWhitelistCloudFront"')
        w('    headers {')
        w(f'      items = {hcl_list_strings(orp_headers)}')
        w('    }')
        w('  }')
        w('')
        # Cloudflare is a reverse proxy: by default it forwards the FULL request
        # (all cookies, all query strings) to origin. CloudFront strips anything
        # not in the cache key unless an ORP forwards it, so forward all to match
        # Cloudflare. This is independent of the cache KEY (the cache policy,
        # which controls hit/miss) — forwarding "all" here does not hurt the
        # cache hit ratio. (A rule that strips query strings from the origin
        # request is a Cloudflare URL-Rewrite transform, converted separately as
        # a CFF request.querystring rewrite — not an ORP setting.)
        w('  cookies_config {')
        w('    cookie_behavior = "all"')
        w('  }')
        w('')
        w('  query_strings_config {')
        w('    query_string_behavior = "all"')
        w('  }')
        w('}')
        w('')

    # Module call
    w(f'module "cdn_{san}" {{')
    w(f'  source = "../../modules/cloudfront_distribution"')
    w('')
    w(f'  hostname = "{hostname}"')
    w(f'  aliases  = ["{hostname}"]')
    w(f'  price_class             = "{ds.get("price_class", "PriceClass_All")}"')
    w(f'  http_version            = "{ds.get("http_version", "http2and3")}"')
    w(f'  is_ipv6_enabled         = {hcl_bool(ds.get("is_ipv6_enabled", True))}')
    w(f'  minimum_protocol_version = "{ds.get("minimum_protocol_version", "TLSv1.2_2021")}"')
    w(f'  wait_for_deployment     = false')
    w(f'  acm_certificate_arn     = {cert_ref}')
    w('')

    # Origins
    w('  origins = [')
    for o in origins:
        w('    {')
        w(f'      origin_id   = "{o["origin_id"]}"')
        w(f'      domain_name = "{o["domain"]}"')
        if o["s3_origin"]:
            w(f'      s3_origin                = true')
            w(f'      origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id')
        else:
            proto = "https-only"
            if o["protocol"] == "http":
                proto = "http-only"
            w(f'      protocol_policy = "{proto}"')
            w(f'      https_port     = {o["port"]}')
            # NOTE: the origin Host header is NOT set here. `Host` is on
            # CloudFront's custom-origin-header denylist (CreateDistribution
            # rejects it), and a Host override is applied in the viewer-request
            # CFF via cf.updateRequestOrigin(hostHeader=…) instead.
        w('    },')
    w('  ]')
    w('')

    # Default cache behavior
    default_origin_id = domain_to_origin_id.get(default_beh["origin"]["domain"], origins[0]["origin_id"])
    w(f'  default_target_origin_id       = "{default_origin_id}"')
    w(f'  default_viewer_protocol_policy = "{ds.get("viewer_protocol_policy", "redirect-to-https")}"')
    w(f'  default_compress               = true')

    cp_id = default_beh.get("cache_policy_id")
    if cp_id:
        w(f'  default_cache_policy_id = data.aws_cloudfront_cache_policy.{hcl_id(cp_id)}.id')

    # ORP: custom ORP takes precedence over shared (see _orp_reference)
    default_orp = _orp_reference(default_beh, orp_headers, san)
    if default_orp:
        w(f'  default_origin_request_policy_id = {default_orp}')

    rhp_id = default_beh.get("response_headers_policy_id")
    if rhp_id:
        w(f'  default_response_headers_policy_id = data.aws_cloudfront_response_headers_policy.{hcl_id(rhp_id)}.id')
    w('')

    # Default function associations (use locals defined in functions.tf for dedup
    # compatibility). Attach a viewer CFF only if the default behavior actually
    # needs it — a domain whose only ops are path-specific (on ordered behaviors)
    # leaves the default behavior with a no-op passthrough CFF, which we now omit.
    func_assocs = []
    if _behavior_needs_cff(ir, default_beh, "viewer_request_ops"):
        func_assocs.append(f'    {{ event_type = "viewer-request", function_arn = local.viewer_request_arn }}')
    if _behavior_needs_cff(ir, default_beh, "viewer_response_ops"):
        func_assocs.append(f'    {{ event_type = "viewer-response", function_arn = local.viewer_response_arn }}')
    if func_assocs:
        w('  default_function_associations = [')
        for fa in func_assocs:
            w(f'{fa},')
        w('  ]')
        w('')

    # Default Lambda@Edge associations
    le_assocs = []
    if has_le_origin_resp:
        le_assocs.append(f'    {{ event_type = "origin-response", lambda_arn = aws_lambda_function.{san}_origin_response.qualified_arn, include_body = false }}')
    # No viewer-event Lambda@Edge: viewer-request/response are CFF-only (a CFF
    # over 10 KB is reported SIZE_EXCEEDED for human intervention, never auto-
    # escalated to L@E). Only origin-response L@E (above) is used.
    if le_assocs:
        w('  default_lambda_function_associations = [')
        for la in le_assocs:
            w(f'{la},')
        w('  ]')
        w('')

    # Ordered cache behaviors
    if ordered_behs:
        w('  ordered_cache_behaviors = [')
        for b in ordered_behs:
            b_origin_id = domain_to_origin_id.get(b["origin"]["domain"], default_origin_id)
            w('    {')
            w(f'      path_pattern           = "{b["path_pattern"]}"')
            w(f'      target_origin_id       = "{b_origin_id}"')
            w(f'      viewer_protocol_policy = "redirect-to-https"')
            w(f'      compress               = true')
            b_cp = b.get("cache_policy_id")
            if b_cp:
                w(f'      cache_policy_id = data.aws_cloudfront_cache_policy.{hcl_id(b_cp)}.id')
            # ORP: the custom geo ORP forwards the CloudFront-Viewer-* headers
            # the shared CFF reads. Since the CFF runs on EVERY behavior (they
            # don't inherit associations), every behavior must forward those
            # headers too — else a geo rule landing on this path behavior reads
            # an undefined header. Same decision as the default behavior, via the
            # shared _orp_reference helper (so the two can't diverge).
            b_orp_ref = _orp_reference(b, orp_headers, san)
            if b_orp_ref:
                w(f'      origin_request_policy_id = {b_orp_ref}')
            b_rhp = b.get("response_headers_policy_id")
            if b_rhp:
                w(f'      response_headers_policy_id = data.aws_cloudfront_response_headers_policy.{hcl_id(b_rhp)}.id')
            # Attach the domain's shared CFF only to behaviors that need it —
            # CloudFront requires explicit function_associations per behavior (no
            # inheritance). This ordered behavior needs it iff it has its own ops
            # OR the default behavior has a zone-wide (scope='all') op that must
            # run everywhere. A behavior created only for a TTL/cache-key setting,
            # with no ops and no zone-wide default op, gets no CFF.
            b_func = []
            if _behavior_needs_cff(ir, b, "viewer_request_ops"):
                b_func.append(f'{{ event_type = "viewer-request", function_arn = local.viewer_request_arn }}')
            if _behavior_needs_cff(ir, b, "viewer_response_ops"):
                b_func.append(f'{{ event_type = "viewer-response", function_arn = local.viewer_response_arn }}')
            if b_func:
                w('      function_associations = [')
                for bf in b_func:
                    w(f'        {bf},')
                w('      ]')
            w('    },')
        w('  ]')
        w('')

    # Geo restriction
    geo_type = ds.get("geo_restriction_type", "none")
    geo_locs = ds.get("geo_restriction_locations", [])
    w(f'  geo_restriction_type      = "{geo_type}"')
    w(f'  geo_restriction_locations = {hcl_list_strings(geo_locs)}')

    # WAF
    waf_arn = ds.get("waf_acl_arn")
    if waf_arn:
        w(f'  web_acl_id = "{waf_arn}"')

    # Custom error responses
    if custom_errors:
        w('')
        w('  custom_error_responses = [')
        for ce in custom_errors:
            w('    {')
            w(f'      error_code            = {ce["error_code"]}')
            if ce.get("response_code"):
                w(f'      response_code         = {ce["response_code"]}')
                w(f'      response_page_path    = ""')
            else:
                w(f'      response_code         = {ce["error_code"]}')
                w(f'      response_page_path    = ""')
            w(f'      error_caching_min_ttl = 10')
            w('    },')
        w('  ]')

    w('')
    w(f'  tags = {{ Domain = "{hostname}" }}')
    w('}')

    return "\n".join(lines) + "\n"


def _collect_policy_ids(behaviors):
    ids = set()
    for b in behaviors:
        for key in ("cache_policy_id", "origin_request_policy_id", "response_headers_policy_id"):
            pid = b.get(key)
            if pid:
                ids.add(pid)
    return ids


# ── functions.tf generation ──────────────────────────────────────────────────

def generate_functions_tf(ir):
    san = ir["metadata"]["sanitized_name"]
    hostname = ir["metadata"]["hostname"]
    has_vresp = has_viewer_response_ops(ir)
    has_kvs = any(ir["metadata"].get("kvs_requirements", {}).values())
    le = ir["metadata"].get("lambda_edge", {})
    has_le_origin_resp = le.get("origin_response") is not None

    lines = []
    w = lines.append

    # viewer_request function (always)
    w(f'resource "aws_cloudfront_function" "{san}_viewer_request" {{')
    w(f'  name    = "cfcdn-{san}-viewer-request"')
    w(f'  runtime = "cloudfront-js-2.0"')
    w(f'  publish = true')
    w(f'  code    = file("${{path.module}}/functions/{san}_viewer_request.js")')
    if has_kvs:
        w(f'  key_value_store_associations = [aws_cloudfront_key_value_store.{san}_kvs.arn]')
    w('}')

    if has_vresp:
        w('')
        w(f'resource "aws_cloudfront_function" "{san}_viewer_response" {{')
        w(f'  name    = "cfcdn-{san}-viewer-response"')
        w(f'  runtime = "cloudfront-js-2.0"')
        w(f'  publish = true')
        w(f'  code    = file("${{path.module}}/functions/{san}_viewer_response.js")')
        w('}')

    # Lambda@Edge origin-response (deterministic — from IR)
    if has_le_origin_resp:
        w('')
        w(f'# --- Lambda@Edge: origin-response (default cache TTL) ---')
        w('')
        w(f'resource "aws_iam_role" "{san}_lambda_edge" {{')
        w(f'  name = "cfcdn-{san}-lambda-edge"')
        w(f'  assume_role_policy = jsonencode({{')
        w(f'    Version = "2012-10-17"')
        w(f'    Statement = [{{')
        w(f'      Action = "sts:AssumeRole"')
        w(f'      Effect = "Allow"')
        w(f'      Principal = {{')
        w(f'        Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]')
        w(f'      }}')
        w(f'    }}]')
        w(f'  }})')
        w(f'}}')
        w('')
        w(f'resource "aws_iam_role_policy_attachment" "{san}_lambda_edge_basic" {{')
        w(f'  role       = aws_iam_role.{san}_lambda_edge.name')
        w(f'  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"')
        w(f'}}')
        w('')
        w(f'data "archive_file" "{san}_origin_response_zip" {{')
        w(f'  type        = "zip"')
        w(f'  source_file = "${{path.module}}/lambda/default_cache_origin_response.js"')
        w(f'  output_path = "${{path.module}}/lambda/default_cache_origin_response.zip"')
        w(f'}}')
        w('')
        w(f'resource "aws_lambda_function" "{san}_origin_response" {{')
        w(f'  provider         = aws.us_east_1')
        w(f'  filename         = data.archive_file.{san}_origin_response_zip.output_path')
        w(f'  source_code_hash = data.archive_file.{san}_origin_response_zip.output_base64sha256')
        w(f'  function_name    = "cfcdn-{san}-origin-response"')
        w(f'  role             = aws_iam_role.{san}_lambda_edge.arn')
        w(f'  handler          = "default_cache_origin_response.handler"')
        w(f'  runtime          = "nodejs20.x"')
        w(f'  publish          = true')
        w(f'}}')

    return "\n".join(lines) + "\n"


# ── kvs.tf generation ────────────────────────────────────────────────────────

def generate_kvs_tf(ir):
    san = ir["metadata"]["sanitized_name"]
    hostname = ir["metadata"]["hostname"]

    lines = []
    w = lines.append

    w(f'resource "aws_cloudfront_key_value_store" "{san}_kvs" {{')
    w(f'  name    = "cfcdn-{san}-kvs"')
    w(f'  comment = "KVS for {hostname}"')
    w('}')
    w('')
    w(f'output "{san}_kvs_arn" {{')
    w(f'  description = "KVS ARN for {hostname}"')
    w(f'  value       = aws_cloudfront_key_value_store.{san}_kvs.arn')
    w('}')

    return "\n".join(lines) + "\n"


# ── kvs-data.json generation ─────────────────────────────────────────────────

def generate_seed_kvs_script(ir):
    """Generate seed-kvs.py script for populating KVS data after terraform apply."""
    san = ir["metadata"]["sanitized_name"]
    return f'''#!/usr/bin/env python3
"""Seed KVS data for {ir["metadata"]["hostname"]}.

Run after 'terraform apply' to populate the KeyValueStore.
Requires: boto3 (pip install boto3), AWS credentials configured.

Usage:
    python3 seed-kvs.py
"""
import json, subprocess, sys, time

def get_kvs_arn():
    result = subprocess.run(
        ["terraform", "output", "-raw", "{san}_kvs_arn"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("ERROR: terraform output failed. Run 'terraform apply' first.", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()

def main():
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        print("ERROR: boto3 required. Install with: pip install boto3", file=sys.stderr)
        sys.exit(1)

    kvs_arn = get_kvs_arn()
    with open("kvs-data.json") as f:
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

    print(f"Done: {{total}} keys seeded into KVS")

if __name__ == "__main__":
    main()
'''


def generate_kvs_data(ir):
    kvs_data = ir["metadata"].get("kvs_data", [])
    # Add continent/EU mappings if needed
    kvs_req = ir["metadata"].get("kvs_requirements", {})
    if kvs_req.get("needs_continent"):
        kvs_data.extend(_continent_kvs_entries())
    if kvs_req.get("needs_eu"):
        kvs_data.extend(_eu_kvs_entries())
    return json.dumps({"data": kvs_data}, indent=2, ensure_ascii=False) + "\n"


def _continent_kvs_entries():
    """Country → continent mapping for KVS."""
    # ISO 3166-1 alpha-2 → continent code
    mapping = {
        "AF": "AS", "AX": "EU", "AL": "EU", "DZ": "AF", "AS": "OC", "AD": "EU",
        "AO": "AF", "AI": "NA", "AQ": "AN", "AG": "NA", "AR": "SA", "AM": "AS",
        "AW": "NA", "AU": "OC", "AT": "EU", "AZ": "AS", "BS": "NA", "BH": "AS",
        "BD": "AS", "BB": "NA", "BY": "EU", "BE": "EU", "BZ": "NA", "BJ": "AF",
        "BM": "NA", "BT": "AS", "BO": "SA", "BQ": "NA", "BA": "EU", "BW": "AF",
        "BR": "SA", "IO": "AS", "BN": "AS", "BG": "EU", "BF": "AF", "BI": "AF",
        "CV": "AF", "KH": "AS", "CM": "AF", "CA": "NA", "KY": "NA", "CF": "AF",
        "TD": "AF", "CL": "SA", "CN": "AS", "CX": "AS", "CC": "AS", "CO": "SA",
        "KM": "AF", "CG": "AF", "CD": "AF", "CK": "OC", "CR": "NA", "CI": "AF",
        "HR": "EU", "CU": "NA", "CW": "NA", "CY": "AS", "CZ": "EU", "DK": "EU",
        "DJ": "AF", "DM": "NA", "DO": "NA", "EC": "SA", "EG": "AF", "SV": "NA",
        "GQ": "AF", "ER": "AF", "EE": "EU", "SZ": "AF", "ET": "AF", "FK": "SA",
        "FO": "EU", "FJ": "OC", "FI": "EU", "FR": "EU", "GF": "SA", "PF": "OC",
        "GA": "AF", "GM": "AF", "GE": "AS", "DE": "EU", "GH": "AF", "GI": "EU",
        "GR": "EU", "GL": "NA", "GD": "NA", "GP": "NA", "GU": "OC", "GT": "NA",
        "GG": "EU", "GN": "AF", "GW": "AF", "GY": "SA", "HT": "NA", "VA": "EU",
        "HN": "NA", "HK": "AS", "HU": "EU", "IS": "EU", "IN": "AS", "ID": "AS",
        "IR": "AS", "IQ": "AS", "IE": "EU", "IM": "EU", "IL": "AS", "IT": "EU",
        "JM": "NA", "JP": "AS", "JE": "EU", "JO": "AS", "KZ": "AS", "KE": "AF",
        "KI": "OC", "KP": "AS", "KR": "AS", "KW": "AS", "KG": "AS", "LA": "AS",
        "LV": "EU", "LB": "AS", "LS": "AF", "LR": "AF", "LY": "AF", "LI": "EU",
        "LT": "EU", "LU": "EU", "MO": "AS", "MG": "AF", "MW": "AF", "MY": "AS",
        "MV": "AS", "ML": "AF", "MT": "EU", "MH": "OC", "MQ": "NA", "MR": "AF",
        "MU": "AF", "YT": "AF", "MX": "NA", "FM": "OC", "MD": "EU", "MC": "EU",
        "MN": "AS", "ME": "EU", "MS": "NA", "MA": "AF", "MZ": "AF", "MM": "AS",
        "NA": "AF", "NR": "OC", "NP": "AS", "NL": "EU", "NC": "OC", "NZ": "OC",
        "NI": "NA", "NE": "AF", "NG": "AF", "NU": "OC", "NF": "OC", "MK": "EU",
        "MP": "OC", "NO": "EU", "OM": "AS", "PK": "AS", "PW": "OC", "PS": "AS",
        "PA": "NA", "PG": "OC", "PY": "SA", "PE": "SA", "PH": "AS", "PN": "OC",
        "PL": "EU", "PT": "EU", "PR": "NA", "QA": "AS", "RE": "AF", "RO": "EU",
        "RU": "EU", "RW": "AF", "BL": "NA", "SH": "AF", "KN": "NA", "LC": "NA",
        "MF": "NA", "PM": "NA", "VC": "NA", "WS": "OC", "SM": "EU", "ST": "AF",
        "SA": "AS", "SN": "AF", "RS": "EU", "SC": "AF", "SL": "AF", "SG": "AS",
        "SX": "NA", "SK": "EU", "SI": "EU", "SB": "OC", "SO": "AF", "ZA": "AF",
        "SS": "AF", "ES": "EU", "LK": "AS", "SD": "AF", "SR": "SA", "SJ": "EU",
        "SE": "EU", "CH": "EU", "SY": "AS", "TW": "AS", "TJ": "AS", "TZ": "AF",
        "TH": "AS", "TL": "AS", "TG": "AF", "TK": "OC", "TO": "OC", "TT": "NA",
        "TN": "AF", "TR": "AS", "TM": "AS", "TC": "NA", "TV": "OC", "UG": "AF",
        "UA": "EU", "AE": "AS", "GB": "EU", "US": "NA", "UM": "OC", "UY": "SA",
        "UZ": "AS", "VU": "OC", "VE": "SA", "VN": "AS", "VG": "NA", "VI": "NA",
        "WF": "OC", "EH": "AF", "YE": "AS", "ZM": "AF", "ZW": "AF",
    }
    return [{"key": f"continent:{cc}", "value": cont} for cc, cont in sorted(mapping.items())]


def _eu_kvs_entries():
    """EU member country codes for KVS."""
    eu_countries = [
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "PL", "PT", "RO", "SK", "SI", "ES", "SE",
    ]
    return [{"key": f"eu:{cc}", "value": "1"} for cc in eu_countries]


# ── outputs.tf generation ────────────────────────────────────────────────────

def generate_outputs_tf(ir):
    san = ir["metadata"]["sanitized_name"]
    lines = [
        f'output "distribution_id" {{',
        f'  value = module.cdn_{san}.distribution_id',
        f'}}',
        f'',
        f'output "distribution_domain_name" {{',
        f'  value = module.cdn_{san}.domain_name',
        f'}}',
    ]
    return "\n".join(lines) + "\n"


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-generate-tf-scaffold.py <output_dir>", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
    final_dir = os.path.join(output_dir, "ir", "final")
    shared_dir = os.path.join(output_dir, "shared")
    tf_domains_dir = os.path.join(output_dir, "terraform", "domains")

    manifest = load_manifest(shared_dir)

    json_files = sorted(f for f in os.listdir(final_dir) if f.endswith(".json"))
    if not json_files:
        print("ERROR: no finalized IR files found", file=sys.stderr)
        sys.exit(1)

    for filename in json_files:
        hostname = filename.replace(".json", "")
        ir = load_ir(final_dir, hostname)
        san = ir["metadata"]["sanitized_name"]
        domain_dir = os.path.join(tf_domains_dir, san)
        func_dir = os.path.join(domain_dir, "functions")
        os.makedirs(func_dir, exist_ok=True)

        origins, domain_to_origin_id = collect_origins(ir)

        # main.tf
        main_tf = generate_main_tf(ir, manifest, domain_to_origin_id, origins)
        _write(os.path.join(domain_dir, "main.tf"), main_tf)

        # functions.tf
        functions_tf = generate_functions_tf(ir)
        _write(os.path.join(domain_dir, "functions.tf"), functions_tf)

        # outputs.tf
        outputs_tf = generate_outputs_tf(ir)
        _write(os.path.join(domain_dir, "outputs.tf"), outputs_tf)

        # kvs.tf + kvs-data.json + seed-kvs.py (conditional)
        kvs_req = ir["metadata"].get("kvs_requirements", {})
        if any(kvs_req.values()):
            kvs_tf = generate_kvs_tf(ir)
            _write(os.path.join(domain_dir, "kvs.tf"), kvs_tf)
            kvs_data = generate_kvs_data(ir)
            _write(os.path.join(domain_dir, "kvs-data.json"), kvs_data)
            seed_script = generate_seed_kvs_script(ir)
            _write(os.path.join(domain_dir, "seed-kvs.py"), seed_script)

        file_count = 3 + (3 if any(kvs_req.values()) else 0)
        print(f"OK: {hostname} → {file_count} scaffold files in terraform/domains/{san}/")

    print(f"\n{'='*60}")
    print(f"Generated scaffold for {len(json_files)} domains")


def _write(path, content):
    with open(path, "w") as f:
        f.write(content)


if __name__ == "__main__":
    main()
