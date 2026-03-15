# Cache Behavior Assembly, IR Output, and Summary

This document covers Step 4 (Build Cache Behaviors), Step 5 (Write IR Accumulator
File), and Step 6 (Print Summary). Read this after all Step 3 rule processing is
complete.

---

## Step 4 — Build Cache Behaviors

### 4a. Collect all distinct path_patterns

From all rules processed in Step 3, gather every unique `path_pattern` value.
Each becomes one Cache Behavior document.

### 4b. Assign precedence

Use these initial values; re-sort all behaviors after collection:

| Pattern type | Precedence formula |
|---|---|
| Exact path (no wildcards) | `10` |
| `/prefix/path/*` (depth ≥ 3) | `20 + len(prefix)` |
| `/prefix/*` (depth 2) | `20 + len(prefix)` |
| `*.ext` (extension match) | `100–169` (from 3g) |
| `/*` | `990` |
| `*` (default) | `999` |

Lower precedence number = higher CloudFront priority (evaluated first).

### 4c. Warn on high Cache Behavior count

CloudFront's default quota is **75** cache behaviors per distribution (including the
default). This is a soft limit — users can request an increase via AWS Support.

If the collected set exceeds 75 non-default cache behaviors, do **not** merge them.
Instead, add a warning entry to `non_convertible`:
```yaml
- cf_source_rule: "system"
  rule_type: "system_limit"
  reason: "Cache behavior count (N) exceeds CloudFront default quota of 75; request a quota increase via AWS Support before deploying"
  shadowed: false
```

### 4d. Populate distribution_settings on all behaviors

Copy `distribution_settings` values derived from Configuration Rules (3c) to every
Cache Behavior document. Each document is self-contained for the Terraform generator.

### 4e. Set default origin

For every Cache Behavior, set:
```yaml
origin:
  id: "origin_<sanitized_hostname>"
  domain: "<origin_content from domain_scope.json>"
  protocol: "https"
  port: 443
  custom_origin_headers: []
```
Unless overridden by an Origin Rule for that specific path.

---

## Step 5 — Write IR Accumulator File

### Output path

```
cloudflare-to-aws-cdn/ir/accumulator/<sanitized_hostname>.yaml
```

The directory should already exist (created by cdn-init.sh). If not, create it.

### File format

The output is a **multi-document YAML file** separated by `---`.

**Document 1 (metadata):** Always present, always first.
**Documents 2…N (cache_behavior):** One per Cache Behavior, sorted by ascending precedence.
**Last cache_behavior document:** Default Cache Behavior (`path_pattern: "*"`, `precedence: 999`).

### Metadata document schema

```yaml
document_type: metadata
hostname: "cdn.c.example.com"
sanitized_name: "cdn_c_example_com"
apex_domain: "c.example.com"
origin_type: "server"              # "s3" | "object_storage" | "server" — from domain_scope.json
cert_arn_mode: "explicit"        # or "data_source"
cert_arn: "arn:aws:acm:..."      # null if cert_arn_mode == "data_source"
kvs_requirements:
  needs_redirects: false
  needs_continent: false
  needs_eu: false
kvs_data: []                     # populated by Step 3e if bulk redirects exist
custom_error_responses: []       # populated by Step 3i; distribution-level setting
lambda_edge:                     # populated by Step 3i if advanced error handling needed
  origin_request: null
  origin_response: null
```

### Required schema per cache_behavior document

```yaml
document_type: cache_behavior
hostname: "cdn.c.example.com"
path_pattern: "/api/*"
precedence: 20

distribution_settings:
  viewer_protocol_policy: "redirect-to-https"
  minimum_protocol_version: "TLSv1.2_2021"
  http_version: "http2and3"
  is_ipv6_enabled: true
  cert_arn_mode: "explicit"
  price_class: "PriceClass_All"
  waf_acl_arn: null
  geo_restriction_type: "none"
  geo_restriction_locations: []

origin:
  id: "origin_cdn_c_example_com"
  domain: "httpecho.a.letsmakeit.link"
  protocol: "https"
  port: 443
  custom_origin_headers: []
  s3_origin: false

cache_policy:
  bypass: false
  ttl:
    min: 0
    default: 300
    max: 3600
  cache_key:
    headers: []
    cookies: []
    query_strings: "none"
  enable_gzip: true
  enable_brotli: true
  ttl_sources: []
  resolved_ttl: 300

origin_request_policy:
  forward:
    headers: "none"
    headers_list: []
    cookies: "none"
    cookies_list: []
    query_strings: "none"
    query_strings_list: []

response_headers_policy:
  security_headers: {}
  custom_headers: []
  cors: null

viewer_request_ops: []
viewer_response_ops: []

lambda_edge:
  origin_request: null
  origin_response: null
  viewer_request: null

non_convertible: []
```

### Defaults when source data is absent or ambiguous

| Field | Default | Rationale |
|-------|---------|-----------|
| `viewer_protocol_policy` | `"redirect-to-https"` | Security best practice |
| `minimum_protocol_version` | `"TLSv1.2_2021"` | AWS recommended |
| `http_version` | `"http2and3"` | Enables QUIC/HTTP3 |
| `is_ipv6_enabled` | `true` | No cost; broad compatibility |
| `cache_policy.ttl.min` | `0` | Allows origin to override |
| `cache_policy.ttl.default` | `300` | 5-minute safe default |
| `cache_policy.ttl.max` | `3600` | 1-hour cap |
| `cache_policy.enable_gzip` | `true` | Default: enable both encodings |
| `cache_policy.enable_brotli` | `true` | Default: enable both encodings |
| `origin.protocol` | `"https"` | Encrypted in transit |
| `origin.port` | `443` | Matches https default |

If a value is missing **and** there is no safe default, do **not** guess.
Leave the field as `null` and add a `non_convertible` entry with reason:
`"Unable to determine <field> from source data; manual review required"`.

---

## Step 6 — Print Summary

After writing the file, output a plain-text summary to stdout:

```
=== cf-cdn-per-domain-processor summary ===
Hostname:            cdn.c.example.com
Output file:         cloudflare-to-aws-cdn/ir/accumulator/cdn_c_example_com.yaml
Cache behaviors:     8  (7 path-specific + 1 default)
Non-convertible:     3 rules flagged
KVS requirements:    needs_redirects=true, needs_continent=false, needs_eu=false
KVS entries:         42

Warnings:
  - [WARN] Cache behavior count (82) exceeds CloudFront default quota of 75
  - [WARN] Rule cf-rule-abc123: regex expression not representable as CloudFront wildcard

Non-convertible rules:
  - cf-rule-xyz789 [configuration_rule]: Browser Integrity Check has no CloudFront equivalent
  - cf-rule-def456 [cache_rule]: serve_stale has no direct CloudFront cache policy equivalent
  - cf-rule-ghi012 [request_header]: Device detection headers should use CloudFront native device detection
```
