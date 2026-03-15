---
name: cf-cdn-per-domain-processor
description: Core CDN processing skill. For a single proxied hostname, reads all relevant Cloudflare CDN configuration files, processes all 11 rule types in Cloudflare execution order, and generates a complete CloudFront-native IR accumulator YAML file (ir/accumulator/<hostname>.yaml). This skill is invoked once per domain — for N domains, N parallel invocations are used. The IR format contains fully resolved CloudFront resource specs that downstream Terraform generators can consume directly without re-reading Cloudflare files.
---

# cf-cdn-per-domain-processor

Core per-domain processing skill for the Cloudflare → CloudFront migration pipeline.
Consumes raw Cloudflare backup files for a single hostname and emits a fully resolved
IR accumulator YAML that downstream Terraform generators can consume without re-parsing
any Cloudflare source.

---

## Path Resolution

| Category        | Base path                                               |
|-----------------|--------------------------------------------------------|
| Reference files | Relative to **this skill directory**                    |
| User data       | `backup_path` value provided by the orchestrator prompt |
| Output          | `cloudflare-to-aws-cdn/ir/accumulator/`                 |

---

## Output File Naming

Sanitize the hostname for the filename:
- Replace every `.` and `-` with `_`
- Keep the original hostname as the value of the `hostname:` field inside the YAML

**Example:** `cdn.c.example.com` → `cdn_c_example_com.yaml`

The orchestrator passes the raw hostname (e.g. `cdn.c.example.com`) as the `{domain}`
parameter. This skill must derive the sanitized filename from it.

---

## Reference Documents

Read references using the `read` tool. Resolve paths relative to **this skill's
directory** (i.e., `cf-cdn-per-domain-processor/`).

### Pre-read before Step 1 (required — read all 6 before processing any rules)

| # | Relative path | Purpose |
|---|---------------|---------|
| 1 | `references/cloudflare-rule-execution-order.md` | Canonical execution order for all 11 rule types |
| 3 | `references/cloudfront-cache-behavior-path-pattern.md` | CloudFront wildcard rules (`*`, `?`), regex limitations |
| 4 | `references/convertible-rules.md` | Which Cloudflare rule actions can be expressed in CF Functions |
| 5 | `references/field-mapping.md` | Cloudflare field names → CloudFront / CF Functions equivalents |
| 6 | `references/cloudfront-function-limits.md` | JS 10 KB size cap, forbidden syntax, runtime constraints |
| 9 | `references/non-convertible-rules.md` | Rules that cannot be converted and why — mark as non_convertible |

### On-demand references (read only when triggered — do NOT pre-read)

| # | Relative path | When to read |
|---|---------------|--------------|
| 2 | `references/cloudflare-default-cache-behavior.md` | ⚠️ Step 3g, only when `apply_default_cache_behavior: true` |
| 7 | `references/cloudfront-origin-request-policy.md` | ⚠️ Step 3d (Origin Rules) or Step 3f (Request Header Transform) |
| 8 | `references/bulk-redirects-handling.md` | ⚠️ Step 3e, only when Bulk-Redirect-Rules.txt exists |
| 10 | `references/cloudfront-viewer-headers.md` | ⚠️ Step 3f (Request Header Transform) |
| 11 | `references/kvs-usage-and-limits.md` | ⚠️ Step 3e (Bulk Redirects) or when continent/EU matching needed |
| 12 | `references/continent-countries.md` | ⚠️ Only when `ip.src.continent` or `ip.src.is_in_european_union` appears |
| — | `references/bulk-redirect-processing.md` | ⚠️ Step 3e, only when Bulk-Redirect-Rules.txt exists |
| — | `references/behavior-assembly.md` | ⚠️ After ALL Step 3 rule processing is complete (Step 4-6) |

---

## Step 0 — Pre-read Reference Documents

Use the `read` tool on the 6 pre-read references listed above (#1, #3, #4, #5, #6, #9).
Store key facts mentally (execution order, field mappings, path pattern rules, function
limits, convertible/non-convertible rules).

Do **not** read on-demand references now. Each has a ⚠️ trigger point in the workflow
where you will be reminded to read it.

Only proceed to Step 1 after all six pre-read files have been read.

---

## Step 1 — Parse Inputs

### 1a. Read domain_scope.json

Path: `cloudflare-to-aws-cdn/domain_scope.json` (relative to current working directory,
or as provided by orchestrator).

Extract:

| Field | Type | Usage |
|-------|------|-------|
| `hostname` | string | The FQDN being processed (e.g. `cdn.c.example.com`) |
| `apex_domain` | string | Parent zone (e.g. `example.com`) |
| `apply_default_cache_behavior` | boolean | Whether to emit cache behaviors for all ~70 default extensions |
| `origin_content` | string | DNS CNAME target — used as the default CloudFront origin domain |
| `origin_type` | string | `"s3"` / `"object_storage"` / `"server"` — determines origin config strategy |
| `cert_arn_mode` | string | `"explicit"` or `"data_source"` — passed through to metadata doc |
| `cert_arn` | string\|null | ACM certificate ARN if `cert_arn_mode == "explicit"`, else null |

### 1b. Determine backup_path

Use the value provided in the orchestrator prompt.
Expected layout:
```
<backup_path>/
  Redirect-Rules.txt
  URL-Rewrite-Rules.txt
  Configuration-Rules.txt
  Origin-Rules.txt
  Bulk-Redirect-Rules.txt
  Request-Header-Transform.txt
  Cache-Rules.txt
  Custom-Error-Rules.txt
  Response-Header-Transform.txt
  Compression-Rules.txt
  Cloud-Connector-Rules.txt
  Managed-Transforms.txt
  account/
    Bulk-Redirect-Rules.txt      # account-level bulk redirect activation
    List-Items-redirect-*.txt    # actual redirect list items
```

### 1c. Initialize IR accumulator

Create an empty in-memory accumulator keyed by `path_pattern`. Pre-populate with a
Default Cache Behavior entry:

```
path_pattern: "*"
precedence: 999
```

All subsequent rule processing appends to or updates entries in this accumulator.

---

## Step 2 — Discover Cloudflare Backup Files

**File format:** All Cloudflare backup files are raw API responses in JSON format.

- **Ruleset files** (Redirect-Rules.txt, URL-Rewrite-Rules.txt, Configuration-Rules.txt,
  Origin-Rules.txt, Cache-Rules.txt, Custom-Error-Rules.txt, Request-Header-Transform.txt,
  Response-Header-Transform.txt, Compression-Rules.txt): `{"result": {"rules": [...]}, "success": true}`.
  The rules array is at `.result.rules`. Each rule has `action`, `action_parameters`,
  `expression`, `enabled`, `id`, and `description` fields.
- **Cloud-Connector-Rules.txt**: `{"result": [...], "success": true}`. Rules are directly
  in `.result` (an array, not a nested object).
- **Bulk-Redirect-Rules.txt**: Same ruleset format (`.result.rules`).
- **List-Items-redirect-*.txt**: `{"result": [...]}` — array of redirect list items.
- **Managed-Transforms.txt**: `{"result": {...}}` — object with managed header settings.

Skip disabled rules (`"enabled": false`) in all rule files.
If a file's `success` field is `false`, treat it as "no rules of this type".

Attempt to `read` each file listed below. A missing file is **not an error** — treat it as
"no rules of this type" and continue.

```
Redirect-Rules.txt
URL-Rewrite-Rules.txt
Configuration-Rules.txt
Origin-Rules.txt
Bulk-Redirect-Rules.txt  (also check account/ subdirectory)
List-Items-redirect-*.txt  (account/ subdirectory; glob pattern — read all matching)
Request-Header-Transform.txt
Cache-Rules.txt
Custom-Error-Rules.txt
Response-Header-Transform.txt
Compression-Rules.txt
Cloud-Connector-Rules.txt
Managed-Transforms.txt
```

---

## Step 3 — Process Rules in Execution Order

**Hostname filtering — apply to EVERY rule file:**

- **Include** rules whose `expression` contains `http.host eq "<HOSTNAME>"`
- **Include** rules whose `expression` contains `http.host in { ... "<HOSTNAME>" ... }`
- **Include** rules with **no** `http.host` condition (global rules — apply to all domains)
- **Exclude** rules that contain an explicit `http.host` condition matching only OTHER hostnames

Process the 11 rule types in the order documented in
`cloudflare-rule-execution-order.md` (reference #1). The subsections below follow
that canonical order.

---

### 3a — Redirect Rules (`Redirect-Rules.txt`)

Action type: `redirect` with `action_parameters.response` containing `status_code` and `target_url`.

**HTTP → HTTPS redirects:**
- Detection: expression matches `not ssl` or `not http.request.uri.scheme eq "https"`
- **Do NOT** convert to a CF Function.
- Set `distribution_settings.viewer_protocol_policy = "redirect-to-https"` on the
  affected Cache Behavior (or default if no path condition).

**All other redirects:**
- Add to `viewer_request_ops` as `type: redirect`.
- Fields: `cf_source_rule`, `condition` (extracted from expression), `params.target`,
  `params.status_code`, `params.preserve_query_string`.
- Use `${captured_N}` notation for wildcard capture groups from the source path.
- If the rule has a path condition expressible as a CloudFront wildcard (`/foo/*`),
  also register that path as a Cache Behavior `path_pattern`.
- Use the rule's `priority` field (lower number = higher Cloudflare priority) as the
  initial `precedence` value. Re-sort after all rules are processed.
- If a redirect rule's condition is fully dominated by an earlier rule (same path,
  earlier priority), set `shadowed: true` on the entry and add a warning.

---

### 3b — URL Rewrite Rules (`URL-Rewrite-Rules.txt`)

Action type: `rewrite` with `action_parameters.uri` containing `path` or `query`.

- Add to `viewer_request_ops` as `type: rewrite`.
- Fields: `cf_source_rule`, `condition`, `params.new_uri`.
- If `action_parameters.uri.query` is present, note it in `non_convertible` with reason:
  `"Query string rewrite requires Lambda@Edge; CF Functions cannot modify query strings independently"`.
- Extract path conditions for Cache Behavior mapping (same logic as 3a).

---

### 3c — Configuration Rules (`Configuration-Rules.txt`)

Action type: `set_config` with various action_parameters.

These rules apply at **distribution level**, not per Cache Behavior. Write results to
`distribution_settings` on the **Default Cache Behavior** (`path_pattern: "*"`), and
propagate to all Cache Behaviors during Step 4.

**Convertible settings:**

| Cloudflare parameter | CloudFront field | Notes |
|----------------------|------------------|-------|
| `tls_client_auth.min_tls_version` | `minimum_protocol_version` | Map: "1.2" → `TLSv1.2_2021`, "1.3" → `TLSv1.2_2021` (CF has no TLS 1.3-only mode) |
| `http2` enabled | `http_version: "http2"` | |
| `http3` / `0rtt` enabled | `http_version: "http2and3"` | |

**Hardcoded best-practice defaults (do NOT derive from Cloudflare config):**

- `viewer_protocol_policy`: always `"redirect-to-https"`. Do NOT read Cloudflare's
  `ssl` mode setting — CloudFront best practice is always HTTPS redirect regardless
  of what Cloudflare was configured to do. The `ssl: flexible` (allow HTTP) and
  `ssl: strict` (HTTPS only) settings are Cloudflare-specific and should not influence
  the CloudFront configuration.

**Non-convertible settings (mark in `non_convertible`, do not convert):**

| Cloudflare parameter | Reason |
|----------------------|--------|
| `ssl` mode | Ignored — CloudFront always uses `redirect-to-https` (best practice) |
| `browser_check` | `"Browser Integrity Check has no CloudFront equivalent"` |
| `minify` | `"HTML/CSS/JS minification not supported natively in CloudFront"` |
| `rocket_loader` | `"Rocket Loader is a Cloudflare-specific JS optimization"` |
| `hotlink_protection` | `"Hotlink protection requires Lambda@Edge custom logic"` |

---

### 3d — Origin Rules (`Origin-Rules.txt`)

**⚠️ READ NOW:** `references/cloudfront-origin-request-policy.md` — ORP behavior values and Terraform syntax.

Action type: `route` with `action_parameters.origin` containing override fields.

**Two implementation paths — choose based on expression complexity:**

**Path A — Simple URI path → independent cache behavior (no CF Function needed):**

If the Origin Rule's expression is a **pure URI path condition** that can be expressed
as a CloudFront cache behavior path pattern (only `*` and `?` wildcards, no header/geo/
regex/other fields), create an independent cache behavior:

- Extract the path pattern from the expression (e.g., `http.request.uri.path wildcard "/api/*"` → `/api/*`)
- Create a new cache behavior with that `path_pattern`
- Set its `origin` to the target origin from `action_parameters.origin`:
  - The origin hostname comes from `action_parameters.origin.host` (the DNS name
    of the target server). Do NOT use `host_header` for the origin domain —
    `host_header` is the Host header value sent to the origin, which may differ.
  - `origin.id`: sanitize the origin hostname (replace every `.` and `-` with `_`)
    and prefix with `origin_`. Example: `api-backend.example.com` → `origin_api_backend_example_com`
  ```yaml
  origin:
    id: "origin_<sanitized_origin_hostname>"
    domain: "<action_parameters.origin.host>"
    protocol: "https"
    port: 443
    host_header: "<action_parameters.origin.host_header or null>"
    custom_origin_headers: []
    s3_origin: false
  ```
- Do NOT add anything to `viewer_request_ops` — the cache behavior handles routing.

**Path B — Complex condition → `origin_override` in viewer_request_ops (CF Function):**

If the expression contains header conditions, geo conditions, regex, multiple fields
combined with AND/OR, or a URI path that cannot be expressed as a CloudFront path
pattern, add to the **default behavior's** `viewer_request_ops`:

- Structure: `conditions` list (ordered, first-match-wins) + `default_origin_id`.
- Each condition entry:
  ```yaml
  match:
    field: "uri"         # or host, header, method
    op: "wildcard"       # eq, ne, wildcard, starts_with, ends_with, contains
    value: "/api/*"
  origin:
    domain: "api-backend.example.com"
    protocol: "https"
    port: 443
    host_header: null
    strip_path_prefix: null
    custom_headers: []
  ```
- `default_origin_id`: `"origin_<sanitized_hostname>"` using the same sanitization
  rule as the filename.

**Boundary case:** If an Origin Rule has a URI path condition AND other conditions
(e.g., `http.request.uri.path wildcard "/api/*" AND http.request.headers["X-Internal"] eq "1"`),
this cannot be expressed as a pure path pattern → use Path B. Add a `non_convertible`
note: `"Origin Rule condition combines URI path with non-path fields; converted to CF Function origin override instead of cache behavior"`.

**Common rules for both paths:**
- If `action_parameters.origin.port` is absent, default to 443 for https, 80 for http.
- **S3 origin handling:** When `origin_type == "s3"` (from domain_scope.json), Origin Rules
  that only override host header and/or switch protocol to HTTP for S3 website endpoint
  access are **redundant** after migration — CloudFront uses OAC with the S3 REST API
  endpoint directly. Skip these rules silently (do not add to `viewer_request_ops` or
  `non_convertible`). Only convert Origin Rules that perform **business-logic changes**
  such as URI path prefix insertion, conditional origin routing to non-S3 backends, or
  custom header injection.

---

### 3e — Bulk Redirects

**⚠️ READ NOW:** If `Bulk-Redirect-Rules.txt` exists in the backup directory, read
these references before proceeding:
- `references/bulk-redirect-processing.md` — complete processing logic for this step
- `references/bulk-redirects-handling.md` — KVS key format, validation checklist
- `references/kvs-usage-and-limits.md` — KVS size and key constraints

If `Bulk-Redirect-Rules.txt` does not exist, skip this step entirely.

Follow the workflow in `references/bulk-redirect-processing.md` for Phase 1 (discover
lists), Phase 2 (read list items), and Phase 3 (generate IR output).

---

### 3f — Request Header Transform (`Request-Header-Transform.txt`)

**⚠️ READ NOW:** Read these references if not already loaded:
- `references/cloudfront-origin-request-policy.md` — ORP behavior values (if not read in 3d)
- `references/cloudfront-viewer-headers.md` — CloudFront viewer headers and Cloudflare→CloudFront mapping

Action type: `rewrite` with `action_parameters.headers` list.

Each header operation has an `operation` field: `"set"`, `"add"`, or `"remove"`.

| Operation | Handling |
|-----------|----------|
| `"set"` with static value | Add `type: set_header` to `viewer_request_ops` |
| `"add"` with static value | Add `type: add_header` to `viewer_request_ops` |
| `"remove"` | Use `origin_request_policy.forward.headers: "allExcept"` and add the header name to `origin_request_policy.forward.headers_list` (which acts as an exclusion list when behavior is `allExcept`). This tells CloudFront to forward all viewer headers to origin **except** the listed ones. No CF Function needed. |
| `"set"` with dynamic value (e.g. `concat(...)`) | Add to `viewer_request_ops`; note in `non_convertible` if CF Functions cannot evaluate the expression |
| Device detection (e.g. `X-Is-Mobile` set from user-agent regex) | **Do NOT** convert. Note in `non_convertible`: `"Device detection headers should use CloudFront's native device detection via origin_request_policy"`. Set `kvs_requirements.needs_continent: true` if continent-based. |

**Managed-Transforms.txt handling (True-Client-IP):**
- If `add_true_client_ip_headers` is enabled in `Managed-Transforms.txt`
  (check `.result.managed_request_headers` for an entry with
  `"id": "add_true_client_ip_headers"` and `"enabled": true`):
  ```yaml
  - type: add_header
    cf_source_rule: "managed-transform:true_client_ip"
    condition: null
    params:
      name: "True-Client-IP"
      value: "${event.viewer.ip}"
  ```
  (The `${event.viewer.ip}` token is resolved by the CF Functions generator, not here.)

---

### 3g — Cache Rules (`Cache-Rules.txt`)

Action type: `set_cache_settings`.

**Path pattern extraction:**
- Parse `expression` for `http.request.uri.path` conditions.
- Wildcard patterns (`wildcard_strict`, `wildcard`) → use as `path_pattern` if they can
  be expressed with CloudFront's `*` and `?` only.
- Regex patterns or complex boolean combinations → map to Default `"*"` behavior and
  add `non_convertible` entry.

**Cache policy field mapping:**

| Cloudflare parameter | IR field | Notes |
|----------------------|----------|-------|
| `edge_ttl.value` | `cache_policy.ttl.default` | Value in seconds. Set `cache_policy.ttl.max` to `max(edge_ttl.value * 2, 86400)` to allow origin Cache-Control headers to extend beyond the default. |
| `edge_ttl.mode: "bypass_by_default"` | `cache_policy.bypass: false`, use `edge_ttl.value` | Cache only on explicit cache headers |
| `cache: false` | `cache_policy.bypass: true`, all TTL = 0 | Pass-through, no caching |
| `cache_key.custom_key.header.include` | `cache_policy.cache_key.headers` | List of header names |
| `cache_key.custom_key.cookie.include` | `cache_policy.cache_key.cookies` | List of cookie names |
| `cache_key.custom_key.query_string.include` | `cache_policy.cache_key.query_strings` | `"all"`, `"none"`, or list |
| `serve_stale` | `non_convertible` | Reason: `"Serve-stale (SWR/SIE) has no direct CloudFront cache policy equivalent"` |
| `origin_error_page_passthru` | `non_convertible` | Reason: `"Origin error page passthrough requires Lambda@Edge"` |

**TTL resolution (last-match-wins):**
- Store all matching rules for a path in `cache_policy.ttl_sources` (array of
  `{cf_source_rule, ttl}` objects).
- Set `cache_policy.resolved_ttl` = the TTL from the **last** matching rule
  (Cloudflare evaluates all rules and the last one wins).

**Default cache behavior — Lambda@Edge + selective cache behaviors:**
- If `apply_default_cache_behavior: true`:
  **⚠️ READ NOW:** `references/cloudflare-default-cache-behavior.md` — the ~70 cacheable file extensions.
  Read the extension list from that reference.

  **Step A — Count custom-TTL extensions from Cache Rules:**
  Collect all Cache Rules processed above that target a specific file extension
  pattern (e.g., `*.apk`, `*.iso`). Count how many unique extensions have custom TTLs.

  **Step B — Choose implementation path based on count:**

  **If 0 custom-TTL extensions:**
  - Set `lambda_edge.origin_response` in the metadata document:
    ```yaml
    lambda_edge:
      origin_response:
        type: "default_cache"
        custom_ttl_map: {}
    ```
  - Do NOT create any per-extension cache behaviors.

  **If ≤20 custom-TTL extensions:**
  - For each custom-TTL extension, create an independent cache behavior:
    - `path_pattern`: `"*.<ext>"`
    - `cache_policy.ttl.default`: the custom TTL value from the Cache Rule
    - `cache_policy.ttl.max`: `31536000` (1 year — respect origin Cache-Control)
    - `cache_policy.ttl.min`: `0`
    - `cache_policy.bypass: false`
  - Set `lambda_edge.origin_response` in the metadata document to handle the
    remaining ~50+ extensions:
    ```yaml
    lambda_edge:
      origin_response:
        type: "default_cache"
        custom_ttl_map: {}
    ```
  - `custom_ttl_map` is empty because custom TTLs are already handled by the
    independent cache behaviors above. The Lambda only needs the default 7200s
    TTL for extensions not covered by cache behaviors.

  **If >20 custom-TTL extensions:**
  - Do NOT create per-extension cache behaviors (too many, wastes quota).
  - Set `lambda_edge.origin_response` with the full custom TTL map:
    ```yaml
    lambda_edge:
      origin_response:
        type: "default_cache"
        custom_ttl_map:
          apk: 31536000
          iso: 604800
          # ... all custom TTLs
    ```
  - The Lambda uses the map to apply custom TTLs, falling back to 7200 for
    extensions not in the map.

---

### 3h — Cloud Connector Rules (`Cloud-Connector-Rules.txt`)

Cloud Connector rules route matching traffic to a cloud provider's object storage.
In Cloudflare's execution order, Cloud Connector runs after Cache Rules and before
Workers — it is the last convertible request-phase rule.

The backup file is a Cloudflare API response: `{"result": [...]}`. Each rule has:

```json
{
  "expression": "(http.request.uri.path wildcard r\"/images/*\")",
  "description": "images",
  "enabled": true,
  "parameters": {"host": "my-bucket.s3.amazonaws.com"},
  "provider": "aws_s3"
}
```

**Processing rules:**

- Skip disabled rules (`enabled: false`).
- **Only convert** rules whose `expression` is a URI path condition that can be
  expressed as a CloudFront cache behavior path pattern (e.g.,
  `http.request.uri.path wildcard "/images/*"` → path pattern `/images/*`).
- Rules with `expression` set to `true` (all incoming requests) or non-URI-path
  conditions (header, geo, etc.) → add to `non_convertible` with reason:
  `"Cloud Connector with non-path-pattern expression cannot be automatically converted to a CloudFront cache behavior; manual origin configuration required"`.
- For `provider: "aws_s3"` when `origin_type == "s3"` and the Cloud Connector
  points to the same S3 bucket as `origin_content`: the rule is redundant after
  migration (CloudFront uses OAC + S3 REST endpoint directly). Skip silently.

**For convertible rules** (URI path → path pattern):

- Check `parameters.host` to determine origin type:
  - S3 REST endpoint (`*.s3.amazonaws.com`, `*.s3.<region>.amazonaws.com`):
    generate a **separate cache behavior** with the path pattern, targeting a
    new S3 origin with `s3_origin: true`. OAC is required — S3 OAC needs static
    `origin_access_control_id` in Terraform, not runtime `cf.updateRequestOrigin()`.
  - S3 website endpoint (`*s3-website*`): generate a **separate cache behavior**
    targeting a custom origin (`protocol: "http"`, `port: 80`, `s3_origin: false`).
  - Other providers (`gcp_gcs`, `azure_storage`): generate a **separate cache
    behavior** targeting a custom origin (`protocol: "https"`, `port: 443`).

---

### 3i — Custom Error Rules (`Custom-Error-Rules.txt`)

Action type: `serve_error` (fixed response) or conditional error handling.

**Case 1 — Simple error page / status code remap** (action specifies a static page path or just a status code change):

Add to the **metadata document** under `custom_error_responses`:
```yaml
custom_error_responses:
  - error_code: 404              # HTTP status code from origin to intercept
    response_page_path: "/errors/404.html"  # path to static file in origin; omit if no custom page
    response_code: 404           # HTTP status code to return to viewer (can differ from error_code)
    error_caching_min_ttl: 10    # seconds to cache this error response
```

CloudFront `custom_error_response` supports exactly these 4 fields. It can:
- Serve a static error page from your origin
- Change the HTTP status code returned to the viewer (e.g., 403 → 200 for SPAs)
- Control error caching TTL

It **cannot** add response headers or return inline JSON bodies.

**Case 2 — Advanced error handling** (requires adding headers, returning JSON body, or dynamic logic):

CloudFront Functions **do NOT execute** when the origin returns HTTP 400+. Only Lambda@Edge `origin-response` is invoked for all origin responses including errors.

Set `lambda_edge.origin_response` in the metadata document:
```yaml
lambda_edge:
  origin_response:
    cf_source_rule: "<rule_id>"
    reason: "Advanced custom error handling (add headers / return JSON body) requires Lambda@Edge origin-response — CloudFront Functions do not execute on HTTP 400+ responses"
```

---

### 3j — Response Header Transform (`Response-Header-Transform.txt`)

Action type: `rewrite` with `action_parameters.headers`.

| Pattern | IR field |
|---------|----------|
| Static `set` with no condition | `response_headers_policy.custom_headers` |
| Security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) | `response_headers_policy.security_headers` |
| CORS headers (Access-Control-Allow-*) | `response_headers_policy.cors` |
| Conditional headers (expression present) | `viewer_response_ops` as `type: set_header` / `add_header` |
| Dynamic values (cf vars, concat) | `viewer_response_ops`; flag in `non_convertible` if CF Functions cannot evaluate |

**`response_headers_policy.security_headers` schema:**
```yaml
security_headers:
  strict_transport_security:
    enabled: true
    max_age: 31536000
    include_subdomains: true
    preload: false
  x_frame_options: "DENY"         # or "SAMEORIGIN"
  x_content_type_options: true
  referrer_policy: "strict-origin-when-cross-origin"
  content_security_policy: null   # value string or null
```

---

### 3k — Compression Rules (`Compression-Rules.txt`)

Action type: `compress` with `action_parameters.algorithms`.

**Simplified strategy:** All CloudFront cache behaviors always have `compress = true` (the behavior-level switch is always on). The Cache Policy controls which encodings are included in the cache key via `enable_gzip` and `enable_brotli`. Unsupported algorithms are ignored.

Mapping rules based on Cloudflare `algorithms`:

| Cloudflare `algorithms` | `cache_policy.enable_gzip` | `cache_policy.enable_brotli` |
|------------------------|---------------------------|------------------------------|
| `["gzip"]` | `true` | `false` |
| `["brotli"]` | `false` | `true` |
| `["gzip", "brotli"]` or unspecified | `true` | `true` |
| disabled / `[]` | `false` | `false` |

- If the rule has a path condition → apply to the matching Cache Behavior's cache policy.
- If no path condition → apply to the Default `"*"` Cache Behavior's cache policy.
- Default (no Compression Rules present): `enable_gzip: true, enable_brotli: true`.

---

## Steps 4–6 — Build Cache Behaviors, Write IR, Print Summary

**⚠️ READ NOW:** `references/behavior-assembly.md` — contains the complete workflow
for Step 4 (Build Cache Behaviors), Step 5 (Write IR Accumulator File), and
Step 6 (Print Summary). Read it now and follow its instructions.

---

## viewer_request_ops Type Definitions

All entries in `viewer_request_ops` and `viewer_response_ops` follow these schemas:

```yaml
# ── redirect ──────────────────────────────────────────────────────────────────
- type: redirect
  cf_source_rule: "<rule_id>"
  shadowed: false                  # true if dominated by an earlier rule
  condition:
    field: "uri"                   # uri | host | header | method | cookie
    op: "wildcard"                 # eq | ne | wildcard | matches | starts_with | ends_with | contains | in
    value: "/old/*"
  params:
    target: "/new/${captured_1}"   # ${captured_N} for wildcard groups
    status_code: 301
    preserve_query_string: true

# ── rewrite ───────────────────────────────────────────────────────────────────
- type: rewrite
  cf_source_rule: "<rule_id>"
  condition:
    field: "uri"
    op: "starts_with"
    value: "/v1/"
  params:
    new_uri: "/v2/${remainder}"

# ── origin_override ───────────────────────────────────────────────────────────
- type: origin_override
  cf_source_rule: "<rule_id>"
  conditions:
    - match: {field: uri, op: wildcard, value: "/api/*"}
      origin:
        domain: "api-backend.example.com"
        protocol: "https"
        port: 443
        host_header: null
        strip_path_prefix: null
        custom_headers: []
        s3_origin: false           # true if this origin is an S3 bucket (Cloud Connector aws_s3)
  default_origin_id: "origin_cdn_c_example_com"

# ── bulk_redirect (KVS lookup) ─────────────────────────────────────────────────
- type: bulk_redirect
  cf_source_rule: "<rule_id>"
  condition: null
  params:
    kvs_prefix: "redirect:"

# ── header operations ─────────────────────────────────────────────────────────
- type: add_header          # also: set_header, remove_header
  cf_source_rule: "<rule_id>"
  condition: null
  params:
    name: "X-Custom-Header"
    value: "static-value"   # use ${event.viewer.ip} for client IP token
```

---

## non_convertible Entry Format

```yaml
- cf_source_rule: "<rule_id>"       # "managed-transform:<name>" or "system" for synthetic entries
  rule_type: "<type>"               # redirect_rule | rewrite_rule | configuration_rule |
                                    # origin_rule | bulk_redirect | request_header |
                                    # cache_rule | custom_error_rule | response_header |
                                    # compression_rule | system_limit
  reason: "Human-readable explanation of why this rule cannot be converted"
  shadowed: false                   # true if the rule would be unreachable even if converted
```

---

## Important Constraints

### Single-zone scope
This skill processes one domain within one zone. All rule files (Cache-Rules.txt,
Origin-Rules.txt, etc.) are read from the single `backup_path` provided by the
orchestrator. Do not search parent or sibling directories for files belonging to
other zones. If a rule file is not found at `backup_path`, treat it as "no rules
of this type" — do not attempt to locate it elsewhere.

### Do NOT generate JavaScript
This skill outputs IR YAML only. CF Functions JavaScript is the responsibility of the
`cf-cdn-tf-domain` downstream skill. Do not emit any JS code.

### Do NOT assume missing fields
If a required field is absent from the source backup, use the documented default or,
if no safe default exists, emit `null` and add a `non_convertible` entry.

### CloudFront path pattern rules
- Supported wildcards: `*` (zero or more characters) and `?` (exactly one character).
- No regex. No character classes. No anchors.
- Complex Cloudflare `matches` (regex) expressions → Default `"*"` behavior +
  `non_convertible` note with the original regex.
- Multiple path conditions combined with `and`/`or` → create one Cache Behavior per
  feasible branch; flag unsupported branches as `non_convertible`.

### 75 Cache Behavior default quota
CloudFront's default quota is **75** cache behaviors per distribution (soft limit,
can be increased via AWS Support). If processing would generate more than 75
non-default behaviors, add a system-level `non_convertible` warning (see Step 4c).
Do not merge behaviors automatically.

### Last-match-wins for Cache Rules
Unlike most Cloudflare rule types (first-match-wins), Cache Rules use last-match-wins.
This is confirmed by Cloudflare's official documentation: "modern Rules are stackable,
meaning multiple matching rules can combine and apply to the same request (last match
wins). If several matching rules set a value for the same setting, the value in the
last matching rule wins."

When multiple Cache Rules apply to the same path, `resolved_ttl` must reflect the
**last** matching rule's TTL value. Keep all sources in `ttl_sources` for auditability.

**Rule type semantics summary:**
- **Redirect Rules, Origin Rules**: first-match-wins (early return on match)
- **Cache Rules, Configuration Rules, Compression Rules**: last-match-wins (stackable)
- **viewer_request_ops** in the IR: first-match-wins (redirect/rewrite ops return early)

### Rule execution order
Always process rule types in the order defined in reference #1
(`cloudflare-rule-execution-order.md`). This order affects which rules are marked
`shadowed` and how precedence values are assigned.

### Self-contained documents
Each Cache Behavior YAML document must be fully self-contained — i.e., it must include
`distribution_settings`, `origin`, and all policy fields. Downstream Terraform generators
read one document at a time and must not need to cross-reference other documents.

### Cloudflare `concat()` semantics
`concat("/prefix", http.request.uri.path)` **prepends** — it does NOT replace.
Example: if `http.request.uri.path` is `/old/page`, the result is `/prefix/old/page`.
Do NOT strip the original path when converting concat-based rewrites.

### Continent and EU matching — KVS required

**⚠️ READ NOW: If you have not already read `references/continent-countries.md`,
read it now before proceeding.** It contains the 239 country→continent mappings
needed to generate KVS data below.

Cloudflare `ip.src.continent` returns continent codes (`AS`, `EU`, `AF`, `NA`, `SA`,
`OC`, `AN`). CloudFront only provides `cloudfront-viewer-country` (country codes like
`CN`, `US`, `GB`). These are **different data types** — you MUST derive continent from
country code via KVS lookup, never compare directly.

When `needs_continent: true`:
- Read `references/continent-countries.md` for the full mapping table.
- Generate KVS entries with prefix `continent:` for all 239 countries:
  `continent:CN` → `AS`, `continent:US` → `NA`, etc.
- CF Function code: `const continent = await kvsHandle.get('continent:' + country);`

When `needs_eu: true`:
- Generate KVS entries with prefix `eu:` for all 27 EU countries:
  AT, BE, BG, CY, CZ, DE, DK, EE, ES, FI, FR, GR, HR, HU, IE, IT, LT, LU, LV,
  MT, NL, PL, PT, RO, SE, SI, SK
- Value is `1` (existence check): `eu:AT` → `1`, `eu:BE` → `1`, etc.
- CF Function code: `const isEU = await kvsHandle.exists('eu:' + country);`

### Response Header Transform — cost consideration
For `viewer_response_ops` on cacheable objects (images, CSS, JS, fonts):
- CloudFront Functions viewer-response runs on **every** request (including cache hits)
- Lambda@Edge origin-response runs only on **cache misses**
- For high-traffic cacheable paths, Lambda@Edge is more cost-effective
- Add a `non_convertible` note when response header transforms apply to cacheable paths:
  `"Response header transform on cacheable path — consider Lambda@Edge origin-response for cost efficiency"`

### URL Normalization — do not convert
Cloudflare URL Normalization has no CloudFront equivalent and is not needed.
CloudFront normalizes URI paths consistent with RFC 3986 before cache behavior matching.
If encountered, skip silently — do not add to `non_convertible`.

### Header value substitution
When a Cloudflare rule sets a header value containing the string `"Cloudflare"`,
replace it with `"CloudFront"` in the IR. Example: `X-CDN: Cloudflare` → `X-CDN: CloudFront`.

### `CloudFront-Viewer-Address` format
The `CloudFront-Viewer-Address` header value is `ip:port` (e.g., `14.155.12.123:61246`),
not just an IP address. If converting rules that reference client IP via this header,
the port must be stripped: `address.split(':')[0]`.

### Bulk redirect subdomain wildcard key derivation
When generating subdomain wildcard KVS keys (`include_subdomains: true`), the domain
in the key MUST come from the **hostname being processed** (from `domain_scope.json`),
NOT extracted from the `source_url` field. The hostname is the authoritative source.

Example: hostname is `app.example.com`, source_url is `app.example.com/about`
- Correct wildcard key: `redirect:.app.example.com/about`
- WRONG: `redirect:.example.com/about` (extracted from source_url, missing `app`)
