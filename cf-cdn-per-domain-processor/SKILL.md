---
name: cf-cdn-per-domain-processor
description: Core CDN processing skill. For a single proxied hostname, reads all relevant Cloudflare CDN configuration files, processes all 10 rule types in Cloudflare execution order, and generates a complete CloudFront-native IR accumulator YAML file (ir_accumulator/<hostname>.yaml). This skill is invoked once per domain — for N domains, N parallel invocations are used. The IR format contains fully resolved CloudFront resource specs that downstream Terraform generators can consume directly without re-reading Cloudflare files.
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

---

## Reference Documents — MUST Read ALL Before Processing

Read each file with the `read` tool before starting Step 1.
Resolve paths relative to **this skill's directory** (i.e., `cf-cdn-per-domain-processor/`).

| # | Relative path | Purpose |
|---|---------------|---------|
| 1 | `../cf-cdn-analyzer/references/cloudflare-rule-execution-order.md` | Canonical execution order for all 10 rule types |
| 2 | `../cf-cdn-analyzer/references/cloudflare-default-cache-behavior.md` | ~70 cacheable file extensions with default 2 h TTL |
| 3 | `../cf-cdn-analyzer/references/cloudfront-cache-behavior-path-pattern.md` | CloudFront wildcard rules (`*`, `?`), regex limitations |
| 4 | `../cf-functions-converter/references/convertible-rules.md` | Which Cloudflare rule actions can be expressed in CF Functions |
| 5 | `../cf-functions-converter/references/field-mapping.md` | Cloudflare field names → CloudFront / CF Functions equivalents |
| 6 | `../cf-functions-converter/references/cloudfront-function-limits.md` | JS 10 KB size cap, forbidden syntax, runtime constraints |

**Do not skip any.** Processing without these references risks incorrect field mapping,
missed non-convertibles, or invalid path patterns.

---

## Step 0 — Read ALL Reference Documents

Use the `read` tool on each path listed above, in order.
Store key facts mentally (execution order, extension list, field mappings, limits).
Only proceed to Step 1 after all six files have been read.

---

## Step 1 — Parse Inputs

### 1a. Read domain_scope.json

Path: `<backup_path>/domain_scope.json` (or as provided by orchestrator).

Extract:

| Field | Type | Usage |
|-------|------|-------|
| `hostname` | string | The FQDN being processed (e.g. `cdn.c.example.com`) |
| `apex_domain` | string | Parent zone (e.g. `example.com`) |
| `apply_default_cache_behavior` | boolean | Whether to emit cache behaviors for all ~70 default extensions |
| `origin_content` | string | DNS CNAME target — used as the default CloudFront origin domain |
| `cert_arn_mode` | string | `"acm"` or `"iam"` — passed through to distribution_settings |

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
Managed-Transforms.txt
```

---

## Step 3 — Process Rules in Execution Order

**Hostname filtering — apply to EVERY rule file:**

- **Include** rules whose `expression` contains `http.host eq "<HOSTNAME>"`
- **Include** rules whose `expression` contains `http.host in { ... "<HOSTNAME>" ... }`
- **Include** rules with **no** `http.host` condition (global rules — apply to all domains)
- **Exclude** rules that contain an explicit `http.host` condition matching only OTHER hostnames

Process the 10 rule types in the order documented in
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

| Cloudflare parameter | CloudFront field | Notes |
|----------------------|------------------|-------|
| `tls_client_auth.min_tls_version` | `minimum_protocol_version` | Map: "1.2" → `TLSv1.2_2021`, "1.3" → `TLSv1.2_2021` (CF has no TLS 1.3-only mode) |
| `http2` enabled | `http_version: "http2"` | |
| `http3` / `0rtt` enabled | `http_version: "http2and3"` | |
| `ssl` mode `"strict"` | `viewer_protocol_policy: "https-only"` | |
| `ssl` mode `"flexible"` | `viewer_protocol_policy: "allow-all"` | |
| `browser_check` | `non_convertible` | Reason: `"Browser Integrity Check has no CloudFront equivalent"` |
| `minify` | `non_convertible` | Reason: `"HTML/CSS/JS minification not supported natively in CloudFront"` |
| `rocket_loader` | `non_convertible` | Reason: `"Rocket Loader is a Cloudflare-specific JS optimization"` |
| `hotlink_protection` | `non_convertible` | Reason: `"Hotlink protection requires Lambda@Edge custom logic"` |

---

### 3d — Origin Rules (`Origin-Rules.txt`)

Action type: `route` with `action_parameters.origin` containing override fields.

- Add a single `type: origin_override` entry to `viewer_request_ops`.
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
    host_header: null    # null = use domain; explicit value overrides Host header
    strip_path_prefix: null
    custom_headers: []
  ```
- `default_origin_id`: `"origin-<sanitized_hostname>"` using the same sanitization
  rule as the filename.
- If `action_parameters.origin.port` is absent, default to 443 for https, 80 for http.

---

### 3e — Bulk Redirects

**Phase 1:** Read `Bulk-Redirect-Rules.txt` (check both `<backup_path>/` and
`<backup_path>/account/`). Identify which redirect lists are referenced.

**Phase 2:** For each referenced list name `<name>`, read
`<backup_path>/account/List-Items-redirect-<name>.txt`.

Each line format: `<source_path> <status_code> <target_url> [preserve_qs=true|false]`
(exact format may vary — parse defensively).

**IR output:**
- Add `type: bulk_redirect` to `viewer_request_ops`:
  ```yaml
  - type: bulk_redirect
    cf_source_rule: "<rule_id>"
    condition: null
    params:
      kvs_prefix: "redirect:"
  ```
- Set `kvs_requirements.needs_redirects: true`.
- For each redirect item, generate a `kvs_data` entry:
  ```yaml
  - key: "redirect:/old/path"
    value: "301|true|/new/path"   # status|preserve_qs|target
  ```
- Subdomain wildcard entries (source starts with `*.`): use key prefix `"redirect:."`:
  ```yaml
  - key: "redirect:.example.com"
    value: "301|false|https://www.example.com"
  ```

---

### 3f — Request Header Transform (`Request-Header-Transform.txt`)

Action type: `rewrite` with `action_parameters.headers` list.

Each header operation has an `operation` field: `"set"`, `"add"`, or `"remove"`.

| Operation | Handling |
|-----------|----------|
| `"set"` with static value | Add `type: set_header` to `viewer_request_ops` |
| `"add"` with static value | Add `type: add_header` to `viewer_request_ops` |
| `"remove"` | **Do NOT** add to function. Add the header name to `origin_request_policy.forward.headers_whitelist` exclusion list with a comment. Set `origin_request_policy.forward.headers: "whitelist"`. |
| `"set"` with dynamic value (e.g. `concat(...)`) | Add to `viewer_request_ops`; note in `non_convertible` if CF Functions cannot evaluate the expression |
| Device detection (e.g. `X-Is-Mobile` set from user-agent regex) | **Do NOT** convert. Note in `non_convertible`: `"Device detection headers should use CloudFront's native device detection via origin_request_policy"`. Set `kvs_requirements.needs_continent: true` if continent-based. |

**Managed-Transforms.txt handling (True-Client-IP):**
- If `true_client_ip_header` is enabled in `Managed-Transforms.txt`:
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
| `edge_ttl.value` | `cache_policy.ttl.default` and `cache_policy.ttl.max` | Value in seconds |
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

**Default cache behavior extension list:**
- If `apply_default_cache_behavior: true`, read the extension list from reference #2.
- For each extension (e.g. `.jpg`, `.css`, `.js`), add a Cache Behavior:
  - `path_pattern`: `"*.<ext>"`
  - `cache_policy.ttl.default`: `7200` (2 h)
  - `cache_policy.ttl.max`: `7200`
  - `cache_policy.bypass: false`
  - Assign precedence starting at 100, incrementing by 1 per extension.

---

### 3h — Custom Error Rules (`Custom-Error-Rules.txt`)

Action type: `serve_error` (fixed response) or conditional error handling.

**Static error pages** (action has `action_parameters.response.content` — fixed body):
```yaml
custom_error_response:
  - error_code: 404
    response_page_path: "/errors/404.html"  # if path-based
    response_code: 404
    ttl: 10
```
Add `custom_error_response` as a top-level field in the Cache Behavior document.

**Dynamic error handling** (condition-based, requires request inspection):
- Set `lambda_edge.origin_response` to a placeholder object:
  ```yaml
  lambda_edge:
    origin_response:
      cf_source_rule: "<rule_id>"
      reason: "Dynamic custom error page requires Lambda@Edge origin-response trigger"
  ```

---

### 3i — Response Header Transform (`Response-Header-Transform.txt`)

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

### 3j — Compression Rules (`Compression-Rules.txt`)

Action type: `compress` with `action_parameters.algorithms`.

- Gzip or Brotli enabled for a path → set `cache_policy.compress: true` on the
  affected Cache Behavior.
- No path condition → set `compress: true` on the Default `"*"` Cache Behavior.
- If compression is **disabled** for a path that inherits compression from a wider rule,
  set `compress: false` and add a `non_convertible` note:
  `"CloudFront compress setting is per-distribution and cannot be disabled per path"`.

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

### 4c. Enforce the 25 Cache Behavior limit

CloudFront allows a maximum of **25** non-default Cache Behaviors per distribution.

If the collected set would exceed 25:
1. Identify the least-specific patterns (longest common prefix groups, extension patterns).
2. Merge them into a single broader pattern (e.g. `/static/*` absorbs `*.jpg`, `*.png`, `*.gif`).
3. Add a warning entry to `non_convertible`:
   ```yaml
   - cf_source_rule: "system"
     rule_type: "system_limit"
     reason: "Cache behavior count exceeded CloudFront 25-behavior limit; merged: [list of merged patterns]"
     shadowed: false
   ```

### 4d. Populate distribution_settings on all behaviors

Copy `distribution_settings` values derived from Configuration Rules (3c) to every
Cache Behavior document. Each document is self-contained for the Terraform generator.

### 4e. Set default origin

For every Cache Behavior, set:
```yaml
origin:
  id: "origin-<sanitized_hostname>"
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

Create the directory if it does not exist.

### File format

One YAML document per Cache Behavior, separated by `---`.
**First document** = lowest precedence number (most specific path, evaluated first by CloudFront).
**Last document** = Default Cache Behavior (`path_pattern: "*"`, `precedence: 999`).

### Required schema per document

```yaml
hostname: "cdn.c.example.com"
path_pattern: "/api/*"
precedence: 20

distribution_settings:
  viewer_protocol_policy: "redirect-to-https"   # "allow-all" | "redirect-to-https" | "https-only"
  minimum_protocol_version: "TLSv1.2_2021"
  http_version: "http2and3"                      # "http1.1" | "http2" | "http2and3"
  is_ipv6_enabled: true
  compress: true
  cert_arn_mode: "acm"                           # from domain_scope.json

origin:
  id: "origin-cdn-c-example-com"
  domain: "httpecho.a.letsmakeit.link"           # from origin_content (CNAME target)
  protocol: "https"
  port: 443
  custom_origin_headers: []

cache_policy:
  bypass: false
  ttl:
    min: 0
    default: 300
    max: 3600
  cache_key:
    headers: []
    cookies: []
    query_strings: "none"                        # "none" | "all" | ["param1", "param2"]
  compress: true
  ttl_sources: []                                # [{cf_source_rule, ttl}]
  resolved_ttl: 300

origin_request_policy:
  forward:
    headers: "none"                              # "none" | "all" | "whitelist"
    headers_whitelist: []
    cookies: "none"                              # "none" | "all" | "whitelist"
    cookies_whitelist: []
    query_strings: "none"                        # "none" | "all" | "whitelist"
    query_strings_whitelist: []

response_headers_policy:
  security_headers: {}
  custom_headers: []
  cors: null

viewer_request_ops: []
viewer_response_ops: []

kvs_requirements:
  needs_redirects: false
  needs_continent: false
  needs_eu: false

kvs_data: []

custom_error_response: []                        # omit if empty

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
| `cache_policy.compress` | `true` | Cost and performance benefit |
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
  - [WARN] Cache behavior count was 28; merged 4 extension patterns into /static/*
  - [WARN] Rule cf-rule-abc123: regex expression not representable as CloudFront wildcard; moved to default behavior

Non-convertible rules:
  - cf-rule-xyz789 [configuration_rule]: Browser Integrity Check has no CloudFront equivalent
  - cf-rule-def456 [cache_rule]: serve_stale has no direct CloudFront cache policy equivalent
  - cf-rule-ghi012 [request_header]: Device detection headers should use CloudFront native device detection
```

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
  default_origin_id: "origin-cdn-c-example-com"

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

### Do NOT generate JavaScript
This skill outputs IR YAML only. CF Functions JavaScript is the responsibility of the
`cf-functions-generator` downstream skill. Do not emit any JS code.

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

### 25 Cache Behavior limit
CloudFront enforces a hard limit of **25** non-default Cache Behaviors per distribution.
If processing would generate more, merge less-specific patterns before writing output
and add a system-level `non_convertible` warning (see Step 4c).

### Last-match-wins for Cache Rules
Unlike most Cloudflare rule types (first-match-wins), Cache Rules use last-match-wins.
When multiple Cache Rules apply to the same path, `resolved_ttl` must reflect the
**last** matching rule's TTL value. Keep all sources in `ttl_sources` for auditability.

### Rule execution order
Always process rule types in the order defined in reference #1
(`cloudflare-rule-execution-order.md`). This order affects which rules are marked
`shadowed` and how precedence values are assigned.

### Self-contained documents
Each Cache Behavior YAML document must be fully self-contained — i.e., it must include
`distribution_settings`, `origin`, and all policy fields. Downstream Terraform generators
read one document at a time and must not need to cross-reference other documents.
