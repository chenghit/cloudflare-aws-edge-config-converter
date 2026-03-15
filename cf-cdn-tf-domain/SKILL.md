---
name: cf-cdn-tf-domain
description: >
  Main Terraform generator for a single CDN domain. Reads the domain's final IR
  YAML (ir/final/<hostname>.yaml) and the shared dedup manifest, then emits all
  Terraform and JavaScript artefacts needed to deploy a CloudFront distribution
  for that domain. Invoked once per domain; multiple domains may be processed
  in parallel. Handles function-size management, Lambda@Edge fallback, KVS data
  files, and ACM certificate patterns.
---

# cf-cdn-tf-domain

Generates the complete per-domain Terraform workspace under
`cloudflare-to-aws-cdn/terraform/domains/<sanitized-hostname>/`.

---

## Path Resolution

All paths are relative to the current working directory when the skill is invoked.

| Logical name | Resolved path |
|---|---|
| Domain IR (input) | `cloudflare-to-aws-cdn/ir/final/<hostname>.yaml` |
| Dedup manifest (read-only) | `cloudflare-to-aws-cdn/shared/dedup_manifest.json` |
| Domain scope | `cloudflare-to-aws-cdn/domain_scope.json` |
| Output directory | `cloudflare-to-aws-cdn/terraform/domains/<sanitized-hostname>/` |
| Shared module source | `../../modules/cloudfront_distribution` (relative, for Terraform `source`) |
| Module template | `references/modules/cloudfront_distribution/` (in this skill directory) |

**Sanitized hostname**: replace `.` and `-` with `_`, lowercase.
Example: `cdn.c.example.com` → `cdn_c_example_com`.

---

## Output Directory

```
cloudflare-to-aws-cdn/terraform/domains/<sanitized-hostname>/
  main.tf                   ← module call to cloudfront_distribution (always)
  outputs.tf                ← distribution_id, domain_name outputs (always)
  functions.tf              ← aws_cloudfront_function resources (always)
  kvs.tf                    ← KVS store + data (only if kvs_requirements non-empty)
  kvs-data.json             ← bulk redirect seed data (only if kvs_requirements non-empty)
  functions/
    <sanitized_name>_viewer_request.js   ← always (unless all logic in Lambda@Edge)
    <sanitized_name>_viewer_response.js  ← only if viewer_response_ops non-empty
  lambda/                   ← only if lambda_edge in IR is non-null
    origin_request_handler.js   ← only if lambda_edge.origin_request is set
    viewer_request_handler.js   ← only if lambda_edge.viewer_request is set (last resort)
```

---

## Workflow

### Step 0 — Read reference documents first

Before generating any code, read:

1. `references/modules/cloudfront_distribution/variables.tf` — the module's
   input variables. Every variable you pass in `main.tf` must match a declared
   variable here. Do not invent variable names.
2. `references/modules/cloudfront_distribution/main.tf` — the module
   implementation. Understand what each variable controls so you pass correct
   values.
3. `references/cloudfront/runtime2-guide.md` — **MUST READ before generating any JavaScript.** Contains correct API signatures for `rawQueryString()`, `cf.kvs()`, `cf.updateRequestOrigin()`, supported/forbidden syntax, and complete code patterns.
4. `references/cloudfront/operator-conversion.md` — Cloudflare expression operators → JS code patterns. Read before generating condition logic.
5. `references/cloudfront/unsupported-syntax.md` — Tested forbidden ES6+ features. Read before generating any JS.
6. `cloudflare-to-aws-cdn/ir/final/<hostname>.yaml` — the actual
   domain IR you will process.
7. `cloudflare-to-aws-cdn/shared/dedup_manifest.json` — to
   resolve policy hashes to Terraform resource addresses.
8. `cloudflare-to-aws-cdn/domain_scope.json` — global settings
   such as default origin, WAF ACL ARN, tags, etc.

If any of files 6–8 is missing, halt and report the missing path.

Additional references to consult as needed during codegen:
- `references/cloudfront/cloudfront-event-structure.md` — event object shape
- `references/cloudfront/conversion-examples.md` — URL field mapping and wildcard patterns
- `references/cloudfront/cloudfront-viewer-headers.md` — header mapping table
- `references/cloudfront/kvs-usage-and-limits.md` — KVS constraints
- `references/lambda/default-cache-origin-response.js` — Lambda@Edge template for default cache (read only when IR has `lambda_edge.origin_response.type == "default_cache"`)

---

### Step 1 — Parse inputs and derive identifiers

**From the IR metadata document** (`cloudflare-to-aws-cdn/ir/final/<hostname>.yaml`, first document):

```
hostname:              cdn.c.example.com
sanitized_name:        cdn_c_example_com        # computed: replace . and - with _
origin_type:           "s3" | "object_storage" | "server"
cert_arn_mode:         "explicit" | "data_source"
cert_arn:              "arn:aws:acm:..." | null  # null when cert_arn_mode == "data_source"
apex_domain:           "c.example.com"           # used for wildcard cert derivation
kvs_requirements:      { needs_redirects, needs_continent, needs_eu }
kvs_data:              [...]
custom_error_responses: [...]                    # distribution-level error pages (may be empty)
lambda_edge:           { origin_request, origin_response }  # null if no Lambda@Edge needed
```

**From the IR cache_behavior documents** (all documents after the first):

```
distribution_settings.viewer_protocol_policy
distribution_settings.minimum_protocol_version
distribution_settings.http_version
distribution_settings.is_ipv6_enabled
distribution_settings.geo_restriction_type      # "none" | "whitelist" | "blacklist"
distribution_settings.geo_restriction_locations # list of country codes
distribution_settings.price_class               # "PriceClass_All" | "PriceClass_100" | "PriceClass_200"
distribution_settings.waf_acl_arn               # null if no WAF
```

Use the `distribution_settings` from the **default cache behavior** (`path_pattern: "*"`)
as the distribution-level settings. These apply to the entire CloudFront distribution.

**From `cloudflare-to-aws-cdn/shared/dedup_manifest.json`:**

```
cache_policy_id:              "policy-<hash>"   # look up by matching config hash
origin_request_policy_id:     "policy-<hash>"   # null if no ORP
response_headers_policy_id:   "policy-<hash>"   # null if no RHP
```

Derive Terraform data source lookups (each domain is an independent Terraform root
module — it cannot reference resources in `terraform/shared/` directly):

For each unique policy ID referenced by this domain's cache behaviors, generate a
`data` source that looks up the policy by its **name** (as generated by
`cf-cdn-tf-shared-policies`):

```hcl
# Cache policy data sources
data "aws_cloudfront_cache_policy" "policy_<policy_id>" {
  name = "cfcdn-cache-policy-<policy_id>"
}

# If the cache policy has bypass: true, the name is different:
data "aws_cloudfront_cache_policy" "policy_<policy_id>" {
  name = "cfcdn-cache-bypass-<policy_id>"
}

# Origin request policy data sources (only for non-null ORP references)
data "aws_cloudfront_origin_request_policy" "policy_<policy_id>" {
  name = "cfcdn-orp-<policy_id>"
}

# Response headers policy data sources (only for non-null RHP references)
data "aws_cloudfront_response_headers_policy" "policy_<policy_id>" {
  name = "cfcdn-rhp-<policy_id>"
}
```

Then use these references in the module call:
- `cache_policy_ref` = `data.aws_cloudfront_cache_policy.policy_<policy_id>.id`
- `orp_ref` = `data.aws_cloudfront_origin_request_policy.policy_<policy_id>.id` (or null)
- `rhp_ref` = `data.aws_cloudfront_response_headers_policy.policy_<policy_id>.id` (or null)

To determine whether a cache policy uses `cfcdn-cache-policy-` or `cfcdn-cache-bypass-`
prefix, check the `config.bypass` field in the dedup manifest entry for that policy ID.

**Important**: Only generate data sources for policy IDs actually used by this domain.
Collect all unique policy IDs from the default behavior and all ordered behaviors,
then deduplicate before generating data source blocks.

---

### Step 2 — JavaScript function generation

This step generates the CloudFront Function JavaScript **before** writing any
Terraform, because the function file size determines whether Lambda@Edge is
needed.

#### 2a. Generate viewer_request.js draft

Generate a file called `viewer_request.js` (temporary; not written to disk yet)
using the codegen rules below.

**File structure**:

```javascript
import cf from 'cloudfront';

async function handler(event) {
  const request = event.request;

  // --- SECTION 1: redirects ---
  // (generated code here)

  // --- SECTION 2: rewrites ---
  // (generated code here)

  // --- SECTION 3: origin_override ---
  // (generated code here)

  // --- SECTION 4: bulk_redirects ---
  // (generated code here)

  // --- SECTION 5: header mutations ---
  // (generated code here)

  return request;
}
```

**Codegen rules — enforce this order strictly**:

**1. redirects** — for each redirect op in `viewer_request_ops` where type == "redirect":

```javascript
// redirect: <description from IR>
if (<condition>) {
  return {
    statusCode: <301|302>,
    headers: {
      location: { value: "<target_url>" }
    }
  };
}
```

Condition generation:
- `path_prefix`: `request.uri.startsWith("<prefix>")`
- `path_exact`: `request.uri === "<path>"`
- `path_regex`: `/<pattern>/.test(request.uri)` — MUST pre-compile as const above handler if reused
- `host_match`: `request.headers.host && request.headers.host.value === "<host>"`
- Multiple conditions combined with `&&`

**2. rewrites** — for each rewrite op in `viewer_request_ops` where type == "rewrite":

```javascript
// rewrite: <description>
if (<condition>) {
  request.uri = <new_uri_expression>;
}
```

For capture-group rewrites, use `.replace()`:
```javascript
request.uri = request.uri.replace(/<pattern>/, "<replacement>");
```

**3. origin_override** — for each origin_override op:

```javascript
// origin_override: <description>
if (<condition>) {
  cf.updateRequestOrigin({
    domainName: "<new_origin>",
    originPath: "<prefix_path_or_empty_string>",
    customOriginConfig: {
      port: <443|80>,
      protocol: "<https|http>",
      sslProtocols: ["TLSv1.2"]
    }
  });
}
```

Omit `customOriginConfig` entirely if port/protocol match the existing origin
(i.e., only `domainName` changes). Omit `originPath` if empty string.
See `references/cloudfront/runtime2-guide.md` for full `updateRequestOrigin()` API.

**4. bulk_redirects** — if `kvs_requirements` is non-empty AND bulk_redirect ops exist:

```javascript
// bulk_redirects via KVS
const kvsHandle = cf.kvs();
const host = request.headers.host.value;
const uri = request.uri;

// Try exact host match
let kvsValue = null;
try {
  kvsValue = await kvsHandle.get('redirect:' + host + uri);
} catch (e) {}

// Try subdomain match if exact match failed
if (kvsValue === null && host.includes('.')) {
  const dotHost = '.' + host;
  try {
    kvsValue = await kvsHandle.get('redirect:' + dotHost + uri);
  } catch (e) {}
}

if (kvsValue !== null) {
  const parts = kvsValue.split('|');
  const statusCode = parseInt(parts[0], 10);
  const preserveQS = parts[1] === '1';
  let target = parts[2];
  if (preserveQS) {
    const qs = request.rawQueryString();
    if (qs) {
      const sep = target.includes('?') ? '&' : '?';
      target = target + sep + qs;
    }
  }
  return {
    statusCode: statusCode,
    headers: { location: { value: target } }
  };
}
```

**5. Header mutations** — for each header op in `viewer_request_ops`:

```javascript
// remove_header
delete request.headers["<header-name-lowercase>"];

// set_header (replace)
request.headers["<header-name-lowercase>"] = { value: "<value>" };

// add_header (append if not present)
if (!request.headers["<header-name-lowercase>"]) {
  request.headers["<header-name-lowercase>"] = { value: "<value>" };
}
```

**JavaScript constraints (CloudFront Functions Runtime 2.0)**:
- ❌ NEVER use optional chaining (`?.`)
- ❌ NEVER use array destructuring (`const [a, b] = ...`)
- ❌ NEVER use object destructuring (`const { a } = ...` or `let { a } = ...`)
- ❌ AVOID `Promise.all`, `Promise.any`, `.then()`, `.catch()` — syntactically valid
  but risk exceeding memory quota per AWS docs. Always use sequential `await` instead.
- ✅ Use `const` and `let` (not `var`)
- ✅ Use template literals `` `${expr}` ``
- ✅ Use arrow functions `(x) => x`
- ✅ Use `for...of` loops
- ✅ Use `await` sequentially
- First line MUST be: `import cf from 'cloudfront';`
- Handler MUST be: `async function handler(event) {`
- Handler MUST end with: `return request;` (or an early return with statusCode)
- **Prefer string methods over regex** for simple operators: use `startsWith()`,
  `endsWith()`, `includes()`, `===` instead of regex when the Cloudflare expression
  uses `eq`, `contains`, `starts_with`, `ends_with`, or simple `wildcard` patterns.
  See `references/cloudfront/operator-conversion.md` for the full mapping.
- **Preserve regex from `matches` operator unchanged**: when the Cloudflare expression
  uses `matches` with a regex pattern, pass the regex through to `/.../` in JS without
  attempting to simplify it.

**Continent matching codegen** (when `kvs_requirements.needs_continent` is true):

```javascript
// Continent lookup — NEVER compare country code to continent code directly
const countryHeader = request.headers['cloudfront-viewer-country'];
const country = countryHeader ? countryHeader.value : '';
let continent = '';
if (country) {
  try { continent = await kvsHandle.get('continent:' + country); } catch (e) {}
}
if (continent === 'AS') {
  // Asia-specific logic
}
```

**EU country check codegen** (when `kvs_requirements.needs_eu` is true):

```javascript
let isEU = false;
if (country) {
  isEU = await kvsHandle.exists('eu:' + country);
}
```

**Header value substitution**: If any `set_header` op has a value containing
`"Cloudflare"`, replace with `"CloudFront"` in the generated JS.
Example: `request.headers['x-cdn'] = {value: 'CloudFront'};`

**`CloudFront-Viewer-Address` format**: Value is `ip:port`. To extract IP only:
```javascript
const addr = request.headers['cloudfront-viewer-address'];
const ip = addr ? addr.value.split(':')[0] : '';
```

#### 2b. Size check and escalation

After generating the draft, calculate the byte count of the draft string.

**Decision tree**:

```
draft size ≤ 6KB?
  → YES: use as-is, write to functions/<sanitized_name>_viewer_request.js
  → NO:  minify (Step 2c)

After minification:
  minified size ≤ 10KB?
    → YES: write minified to functions/<sanitized_name>_viewer_request.js
    → NO:  escalate (Step 2d)
```

#### 2c. Minification

Minification rules (apply in order):
1. Remove all `// ...` single-line comments
2. Remove all blank lines
3. Shorten variable names: `request` → `req`, `kvsValue` → `kv`,
   `lookupKey` → `lk`, `statusCode` → `sc`, `target` → `tgt`,
   `parts` → `pts`, `kvsHandle` → `kvs`
4. Remove unnecessary whitespace around operators
5. Collapse multi-line `if` bodies to single line where possible

After minification, update the size estimate.

#### 2d. Escalation to Lambda@Edge

If the minified size is still > 10 KB:

**Case A — origin_override ops exist in viewer_request_ops**:
1. Extract all origin_override codegen blocks → move to `lambda/origin_request_handler.js`
2. Remove origin_override blocks from viewer_request.js
3. Re-estimate viewer_request.js size
4. If re-estimated size ≤ 10 KB: proceed with split arrangement
5. If still > 10 KB: fall through to Case B for the remaining viewer_request logic

**Case B — no origin_override ops, OR Case A step 5**:
1. Move ALL viewer_request logic (entire function body) to
   `lambda/viewer_request_handler.js` as Lambda@Edge
2. Remove the CloudFront Function viewer-request association from `main.tf`
   entirely. **CloudFront does not allow a CFF and Lambda@Edge on the same
   event type (viewer-request) for the same cache behavior.** Do not generate
   a pass-through CFF — omit the CFF association and use Lambda@Edge alone.

**Target**: viewer_request.js ≤ 8 KB (leave 2 KB buffer from 10 KB hard limit).

#### 2e. Lambda@Edge file format

Lambda@Edge files use Node.js **CommonJS** syntax (NOT CloudFront Functions
Runtime 2.0 syntax, NOT ESM):

```javascript
// origin_request_handler.js
exports.handler = async (event, context, callback) => {
  const request = event.Records[0].cf.request;

  // origin_override logic translated to Lambda@Edge origin mutation:
  // request.origin.custom.domainName = "<new_origin>";
  // request.origin.custom.port = 443;
  // request.origin.custom.protocol = "https";
  // request.headers.host = [{ key: 'Host', value: "<new_origin>" }];

  callback(null, request);
};
```

Lambda@Edge constraints:
- Must NOT `import cf from 'cloudfront'` (this module does not exist in Lambda)
- Must use `event.Records[0].cf.request` (not `event.request`)
- Must call `callback(null, request)` or `callback(null, response)`
- Optional chaining (`?.`) IS allowed (Node.js runtime)
- Destructuring IS allowed
- Max file size: 1 MB (hard limit)

#### 2f. Lambda@Edge for default cache behavior

If the IR metadata has `lambda_edge.origin_response.type == "default_cache"`:

1. Read the template at `references/lambda/default-cache-origin-response.js`.
2. If `custom_ttl_map` is non-empty (>20 custom-TTL extensions were consolidated
   into Lambda), replace the `CUSTOM_TTL_PLACEHOLDER` comment block with:
   ```javascript
   const customTtl = {"apk": 31536000, "iso": 604800};
   const ttl = customTtl[extension] || 7200;
   ```
   And remove the `const ttl = 7200;` line below it.
3. If `custom_ttl_map` is empty, use the template as-is (remove the placeholder
   comment, keep `const ttl = 7200;`). An empty map means custom-TTL extensions
   are handled by independent cache behaviors (≤20 threshold), so the Lambda
   only needs the default 7200s for remaining extensions.
4. Write to `lambda/default_cache_origin_response.js`.
5. Add the Lambda to `default_lambda_function_associations` in the module call:
   ```hcl
   default_lambda_function_associations = [
     {
       event_type   = "origin-response"
       lambda_arn   = "REPLACE_WITH_DEPLOYED_LAMBDA_ARN"
       include_body = false
     },
   ]
   ```
   The `lambda_arn` placeholder must be filled after deploying the Lambda
   function — Lambda@Edge ARNs include the version number and cannot be
   predicted at generation time. Add a comment in `main.tf` instructing the
   operator to fill it in after deployment.

---

### Step 3 — Generate `functions.tf`

This file declares all `aws_cloudfront_function` resources.

**viewer_request function** (always, unless omitted per Step 2e):
```hcl
resource "aws_cloudfront_function" "<sanitized_name>_viewer_request" {
  name    = "cfcdn-<sanitized_name>-viewer-request"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = file("${path.module}/functions/<sanitized_name>_viewer_request.js")
}
```

**viewer_response function** (only if `viewer_response_ops` in the IR is non-empty):

Generate `functions/<sanitized_name>_viewer_response.js` with this structure:
```javascript
async function handler(event) {
  const response = event.response;

  // --- viewer_response_ops (set_header / add_header / remove_header) ---
  // (generated code here)
  // Note: can modify/add/delete response headers and cookies
  // Note: cannot read the original response body (can only replace it entirely)
  // Note: this function does NOT execute when origin returns HTTP 400+

  return response;
}
```

Note: `import cf from 'cloudfront'` is only needed if the function uses `cf.*` APIs (e.g., KVS). For header-only operations it is not required.

Then declare the Terraform resource:
```hcl
resource "aws_cloudfront_function" "<sanitized_name>_viewer_response" {
  name    = "cfcdn-<sanitized_name>-viewer-response"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = file("${path.module}/functions/<sanitized_name>_viewer_response.js")
}
```

The viewer_response function is associated in `main.tf` with `event_type = "viewer-response"`.

If there are origin_request ops handled at CFF level (not escalated to Lambda),
add a third resource for origin_request similarly.

---

### Step 4 — Generate `kvs.tf` (conditional)

Only generate this file if `kvs_requirements` in the IR is non-empty.

```hcl
# AUTO-GENERATED by cf-cdn-tf-domain skill
# DO NOT EDIT MANUALLY

resource "aws_cloudfront_key_value_store" "<sanitized_name>_kvs" {
  name    = "cfcdn-<sanitized_name>-kvs"
  comment = "KVS for bulk redirects: <hostname>"
}

# Seed data is loaded from kvs-data.json at apply time via a local-exec
# provisioner or external seeding script. See kvs-data.json for entries.
output "<sanitized_name>_kvs_arn" {
  description = "KVS ARN — needed to associate with CloudFront Function"
  value       = aws_cloudfront_key_value_store.<sanitized_name>_kvs.arn
}
```

---

### Step 5 — Generate `kvs-data.json` (conditional)

Only generate if `kvs_requirements` in the metadata document is non-empty (any field is `true`).

Read `kvs_data` directly from the metadata document of the final IR YAML. Each entry has:
- `key`: e.g. `"redirect:example.com/old-path"` (includes host)
- `value`: e.g. `"301|0|https://example.com/new-path"` (status|preserve_qs(1/0)|target)

```json
{
  "data": [
    { "key": "redirect:example.com/old-path", "value": "301|0|https://example.com/new-path" },
    { "key": "redirect:example.com/promo",    "value": "302|1|https://example.com/sale" },
    { "key": "redirect:.example.com/promo",   "value": "302|1|https://example.com/sale" }
  ]
}
```

Write to: `<output_dir>/kvs-data.json`

---

### Step 6 — Generate `main.tf`

This file calls the shared `cloudfront_distribution` module. It must NOT contain
a `resource "aws_cloudfront_distribution"` block — all distribution logic lives
in the module.

#### 6a. ACM certificate locals / data

**Pattern A** — `cert_arn` field in IR is non-empty:

```hcl
locals {
  cert_arn_<sanitized_name> = "<cert_arn_value>"
}
```

**Pattern B** — `cert_arn` is blank or absent:

```hcl
data "aws_acm_certificate" "<sanitized_name>" {
  provider    = aws.us_east_1
  domain      = "<wildcard_or_exact_domain>"
  statuses    = ["ISSUED"]
  most_recent = true
}
```

Wildcard domain derivation: use `apex_domain` from the IR metadata document.
- If hostname == apex_domain (bare zone apex) → use exact domain (e.g. `"c.example.com"`)
- Otherwise → use `"*.<apex_domain>"` (e.g. `"*.c.example.com"`)

This correctly handles zones at any depth without assuming a fixed label count.

#### 6b. Shared policy data sources

Collect all unique policy IDs referenced by this domain's behaviors (default +
ordered). For each unique ID, generate a `data` source block. These must appear
before the module call.

```hcl
# --- Shared policy lookups (created by cf-cdn-tf-shared-policies) ---

data "aws_cloudfront_cache_policy" "policy_<policy_id>" {
  name = "cfcdn-cache-policy-<policy_id>"
  # Use "cfcdn-cache-bypass-<policy_id>" if dedup manifest config.bypass == true
}

data "aws_cloudfront_origin_request_policy" "policy_<policy_id>" {
  name = "cfcdn-orp-<policy_id>"
}

data "aws_cloudfront_response_headers_policy" "policy_<policy_id>" {
  name = "cfcdn-rhp-<policy_id>"
}
```

Only generate data sources for policy types actually used. If no behavior
references an ORP, omit all ORP data sources. Same for RHP.

If the default origin is S3 (`origin_type == "s3"` in metadata) OR any
cache behavior has an origin with `s3_origin: true` (from Cloud Connector),
generate an OAC resource in the domain module (one per domain is sufficient —
all S3 origins in the same distribution share it):

```hcl
resource "aws_cloudfront_origin_access_control" "s3_oac" {
  name                              = "cfcdn-s3-oac-<sanitized_name>"
  description                       = "OAC for S3 origins (<hostname>)"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
```

The `aws_cloudfront_origin_access_control` data source only supports lookup by
`id` (not `name`), so cross-module lookup is not practical — each domain module
creates its own OAC resource.

#### 6c. S3 origin handling

Applies to the default origin when `origin_type == "s3"`, AND to any secondary
origin introduced by Cloud Connector with `s3_origin: true` in the cache behavior's
origin block.

For each S3 origin:

- **`domain_name`**: Use the S3 **REST API endpoint** format:
  `<bucket>.s3.<region>.amazonaws.com`. If the origin hostname already matches
  this format, use it directly.
  - **S3 website endpoints** (`*.s3-website.<region>.amazonaws.com` or
    `*.s3-website-<region>.amazonaws.com`) are a special case: they do NOT
    support OAC and must be treated as **CustomOrigin** (HTTP only), not S3
    origin. Do NOT convert website endpoints to REST format — keep them as
    custom origins with `protocol_policy = "http-only"` and `s3_origin = false`.
    Add a note in the conversion report warning that this origin lacks OAC
    protection.
  - Only origins matching the REST endpoint pattern (`*.s3.amazonaws.com`,
    `*.s3.<region>.amazonaws.com`) qualify for S3 origin + OAC.
- **`origin_access_control_id`**: `aws_cloudfront_origin_access_control.s3_oac.id`
- **No `custom_origin_config`**: S3 origins with OAC in provider >= 6.0 do not need
  `s3_origin_config` or `custom_origin_config` — just set `origin_access_control_id`
  and the provider handles the rest.
- **Drop** any Origin Rules that only override host header or switch protocol to HTTP
  for S3 REST origins — these are Cloudflare workarounds that are unnecessary with OAC.

The module's `origins` variable entry for an S3 origin looks like:

```hcl
{
  origin_id                = "<origin_id>"
  domain_name              = "<bucket>.s3.<region>.amazonaws.com"
  origin_access_control_id = aws_cloudfront_origin_access_control.s3_oac.id
  s3_origin                = true   # skips custom_origin_config, sets OAC
}
```

For non-S3 origins (`origin_type == "object_storage"` or `"server"`, and
cache behaviors without `s3_origin: true` on their origin), use the existing custom
origin format (protocol_policy, ports, headers).

#### 6d. Module call

```hcl
# AUTO-GENERATED by cf-cdn-tf-domain skill
# DO NOT EDIT MANUALLY

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# <Pattern A locals OR Pattern B data source here>

module "cdn_<sanitized_name>" {
  source = "../../modules/cloudfront_distribution"

  hostname    = "<hostname>"
  aliases     = [<quoted list of aliases>]
  price_class = "<price_class>"
  http_version            = "<http_version>"
  is_ipv6_enabled         = <true|false>
  minimum_protocol_version = "<minimum_protocol_version>"
  wait_for_deployment = false

  # ACM certificate — Pattern A or B
  acm_certificate_arn = local.cert_arn_<sanitized_name>   # Pattern A
  # acm_certificate_arn = data.aws_acm_certificate.<sanitized_name>.arn  # Pattern B

  # Origins
  origins = [
    {
      origin_id             = "<origin_id>"
      domain_name           = "<origin_domain>"
      protocol_policy       = "<https-only|http-only|match-viewer>"
      http_port             = 80
      https_port            = 443
      custom_origin_headers = [
        # { name = "X-Header", value = "value" }
      ]
    },
    # additional origins if present
  ]

  # Default cache behavior
  default_target_origin_id           = "<origin_id>"
  default_viewer_protocol_policy     = "redirect-to-https"
  default_compress                   = true
  default_cache_policy_id            = data.aws_cloudfront_cache_policy.policy_<policy_id>.id
  default_origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.policy_<policy_id>.id   # omit line if null
  default_response_headers_policy_id = data.aws_cloudfront_response_headers_policy.policy_<policy_id>.id # omit line if null

  default_function_associations = [
    # Include only if viewer_request CloudFront Function exists
    {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.<sanitized_name>_viewer_request.arn
    },
    # Include only if viewer_response CloudFront Function exists (viewer_response_ops non-empty)
    {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.<sanitized_name>_viewer_response.arn
    },
  ]

  default_lambda_function_associations = [
    # Include only if lambda_edge.origin_request is set in IR
    {
      event_type   = "origin-request"
      lambda_arn   = "REPLACE_WITH_DEPLOYED_LAMBDA_ARN"
      include_body = false
    },
  ]

  # Ordered cache behaviors (one entry per path pattern, sorted by precedence)
  ordered_cache_behaviors = [
    {
      path_pattern               = "<path_pattern>"
      target_origin_id           = "<origin_id>"
      viewer_protocol_policy     = "redirect-to-https"
      compress                   = true
      cache_policy_id            = data.aws_cloudfront_cache_policy.policy_<policy_id>.id
      origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.policy_<policy_id>.id   # omit if null
      response_headers_policy_id = data.aws_cloudfront_response_headers_policy.policy_<policy_id>.id # omit if null
      function_associations = [
        # { event_type = "viewer-request", function_arn = "..." }
      ]
      lambda_function_associations = [
        # { event_type = "origin-request", lambda_arn = "...", include_body = false }
      ]
    },
  ]

  # Geo restriction
  geo_restriction_type      = "none"
  geo_restriction_locations = []

  # WAF — omit if waf_acl_arn is null
  web_acl_id = "<waf_acl_arn>"

  tags = {
    Domain = "<hostname>"
  }
}
```

**`custom_error_response` blocks** (distribution-level, outside the module call):

If `custom_error_responses` in the IR metadata document is non-empty, add these blocks
directly to the `aws_cloudfront_distribution` resource inside the module. Since the
module wraps the distribution, you must pass them as a variable. Add to the module call:

```hcl
  custom_error_responses = [
    {
      error_code            = 404
      response_page_path    = "/errors/404.html"
      response_code         = 404
      error_caching_min_ttl = 10
    },
  ]
```

The module already supports `custom_error_responses` as a variable — do not
modify the module's `variables.tf` or `main.tf`.

**Important rules**:
- Remove every comment line (lines starting with `#` that are instructions)
  from the actual output — emit only real HCL.
- Include only the variables that are relevant (non-null, non-empty). Omit
  optional variables entirely rather than passing `null`.
- `protocol_policy` must be exactly `"https-only"`, `"http-only"`, or
  `"match-viewer"`.
- For `geo_restriction_type == "none"`, set `geo_restriction_locations = []`.
- The `lambda_arn` placeholder `"REPLACE_WITH_DEPLOYED_LAMBDA_ARN"` is
  intentional — Lambda@Edge ARNs include the version and cannot be predicted
  at generation time. Add a comment instructing the operator to fill it in.
- `default_function_associations` and `default_lambda_function_associations`
  must be omitted entirely (not set to `[]`) if there are no associations,
  because the module defaults to `[]` already.
- Policy refs (`cache_policy_ref`, `orp_ref`, `rhp_ref`) are Terraform
  expressions like `data.aws_cloudfront_cache_policy.policy_<id>.id` — they
  reference data sources that look up shared policies by name. They must not be
  quoted as strings.

---

### Step 7 — Write all files

Write files in this order:
1. `functions/<sanitized_name>_viewer_request.js` (always, unless omitted per Step 2e)
2. `functions/<sanitized_name>_viewer_response.js` (only if `viewer_response_ops` non-empty)
3. `lambda/origin_request_handler.js` (if generated by Step 2d)
4. `lambda/viewer_request_handler.js` (if generated by Step 2d)
5. `lambda/default_cache_origin_response.js` (if generated by Step 2f)
6. `kvs-data.json` (if kvs_requirements non-empty)
7. `functions.tf`
8. `kvs.tf` (if kvs_requirements non-empty)
9. `outputs.tf` — always write with these outputs:
   ```hcl
   output "distribution_id" {
     value = module.cdn_<sanitized_name>.distribution_id
   }
   output "domain_name" {
     value = module.cdn_<sanitized_name>.domain_name
   }
   output "hosted_zone_id" {
     value = module.cdn_<sanitized_name>.hosted_zone_id
   }
   ```
10. `main.tf`

Create all parent directories as needed.

---

### Step 8 — Self-validation

After writing all files:

1. **main.tf**: Verify every opened `{` has a matching `}`. Count opening and
   closing braces — they must match.
2. **main.tf**: Verify it contains `module "cdn_<sanitized_name>"` and does NOT
   contain `resource "aws_cloudfront_distribution"` (distribution must be in module).
3. **main.tf**: Verify `source = "../../modules/cloudfront_distribution"` is present.
4. **viewer_request.js**: Verify file size ≤ 8192 bytes. Report the actual byte
   count. If exceeded, re-trigger Step 2d escalation.
5. **viewer_request.js**: Verify `async function handler(event)` is present.
6. **viewer_request.js**: Scan for `?.` — FAIL and escalate if found.
7. **viewer_request.js**: Scan for `const [` or `let [` or `const {` or `let {`
   — FAIL and escalate if found.
8. **viewer_request.js**: Scan for `Promise.` — FAIL and escalate if found.
9. **lambda/*.js** (if present): Verify `exports.handler` is present (CommonJS
   format). Verify `import cf from 'cloudfront'` is ABSENT.
10. **Policy refs**: Verify every `data.aws_cloudfront_*_policy` block in main.tf
   has a matching policy ID in `dedup_manifest.json`, and the `name` attribute
   uses the correct prefix (`cfcdn-cache-policy-`, `cfcdn-cache-bypass-`,
   `cfcdn-orp-`, or `cfcdn-rhp-`). Report any unresolved hash.

Report a summary:
```
✓ main.tf written (<N> bytes)
✓ viewer_request.js written (<N> bytes, within 8KB limit)
✓ [lambda/origin_request_handler.js written (<N> bytes)] (if applicable)
✓ [kvs.tf + kvs-data.json written (<N> entries)] (if applicable)
All policy hashes resolved: <list of hashes>
```

On any FAIL: report specifically which check failed, what was found, and which
file needs to be fixed. Re-generate the affected file only.

---

## Reference Documents

- Module variables: `references/modules/cloudfront_distribution/variables.tf`
- Module implementation: `references/modules/cloudfront_distribution/main.tf`
- **CloudFront Functions Runtime 2.0**: `references/cloudfront/runtime2-guide.md` — complete guide to all Runtime 2.0 APIs (`rawQueryString()`, `cf.kvs()`, `cf.updateRequestOrigin()`, `cf.edgeLocation`), supported/forbidden syntax, and code patterns. **Read this before generating any JavaScript.**
- **Event structure**: `references/cloudfront/cloudfront-event-structure.md` — exact event object shape (headers, querystring, cookies format)
- **Operator conversion**: `references/cloudfront/operator-conversion.md` — Cloudflare expression operators → JS code patterns
- **URL conversion**: `references/cloudfront/conversion-examples.md` — URL field mapping, wildcard patterns, query string handling
- **Unsupported syntax**: `references/cloudfront/unsupported-syntax.md` — tested forbidden ES6+ features with evidence
- **Viewer headers**: `references/cloudfront/cloudfront-viewer-headers.md` — CloudFront viewer headers and Cloudflare→CloudFront mapping
- **KVS limits**: `references/cloudfront/kvs-usage-and-limits.md` — 5 MB store, 512 char key, 1 KB value, 1 KVS per function
- AWS provider ≥ 6.x resource docs:
  - `aws_cloudfront_function`
  - `aws_cloudfront_key_value_store`
  - `aws_acm_certificate` (data source)
- Lambda@Edge developer guide (Node.js runtime, `event.Records[0].cf` shape)
