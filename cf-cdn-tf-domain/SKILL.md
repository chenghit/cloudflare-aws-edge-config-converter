---
name: cf-cdn-tf-domain
description: >
  Main Terraform generator for a single CDN domain. Reads the domain's final IR
  YAML (ir_final/<hostname>.yaml) and the shared dedup manifest, then emits all
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

| Logical name | Resolved path |
|---|---|
| Workspace root | `/home/chencch/.openclaw/workspace/cf-converter` |
| Domain IR (input) | `<workspace>/cloudflare-to-aws-cdn/ir/ir_final/<hostname>.yaml` |
| Dedup manifest (read-only) | `<workspace>/cloudflare-to-aws-cdn/ir/shared/dedup_manifest.json` |
| Domain scope | `<workspace>/cloudflare-to-aws-cdn/ir/domain_scope.json` |
| Output directory | `<workspace>/cloudflare-to-aws-cdn/terraform/domains/<sanitized-hostname>/` |
| Shared module source | `../../modules/cloudfront_distribution` (relative, for Terraform `source`) |

**Sanitized hostname**: replace `.` and `-` with `_`, lowercase.
Example: `cdn.c.example.com` → `cdn_c_example_com`.

---

## Output Directory

```
cloudflare-to-aws-cdn/terraform/domains/<sanitized-hostname>/
  main.tf                   ← aws_cloudfront_distribution (always)
  functions.tf              ← aws_cloudfront_function resources (always)
  kvs.tf                    ← KVS store + data (only if kvs_requirements non-empty)
  kvs-data.json             ← bulk redirect seed data (only if kvs_requirements non-empty)
  lambda/                   ← only if lambda_edge in IR is non-null
    origin_request_handler.js   ← only if lambda_edge.origin_request is set
    viewer_request_handler.js   ← only if lambda_edge.viewer_request is set (last resort)
```

---

## Workflow

### Step 0 — Read reference documents first

Before generating any code, read:

1. `<workspace>/cf-cdn-ir-builder/SKILL.md` — understand the IR schema, field
   names, and what viewer_request_ops / origin_request_ops contain.
2. `<workspace>/cloudflare-to-aws-cdn/ir/ir_final/<hostname>.yaml` — the actual
   domain IR you will process.
3. `<workspace>/cloudflare-to-aws-cdn/ir/shared/dedup_manifest.json` — to
   resolve policy hashes to Terraform resource addresses.
4. `<workspace>/cloudflare-to-aws-cdn/ir/domain_scope.json` — global settings
   such as default origin, WAF ACL ARN, logging bucket, tags, etc.

If any of files 2–4 is missing, halt and report the missing path.

---

### Step 1 — Parse inputs and derive identifiers

From the IR YAML, extract the following top-level fields (non-exhaustive; read
the IR schema for the full list):

```
hostname:              cdn.c.example.com
sanitized_name:        cdn_c_example_com        # computed
cert_arn:              "arn:aws:acm:..." | ""   # blank → Pattern B
origin_domain:         my-origin.example.com
origin_protocol:       https | http
cache_policy_hash:     a3f2b1c4
origin_request_policy_hash: ...
response_headers_policy_hash: ...
viewer_request_ops:    [ ... ]
origin_request_ops:    [ ... ]   # from IR; may be empty
kvs_requirements:      [ ... ]   # may be empty
lambda_edge:           null | { origin_request: ..., viewer_request: ... }
geo_restriction:       none | whitelist | blacklist
geo_locations:         [...]
price_class:           PriceClass_All | PriceClass_100 | PriceClass_200
waf_acl_arn:           "arn:..." | null
logging_bucket:        "..." | null
aliases:               [ "cdn.c.example.com" ]
default_root_object:   "" | "index.html"
http_version:          http2 | http2and3
ipv6_enabled:          true | false
```

Derive:
- `tf_resource_name` = `cdn_c_example_com` (same as sanitized_name)
- `cache_policy_ref` = `aws_cloudfront_cache_policy.policy_<cache_policy_hash>.id`
  (or `policy_bypass_<hash>` for bypass policies; check `dedup_manifest.json`)
- `orp_ref` = `aws_cloudfront_origin_request_policy.policy_<orp_hash>.id`
  (or null if no ORP hash in IR)
- `rhp_ref` = `aws_cloudfront_response_headers_policy.policy_<rhp_hash>.id`
  (or null if no RHP hash in IR)

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
    port: <443|80>,
    protocol: "<https|http>",
    path: "<prefix_path_or_empty_string>"
  });
}
```

**4. bulk_redirects** — if `kvs_requirements` is non-empty AND bulk_redirect ops exist:

```javascript
// bulk_redirects via KVS
const kvsHandle = cf.kvs();
const lookupKey = 'redirect:' + request.uri;
let kvsValue = null;
try {
  kvsValue = await kvsHandle.get(lookupKey);
} catch (e) {
  // key not found — continue
}
if (kvsValue !== null) {
  const parts = kvsValue.split('|');
  const statusCode = parseInt(parts[0], 10);
  const preserveQS = parts[1] === 'true';
  let target = parts[2];
  if (preserveQS && request.querystring) {
    target = target + '?' + request.querystring;
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
- ❌ NEVER use `Promise.all`, `Promise.any`, `.then()`, `.catch()`
- ✅ Use `const` and `let` (not `var`)
- ✅ Use template literals `` `${expr}` ``
- ✅ Use arrow functions `(x) => x`
- ✅ Use `for...of` loops
- ✅ Use `await` sequentially
- First line MUST be: `import cf from 'cloudfront';`
- Handler MUST be: `async function handler(event) {`
- Handler MUST end with: `return request;` (or an early return with statusCode)

#### 2b. Size check and escalation

After generating the draft, calculate the byte count of the draft string.

**Decision tree**:

```
draft size ≤ 6KB?
  → YES: use as-is, write to functions/<hostname>_viewer_request.js
  → NO:  minify (Step 2c)

After minification:
  minified size ≤ 10KB?
    → YES: write minified to functions/<hostname>_viewer_request.js
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
2. Replace `functions/<hostname>_viewer_request.js` with a minimal pass-through:
   ```javascript
   import cf from 'cloudfront';
   async function handler(event) {
     return event.request;
   }
   ```
   (This minimal function still needs to exist because it may be associated in
   main.tf; alternatively, omit the CloudFront Function association entirely and
   use Lambda@Edge alone — prefer omitting the CFF association if Lambda@Edge
   covers all behaviour.)

**Target**: viewer_request.js ≤ 8 KB (leave 2 KB buffer from 10 KB hard limit).

#### 2e. Lambda@Edge file format

Lambda@Edge files use Node.js CommonJS or ESM syntax (NOT CloudFront Functions
Runtime 2.0 syntax):

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

---

### Step 3 — Generate `functions.tf`

This file declares all `aws_cloudfront_function` resources. One function per
`.js` file in the `functions/` directory that is not a pass-through.

```hcl
# AUTO-GENERATED by cf-cdn-tf-domain skill
# DO NOT EDIT MANUALLY

resource "aws_cloudfront_function" "<sanitized_name>_viewer_request" {
  name    = "cfcdn-<sanitized_name>-viewer-request"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = file("${path.module}/functions/<hostname>_viewer_request.js")
}
```

If a viewer_request function file exists (non-trivial), generate the resource.
If only a pass-through exists and Lambda@Edge covers all behaviour, omit the
CloudFront Function resource (do not reference an empty function).

If there are origin_request ops handled at CFF level (not escalated to Lambda),
add a second resource for origin_request similarly.

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

Only generate if `kvs_requirements` is non-empty.

Collect all bulk redirect entries from `viewer_request_ops` where type ==
`bulk_redirect`. For each entry:
- `key`: `"redirect:<source_path>"`
- `value`: `"<status_code>|<preserve_querystring>|<target>"`
  - `preserve_querystring`: `"true"` or `"false"`

```json
{
  "data": [
    { "key": "redirect:/old-path", "value": "301|false|/new-path" },
    { "key": "redirect:/promo",    "value": "302|true|/sale" }
  ]
}
```

Write to: `<output_dir>/kvs-data.json`

---

### Step 6 — Generate `main.tf`

This is the core CloudFront distribution definition.

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

Wildcard domain derivation: if hostname is `cdn.c.example.com`, the wildcard
is `*.c.example.com`. If hostname is a bare apex `example.com`, use `example.com`.

#### 6b. Distribution resource

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

resource "aws_cloudfront_distribution" "<sanitized_name>" {
  aliases             = [<quoted list of aliases>]
  comment             = "CDN for <hostname> — migrated from Cloudflare"
  default_root_object = "<default_root_object>"
  enabled             = true
  http_version        = "<http_version>"
  is_ipv6_enabled     = <true|false>
  price_class         = "<price_class>"
  wait_for_deployment = false

  # ── Origin ──────────────────────────────────────────────────────────────────
  origin {
    domain_name = "<origin_domain>"
    origin_id   = "primary"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "<origin_protocol>-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # ── Default cache behaviour ──────────────────────────────────────────────────
  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "primary"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = "<cache_policy_ref>"
    <# only include orp line if orp_ref is non-null #>
    origin_request_policy_id   = "<orp_ref>"
    <# only include rhp line if rhp_ref is non-null #>
    response_headers_policy_id = "<rhp_ref>"

    <# CloudFront Function associations — include only if functions exist #>
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.<sanitized_name>_viewer_request.arn
    }

    <# Lambda@Edge associations — include only if lambda_edge is non-null in IR #>
    lambda_function_association {
      event_type   = "origin-request"
      lambda_arn   = "<lambda_arn_placeholder>"
      include_body = false
    }
  }

  # ── Restrictions ──────────────────────────────────────────────────────────────
  restrictions {
    geo_restriction {
      restriction_type = "<none|whitelist|blacklist>"
      <# omit locations line if restriction_type == "none" #>
      locations        = [<sorted quoted list of country codes>]
    }
  }

  # ── Viewer certificate ────────────────────────────────────────────────────────
  viewer_certificate {
    <# Pattern A: #>
    acm_certificate_arn      = local.cert_arn_<sanitized_name>
    <# Pattern B: #>
    acm_certificate_arn      = data.aws_acm_certificate.<sanitized_name>.arn

    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  <# WAF — only include if waf_acl_arn is non-null #>
  web_acl_id = "<waf_acl_arn>"

  <# Logging — only include if logging_bucket is non-null #>
  logging_config {
    bucket          = "<logging_bucket>"
    include_cookies = false
    prefix          = "<hostname>/"
  }

  tags = {
    ManagedBy   = "terraform"
    MigratedFrom = "cloudflare"
    Domain      = "<hostname>"
  }
}
```

**Important rules**:
- Remove every comment line (lines starting with `<#`) from the actual output —
  they are instructions to you, not Terraform HCL.
- Include only the blocks and attributes that are relevant (non-null, non-empty).
- `origin_protocol_policy` must be exactly `"https-only"` or `"http-only"` or
  `"match-viewer"` (not `"https"` or `"http"`).
- For `geo_restriction`, if `restriction_type == "none"`, the `locations` list
  MUST be omitted (Terraform will error if both `none` and locations are present).
- The `lambda_arn_placeholder` for Lambda@Edge is intentionally a placeholder
  string (`"REPLACE_WITH_DEPLOYED_LAMBDA_ARN"`) with a comment instructing the
  operator to fill it in after deploying the Lambda function. This is because
  Lambda@Edge ARNs include the function version and cannot be predicted at
  generation time.

---

### Step 7 — Write all files

Write files in this order:
1. `functions/<hostname>_viewer_request.js` (always, unless omitted per Step 2e)
2. `lambda/origin_request_handler.js` (if generated)
3. `lambda/viewer_request_handler.js` (if generated)
4. `kvs-data.json` (if kvs_requirements non-empty)
5. `functions.tf`
6. `kvs.tf` (if kvs_requirements non-empty)
7. `main.tf`

Create all parent directories as needed.

---

### Step 8 — Self-validation

After writing all files:

1. **main.tf**: Verify every opened `{` has a matching `}`. Count opening and
   closing braces — they must match.
2. **viewer_request.js**: Verify file size ≤ 8192 bytes. Report the actual byte
   count. If exceeded, re-trigger Step 2d escalation.
3. **viewer_request.js**: Verify first line is exactly `import cf from 'cloudfront';`
4. **viewer_request.js**: Verify `async function handler(event)` is present.
5. **viewer_request.js**: Scan for `?.` — FAIL and escalate if found.
6. **viewer_request.js**: Scan for `const [` or `let [` or `const {` or `let {`
   — FAIL and escalate if found.
7. **viewer_request.js**: Scan for `Promise.` — FAIL and escalate if found.
8. **lambda/*.js** (if present): Verify `exports.handler` or `export const handler`
   is present. Verify `import cf from 'cloudfront'` is ABSENT.
9. **Policy refs**: Verify every policy hash referenced in main.tf actually
   exists in `dedup_manifest.json`. Report any unresolved hash.

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

- IR schema: `<workspace>/cf-cdn-ir-builder/SKILL.md`
- Dedup manifest: `<workspace>/cloudflare-to-aws-cdn/ir/shared/dedup_manifest.json`
- Shared policies Terraform: `<workspace>/cloudflare-to-aws-cdn/terraform/shared/policies.tf`
- Domain scope: `<workspace>/cloudflare-to-aws-cdn/ir/domain_scope.json`
- AWS provider ≥ 6.x resource docs:
  - `aws_cloudfront_distribution`
  - `aws_cloudfront_function`
  - `aws_cloudfront_key_value_store`
  - `aws_acm_certificate` (data source)
- CloudFront Functions Runtime 2.0 developer guide (JavaScript constraints)
- Lambda@Edge developer guide (Node.js runtime, `event.Records[0].cf` shape)
