---
name: "cloudflare-to-cloudfront-functions-converter"
displayName: "Cloudflare to CloudFront Functions Converter"
description: "Converts Cloudflare transformation rules (redirects, URL rewrites, header modifications, bulk redirects) to AWS CloudFront Functions JavaScript Runtime 2.0"
keywords: ["cloudflare transform", "cloudfront function", "redirect", "url rewrite", "header modification", "header transform", "bulk redirects"]
---

# Cloudflare to CloudFront Functions Converter

Convert Cloudflare transformation rules to CloudFront Functions (JavaScript Runtime 2.0).

## Path Resolution

**Steering files**: Reference files in this power's `steering/` directory
- `steering/field-mapping.md`
- `steering/cloudfront-function-limits.md`
- `steering/cloudfront-event-structure.md`
- `steering/cloudfront-viewer-headers.md`
- `steering/cloudfront-helper-methods.md`
- `steering/kvs-usage-and-limits.md`
- `steering/bulk-redirects-handling.md`
- `steering/convertible-rules.md`
- `steering/non-convertible-rules.md`
- `steering/continent-countries.md`
- `steering/conversion-examples.md`
- `steering/cloudflare-rule-execution-order.md`
- `steering/validation-checklist.md`
- `steering/unsupported-syntax.md`

**User data**: Cloudflare configuration files provided by user (e.g., `./cloudflare_config/`)

When reading reference documentation, use relative paths like `steering/xxx.md`.
When reading user's Cloudflare configs, use the path provided by user.

## Scope

This power converts **transformation rules only**, not security rules:

**In Scope:**
- Redirect Rules
- URL Rewrite Rules
- Request Header Transform Rules
- Bulk Redirects
- Managed Transforms (True-Client-IP only)

**Out of Scope (use Cloudflare to AWS WAF power instead):**
- WAF rules
- Rate limiting rules
- IP access rules
- Firewall rules
- Bot management rules

## Core Principles

Read these references before conversion:
- `steering/cloudflare-rule-execution-order.md` - **CRITICAL**: Cloudflare rule execution order (must follow this order in generated code)
- `steering/cloudfront-function-limits.md` - All constraints (10KB size, 2MB memory, ~1ms execution)
- `steering/cloudfront-event-structure.md` - Event object structure
- `steering/cloudfront-viewer-headers.md` - Available viewer headers
- `steering/cloudfront-helper-methods.md` - Runtime 2.0 helper methods
- `steering/kvs-usage-and-limits.md` - Key Value Store usage
- `steering/bulk-redirects-handling.md` - **CRITICAL**: Bulk redirects processing rules

**CRITICAL constraints**:
- Do NOT use optional chaining (`?.`) or array/object destructuring
- Use sequential `await`, not `Promise.all()`
- Optimize for CPU efficiency (avoid complex regex)

**CRITICAL: Understanding URL Handling Differences**

Cloudflare and CloudFront handle URLs fundamentally differently:

**Key differences**:
1. **Redirect Rules & Bulk Redirects**: Have explicit `preserve_query_string` parameter
2. **CloudFront Functions**: Always split URL into 4 parts (protocol, host, uri, querystring)

**Conversion rules**:
- Redirect Rules → Check `preserve_query_string` flag, append if true
- Bulk Redirects → Check `preserve_query_string` in KVS value
- Single Redirects (wildcard) → Reconstruct path + query for `${1}`, `${2}`, etc.

**See `steering/conversion-examples.md` for detailed code examples.**

## Workflow

### 1. Obtain Cloudflare Configuration

Ask user to provide Cloudflare configuration directory path.

**If user doesn't have configuration files yet:**

Recommend using the standalone backup tool: https://github.com/chenghit/CloudflareBackup

This tool safely exports Cloudflare configuration to local JSON files. Once backed up, user should provide the directory path.

**If a summary file already exists** in the user's Cloudflare configuration directory (e.g., `cloudflare-transformation-rules-summary.md`), ask the user:
> "I found an existing summary file. Would you like to:
> 1. Use the existing summary and proceed directly to CloudFront Function generation
> 2. Re-analyze the Cloudflare configuration files and generate a new summary"

### 2. Read Configuration Files

**CRITICAL: Robust file discovery - never assume file locations, always search and verify**

**Step 2.1: Discover and validate user data directory**

Ask user for Cloudflare configuration directory path. Then use glob patterns to recursively search for all required files:

```bash
# Search for all relevant configuration files
find {user_provided_path} -name "*.txt" -type f 2>/dev/null
find {user_provided_path} -name "*.json" -type f 2>/dev/null
```

**Step 2.2: Discover configuration structure**

Use glob patterns to find:
- Zone-specific directories: `**/*/Redirect-Rules.txt` (parent dir is zone)
- Account-level directories: `**/*/Bulk-Redirect-Rules.txt` (parent dir is account)
- Bulk redirect lists: `**/List-Items-redirect-*.txt`

**Step 2.3: Check for duplicates and validate**

For each file type, check for duplicates:
```bash
# Example: Check for duplicate redirect rules
find {user_provided_path} -name "Redirect-Rules.txt" -type f 2>/dev/null
```

**If duplicates found**: Stop and ask user to resolve - which file to use or merge them.

**Step 2.4: Read discovered files**

Read all discovered files by category:

**Zone-specific files** (search pattern: `**/*/filename.txt`):
- `Redirect-Rules.txt` - Redirect rules
- `URL-Rewrite-Rules.txt` - URL rewrite rules  
- `Request-Header-Transform.txt` - Request header transformation rules
- `Response-Header-Transform.txt` - Response header transformation rules
- `Managed-Transforms.txt` - True-Client-IP configuration

**Account-level files** (search pattern: `**/*/filename.txt`):
- `Bulk-Redirect-Rules.txt` - Bulk redirect rule definitions

**Bulk redirect lists** (search pattern: `**/List-Items-redirect-*.txt`):
- ALL files matching pattern (multiple may exist)

**Step 2.5: Handle missing files gracefully**

For each expected file type:
- If found: Read and process
- If missing: Log as "File not found: {filename} - skipping this rule type"
- Continue processing other files (don't fail entire conversion)

**Step 2.6: Verify bulk redirect completeness**

If `Bulk-Redirect-Rules.txt` exists:
- Parse to find all referenced list IDs
- Search for corresponding `List-Items-redirect-{id}.txt` files
- If any referenced lists are missing: Log warning but continue

### 3. Convert to Cloudflare Rule Expressions

**Before conversion, you MUST:**
- Read `steering/convertible-rules.md` to understand which rules can be converted
- Read `steering/non-convertible-rules.md` to understand which rules cannot be converted and why
- Read `steering/field-mapping.md` section "Device Detection" to identify device detection rules

Convert JSON configurations to Cloudflare rule expressions following [Cloudflare Rules Language](https://developers.cloudflare.com/ruleset-engine/rules-language/) specifications.

**CRITICAL: Cloudflare concat()**

`concat()` prepends, does not replace:
- `concat("/prefix", http.request.uri.path)` → `/prefix/old/page` (from `/old/page`)
- Do NOT strip the original path

**CRITICAL: Device Detection Rules Check**

Identify and exclude device detection rules in Request Header Transform Rules:

**Patterns**:
- Rules that add headers like `X-Is-Mobile`, `X-Is-Desktop`, `X-Is-Tablet`, `X-Is-SmartTV` based on User-Agent
- Rules that check `http.user_agent` and set device type headers
- Any header transformation that replicates device detection logic

**Non-convertible because**:
- CloudFront provides native device detection headers via Origin Request Policy
- No function code needed
- More efficient than User-Agent parsing

**CloudFront native headers**:
- `CloudFront-Is-Mobile-Viewer`
- `CloudFront-Is-Desktop-Viewer`
- `CloudFront-Is-Tablet-Viewer`
- `CloudFront-Is-SmartTV-Viewer`
- `CloudFront-Is-Android-Viewer`
- `CloudFront-Is-IOS-Viewer`

**Action**: Mark these rules as non-convertible with explanation to use Origin Request Policy.

### 4. Generate Markdown Summary

Output a Markdown file (`cloudflare-transformation-rules-summary.md`) with:

1. **Convertible Rules** (organized by category):
   - Bulk Redirects
   - Redirect Rules
   - URL Rewrite Rules
   - Request Header Transform Rules
   - Managed Transforms (True-Client-IP)

**CRITICAL: Preserve Rule Order Within Each Category**

Within each rule type (Redirect Rules, URL Rewrites, etc.), the `rules` array order in the JSON configuration represents the execution order. When listing rules in the summary:
- Maintain the exact array order from the JSON
- Number rules sequentially (Rule 1, Rule 2, Rule 3...)
- This order MUST be preserved when generating CloudFront Function code

Example: If Redirect Rules JSON has 7 rules in array positions [0-6], list them as Rule 1-7 in that exact order.

2. **Non-Convertible Rules**:
   - List each rule
   - Explain why (reference `non-convertible-rules.md`)
   - Provide CloudFront alternatives

**Response Header Transform Rules**:
- Read but NOT automatically converted
- CloudFront Functions are able to modify response headers in viewer-response events. However, for cacheable objects (PDFs, images, static files): Lambda@Edge origin-response is more cost-effective
  - CloudFront Functions run on EVERY request (including cache hits)
  - Lambda@Edge origin-response runs only on cache misses
- List as "Requires Manual Conversion" with cost analysis

Ask user to confirm completeness and correctness.

### 5. Generate CloudFront Function Code

**Before generation, you MUST:**
1. Read `steering/field-mapping.md` completely to understand Cloudflare to CloudFront field mappings
2. Read `steering/cloudflare-rule-execution-order.md` completely to understand Cloudflare rule execution order (must follow this order in generated code)
3. Read `steering/cloudfront-helper-methods.md` for available helper methods
4. Read `steering/bulk-redirects-handling.md` for bulk redirect KVS generation rules
5. Read `steering/unsupported-syntax.md` for forbidden JavaScript syntax
6. Ask user for custom function name (default: `cloudflare-migrated-viewer-request`)

**CRITICAL: Continent Matching Logic**

When converting Cloudflare rules that use `ip.src.continent`:

1. **Understand the data types**:
   - Cloudflare `ip.src.continent` returns: `AS`, `EU`, `AF`, `NA`, `SA`, `OC`, `AN` (continent codes)
   - CloudFront provides: `cloudfront-viewer-country` (country codes like `CN`, `US`, `GB`)
   - **You MUST derive continent from country code - they are different data types**

2. **NEVER directly compare country code to continent code**:
   ```javascript
   // ❌ WRONG - Comparing country code to continent code
   if (country === 'AS' && uri.startsWith('/path')) {
   
   // ❌ WRONG - 'EU' is a continent code, not a country code
   if (country === 'EU' && uri.startsWith('/path')) {
   
   // ✅ CORRECT - Derive continent from country first
   const asiaCountries = ['CN','JP','IN',...];
   const isAsia = country && asiaCountries.includes(country);
   if (isAsia && uri.startsWith('/path')) {
   ```

3. **KVS vs Hardcode Decision**

Apply this decision tree for all data types:

```
Is data >1KB OR frequently updated?
├─ Yes → Use KVS
└─ No → Is function size >6KB?
   ├─ Yes → Move data to KVS
   └─ No → Hardcode (better performance)
```

**Continent size reference** (for quick estimation):
- EU: 50 countries (~300 bytes) | AS: 53 (~318 bytes) | AF: 56 (~336 bytes)
- NA: 36 (~216 bytes) | SA: 14 (~84 bytes) | OC: 25 (~150 bytes)

**Common cases**:
- **Bulk redirects**: Always KVS (efficient lookup, easy updates, scalable)
- **Single continent** (<100 countries, <600 bytes): Hardcode
- **2-3 continents** (100-150 countries, <900 bytes): Hardcode if function <6KB, else KVS
- **4+ continents or global**: Use KVS

**CRITICAL: Bulk Redirects Processing**

For each bulk redirect entry, you MUST:
1. Check `include_subdomains` parameter (default: false)
   - If `false`: Generate 1 KVS entry with exact host
   - If `true`: Generate 2 KVS entries (exact host + subdomain with leading dot)
2. Check `preserve_query_string` parameter (default: false)
3. Check `status_code` parameter (default: 301)
4. Store in KVS value format: `{status}|{preserve_qs}|{target_url}`
   - Use `1` for true, `0` for false (saves characters)
   - Example: `301|1|https://example.com/new`

**CRITICAL: Subdomain Wildcard Key Generation**

When `include_subdomains: true`, you must generate the subdomain wildcard key correctly:

**The subdomain wildcard key is: `.{domain}{path}` where `{domain}` is the Cloudflare domain from the summary file header.**

**DO NOT extract domain from source URL** - always use the domain from summary header.

Example with 2-level domain:
```
Summary header: **Domain**: example.com

Bulk redirect: source_url "example.com/about", include_subdomains: true
Generate:
1. Exact: "redirect:example.com/about"
2. Wildcard: "redirect:.example.com/about"
```

Example with 3-level domain:
```
Summary header: **Domain**: app.example.com

Bulk redirect: source_url "app.example.com/about", include_subdomains: true
Generate:
1. Exact: "redirect:app.example.com/about"
2. Wildcard: "redirect:.app.example.com/about"

❌ WRONG: "redirect:.example.com/about" ← Extracted from source URL, missing "app"
```

**Why this matters**:
- Cloudflare domain can have any number of levels (2, 3, 4, etc.)
- The domain in the summary header is the authoritative source
- Always prepend a dot to the FULL domain from the header

**Example**:
```json
// Cloudflare entry with include_subdomains: true
{
  "source_url": "example.com/old",
  "target_url": "https://example.com/new",
  "status_code": 301,
  "include_subdomains": true,
  "preserve_query_string": true
}

// Must generate TWO KVS entries:
{"key": "redirect:example.com/old", "value": "301|1|https://example.com/new"},
{"key": "redirect:.example.com/old", "value": "301|1|https://example.com/new"}
```

After user confirms, execute in order:

1. **Generate CloudFront Function JavaScript Runtime 2.0 code** (`viewer-request-function.js`):
   - Must start with: `import cf from 'cloudfront';`
   - Add inline comments explaining what each section does
   - Review against all limits in `cloudfront-function-limits.md`

2. **Generate KVS file** (if needed): `key-value-store.json` (see `kvs-usage-and-limits.md`)

3. **Calculate and report function size**

4. **Generate minified version** (MANDATORY if >6KB):
   - File: `viewer-request-function.min.js`
   - Remove comments and whitespace
   - Shorten variable names if needed
   - Move hardcoded data to KVS if needed

**Code requirements:**
- NO optional chaining (`?.`) or destructuring
- Prefer using `endsWith()`, `startsWith()` over regex
- Replace "Cloudflare" with "CloudFront" in header values (e.g., `X-From-CDN: CloudFront`)
- Wrap KVS in `try...catch`, use sequential `await`
- Access arrays by index: `parts[0]`, `parts[1]`
- Use conditionals: `obj ? obj.prop : default`

### 6. Validate and Fix Generated Code

**MUST complete validation before proceeding to Step 7.**

Read and apply `steering/validation-checklist.md` completely. This checklist covers:

1. **Syntax validation** - No forbidden ES6+ features (optional chaining, destructuring, etc.)
2. **Async operations** - Sequential await, no Promise.all()
3. **Rule execution order** - Redirect Rules → URL Rewrites → Bulk Redirects → Header Transforms
4. **Continent logic** - Derive from country code, never compare country to continent code
5. **EU country check** - Complete 27-country list, hardcode recommended
6. **Bulk redirects** - Correct KVS entry generation (1 or 2 entries per rule)
7. **Query string handling** - Preserve/append logic correct
8. **Header handling** - Lowercase names, correct CloudFront viewer headers
9. **KVS decision** - Data size and update frequency justify KVS vs hardcode
10. **Size validation** - Function <10KB, minified version if >6KB
11. **Performance optimization** - Early returns, string methods over regex
12. **Code structure** - Correct imports, function signature, returns
13. **Output files** - All required files generated with correct format

**Validation workflow**:
1. Run all validation checks against generated code
2. **If issues found**: Fix them immediately and re-run validation
3. **Repeat until all checks pass** - Do not proceed with issues
4. Once validation passes, generate summary report for user

**Present final summary report** (see template in validation-checklist.md):
- Total rules converted by type
- Function size (unminified and minified)
- KVS usage and decision table
- Non-convertible rules list
- Validation status: ✅ All checks passed

### 7. Generate Deployment Guide

Create `README_function_and_kvs_deployment.md` with ONLY these 5 sections:

1. **Create Key Value Store** (if needed): Upload JSON to S3, create KVS with S3 import (Console + CLI)
2. **Create CloudFront Function**: Create function, upload code, associate KVS (Console + CLI)
3. **Test the Function**: Console testing with 2-3 test event examples
4. **Publish and Associate**: Publish function, associate with distribution behavior
5. **Non-Converted Rules**: List each rule with brief explanation and CloudFront alternative

**CRITICAL - DO NOT include**:
- Monitoring or CloudWatch instructions
- How to update KVS after deployment
- Troubleshooting sections
- Best practices sections
- Cost estimation details
- Verification steps beyond testing

## Output Files

1. **Summary**: `cloudflare-transformation-rules-summary.md` - Human-readable conversion summary
2. **Function Code**: `viewer-request-function.js` - Main function with comments
3. **Minified Code**: `viewer-request-function.min.js` - Size-optimized version (if needed)
4. **Key Value Store**: `key-value-store.json` - KVS data (if needed)
5. **Deployment Guide**: `README_function_and_kvs_deployment.md` - Step-by-step instructions (function and KVS deployment only, no CDN policy configuration)

## Final Checklist

Before delivering files to user, verify:

**Function Code:**
- [ ] Has inline comments explaining each section
- [ ] No `?.`, no destructuring, no `Promise.all()`
- [ ] KVS lookups use sequential `await` with `try...catch`
- [ ] Bulk redirects with `include_subdomains: true` generate 2 KVS entries
- [ ] Size reported to user

**Minified Version:**
- [ ] Generated if size >6KB
- [ ] Comments and whitespace removed
- [ ] Variable names shortened if needed
- [ ] Hardcoded data moved to KVS if needed

**Deployment Guide:**
- [ ] Contains ONLY 5 sections (KVS, Function, Test, Publish, Non-Converted)
- [ ] NO monitoring, updating, troubleshooting, cost, or verification sections

## Important Notes

1. **CloudFront-Viewer-Address**: Format is `ip:port`, not `ip`
2. **True-Client-IP**: Only Managed Transform to convert; ignore others
3. **HTTP→HTTPS Redirects**: Do not convert; use CloudFront distribution settings
4. **Header Removal**: Do not convert; use CloudFront origin request policy
5. **Device Detection Headers**: Do not convert; use CloudFront viewer headers in origin request policy
6. **URL Normalization**: Do not convert; CloudFront natively supports it.

## Code Generation Rules

**CRITICAL**: When generating CloudFront Function code, you MUST follow these rules:

### ❌ DO NOT USE These Syntax Features

1. **Optional Chaining (`?.`)**
   ```javascript
   // ❌ WRONG - Will cause runtime error
   const country = request.headers['cloudfront-viewer-country']?.value;
   
   // ✅ CORRECT
   const country = request.headers['cloudfront-viewer-country'] 
       ? request.headers['cloudfront-viewer-country'].value 
       : undefined;
   ```

2. **Array Destructuring**
   ```javascript
   // ❌ WRONG - Will cause runtime error
   const [status, preserveQs, target] = redirectData.split('|');
   
   // ✅ CORRECT
   const parts = redirectData.split('|');
   const status = parts[0];
   const preserveQs = parts[1];
   const target = parts[2];
   ```

3. **Object Destructuring**
   ```javascript
   // ❌ WRONG - Will cause runtime error
   const { value } = request.headers.host;
   
   // ✅ CORRECT
   const value = request.headers.host.value;
   ```

### ✅ Safe to Use

- `const` and `let` declarations
- Template literals (backticks)
- Arrow functions
- `async/await`
- Traditional array indexing
- Ternary operators
- Logical operators (`&&`, `||`)

## Reference Files

Read these references as needed during conversion:

- `steering/cloudfront-function-limits.md` - Size, memory, execution time limits
- `steering/cloudfront-event-structure.md` - Event object structure
- `steering/cloudfront-viewer-headers.md` - Available CloudFront headers
- `steering/cloudfront-helper-methods.md` - Runtime 2.0 helper methods
- `steering/kvs-usage-and-limits.md` - Key Value Store usage and limits
- `steering/bulk-redirects-handling.md` - Bulk redirects processing rules
- `steering/convertible-rules.md` - Rules that can be converted
- `steering/non-convertible-rules.md` - Rules requiring manual intervention
- `steering/field-mapping.md` - Cloudflare to CloudFront field mappings
- `steering/continent-countries.md` - Country-to-continent mapping
- `steering/conversion-examples.md` - Detailed URL conversion code examples
- `steering/cloudflare-rule-execution-order.md` - Cloudflare rule execution order (must follow this order in generated code)