# CloudFront Function Code Validation Checklist

This checklist must be completed before generating the deployment guide. It ensures the generated CloudFront Function code is correct, performant, and will not cause runtime errors.

## 1. Syntax Validation

Verify NO forbidden ES6+ features are used (see `unsupported-syntax.md` for details):

- [ ] No optional chaining (`?.`) - causes FunctionExecutionError
- [ ] No nullish coalescing (`??`) - causes FunctionExecutionError
- [ ] No array destructuring (`const [a,b] = arr`) - causes FunctionExecutionError
- [ ] No object destructuring (`const {prop} = obj`) - causes FunctionExecutionError
- [ ] No spread in object literals (`{...obj}`) - likely causes FunctionExecutionError
- [ ] Arrays accessed by index: `parts[0]`, `parts[1]`, not `[a,b] = parts`
- [ ] Objects accessed directly: `obj.prop`, not `{prop} = obj`
- [ ] Use conditional checks: `obj ? obj.prop : default`, not `obj?.prop ?? default`

## 2. Async Operations Validation

- [ ] No `Promise.all()` used - must use sequential `await`
- [ ] No `Promise.any()` used
- [ ] No promise chain methods (`.then()`, `.catch()`)
- [ ] All KVS lookups wrapped in `try...catch` blocks
- [ ] KVS lookups use sequential `await`, not parallel

## 3. Rule Execution Order Validation

Verify code follows Cloudflare execution order (see `cloudflare-rule-execution-order.md`):

- [ ] **Step 1**: Redirect Rules (if any) - execute first
- [ ] **Step 2**: URL Rewrites (if any) - modify `request.uri`
- [ ] **Step 3**: Bulk Redirects (if any) - check KVS with potentially rewritten URI
- [ ] **Step 4**: Request Header Transforms (if any) - modify headers last

Within each rule type:

- [ ] Rules processed in numerical order (Rule 1, Rule 2, Rule 3...)
- [ ] Order matches summary file (which matches Cloudflare JSON array order)
- [ ] First matching redirect rule returns immediately (early return)

## 4. Continent Logic Validation

- [ ] All `ip.src.continent` rules derive continent from country code
- [ ] No direct comparison of country code to continent code (e.g., `country === 'AS'` is WRONG)
- [ ] Continent codes (AS, EU, AF, NA, SA, OC, AN) are NOT used as country codes
- [ ] If hardcoded: Country arrays map to continent codes correctly
- [ ] If KVS: Keys use format `continent:{countryCode}`, values are continent codes

**Why this matters**: Cloudflare `ip.src.continent` returns continent codes (AS, EU, etc.), but CloudFront `cloudfront-viewer-country` returns country codes (CN, US, GB, etc.). You must map country → continent.

## 5. EU Country Check Validation

- [ ] EU country list is complete (27 countries): AT, BE, BG, CY, CZ, DE, DK, EE, ES, FI, FR, GR, HR, HU, IE, IT, LT, LU, LV, MT, NL, PL, PT, RO, SE, SI, SK
- [ ] Decision justified: Hardcode (recommended) or KVS (if size constrained)
- [ ] If hardcoded: Array declared correctly
- [ ] If KVS: Keys use format `eu:{countryCode}`, existence check used

**Recommendation**: Always hardcode EU list (only 162 bytes, static, frequently checked).

## 6. Bulk Redirects Validation

For each bulk redirect entry (see `bulk-redirects-handling.md`):

- [ ] Entries with `include_subdomains: false` generate exactly 1 KVS entry
- [ ] Entries with `include_subdomains: true` generate exactly 2 KVS entries
- [ ] Subdomain wildcard key format: `redirect:.{domain}{path}` (note leading dot)
- [ ] Subdomain wildcard uses domain from summary header, NOT extracted from source URL
- [ ] KVS value format: `{status}|{preserve_qs}|{target_url}`
- [ ] `preserve_qs` stored as `1` (true) or `0` (false), not "true"/"false"
- [ ] Status code stored (default 301 if not specified)
- [ ] Target URL includes protocol (https://)
- [ ] Source URL does NOT include protocol

Function lookup logic:

- [ ] Tries exact host match first: `redirect:{host}{uri}`
- [ ] Tries subdomain match if exact fails: `redirect:.{domain}{uri}`
- [ ] Subdomain extraction logic correct (handles multi-level domains)

## 7. Query String Handling Validation

For redirects with `preserve_query_string`:

- [ ] Checks if query string exists before appending
- [ ] Uses correct separator: `?` if target has no query, `&` if target already has query
- [ ] Uses `request.rawQueryString()` for simple preservation
- [ ] Handles multiValue parameters if using parsed `request.querystring`

For URL rewrites:

- [ ] Query string preserved or modified as specified in Cloudflare rule
- [ ] No accidental query string loss

## 8. Header Handling Validation

- [ ] All header names are lowercase (CloudFront requirement)
- [ ] CloudFront viewer headers accessed correctly:
  - `cloudfront-viewer-country` (not `CloudFront-Viewer-Country`)
  - `cloudfront-viewer-asn`
  - `cloudfront-viewer-city`, etc.
- [ ] "Cloudflare" replaced with "CloudFront" in header values (e.g., `X-From-CDN: CloudFront`)
- [ ] True-Client-IP uses `event.viewer.ip`, not `cloudfront-viewer-address` (which includes port)
- [ ] Header modifications happen AFTER all redirect logic (not wasted if redirecting)

## 9. KVS Decision Validation

Generate a table showing data type decisions:

| Data Type | Size Estimate | Frequently Updated? | Decision | Justification |
|-----------|---------------|---------------------|----------|---------------|
| Bulk redirects | X entries | Yes | KVS | Efficient lookup, easy updates, scalable |
| EU countries | 162 bytes (27 countries) | No | Hardcode | <1KB, static list, frequently checked |
| Asia countries | 318 bytes (53 countries) | No | Hardcode/KVS | Depends on function size |
| Continent mapping | 1170 bytes (195 countries) | No | KVS | >1KB, complete coverage |

Decision tree applied correctly:

- [ ] Data >1KB OR frequently updated → KVS
- [ ] Data <1KB AND static AND function <6KB → Hardcode
- [ ] Data <1KB AND static AND function >6KB → Move to KVS

## 10. Size Validation

- [ ] Function size calculated and reported to user
- [ ] If >6KB: Minified version generated
- [ ] If >10KB: Error reported OR data moved to KVS
- [ ] Minified version removes comments and whitespace
- [ ] Minified version shortens variable names if needed
- [ ] Size optimization techniques applied:
  - Large data moved to KVS
  - Redundant code eliminated
  - Ternary operators used where appropriate

## 11. Performance Optimization Validation

- [ ] Early returns used for redirect responses (don't process remaining rules)
- [ ] String methods preferred over regex:
  - `host.endsWith('.example.com')` not `/.*\.example\.com$/.test(host)`
  - `uri.startsWith('/path/')` not `/^\/path\//.test(uri)`
- [ ] No complex regex patterns (CPU intensive)
- [ ] No redundant checks (e.g., checking bulk redirects after already redirected)

## 12. Code Structure Validation

- [ ] Starts with: `import cf from 'cloudfront';`
- [ ] KVS initialized if needed: `const kvsHandle = cf.kvs();`
- [ ] Function signature: `async function handler(event)`
- [ ] Returns `request` object (or redirect response)
- [ ] Inline comments explain each section
- [ ] Code is readable and maintainable

## 13. Output Files Validation

- [ ] `viewer-request-function.js` generated with comments
- [ ] `viewer-request-function.min.js` generated if size >6KB
- [ ] `key-value-store.json` generated if KVS used
- [ ] KVS JSON format valid (array of objects with `key` and `value` fields)
- [ ] All KVS keys follow naming conventions (e.g., `redirect:`, `continent:`, `eu:`)

## Validation Report Template

After completing all checks and fixing any issues, generate and present this summary report to the user:

```
## Code Generation Summary

### Rules Converted
- Total rules: X
  - Redirect Rules: X
  - URL Rewrites: X
  - Bulk Redirects: X entries
  - Request Header Transforms: X

### Function Size
- Unminified: X KB
- Minified: Y KB (if applicable)
- Status: ✅ Within limits / ⚠️ Approaching limit (but functional)

### KVS Usage
- Total entries: X
- Entry types:
  - Bulk redirects: X
  - Continent mapping: X (if applicable)
  - EU countries: X (if applicable)

### KVS Decision Table
| Data Type | Size | Frequently Updated? | Decision | Justification |
|-----------|------|---------------------|----------|---------------|
| ... | ... | ... | ... | ... |

### Non-Convertible Rules
- Total: X
- List:
  1. [Rule name] - [Reason] - [CloudFront alternative]
  2. ...

### Validation Status
✅ All validation checks passed. Code is ready for deployment.
```

**Do not show validation issues to the user.** If issues are found during validation, fix them automatically and re-validate until all checks pass. Only present the final summary after successful validation.

## Common Validation Failures

### Failure 1: Optional Chaining Used

**Symptom**: Code contains `?.` operator

**Impact**: FunctionExecutionError at runtime (passes validation during deployment)

**Fix**: Replace with conditional checks
```javascript
// ❌ WRONG
const country = request.headers['cloudfront-viewer-country']?.value;

// ✅ CORRECT
const country = request.headers['cloudfront-viewer-country'] 
    ? request.headers['cloudfront-viewer-country'].value 
    : undefined;
```

### Failure 2: Array Destructuring Used

**Symptom**: Code contains `const [a, b] = array`

**Impact**: FunctionExecutionError at runtime

**Fix**: Use array indexing
```javascript
// ❌ WRONG
const [status, preserveQs, target] = redirectData.split('|');

// ✅ CORRECT
const parts = redirectData.split('|');
const status = parts[0];
const preserveQs = parts[1];
const target = parts[2];
```

### Failure 3: Country Code Used as Continent Code

**Symptom**: Code compares `country === 'AS'` or `country === 'EU'`

**Impact**: Logic never matches (AS/EU are continent codes, not country codes)

**Fix**: Derive continent from country
```javascript
// ❌ WRONG
if (country === 'AS') { ... }

// ✅ CORRECT
const asiaCountries = ['CN','JP','IN',...];
if (asiaCountries.includes(country)) { ... }
```

### Failure 4: Bulk Redirect Missing Subdomain Entry

**Symptom**: `include_subdomains: true` but only 1 KVS entry generated

**Impact**: Subdomain requests won't match redirect

**Fix**: Generate 2 entries
```json
// ✅ CORRECT
{"key": "redirect:example.com/path", "value": "301|1|https://..."},
{"key": "redirect:.example.com/path", "value": "301|1|https://..."}
```

### Failure 5: Wrong Rule Execution Order

**Symptom**: Header transforms before redirects, or bulk redirects before URL rewrites

**Impact**: Wasted CPU, incorrect behavior

**Fix**: Follow execution order
1. Redirect Rules
2. URL Rewrites
3. Bulk Redirects
4. Request Header Transforms

### Failure 6: Function Size Exceeds 10KB

**Symptom**: Function size >10KB

**Impact**: Cannot deploy

**Fix**: 
1. Generate minified version
2. Move large data to KVS
3. Remove redundant code
4. Shorten variable names
