# Design: Replace CDN JS Generation and Validation with Python

Author: chenghit
Date: 2026-04-16
Status: Draft (v3 — post-review-2 + AWS/CF verification)
Branch: `feat/cdn-js-python-codegen`

## Problem

CDN pipeline Stages 8 and 9 use LLM subagents to generate and validate CloudFront Function JavaScript. This is the last major LLM bottleneck in the CDN pipeline — Stages 3–7.6 were already replaced with deterministic Python scripts.

### Current performance

For the example config (7 proxied domains, 34 CDN rules):
- Stage 8 (JS generation): ~15 min at batch size 2 (~2 min per domain)
- Stage 9 (JS validation): ~10 min at batch size 2
- **Total: ~25 min for 7 domains**

For a 50-domain zone: ~50 min for Stage 8 alone at batch size 2.

### Why LLM is overkill here

The JS generation work is almost entirely **template filling and deterministic mapping**:

1. **Condition → JS if statement**: The IR contains structured conditions (parsed by `cdn_expr_parser.py`) with a fixed field→accessor mapping table. LLM is just looking up a table.
2. **Action → JS code**: 6 action types (redirect, rewrite, origin_override, header mutation, bulk_redirect, serve_error_inline) each have a fixed JS template. LLM fills in values.
3. **Dynamic expressions**: Only 3 functions appear in action parameters: `concat()`, `regex_replace()`, `wildcard_replace()`. All have fixed translation rules to JS.

The only part that genuinely benefits from LLM is `raw_expression` handling — when `cdn_expr_parser.py` can't parse the condition (currently ~21% of rules in the example config, all due to OR expressions or complex regex). This can be eliminated by upgrading the parser to a full recursive descent parser.

### Data from example config (33 CDN rules)

| Category | Count | % | Python can handle? |
|---|---|---|---|
| Condition: parsed (structured) | 26 | 78% | ✅ Already parsed |
| Condition: raw_expression (OR, regex) | 7 | 21% | ✅ After parser upgrade |
| Action: static value | 21 | 64% | ✅ Template fill |
| Action: `concat()` | 4 | 12% | ✅ Deterministic |
| Action: `regex_replace()` | 5 | 15% | ✅ Deterministic |
| Action: `wildcard_replace()` | 3 | 9% | ✅ Deterministic |
| Action: nested `concat(regex_replace(...))` | 1 | 3% | ✅ Recursive parse |

**100% of rules in the example config can be handled by Python.**

### Cloudflare dynamic expression functions — complete inventory

From [Cloudflare docs](https://developers.cloudflare.com/ruleset-engine/rules-language/functions/), the functions available in rewrite/redirect/header expressions are:

| Function | Used in example? | JS equivalent | Complexity |
|---|---|---|---|
| `concat(a, b, ...)` | ✅ Yes (4×) | `a + b + ...` | Low |
| `regex_replace(field, pat, repl)` | ✅ Yes (5×) | `field.replace(/pat/, repl)` | Low |
| `wildcard_replace(field, pat, repl)` | ✅ Yes (3×) | `field.replace(/glob→regex/, repl)` | Medium |
| `lower(field)` | ❌ No (in action) | `field.toLowerCase()` | Low |
| `upper(field)` | ❌ No (in action) | `field.toUpperCase()` | Low |
| `to_string(field)` | ❌ No | `String(field)` | Low |
| `substring(field, start[, end])` | ❌ No | `field.substring(start, end)` | Low |
| `len(field)` | ❌ No (in action) | `field.length` | Low |
| `url_decode(field)` | ❌ No | `decodeURIComponent(field)` | Low |
| `encode_base64(field)` | ❌ No | Not available in CFF Runtime 2.0 → MANUAL_REQUIRED |
| `decode_base64(field)` | ❌ No | Not available in CFF Runtime 2.0 → MANUAL_REQUIRED |
| `lookup_json_string(field, key, ...)` | ❌ No | `JSON.parse(field)[key]` — but CFF has no `JSON.parse` → MANUAL_REQUIRED |
| `lookup_json_integer(field, key, ...)` | ❌ No | Same as above → MANUAL_REQUIRED |
| `remove_bytes(field, bytes)` | ❌ No | `field.replace(/[charclass]/g, '')` — build regex char class from bytes | Low |
| `split(field, sep)` | ❌ No | `field.split(sep)` | Low |
| `join(items, sep)` | ❌ No | `items.join(sep)` | Low |
| `remove_query_args(field, args)` | ❌ No | Custom JS (parse + filter query string) | Medium |
| `sha256(field)` | ❌ No | Not available in CFF → MANUAL_REQUIRED |
| `hmac(...)` | ❌ No | Not available in CFF → MANUAL_REQUIRED |

**Critical constraint from Cloudflare docs**: `concat()`, `regex_replace()`, and `wildcard_replace()` can each appear **only once** in a rewrite expression. Additionally, `regex_replace()` and `wildcard_replace()` **cannot be nested** inside each other. They CAN be nested inside `concat()`.

This means the nesting complexity is bounded:
- `concat(literal, field, regex_replace(...), literal)` — valid, max depth
- `regex_replace(concat(...), ...)` — **invalid** per Cloudflare docs
- `wildcard_replace(regex_replace(...), ...)` — **invalid** per Cloudflare docs

The only valid nesting pattern is `concat()` wrapping other functions as arguments.

## Solution

Replace Stages 8 and 9 with deterministic Python scripts.

### What changes

| Component | Current | New |
|-----------|---------|-----|
| Stage 8: JS generation | LLM subagent (`cf-cdn-tf-domain`) per domain | Python script (`cdn-generate-js.py`) for all domains |
| Stage 9: JS validation | LLM subagent (`cf-cdn-js-validator`) per domain | Python script (`cdn-validate-js.py`) for all domains |
| Expression parsing | `cdn_expr_parser.py` (regex-based, ~78% parse rate) | Upgraded with `parse_expression_full()` (~100% parse rate) |

### What stays the same

- Stages 1–2: LLM subagents (DNS parsing, input validation)
- Stages 3–7.6: Python scripts (no change)
- Stage 7.5: Terraform scaffold generation (no change)
- IR schema: no change
- Output directory structure: no change

### What gets deleted

- `cf-cdn-tf-domain/` subagent + all reference docs (7 files)
- `cf-cdn-js-validator/` subagent + all reference docs (2 files)
- `subagents/cf-cdn-tf-domain.json`
- `subagents/cf-cdn-js-validator.json`

## Expression parser upgrade

### Current consumers of `cdn_expr_parser.py`

Before modifying the parser, here are all current consumers (must not break):

| Script | Functions used | Output format dependency |
|---|---|---|
| `cdn-preprocess.py` | `parse_expression()`, `split_or()`, `extract_orp_headers()`, `extract_host_filter()`, `extract_path_pattern_single()`, `extract_kvs_triggers()` | `{"field": "uri.path", "op": "eq", "value": "/api"}` (mapped field names) |
| `cdn-finalize.py` | `extract_orp_headers_from_raw()` | Raw expression string scanning |
| `cdn-generate-tests.py` | (none — reads IR, not expressions) | N/A |

**Critical**: `parse_expression()` returns `(condition, raw_expression)` where exactly one is non-None. All downstream scripts handle both cases. The existing interface MUST NOT change.

### Upgrade approach

Add a new function `parse_expression_full()` alongside the existing `parse_expression()`:

```python
def parse_expression_full(expr: str) -> dict:
    """Full recursive descent parse. Returns conditions tree.
    Never returns raw_expression — raises ParseError on failure."""
```

This function:
- Uses a recursive descent parser (shared tokenizer with `waf_expr_parser.py`)
- Returns the **same output format** as existing `parse_expression()` conditions (`{"field": "uri.path", "op": "eq", "value": "/api"}`)
- Handles OR, nested AND/OR, NOT, all operators
- Raises `ParseError` on truly unparseable expressions (instead of returning `raw_expression`)

The existing `parse_expression()` remains unchanged — Stages 3–7.6 continue to use it.

### Consistency check

To ensure `parse_expression()` and `parse_expression_full()` agree on expressions they both can parse:

```python
def _verify_consistency(expr):
    """For expressions parseable by both, verify they produce equivalent trees."""
    old_cond, old_raw = parse_expression(expr)
    if old_raw is not None:
        return  # Old parser can't handle this — no comparison needed
    new_cond = parse_expression_full(expr)
    assert _trees_equivalent(old_cond, new_cond), f"Parser inconsistency on: {expr}"
```

Run this on all expressions during development/testing. Not needed at runtime.

## Dynamic expression parser

### Grammar

```
dyn_expr     = func_call | field_ref | string_literal
func_call    = func_name "(" arg ("," arg)* ")"
func_name    = "concat" | "regex_replace" | "wildcard_replace" | "lower" | "upper"
             | "to_string" | "substring" | "len" | "url_decode" | "split" | "join"
             | "remove_query_args" | "remove_bytes"
arg          = dyn_expr | string_literal | number | raw_string
field_ref    = cloudflare_field_name  (e.g., http.request.uri.path)
```

### Nesting constraints (from Cloudflare docs)

- `concat()` can contain any other function as arguments
- `regex_replace()` and `wildcard_replace()` CANNOT be nested inside each other
- `regex_replace()` and `wildcard_replace()` can each appear only once per expression
- Other functions (`lower()`, `upper()`, `to_string()`, `substring()`) can nest freely

### Output format

```python
# concat("/eu", http.request.uri.path)
{"func": "concat", "args": [
    {"type": "literal", "value": "/eu"},
    {"type": "field", "value": "http.request.uri.path"}
]}

# regex_replace(http.request.uri.path, "^/old/(.*)", "/new/${1}")
{"func": "regex_replace", "args": [
    {"type": "field", "value": "http.request.uri.path"},
    {"type": "literal", "value": "^/old/(.*)"},
    {"type": "literal", "value": "/new/${1}"}
]}

# concat("<https://", http.host, regex_replace(...), ">; rel=\"canonical\"")
{"func": "concat", "args": [
    {"type": "literal", "value": "<https://"},
    {"type": "field", "value": "http.host"},
    {"type": "func_call", "value": {"func": "regex_replace", "args": [...]}},
    {"type": "literal", "value": ">; rel=\"canonical\""}
]}
```

### JS conversion (deterministic)

| Function | JS output |
|---|---|
| `concat(a, b, ...)` | `a + b + ...` (each arg converted recursively) |
| `regex_replace(field, pat, repl)` | `field.replace(/pat/, repl)` — `${N}` → `$N` in replacement |
| `wildcard_replace(field, pat, repl)` | `field.replace(/glob_to_regex(pat)/, repl)` — `*` → `(.*)`, `${N}` → `$N` |
| `lower(field)` | `field.toLowerCase()` |
| `upper(field)` | `field.toUpperCase()` |
| `to_string(field)` | `String(field)` |
| `substring(field, start, end)` | `field.substring(start, end)` |
| `url_decode(field)` | `decodeURIComponent(field)` |
| `split(field, sep)` | `field.split(sep)` |
| `join(items, sep)` | `items.join(sep)` |
| `remove_query_args(field, ...)` | Custom: parse query string, filter, rejoin |
| `remove_bytes(field, bytes)` | `field.replace(/[charclass]/g, '')` — parse each byte in `bytes` arg into a JS regex character class, escape regex-special chars |
| `encode_base64`, `decode_base64`, `sha256`, `hmac` | → `MANUAL_REQUIRED` (not available in CFF Runtime 2.0) |
| `lookup_json_string`, `lookup_json_integer` | → `MANUAL_REQUIRED` (CFF has no JSON.parse) |
| `remove_bytes` | `field.replace(/[charclass]/g, '')` — build char class from byte args | ✅ |

Field references in dynamic expressions use the same CDN field mapping table as conditions.

## JS code generation (`cdn-generate-js.py`)

### Input/Output

- Input: `cloudflare-to-aws-cdn/ir/final/<hostname>.json` for each domain
- Processes **all domains** in a single invocation
- Output: JS files in `cloudflare-to-aws-cdn/terraform/domains/<sanitized>/functions/` and `lambda/`

### viewer_request.js template

```javascript
import cf from 'cloudfront';
// KVS initialization (only if kvs_requirements non-empty)
const kvsHandle = cf.kvs('<KVS_ID>');

async function handler(event) {
  const request = event.request;

  // --- SECTION 1: redirects ---
  // --- SECTION 2: rewrites ---
  // --- SECTION 3: origin_override ---
  // --- SECTION 4: bulk_redirects ---
  // --- SECTION 5: header mutations ---
  // --- SECTION 6: serve_error_inline ---

  return request;
}
```

### viewer_response.js template

Only generated if any cache behavior has non-empty `viewer_response_ops`.

```javascript
async function handler(event) {
  const response = event.response;
  const request = event.request;  // available in viewer-response

  // --- header mutations (set/add/remove on response.headers) ---

  return response;
}
```

Key differences from viewer_request:
- Operates on `event.response`, not `event.request`
- `import cf from 'cloudfront'` only if KVS used (rare in response handler)
- Header mutations target `response.headers` not `request.headers`
- No redirects, rewrites, origin_override, or bulk_redirects
- `event.viewer.ip` is available (confirmed by AWS docs)

### Condition → JS mapping

Same table as `cf-cdn-tf-domain/SKILL.md` Step 2a, implemented as a Python dict:

```python
FIELD_TO_JS = {
    "uri.path": "request.uri",
    "uri": "request.uri",
    "uri.query": "request.rawQueryString()",
    "host": "request.headers.host.value",
    "method": "request.method",
    "user_agent": ("request.headers['user-agent']", True),  # (accessor, needs_existence_check)
    "country": ("request.headers['cloudfront-viewer-country']", True),
    "ip.src": "event.viewer.ip",
    # ... full table
}

OP_TO_JS = {
    "eq": lambda acc, val: f"{acc} === {js_string(val)}",
    "ne": lambda acc, val: f"{acc} !== {js_string(val)}",
    "contains": lambda acc, val: f"{acc}.includes({js_string(val)})",
    "starts_with": lambda acc, val: f"{acc}.startsWith({js_string(val)})",
    "ends_with": lambda acc, val: f"{acc}.endsWith({js_string(val)})",
    "in": lambda acc, val: f"{js_array(val)}.includes({acc})",
    "wildcard": lambda acc, val: wildcard_to_js(acc, val),
    "matches": lambda acc, val: f"/{cf_regex_to_js(val)}/.test({acc})",
}
```

### Action type → JS code

| Type | JS pattern |
|---|---|
| `redirect` | `return { statusCode: N, headers: { location: { value: target } } }` |
| `rewrite` | `request.uri = new_path` |
| `origin_override` | `cf.updateRequestOrigin({ domainName: host, ... })` |
| `set_header` | `request.headers["name"] = { value: val }` |
| `add_header` | `if (!request.headers["name"]) { request.headers["name"] = { value: val } }` |
| `remove_header` | `delete request.headers["name"]` |
| `bulk_redirect` | KVS lookup template (~30 lines, fixed) |
| `serve_error_inline` | KVS get + synthetic response |

### Size check and Lambda@Edge escalation

After generating viewer_request.js, check byte count:

**Decision tree** (from `cf-cdn-tf-domain/SKILL.md` Step 2b–2d):

1. If total size ≤ 10,240 bytes → write as CloudFront Function. Done.
2. If total size > 10,240 bytes:
   a. Check if `origin_override` ops exist. If yes → move ALL origin_override ops to `lambda/origin_request_handler.js`. Remove from CFF. Re-check CFF size.
   b. If CFF still > 10,240 bytes after removing origin_override → mark domain as `SIZE_EXCEEDED`, write a comment in JS, record in validation report.
3. If Lambda@Edge origin_request is generated:
   - Update `functions.tf`: replace `LAMBDA_EDGE_PLACEHOLDER` comment with Lambda@Edge resource blocks
   - The placeholder replacement uses a fixed Terraform template (same as `cdn-generate-tf-scaffold.py` output format)

**Lambda@Edge origin_response handler** (Step 2f in SKILL.md):
- If `metadata.lambda_edge.origin_response` is non-null → copy template from `references/lambda/default-cache-origin-response.js`, fill in custom error response mappings
- This is a fixed template, no dynamic generation needed

### CloudFront Function syntax constraints

Enforced during generation (not just validation):

- ❌ No optional chaining (`?.`)
- ❌ No destructuring (`const { a } = ...`, `const [a] = ...`)
- ❌ No `Promise.all`, `.then()`, `.catch()`
- ✅ `const`, `let` (not `var`)
- ✅ Template literals
- ✅ Arrow functions
- ✅ `for...of`
- ✅ Sequential `await`
- First line: `import cf from 'cloudfront';` (if KVS or updateRequestOrigin used)
- Handler: `async function handler(event) {`
- Must end with `return request;` or `return response;`

Since Python generates the JS, these constraints are guaranteed by construction — the templates don't use forbidden syntax.

## JS validation (`cdn-validate-js.py`)

### Checks

1. **Forbidden syntax** (regex scan):
   - `?.` → optional chaining
   - `const {` / `let {` → object destructuring
   - `const [` / `let [` → array destructuring
   - `Promise.all` / `Promise.any` / `.then(` / `.catch(`

2. **Required structure** (string check):
   - `import cf from 'cloudfront'` present if KVS or updateRequestOrigin used
   - `async function handler(event)` present
   - `return request;` or `return response;` present

3. **IR coverage** (per-op check):
   - Each redirect op → `statusCode` + `location` in JS
   - Each rewrite op → `request.uri =` in JS
   - Each origin_override op → `updateRequestOrigin` in JS
   - Each header op → header name in JS
   - bulk_redirect → `kvsHandle.get('redirect:` in JS
   - serve_error_inline → KVS key in JS

4. **KVS consistency**:
   - IR has `kvs_requirements` → `cf.kvs()` in JS
   - No `kvs_requirements` → no `cf.kvs()` in JS

5. **Size limit**:
   - CFF: ≤ 10,240 bytes
   - Lambda@Edge: ≤ 1 MB

### Output

`cloudflare-to-aws-cdn/ir/validation/js/<hostname>-v3.json` (same format as current LLM validator output)

## Pipeline changes

### Current Stages 8–9 (~90 lines in orchestrator SKILL.md)

```
Stage 8:  For each domain:
            Invoke cf-cdn-tf-domain (LLM)
          Verify output files exist per domain
          Re-invoke on missing files
Stage 9:  For each domain:
            Invoke cf-cdn-js-validator (LLM)
          Check validation reports
          Auto-retry on FAIL: delete JS, re-scaffold, re-invoke tf-domain, re-validate
```

### New Stages 8–9 (~10 lines in orchestrator SKILL.md)

```
Stage 8:  python3 cdn-generate-js.py "cloudflare-to-aws-cdn"
          Check ---RESULT--- block
Stage 9:  python3 cdn-validate-js.py "cloudflare-to-aws-cdn"
          Check ---RESULT--- block
```

## Verification strategy

### Diff against LLM output

Before shipping, run both pipelines on the example config and diff:

1. Run current LLM pipeline → save JS files as `js-llm/`
2. Run new Python pipeline → save JS files as `js-python/`
3. For each domain, compare:
   - Same sections present (redirects, rewrites, etc.)
   - Same conditions (may differ in formatting but must be semantically equivalent)
   - Same action logic (redirect targets, rewrite paths, origin hosts)
   - Same KVS initialization

Exact character-level match is NOT expected (LLM output varies). Semantic equivalence is the goal.

### Unit tests

- Parser: all 33 expressions from example config
- Dynamic expression parser: all 12 dynamic expressions from example config
- JS codegen: each action type with representative conditions
- Validation: positive (valid JS) and negative (inject forbidden syntax) cases

## Implementation plan

### Phase 1: Parser upgrade + JS codegen + validation

- Shared tokenizer extraction (or inline in `cdn_expr_parser.py`)
- `parse_expression_full()` — recursive descent, CDN field mapping, handles OR/NOT/nested
- `parse_dynamic_expression()` — parses `concat`/`regex_replace`/`wildcard_replace` with nesting
- `cdn-generate-js.py` — reads all domain IRs, generates all JS files
  - Condition → JS (full mapping table)
  - Dynamic expression → JS (3 core functions + fallback for rare functions)
  - 6 action type templates
  - viewer_request.js + viewer_response.js generation
  - Size check + Lambda@Edge escalation
  - Lambda@Edge origin_response handler (template copy)
  - `functions.tf` LAMBDA_EDGE_PLACEHOLDER replacement
- `cdn-validate-js.py` — validates all domain JS files
  - 5 check categories
  - Per-domain v3.json report output
- Unit tests with example config
- Diff verification against LLM output

### Phase 2: Orchestrator + cleanup

- Updated orchestrator `SKILL.md` — Stages 8–9 use Python scripts
- Updated `install.sh` — remove CDN JS subagent installation
- Delete `cf-cdn-tf-domain/` and `cf-cdn-js-validator/` subagents
- Delete `subagents/cf-cdn-tf-domain.json` and `subagents/cf-cdn-js-validator.json`
- Updated docs (README, deployment guide)

Both phases must be complete for the project to ship.

## Risk assessment

### Low risk
- Condition → JS mapping: deterministic, well-defined table, identical to SKILL.md
- Static action templates: fixed patterns, no ambiguity
- Validation checks: regex/string matching
- Parser upgrade: proven architecture from WAF

### Medium risk
- `wildcard_replace()` with multiple `*` capture groups: need to correctly number `(.*)` groups and map `${N}` → `$N`. Test with all 3 wildcard_replace examples.
- Nested `concat(regex_replace(...))`: 1 case in example config (Response-Header-Transform SEO rule). Parser must handle recursive function arguments.
- Lambda@Edge escalation: size threshold + ops splitting + functions.tf modification. Port logic precisely from SKILL.md Step 2b–2d.

### Low probability, high impact
- `encode_base64()`, `lookup_json_string()`, `sha256()` in customer configs: these have no CFF equivalent. Flagged as MANUAL_REQUIRED — same as current LLM behavior (LLM also can't convert these).
- `remove_query_args()`: medium complexity JS generation (parse query string, filter, rejoin). Implement if encountered; flag as MANUAL_REQUIRED initially.

### Mitigated by design
- Existing `parse_expression()` unchanged → Stages 3–7.6 unaffected
- Consistency check between old and new parser during testing
- MANUAL_REQUIRED fallback for any unparseable expression → explicit, not silent
- Diff verification against LLM output before shipping

## Estimated line count

| Component | Lines | Notes |
|---|---|---|
| Parser upgrade (`parse_expression_full`) | ~150 | Recursive descent, reuse tokenizer patterns |
| Dynamic expression parser | ~150 | `concat`/`regex_replace`/`wildcard_replace` + nesting |
| `cdn-generate-js.py` | ~700–900 | 6 action types + conditions + dynamic exprs + L@E escalation |
| `cdn-validate-js.py` | ~150 | 5 check categories |
| **Total** | **~1,150–1,350** | |

## v3 Corrections (from AWS/Cloudflare verification)

### Correction 1: wildcard_replace uses LAZY matching (HIGH — semantic correctness)

Cloudflare docs explicitly state: "This function uses lazy matching, that is, it tries to match each `*` metacharacter with the shortest possible string."

Example: `wildcard_replace(path, "/apps/*/login", "/${1}/login")` on `/apps/calendar/admin/login`:
- Cloudflare (lazy): `*` matches `calendar` → result: `/calendar/login`
- JS `(.*)` (greedy): `*` matches `calendar/admin` → result: `/calendar/admin/login` ❌

**Fix**: Use `(.*?)` (lazy quantifier) instead of `(.*)` in the glob-to-regex conversion for `wildcard_replace`. Note: the `wildcard` **operator** (used in conditions) matches the entire field value, so greedy vs lazy doesn't matter there — only `wildcard_replace` is affected.

### Correction 2: wildcard_replace has optional `flags` parameter

`wildcard_replace(source, pattern, replacement, flags)` — the 4th parameter `flags` can be `"s"` for case-sensitive matching. Default (no flags) is **case-insensitive**.

**Fix**: Dynamic expression parser must handle 4th argument. JS conversion:
- No flags or flags != "s" → add `/i` flag to regex: `source.replace(/pattern/i, replacement)`
- flags == "s" → no `/i` flag: `source.replace(/pattern/, replacement)`

### Correction 3: wildcard_replace matches ENTIRE source value

Cloudflare docs: "the entire source value must match the wildcard_pattern parameter (it cannot match only part of the field value)."

**Fix**: Always anchor the regex with `^` and `$`: `source.replace(/^pattern$/i, replacement)`

### Correction 4: CFF Runtime 2.0 supports btoa/atob and JSON.parse

Both AWS subagents confirmed:
- `btoa()` / `atob()` — ✅ supported (new in Runtime 2.0)
- `JSON.parse()` / `JSON.stringify()` — ✅ supported
- `Buffer.from()` with base64 encoding — ✅ supported

**Impact on design**: `encode_base64()` and `decode_base64()` can be converted to `btoa()`/`atob()` instead of MANUAL_REQUIRED. `lookup_json_string()` and `lookup_json_integer()` can be converted to `JSON.parse()` + key access.

Updated function table:

| Function | Previous status | Updated status | JS equivalent |
|---|---|---|---|
| `encode_base64(field)` | MANUAL_REQUIRED | ✅ Convertible | `btoa(field)` |
| `decode_base64(field)` | MANUAL_REQUIRED | ✅ Convertible | `atob(field)` |
| `lookup_json_string(field, key, ...)` | MANUAL_REQUIRED | ✅ Convertible | `JSON.parse(field)[key]` (chain for nested keys) |
| `lookup_json_integer(field, key, ...)` | MANUAL_REQUIRED | ✅ Convertible | `JSON.parse(field)[key]` (same, returns number) |
| `sha256(field)` | MANUAL_REQUIRED | ✅ Convertible | `require('crypto').createHash('sha256').update(field).digest('hex')` |
| `uuidv4(seed)` | Not listed | MANUAL_REQUIRED | No `crypto.randomUUID()` in CFF. Workaround: `Math.random()` based UUID (not cryptographically secure). Flag in README. |
| `remove_bytes(field, bytes)` | MANUAL_REQUIRED | ✅ Convertible | `field.replace(/[charclass]/g, '')` — parse bytes into regex character class |

### Correction 5: regex_replace is case-sensitive by default

Cloudflare docs: "Match is case-sensitive by default: `regex_replace("/foo", "^/FOO$", "/x") == "/foo"`"

JS `String.replace(/regex/, repl)` is also case-sensitive by default. ✅ Behavior matches — no flag needed.

But: do NOT add `/i` flag to regex_replace conversions. Only wildcard_replace (without "s" flag) needs `/i`.

### Correction 6: regex_replace only replaces first match

Cloudflare docs: "When there are multiple matches, only one replacement occurs (the first one)."

JS `String.replace(/regex/, repl)` without `g` flag also only replaces the first match. ✅ Behavior matches.

**Explicit rule**: NEVER add `g` flag to regex in `regex_replace` conversion.

### Correction 7: Response event structure

AWS subagents confirmed:
- `response.statusCode` — correct property name (integer, not string)
- `response.status` does NOT exist
- `event.viewer.ip` is available in viewer-response events

viewer_response.js field mapping additions:

| Cloudflare field | JS accessor (viewer_response) |
|---|---|
| `http.response.code` | `response.statusCode` |
| `http.response.headers["name"]` | `response.headers["name"].value` |
| `cf.response.1xxx_code` | Not available in CFF → MANUAL_REQUIRED |
| `cf.response.error_type` | Not available in CFF → MANUAL_REQUIRED |

### Correction 8: lower()/upper() can nest inside concat()

Confirmed by real-world examples: `concat("https://", http.host, lower(regex_replace(...)))`.

Dynamic expression parser must handle `lower()` and `upper()` as valid arguments inside `concat()`. The parser already supports recursive `func_call` in args — just need to add `lower` and `upper` to the recognized function names in the dynamic expression parser (they're already in the condition parser).

### Correction 9: url_decode options parameter

`url_decode(field, options)` — options can be `"r"` (recursive) or `"u"` (Unicode).

- `url_decode(field)` → `decodeURIComponent(field)` ✅
- `url_decode(field, "r")` → recursive decode: `while (decoded !== prev) { prev = decoded; decoded = decodeURIComponent(decoded); }` — implement as helper function
- `url_decode(field, "u")` → Unicode decode: `decodeURIComponent(field)` handles Unicode by default in JS ✅

### Correction 10: uuidv4() function

`uuidv4(cf.random_seed)` can appear in request header transform value expressions (e.g., setting X-Request-ID header).

CFF has no `crypto.randomUUID()`. Options:
1. Generate UUID v4 using `Math.random()` (not cryptographically secure but functional)
2. Flag as MANUAL_REQUIRED with note to use Lambda@Edge for secure UUIDs

**Decision**: Implement Math.random()-based UUID v4 as default, add comment in generated JS warning it's not cryptographically secure. Record in conversion_report.md.

### Correction 11: Maximum function size

AWS docs say "10 KB" without specifying exact bytes. Use 10,240 bytes (1 KB = 1,024 bytes) as the threshold, consistent with current SKILL.md.

### Correction 12: CFF crypto module

CFF Runtime 2.0 has a built-in `crypto` module (Node.js-style, not Web Crypto):
- `crypto.createHash('sha256')` → `.update(data).digest('hex'|'base64')`
- `crypto.createHmac('sha256', key)` → `.update(data).digest('hex'|'base64')`

This means Cloudflare's `sha256()` function CAN be converted (not MANUAL_REQUIRED as originally assumed).

### Updated complete function conversion table

| Cloudflare function | JS equivalent in CFF Runtime 2.0 | Status |
|---|---|---|
| `concat(a, b, ...)` | `a + b + ...` | ✅ |
| `regex_replace(field, pat, repl)` | `field.replace(/pat/, repl)` — no `g` flag, no `i` flag | ✅ |
| `wildcard_replace(field, pat, repl[, flags])` | `field.replace(/^glob_regex$/[i], repl)` — lazy `(.*?)`, `i` unless flags=="s" | ✅ |
| `lower(field)` | `field.toLowerCase()` | ✅ |
| `upper(field)` | `field.toUpperCase()` | ✅ |
| `to_string(field)` | `String(field)` | ✅ |
| `substring(field, start[, end])` | `field.substring(start, end)` | ✅ |
| `len(field)` | `field.length` | ✅ |
| `url_decode(field)` | `decodeURIComponent(field)` | ✅ |
| `url_decode(field, "r")` | Recursive decodeURIComponent loop | ✅ (helper function) |
| `encode_base64(field)` | `btoa(field)` | ✅ (Runtime 2.0) |
| `decode_base64(field)` | `atob(field)` | ✅ (Runtime 2.0) |
| `lookup_json_string(field, key, ...)` | `JSON.parse(field)[key]...` | ✅ (Runtime 2.0) |
| `lookup_json_integer(field, key, ...)` | `JSON.parse(field)[key]...` | ✅ (Runtime 2.0) |
| `sha256(field)` | `require('crypto').createHash('sha256').update(field).digest('hex')` | ✅ (Runtime 2.0) |
| `split(field, sep)` | `field.split(sep)` | ✅ |
| `join(items, sep)` | `items.join(sep)` | ✅ |
| `remove_query_args(field, ...)` | Custom: parse QS, filter, rejoin | ✅ (helper function) |
| `uuidv4(seed)` | Math.random()-based UUID v4 (with warning) | ⚠️ Functional but not crypto-secure |
| `remove_bytes(field, bytes)` | `field.replace(/[charclass]/g, '')` — parse byte args into regex char class | ✅ |
| `is_timed_hmac_valid_v0(...)` | Condition-only (WAF), not in CDN actions | N/A |
| `any()` / `all()` | Condition-only, not in CDN actions | N/A |
| `cidr()` / `cidr6()` | WAF-only | N/A |
| `has_key()` / `has_value()` | Condition-only | N/A |
| `bit_slice()` | Network firewall only | N/A |

**Result**: All Cloudflare functions are either convertible or not applicable to CDN action expressions. Zero MANUAL_REQUIRED. This is a significant improvement over the v2 estimate of 5 MANUAL_REQUIRED functions.

## v3b Corrections (from review-3)

### Correction 13: import crypto vs require('crypto')

CFF Runtime 2.0 supports both `require('crypto')` and `import crypto from 'crypto'`. Since the JS template already uses `import cf from 'cloudfront'` (ES module style), all imports should be consistent:

```javascript
import cf from 'cloudfront';
import crypto from 'crypto';  // only if sha256/hmac functions used
```

Place all imports at the top of the file. Never mix `import` and `require` in the same file.

### Correction 14: sha256() returns Bytes, not hex string

Cloudflare's `sha256()` returns a `Bytes` value. When used standalone, the result is typically passed to another function (e.g., `encode_base64(sha256(field))`).

JS conversion rules:
- `sha256(field)` standalone (rare) → `crypto.createHash('sha256').update(field).digest()` (returns Buffer)
- `encode_base64(sha256(field))` → optimize to `crypto.createHash('sha256').update(field).digest('base64')` (single call)
- `encode_base64(sha256(field), "u")` → `crypto.createHash('sha256').update(field).digest('base64url')`

The dynamic expression parser should detect the `encode_base64(sha256(...))` pattern and emit the optimized single-call form. This is a peephole optimization in the JS codegen, not the parser.

### Correction 15: encode_base64 flags parameter

`encode_base64(input, flags)` — flags is optional:
- No flags → standard Base64 without padding: `btoa(field).replace(/=+$/, '')`
- `"p"` → standard Base64 with padding: `btoa(field)`
- `"u"` → URL-safe Base64 without padding: `Buffer.from(field).toString('base64url')`
- `"up"` → URL-safe Base64 with padding: `Buffer.from(field).toString('base64url')` + manual padding

Note: `btoa()` always includes padding. Cloudflare's default (no flags) does NOT include padding. So the default case needs `.replace(/=+$/, '')`.

Simplest implementation using Buffer (available in Runtime 2.0):
- No flags → `Buffer.from(field, 'utf8').toString('base64').replace(/=+$/, '')`
- `"p"` → `Buffer.from(field, 'utf8').toString('base64')`
- `"u"` → `Buffer.from(field, 'utf8').toString('base64url')`
- `"up"` → `Buffer.from(field, 'utf8').toString('base64url')` + pad to multiple of 4 with `=`

### Correction 16: hmac table entry sync

Remove `hmac(...)` → `MANUAL_REQUIRED` from the function table. The only HMAC function in Cloudflare is `is_timed_hmac_valid_v0()`, which is a WAF condition function (not a CDN action expression function). Already correctly marked as N/A in the final table.

### Correction 17: lookup_json_string multi-level key access

`lookup_json_string(field, key1, key2, ...)` supports:
- String keys: `lookup_json_string(field, "product", "id")` → `JSON.parse(field)["product"]["id"]`
- Integer keys (array index): `lookup_json_string(field, "networks", 1)` → `JSON.parse(field)["networks"][1]`
- Mixed: `lookup_json_string(field, 1, "product_id")` → `JSON.parse(field)[1]["product_id"]`

Dynamic expression parser must:
1. Accept variable number of arguments (2+) for `lookup_json_string` and `lookup_json_integer`
2. Each key argument can be a string literal or integer

JS codegen:
```javascript
// lookup_json_string(http.request.body.raw, "product", "id")
(() => { try { return JSON.parse(requestBody)["product"]["id"]; } catch(e) { return ''; } })()

// lookup_json_integer(http.request.body.raw, "networks", 0)
(() => { try { return JSON.parse(requestBody)["networks"][0]; } catch(e) { return 0; } })()
```

Wrap in try-catch IIFE because:
- `JSON.parse()` throws on invalid JSON
- Property access on `undefined` throws
- Cloudflare returns empty string/0 on failure; JS should match this behavior

### Updated MANUAL_REQUIRED count

After all corrections: **zero** MANUAL_REQUIRED functions. `remove_bytes()` is convertible via regex character class. Everything is either convertible or N/A for CDN action expressions.

## v3c: Exhaustive branch definitions for JS codegen

This section defines every if/elif branch the Python codegen must handle. No "as appropriate" — every case is explicit.

### A. Wildcard condition → JS (all pattern types)

The `wildcard` operator in conditions matches the **entire** field value (case-insensitive). The `strict_wildcard` variant is case-sensitive.

Python classification function:

```python
def wildcard_to_js(accessor, pattern, strict=False):
    """Convert wildcard pattern to optimal JS code."""
    stars = pattern.count('*')
    escaped_stars = pattern.count('\\*')
    real_stars = stars - escaped_stars

    if real_stars == 0:
        # No wildcards — exact match
        if strict:
            return f"{accessor} === {js_string(pattern)}"
        return f"{accessor}.toLowerCase() === {js_string(pattern.lower())}"

    if pattern == '*':
        # Match everything
        return 'true'

    if real_stars == 1:
        if pattern.endswith('*') and '*' not in pattern[:-1]:
            # Prefix match: "/api/*" → startsWith("/api/")
            prefix = pattern[:-1]
            if strict:
                return f"{accessor}.startsWith({js_string(prefix)})"
            return f"{accessor}.toLowerCase().startsWith({js_string(prefix.lower())})"

        if pattern.startswith('*') and '*' not in pattern[1:]:
            # Suffix match: "*.jpg" → endsWith(".jpg")
            suffix = pattern[1:]
            if strict:
                return f"{accessor}.endsWith({js_string(suffix)})"
            return f"{accessor}.toLowerCase().endsWith({js_string(suffix.lower())})"

    # All other patterns (middle *, multiple *, complex) → regex
    regex = wildcard_pattern_to_regex(pattern)
    flags = '' if strict else 'i'
    return f"/{regex}/{flags}.test({accessor})"


def wildcard_pattern_to_regex(pattern):
    """Convert wildcard pattern to anchored regex string.
    Escapes regex metacharacters, replaces * with .*"""
    result = '^'
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == '\\' and i + 1 < len(pattern) and pattern[i+1] == '*':
            result += '\\*'  # literal *
            i += 2
        elif ch == '*':
            result += '.*'
            i += 1
        elif ch in r'\.+?^${}()|[]':
            result += '\\' + ch
            i += 1
        else:
            result += ch
            i += 1
    result += '$'
    return result
```

### B. full_uri wildcard splitting

`http.request.full_uri wildcard r"https://*.example.com/files/*"` must be split into host + path components because CloudFront Functions don't have a single "full URI" accessor.

Splitting rules:

```python
def split_full_uri_wildcard(pattern):
    """Split full_uri wildcard into (host_pattern, path_pattern) or None.

    Returns:
        (host_pattern, path_pattern) if splittable
        None if not splittable (use regex on reconstructed full_uri)
    """
    # Strip r"..." or "..." wrapper
    p = pattern.strip()
    if p.startswith('r"') or p.startswith("r'"):
        p = p[2:-1]
    elif p.startswith('"') or p.startswith("'"):
        p = p[1:-1]

    # Must start with http:// or https://
    m = re.match(r'https?://', p)
    if not m:
        return None  # not a full URI pattern

    rest = p[m.end():]  # everything after protocol://

    # Find the first / after the host part
    slash_idx = rest.find('/')
    if slash_idx == -1:
        # No path — host-only pattern
        return rest, '/*'

    host_part = rest[:slash_idx]
    path_part = rest[slash_idx:]

    return host_part, path_part
```

JS codegen for split full_uri:
```python
def full_uri_wildcard_to_js(host_pattern, path_pattern, strict=False):
    host_js = wildcard_to_js("request.headers.host.value", host_pattern, strict)
    path_js = wildcard_to_js("request.uri", path_pattern, strict)

    if host_js == 'true':
        return path_js
    if path_js == 'true':
        return host_js
    return f"({host_js} && {path_js})"
```

If `split_full_uri_wildcard` returns None (unusual pattern like `http*://...`), fall back to regex on reconstructed full URI:
```javascript
const fullUri = `https://${request.headers.host.value}${request.uri}`;
if (/^http.*:\/\/.*$/i.test(fullUri)) { ... }
```

### C. `not_` prefix operators

`cdn_expr_parser.py` outputs negated operators as `not_eq`, `not_contains`, etc. The JS codegen must handle every `not_` variant:

```python
def condition_to_js(cond):
    field = cond['field']
    op = cond['op']
    value = cond['value']

    # Handle not_ prefix
    negated = False
    if op.startswith('not_'):
        negated = True
        op = op[4:]  # strip "not_"

    js_expr = _positive_condition_to_js(field, op, value)

    if negated:
        # For header fields that need existence check, negation logic differs:
        # "not user_agent contains X" → !ua || !ua.value.includes(X)
        # (if header doesn't exist, NOT condition is true)
        if _needs_existence_check(field):
            accessor, header_ref = _get_accessor_with_check(field)
            positive = _positive_op_to_js(f"{header_ref}.value", op, value)
            return f"(!{accessor} || !{positive.replace(f'{header_ref}.value', f'{accessor}.value')})"
            # Simplified: just negate the whole expression
        return f"!({js_expr})"

    return js_expr
```

Complete list of `not_` variants to handle:

| IR op | JS output |
|---|---|
| `not_eq` | `!== value` or `!(accessor === value)` |
| `not_ne` | `=== value` (double negation) |
| `not_contains` | `!accessor.includes(value)` |
| `not_starts_with` | `!accessor.startsWith(value)` |
| `not_ends_with` | `!accessor.endsWith(value)` |
| `not_in` | `![...].includes(accessor)` |
| `not_wildcard` | `!regex.test(accessor)` |
| `not_matches` | `!regex.test(accessor)` |

For header fields with existence check, `not_` means "header doesn't exist OR value doesn't match":
```javascript
// not http.user_agent contains "bot"
const ua = request.headers['user-agent'];
if (!ua || !ua.value.includes('bot')) { ... }
```

### D. Header existence check rules

Complete classification of which fields need existence checks:

```python
# Fields that are ALWAYS available (no existence check needed)
ALWAYS_AVAILABLE = {
    'uri.path', 'uri', 'host', 'method', 'ip.src',
}

# Fields that need existence check (optional headers)
NEEDS_EXISTENCE_CHECK = {
    'user_agent', 'referer', 'http_version',
    'country', 'city', 'region', 'region_code',
    'subdivision_1', 'latitude', 'longitude',
    'postal_code', 'metro_code', 'timezone', 'asnum',
    'continent', 'is_eu',
}

# Special cases
# 'uri.query' — rawQueryString() always returns a string (empty if no QS), no check needed
# 'uri.path.extension' — derived from uri, always available
# 'full_uri' — constructed from host + uri, always available
# 'response_code' — only in viewer_response, always available as response.statusCode
```

For fields in `NEEDS_EXISTENCE_CHECK`, the JS pattern is:
```javascript
// Positive condition: header must exist AND match
const header = request.headers['header-name'];
if (header && header.value === 'X') { ... }

// Negative condition: header doesn't exist OR doesn't match
const header = request.headers['header-name'];
if (!header || header.value !== 'X') { ... }
```

### E. viewer_response field mapping (complete)

Fields available in viewer_response that differ from viewer_request:

```python
VIEWER_RESPONSE_FIELDS = {
    # Response-specific fields
    'response_code': 'response.statusCode',           # integer
    # All request fields are also available via event.request:
    'uri.path': 'event.request.uri',
    'uri': 'event.request.uri',
    'host': 'event.request.headers.host.value',
    'method': 'event.request.method',
    'ip.src': 'event.viewer.ip',
    'user_agent': ('event.request.headers["user-agent"]', True),
    # ... all other request fields use event.request instead of request
    # Response header access:
    # http.response.headers["name"] → response.headers["name"] && response.headers["name"].value
}
```

Header mutations in viewer_response target `response.headers`:
```javascript
// set_header in viewer_response
response.headers['x-custom'] = { value: 'val' };

// remove_header in viewer_response
delete response.headers['x-custom'];

// add_header in viewer_response
if (!response.headers['x-custom']) {
    response.headers['x-custom'] = { value: 'val' };
}
```

### F. Updated function conversion table (v3c — all MANUAL_REQUIRED eliminated)

Replaces ALL previous function tables in this document.

| Cloudflare function | JS equivalent in CFF Runtime 2.0 | Status |
|---|---|---|
| `concat(a, b, ...)` | `a + b + ...` | ✅ |
| `regex_replace(field, pat, repl)` | `field.replace(/pat/, repl)` — no `g` flag, no `i` flag | ✅ |
| `wildcard_replace(field, pat, repl[, flags])` | `field.replace(/^glob_regex$/[i], repl)` — lazy `(.*?)`, `i` unless flags=="s", anchored `^...$` | ✅ |
| `lower(field)` | `field.toLowerCase()` | ✅ |
| `upper(field)` | `field.toUpperCase()` | ✅ |
| `to_string(field)` | `String(field)` | ✅ |
| `substring(field, start[, end])` | `field.substring(start, end)` | ✅ |
| `len(field)` | `field.length` | ✅ |
| `url_decode(field)` | `decodeURIComponent(field)` | ✅ |
| `url_decode(field, "r")` | Recursive decodeURIComponent loop | ✅ (helper) |
| `url_decode(field, "u")` | `decodeURIComponent(field)` (handles Unicode natively) | ✅ |
| `encode_base64(field)` | `Buffer.from(field, 'utf8').toString('base64').replace(/=+$/, '')` | ✅ |
| `encode_base64(field, "p")` | `Buffer.from(field, 'utf8').toString('base64')` | ✅ |
| `encode_base64(field, "u")` | `Buffer.from(field, 'utf8').toString('base64url')` | ✅ |
| `encode_base64(field, "up")` | `Buffer.from(field, 'utf8').toString('base64url')` + pad with `=` | ✅ |
| `decode_base64(field)` | `atob(field)` or `Buffer.from(field, 'base64').toString('utf8')` | ✅ |
| `lookup_json_string(field, k1, k2, ...)` | `(() => { try { return JSON.parse(field)[k1][k2]; } catch(e) { return ''; } })()` | ✅ |
| `lookup_json_integer(field, k1, k2, ...)` | `(() => { try { return JSON.parse(field)[k1][k2]; } catch(e) { return 0; } })()` | ✅ |
| `sha256(field)` | `(() => { import crypto from 'crypto'; return crypto.createHash('sha256').update(field).digest(); })()` | ✅ |
| `encode_base64(sha256(field))` | `crypto.createHash('sha256').update(field).digest('base64')` (optimized) | ✅ |
| `encode_base64(sha256(field), "u")` | `crypto.createHash('sha256').update(field).digest('base64url')` | ✅ |
| `split(field, sep)` | `field.split(sep)` | ✅ |
| `join(items, sep)` | `items.join(sep)` | ✅ |
| `remove_query_args(field, arg1, arg2, ...)` | Parse QS, filter out named args, rejoin (helper function) | ✅ (helper) |
| `remove_bytes(field, bytes)` | Parse byte sequence → JS regex character class: `field.replace(/[chars]/g, '')` | ✅ |
| `uuidv4(seed)` | Math.random()-based UUID v4 (with non-crypto-secure warning in generated JS comment + conversion_report.md) | ✅ (⚠️ warning) |
| `has_key(map, key)` | Condition-only, not in CDN action expressions | N/A |
| `has_value(collection, value)` | Condition-only | N/A |
| `any()` / `all()` | Condition-only (array operations) | N/A |
| `cidr()` / `cidr6()` | WAF custom/rate rules only | N/A |
| `is_timed_hmac_valid_v0(...)` | WAF condition-only | N/A |
| `bit_slice()` | Network firewall only | N/A |

**MANUAL_REQUIRED count: 0.** All Cloudflare functions that can appear in CDN action expressions are convertible.

### G. remove_bytes conversion logic

```python
def remove_bytes_to_js(field_js, bytes_literal):
    """Convert remove_bytes(field, "\\x2e\\x77") to JS regex replacement.

    bytes_literal is the raw string from Cloudflare, e.g., "\\x2e\\x77"
    Each \\xNN is a single byte to remove.
    """
    # Parse hex escapes
    chars = []
    i = 0
    raw = bytes_literal
    while i < len(raw):
        if raw[i:i+2] == '\\x' and i + 3 < len(raw):
            hex_val = raw[i+2:i+4]
            char = chr(int(hex_val, 16))
            chars.append(char)
            i += 4
        else:
            chars.append(raw[i])
            i += 1

    # Build JS regex character class, escaping regex-special chars
    regex_chars = ''
    for ch in chars:
        if ch in r'\]^-':
            regex_chars += '\\' + ch
        elif ch == '.':
            regex_chars += '\\.'
        else:
            regex_chars += ch

    return f"{field_js}.replace(/[{regex_chars}]/g, '')"
```

### H. remove_query_args conversion logic

```python
def remove_query_args_to_js(field_js, *arg_names):
    """Convert remove_query_args(field, "param1", "param2") to JS.

    Generates a helper that parses the query string, filters out named params,
    and rejoins.
    """
    args_array = ', '.join(f"'{a}'" for a in arg_names)
    return f"""(() => {{
  const qs = {field_js};
  if (!qs) return '';
  const remove = new Set([{args_array}]);
  return qs.split('&').filter(p => !remove.has(p.split('=')[0])).join('&');
}})()"""
```

### I. url_decode recursive ("r" flag) helper

```python
def url_decode_recursive_js(field_js):
    """Generate JS for url_decode(field, "r") — recursive decoding."""
    return f"""(() => {{
  let prev = '', cur = {field_js};
  while (cur !== prev) {{ prev = cur; cur = decodeURIComponent(cur); }}
  return cur;
}})()"""
```
