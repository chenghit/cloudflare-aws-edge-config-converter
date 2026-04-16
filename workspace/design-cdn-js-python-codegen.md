# Design: Replace CDN JS Generation and Validation with Python

Author: chenghit
Date: 2026-04-16
Status: Draft
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
3. **Dynamic expressions**: `concat()`, `regex_replace()`, `wildcard_replace()` are 3 functions with fixed translation rules to JS.

The only part that genuinely benefits from LLM is `raw_expression` handling — when `cdn_expr_parser.py` can't parse the condition (currently ~21% of rules in the example config). But this can be eliminated by upgrading the parser to a full recursive descent parser (same architecture as the WAF parser).

### Validation is pure pattern matching

Stage 9 (JS validation) checks:
- Forbidden syntax (`?.`, destructuring, `Promise.all`)
- Required structure (`import cf`, `async function handler`, `return request`)
- IR coverage (each op has corresponding JS code)
- KVS handle initialization

All of these are regex/string checks. No language understanding needed.

## Solution

Replace Stages 8 and 9 with deterministic Python scripts.

### What changes

| Component | Current | New |
|-----------|---------|-----|
| Stage 8: JS generation | LLM subagent (`cf-cdn-tf-domain`) per domain | Python script (`cdn-generate-js.py`) for all domains |
| Stage 9: JS validation | LLM subagent (`cf-cdn-js-validator`) per domain | Python script (`cdn-validate-js.py`) for all domains |
| Expression parsing | `cdn_expr_parser.py` (regex-based, ~78% parse rate) | Upgraded recursive descent parser (~100% parse rate) |

### What stays the same

- Stages 1–2: LLM subagents (DNS parsing, input validation) — these involve YAML/CSV generation and user interaction, LLM adds genuine value
- Stages 3–7.6: Python scripts (no change)
- Stage 7.5: Terraform scaffold generation (no change — JS files are separate from .tf files)
- Stage 7.5b: Terraform validate for shared policies (no change)
- IR schema: no change — `cdn-generate-js.py` reads the same `ir/final/<hostname>.json`
- Output structure: no change — same JS files in same directories

### What gets deleted

- `cf-cdn-tf-domain/` subagent (replaced by `cdn-generate-js.py`)
- `cf-cdn-js-validator/` subagent (replaced by `cdn-validate-js.py`)
- `subagents/cf-cdn-tf-domain.json` agent config
- `subagents/cf-cdn-js-validator.json` agent config

## Expression parser upgrade

### Current `cdn_expr_parser.py` limitations

The current parser is regex-based (Phase 1 design):
- Cannot handle OR expressions → falls back to `raw_expression`
- Cannot handle 3+ AND conditions → falls back to `raw_expression`
- Cannot handle nested logic → falls back to `raw_expression`
- Parse rate: ~78% on example config

### Upgrade to recursive descent

Reuse the architecture from `waf_expr_parser.py`:
- Same tokenizer (Cloudflare expression syntax is identical for WAF and CDN)
- Same recursive descent parser (or > and > not > atom)
- Same function call handling (starts_with, ends_with, lower)
- Different field mapping table (CDN fields → CloudFront accessor names)

The WAF parser already handles all the patterns that cause `cdn_expr_parser.py` to fall back:
- OR expressions: `(A) or (B) or (C)` → `{"op": "or", "items": [...]}`
- 3+ AND: `A and B and C` → `{"op": "and", "items": [...]}`
- Nested logic: `(A or B) and C` → proper tree
- NOT: `not A` → `{"op": "not", "item": ...}`

### Implementation approach

Two options:

**Option A: Shared parser module**
Extract the tokenizer and recursive descent parser from `waf_expr_parser.py` into a shared `cf_expr_parser.py`. WAF and CDN scripts both import from it, with different field mapping tables.

**Option B: Separate parsers, shared tokenizer**
Keep `waf_expr_parser.py` and create `cdn_expr_parser_v2.py` that imports the tokenizer from a shared module but has its own field mapping and output format.

**Recommendation: Option A.** The tokenizer and parser are identical — only the field mapping and post-processing differ. The current `cdn_expr_parser.py` output format (`{"field": "uri.path", "op": "eq", "value": "/api"}`) is slightly different from the WAF format (`{"field": "http.request.uri.path", "operator": "eq", "value": "/api"}`), but the CDN format uses mapped field names while WAF uses raw Cloudflare field names. The shared parser can output raw Cloudflare field names, and each pipeline applies its own mapping.

However, changing `cdn_expr_parser.py`'s output format would require updating all downstream consumers (Stages 3–7.6 Python scripts). This is risky — those scripts are tested and working.

**Revised recommendation: Option B.** Keep the existing `cdn_expr_parser.py` interface unchanged for Stages 3–7.6. Create a new function `parse_expression_full()` that returns the full recursive descent tree (for JS codegen), while `parse_expression()` continues to return the existing format (for preprocess/finalize). The new function can share the tokenizer internally.

## JS code generation (`cdn-generate-js.py`)

### Input

- `cloudflare-to-aws-cdn/ir/final/<hostname>.json` — per-domain final IR
- Processes all domains in a single invocation (no parallelization needed — generation is instant)

### Output

For each domain:
- `cloudflare-to-aws-cdn/terraform/domains/<sanitized>/functions/<name>_viewer_request.js`
- `cloudflare-to-aws-cdn/terraform/domains/<sanitized>/functions/<name>_viewer_response.js` (if viewer_response_ops exist)
- `cloudflare-to-aws-cdn/terraform/domains/<sanitized>/lambda/origin_request_handler.js` (if CFF overflow)
- `cloudflare-to-aws-cdn/terraform/domains/<sanitized>/lambda/default_cache_origin_response.js` (if lambda_edge.origin_response)

### Condition → JS mapping (deterministic)

Direct port of the mapping table from `cf-cdn-tf-domain/SKILL.md`:

| IR condition field | JS accessor |
|---|---|
| `uri.path` | `request.uri` |
| `uri.query` | `request.rawQueryString()` |
| `host` | `request.headers.host.value` |
| `method` | `request.method` |
| `user_agent` | `request.headers['user-agent'] && request.headers['user-agent'].value` |
| `country` | `request.headers['cloudfront-viewer-country'] && request.headers['cloudfront-viewer-country'].value` |
| `ip.src` | `event.viewer.ip` |
| `continent` | KVS lookup pattern |
| `is_eu` | KVS lookup pattern |
| ... | (full table in SKILL.md) |

Operator mapping:

| IR op | JS code |
|---|---|
| `eq` | `=== value` |
| `ne` | `!== value` |
| `contains` | `.includes(value)` |
| `starts_with` | `.startsWith(value)` |
| `ends_with` | `.endsWith(value)` |
| `wildcard` | Convert to `startsWith`/`endsWith`/regex |
| `matches` | `/.../test(accessor)` |
| `in` | `[...].includes(accessor)` |
| `and` | `&&` |
| `or` | `||` |
| `not` | `!` |

### Dynamic expression → JS conversion (deterministic)

Only 3 Cloudflare functions need translation:

**`concat(arg1, arg2, ...)`**

Arguments can be string literals or field references.

```
concat("/eu", http.request.uri.path)
→ '/eu' + request.uri

concat("https://", http.host, regex_replace(http.request.uri.path, "/docs/(.*)\\.pdf", "/html/${1}/"), ">; rel=\"canonical\"")
→ 'https://' + request.headers.host.value + request.uri.replace(/\/docs\/(.*?)\.pdf/, '/html/$1/') + '>; rel="canonical"'
```

Implementation: parse the argument list (string literals and field references), map each to JS, join with `+`.

**`regex_replace(field, pattern, replacement)`**

```
regex_replace(http.request.uri.path, "^/products/([0-9]+)/([a-z\\-]+)$", "/items/${1}?slug=${2}")
→ request.uri.replace(/^\/products\/([0-9]+)\/([a-z\-]+)$/, '/items/$1?slug=$2')
```

Implementation: map field to JS accessor, convert Cloudflare regex to JS regex (mostly identical — escape `/` for JS regex literal), convert `${N}` capture group references to `$N`.

**`wildcard_replace(field, pattern, replacement)`**

```
wildcard_replace(http.request.uri.path, r"/files/*", r"/newfiles/${1}")
→ request.uri.replace(/^\/files\/(.*)$/, '/newfiles/$1')

wildcard_replace(http.request.full_uri, r"http://*", r"https://${1}")
→ (full_uri).replace(/^http:\/\/(.*)$/, 'https://$1')
```

Implementation: convert wildcard `*` to capture group `(.*)`, anchor with `^` and `$`, convert `${N}` to `$N`.

### Action type → JS template

6 action types, each with a fixed JS template:

**redirect**: `return { statusCode: N, headers: { location: { value: "..." } } }`
**rewrite**: `request.uri = "..."`
**origin_override**: `cf.updateRequestOrigin({ domainName: "..." })`
**header mutation**: `request.headers["x"] = { value: "..." }` / `delete request.headers["x"]`
**bulk_redirect**: KVS lookup template (fixed ~30 lines)
**serve_error_inline**: KVS get + synthetic response template

### File assembly

The generator assembles the complete JS file:

```javascript
import cf from 'cloudfront';

// KVS initialization (if needed)
const kvsHandle = cf.kvs('<KVS_ID>');

async function handler(event) {
  const request = event.request;

  // --- SECTION 1: redirects ---
  // (generated from redirect ops)

  // --- SECTION 2: rewrites ---
  // (generated from rewrite ops)

  // --- SECTION 3: origin_override ---
  // (generated from origin_override ops)

  // --- SECTION 4: bulk_redirects ---
  // (generated from bulk_redirect ops, if KVS exists)

  // --- SECTION 5: header mutations ---
  // (generated from header ops)

  // --- SECTION 6: serve_error_inline ---
  // (generated from serve_error_inline ops)

  return request;
}
```

### Size check and Lambda@Edge escalation

After generating the JS, check byte count:
- ≤ 10,240 bytes → CloudFront Function (write to `functions/`)
- > 10,240 bytes → split origin_override ops to Lambda@Edge `origin_request_handler.js`, keep rest in CFF

This is the same logic currently in `cf-cdn-tf-domain/SKILL.md` Step 2b–2d, implemented deterministically.

### Lambda@Edge origin response handler

If `metadata.lambda_edge.origin_response` is non-null in the IR, copy the template from `references/lambda/default-cache-origin-response.js` and fill in the custom error response mappings. This is a fixed template — no LLM needed.

## JS validation (`cdn-validate-js.py`)

### Checks (all regex/string matching)

1. **Forbidden syntax**:
   - `?.` (optional chaining)
   - `const {` or `let {` (object destructuring)
   - `const [` or `let [` (array destructuring)
   - `Promise.all` / `Promise.any` / `.then(` / `.catch(`

2. **Required structure**:
   - First line: `import cf from 'cloudfront';` (if KVS or updateRequestOrigin used)
   - Handler: `async function handler(event)`
   - Return: `return request;` or `return response;` (depending on event type)

3. **IR coverage**:
   - For each op in the IR, verify a corresponding code pattern exists in the JS
   - redirect ops → `statusCode` + `location` present
   - rewrite ops → `request.uri =` present
   - origin_override ops → `updateRequestOrigin` present
   - header ops → header name present in JS
   - bulk_redirect → `kvsHandle.get('redirect:` present
   - serve_error_inline → KVS key present

4. **KVS consistency**:
   - If IR has `kvs_requirements`, verify `cf.kvs()` is initialized
   - If no KVS needed, verify no `cf.kvs()` call

5. **Size limit**:
   - CloudFront Function: ≤ 10,240 bytes
   - Lambda@Edge: ≤ 1 MB (practically never hit)

### Output

Per-domain validation report: `cloudflare-to-aws-cdn/ir/validation/js/<hostname>-v3.json`

```json
{
  "hostname": "cdn.c.example.com",
  "overall_status": "PASS",
  "checks": [
    {"name": "forbidden_syntax", "status": "PASS"},
    {"name": "required_structure", "status": "PASS"},
    {"name": "ir_coverage", "status": "PASS", "ops_checked": 12},
    {"name": "kvs_consistency", "status": "PASS"},
    {"name": "size_limit", "status": "PASS", "bytes": 3421}
  ]
}
```

## Pipeline changes

### Current Stages 8–9

```
Stage 8:  Invoke cf-cdn-tf-domain (LLM) × N domains (parallel, batch size 2)
          Verify output files exist
Stage 9:  Invoke cf-cdn-js-validator (LLM) × N domains (parallel, batch size 2)
          Check validation reports
          Auto-retry on FAIL (re-generate + re-validate)
```

### New Stages 8–9

```
Stage 8:  python3 cdn-generate-js.py "cloudflare-to-aws-cdn"
          (processes all domains in one invocation, <1 second)
Stage 9:  python3 cdn-validate-js.py "cloudflare-to-aws-cdn"
          (validates all domains in one invocation, <1 second)
```

### Orchestrator SKILL.md changes

Stage 8 section: replace LLM subagent dispatch + verify + retry logic (~50 lines) with single script call (~5 lines).
Stage 9 section: replace LLM subagent dispatch + verify + retry logic (~40 lines) with single script call (~5 lines).

Remove references to `cf-cdn-tf-domain` and `cf-cdn-js-validator` subagents.

### Fallback for unparseable expressions

If the upgraded parser still can't parse an expression (truly unknown syntax), the codegen script:
1. Writes a `// TODO: manual conversion needed` comment in the JS
2. Records the rule in the validation report as `MANUAL_REQUIRED`
3. Pipeline continues (does not fail)
4. README lists rules requiring manual JS conversion

This is better than the current LLM approach — LLM might generate incorrect JS silently, while Python explicitly flags what it can't handle.

## Expression parser upgrade details

### Shared tokenizer

Extract from `waf_expr_parser.py`:
- `Token` class
- `TT` enum (token types)
- `tokenize()` function

These are identical for WAF and CDN — Cloudflare expression syntax is the same.

### CDN-specific parser

New function `parse_expression_full(expr)` in `cdn_expr_parser.py`:
- Uses the shared tokenizer
- Returns a conditions tree in the **existing CDN format** (`field` uses mapped names like `uri.path`, `op` instead of `operator`)
- Handles all patterns including OR, nested AND/OR, NOT

The existing `parse_expression()` function remains unchanged — Stages 3–7.6 continue to use it. `parse_expression_full()` is only used by `cdn-generate-js.py`.

### Dynamic expression parser

New function `parse_dynamic_expression(expr)` for action parameters:
- Parses `concat(...)`, `regex_replace(...)`, `wildcard_replace(...)`
- Returns a structured representation:

```python
# concat("/eu", http.request.uri.path)
{"func": "concat", "args": [{"type": "literal", "value": "/eu"}, {"type": "field", "value": "http.request.uri.path"}]}

# regex_replace(http.request.uri.path, "^/old/(.*)", "/new/${1}")
{"func": "regex_replace", "args": [{"type": "field", "value": "http.request.uri.path"}, {"type": "literal", "value": "^/old/(.*)"}, {"type": "literal", "value": "/new/${1}"}]}
```

The JS codegen then converts this to JS code deterministically.

## Implementation plan

### Phase 1: Parser upgrade + JS codegen

- Shared tokenizer extraction (from `waf_expr_parser.py`)
- `parse_expression_full()` in `cdn_expr_parser.py` — recursive descent, CDN field mapping
- `parse_dynamic_expression()` — concat/regex_replace/wildcard_replace parser
- `cdn-generate-js.py` — reads all domain IRs, generates all JS files
  - Condition → JS mapping
  - Dynamic expression → JS conversion
  - 6 action type templates
  - Size check + Lambda@Edge escalation
  - Lambda@Edge origin response handler
- Unit tests with example config

### Phase 2: JS validation + orchestrator + cleanup

- `cdn-validate-js.py` — validates all domain JS files
  - Forbidden syntax, required structure, IR coverage, KVS consistency, size limit
- Updated orchestrator `SKILL.md` — Stages 8–9 use Python scripts
- Updated `install.sh` — remove CDN JS subagent installation
- Delete `cf-cdn-tf-domain/` subagent + references
- Delete `cf-cdn-js-validator/` subagent + references
- Delete `subagents/cf-cdn-tf-domain.json` and `subagents/cf-cdn-js-validator.json`
- Updated docs (README, deployment guide, troubleshooting)

Both phases must be complete for the project to ship.

## Risk assessment

### Low risk
- Condition → JS mapping: deterministic, well-defined table, same as SKILL.md
- Action templates: fixed patterns, no ambiguity
- Validation checks: regex/string matching, straightforward

### Medium risk
- `wildcard_replace()` with multiple capture groups: need to correctly map `*` → `(.*)` and `${N}` → `$N`. Test with example config's `wildcard_replace` rules.
- Nested `concat()` + `regex_replace()`: the example config has one case (`Response-Header-Transform.txt: SEO - PDF Canonical Link`). Need to handle function nesting.

### Mitigated by WAF experience
- Parser upgrade: same architecture as proven `waf_expr_parser.py`
- Round-trip validation: can reuse the same approach if needed
- Error handling: unknown syntax → explicit `MANUAL_REQUIRED` flag, not silent failure
