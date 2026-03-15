---
name: cf-cdn-ir-final-validator
description: >
  Validator V2 for the Cloudflare → CloudFront migration pipeline.
  Runs after cf-cdn-ir-finalizer completes for all domains.
  Validates ir/final/<hostname>.yaml files for correct sorting, CloudFront
  hard limits, cross-reference integrity, and required output files.
  Uses the same adversarial checking posture as V1: input is assumed wrong
  until every check passes. Never suggests fixes — only reports errors.
---

# cf-cdn-ir-final-validator

**Validator V2 — Finalized IR Structural and Integrity Validation**

This skill validates the output of `cf-cdn-ir-finalizer`. It checks that
finalized IR files satisfy CloudFront's structural requirements (sort order,
hard limits, no duplicates), that cross-references are internally consistent
(policy IDs all resolve), and that required companion files exist. It does not
re-run V1 checks — it validates finalization-specific properties only.

---

## Adversarial Checking Posture

> These rules are identical to V1 and are non-negotiable.

- **Default assumption: the input is WRONG** until every explicit check passes.
- **Find failures. Do not confirm success.** Success is the absence of detected
  failures.
- **Ambiguous results → FAIL** with a precise explanation. Do not resolve
  ambiguity charitably.
- **Missing field = missing.** No defaults. No assumptions about intent.
- **Do NOT suggest fixes.** Errors only. No repair. No re-run instructions.
- **A false negative (missed error) is worse than a false positive.**
- **Whitespace-only strings are not valid strings.**

---

## Path Resolution

All paths are resolved relative to the **project output root**:

```
cloudflare-to-aws-cdn/
```

| Logical path              | Resolved path                                                         |
|---------------------------|-----------------------------------------------------------------------|
| Finalized IR input        | `cloudflare-to-aws-cdn/ir/final/<hostname>.yaml`                     |
| V2 validation output      | `cloudflare-to-aws-cdn/ir/validation/final/<hostname>-v2.json`       |
| Dedup manifest            | `cloudflare-to-aws-cdn/shared/dedup_manifest.json`                   |
| Conversion report         | `cloudflare-to-aws-cdn/conversion_report.md`                         |

---

## Output Directory

```
cloudflare-to-aws-cdn/ir/validation/final/
```

Create this directory if it does not exist. Write one JSON file per validated
domain. Do not write any other files. Do not modify any input files.

---

## Output Format

Every run — pass or fail — produces a JSON file at:

```
cloudflare-to-aws-cdn/ir/validation/final/<hostname>-v2.json
```

Schema (identical to V1 format):

```json
{
  "hostname": "<hostname>",
  "validator": "cf-cdn-ir-final-validator",
  "status": "PASS" | "FAIL",
  "errors": [
    "<check_id>: <detailed description including observed values>"
  ],
  "warnings": [
    "<optional informational messages>"
  ]
}
```

Rules:
- `status` is `"FAIL"` if `errors` is non-empty; `"PASS"` otherwise.
- Include every error found — do not truncate.
- `errors` and `warnings` must both be present even if empty arrays.
- Error entries must include: which document (by index or path_pattern),
  which field, and the observed value.

---

## Workflow

### Step 0 — Read Reference Documents First

Before any validation logic, read the following documents in order:

1. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-per-domain-processor/SKILL.md` — IR schema reference.
2. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md` — V1 validation rules
   (to understand what was already checked and must not be re-checked here).
3. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-finalizer/SKILL.md` — finalization logic, including
   the sorting algorithm, policy deduplication scheme, and shadowing detection.
4. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-final-validator/SKILL.md` (this file) — V2 checks.

Do not proceed without reading these. The sorting algorithm and policy ID
format defined in the finalizer SKILL.md are required to verify Check 7.

---

### Step 1 — Identify the Target Hostname

This skill is invoked with a single hostname parameter (e.g., `cdn.example.com`).

Derive:
- **Input file path:** `cloudflare-to-aws-cdn/ir/final/<hostname>.yaml`
- **Output file path:** `cloudflare-to-aws-cdn/ir/validation/final/<hostname>-v2.json`

If no hostname parameter is provided, FAIL immediately with:

```
SETUP_ERROR: No hostname parameter supplied. Cannot determine input file.
```

---

### Step 2 — Verify Input File Exists

Check that the finalized YAML file exists at:
```
cloudflare-to-aws-cdn/ir/final/<hostname>.yaml
```

If missing:
```
FILE_NOT_FOUND: Expected finalized IR file does not exist: cloudflare-to-aws-cdn/ir/final/<hostname>.yaml
```
Write validation JSON, output FAILURE message, **stop.**

---

### Step 3 — Verify Global Companion Files Exist

**These checks are performed once per V2 validation run, not per-domain:**

**3a. `dedup_manifest.json` must exist:**

Check for:
```
cloudflare-to-aws-cdn/shared/dedup_manifest.json
```

If absent:
```
GLOBAL_DEDUP_MANIFEST_MISSING: cloudflare-to-aws-cdn/shared/dedup_manifest.json does not exist. This file is required for policy cross-reference validation.
```

If the file exists but fails JSON parsing:
```
GLOBAL_DEDUP_MANIFEST_INVALID_JSON: cloudflare-to-aws-cdn/shared/dedup_manifest.json exists but is not valid JSON. Parse error: <message>
```

If either error occurs for the manifest: append to errors list AND mark the
dedup manifest as unreadable. In subsequent checks that require it (Check 6,
Check 7), skip those checks and append a note:
```
GLOBAL_DEDUP_MANIFEST_SKIPPED: Checks 6–7 skipped because dedup_manifest.json is missing or invalid.
```

**3b. `conversion_report.md` must exist:**

Check for:
```
cloudflare-to-aws-cdn/conversion_report.md
```

If absent:
```
GLOBAL_CONVERSION_REPORT_MISSING: cloudflare-to-aws-cdn/conversion_report.md does not exist. This file must be written by cf-cdn-ir-finalizer even if empty.
```

Note: the report may be empty (zero bytes). An empty file is acceptable. Only
absence is an error.

---

### Step 4 — Parse the Finalized YAML File

Load and parse the multi-document YAML file.

If parsing fails:
```
PARSE_ERROR: YAML parsing failed for cloudflare-to-aws-cdn/ir/final/<hostname>.yaml. Parser error: <message>
```
Write validation JSON, output FAILURE message, **stop.**

Separate documents:
- Documents with `document_type: cache_behavior` → `cache_behavior_docs` (ordered list)
- Documents with `document_type: metadata` → `metadata_doc`

Note the **file-order position** of each document (0-indexed). This is needed
for precise error reporting.

---

### Step 5 — Run All Validation Checks

Execute every check below in sequence. Collect ALL errors before writing
output. Do not short-circuit.

---

#### Check 1 — Precedence values are strictly ascending

Collect all `precedence` values from `cache_behavior_docs` in file order.

**1a. No equal precedence values:**
For any two documents at indices `i` and `j` where `i < j`:
- If `precedence[i] == precedence[j]`:
  ```
  PRECEDENCE_DUPLICATE[<i>][<j>]: cache_behavior documents at indices <i> (precedence=<val>, path_pattern="<pattern_i>") and <j> (precedence=<val>, path_pattern="<pattern_j>") have identical precedence values. Precedence must be strictly unique across all behaviors.
  ```

**1b. Strictly ascending order (no decreasing values):**
Iterate sequentially through `cache_behavior_docs`. Track `prev_precedence`.

If `precedence[i] < precedence[i-1]`:
```
PRECEDENCE_NOT_ASCENDING[<i>]: cache_behavior at index <i> (precedence=<val_i>, path_pattern="<pattern_i>") has a lower precedence than the previous document at index <i-1> (precedence=<val_prev>, path_pattern="<pattern_prev>"). Precedence must be strictly ascending in file order.
```

**1c. Precedence values must be positive integers greater than zero:**
If any `precedence` value is ≤ 0:
```
PRECEDENCE_INVALID_VALUE[<i>]: cache_behavior at index <i> has precedence=<val> which is ≤ 0. Precedence must be a positive integer.
```

---

#### Check 2 — Most-specific patterns appear before wildcard patterns

This check enforces that the sort order from `cf-cdn-ir-finalizer` is correct:
more-specific patterns must have lower precedence numbers and thus appear
earlier in the file.

**2a. Default `"*"` must be the last behavior (precedence 999):**

Scan all `cache_behavior_docs` for any with `path_pattern == "*"`.

If found at index `i` where `i` is NOT the last document in the list:
```
DEFAULT_PATTERN_NOT_LAST[<i>]: Default catch-all pattern "*" found at index <i> but it is not the last cache_behavior document (total: <count>). The default "*" pattern must always appear last with precedence=999.
```

If the `"*"` pattern's `precedence` is not `999`:
```
DEFAULT_PATTERN_WRONG_PRECEDENCE[<i>]: Default catch-all pattern "*" at index <i> has precedence=<val> instead of the required 999.
```

**2b. No more-specific pattern may appear after a less-specific pattern that
covers it (specificity ordering check):**

Use the same scoring function defined in `cf-cdn-ir-finalizer`:

```
function specificity_score(pattern):
  if pattern == "*": return 0
  wildcard_pos = index of first '*' or '?' in pattern
  if wildcard_pos == -1:
    return len(pattern) * 10 + 100  # exact match
  else:
    return wildcard_pos * 10
```

Iterate through `cache_behavior_docs` in file order. Track a running list of
seen `(score, pattern, index)` tuples.

For each document at index `i` with `path_pattern = P_i` and score `S_i`:

Check all previously seen documents at index `j < i` with score `S_j` and
pattern `P_j`:

If `S_j < S_i` (meaning P_j is less specific than P_i, but P_j appeared
earlier in the file):
- AND if P_j is a strict superset of P_i (P_j covers all requests P_i would
  match):

```
SPECIFICITY_ORDER_VIOLATION[<j>][<i>]: Pattern "<P_j>" (index <j>, score <S_j>) is less specific than pattern "<P_i>" (index <i>, score <S_i>), but appears first. More specific patterns must have lower precedence numbers (appear earlier). Example: "/api/*" must come before "/*".
```

**Superset test for CloudFront specificity ordering:**

Pattern A is a superset of pattern B if:
- A == `"*"` (matches everything)
- A == `"/*"` and B starts with `"/"`
- A ends with `"/*"` and B starts with the prefix of A before `"/*"`
  (e.g., A=`"/api/*"` covers B=`"/api/v2/*"` because `"/api/v2"` starts with
  `"/api"`)

**Hard-coded test cases the agent must verify mentally before writing output:**
- `"/*"` after `"/api/*"` → no violation (`/*` is less specific than `/api/*`,
  but `/api/*` appearing before `/*` is correct)
- `"/api/*"` after `"/*"` → VIOLATION (more specific `/api/*` appears after
  less specific `/*`)
- `"*"` before `/anything` → VIOLATION (default must be last)

---

#### Check 3 — Total Cache Behavior count ≤ 75

Count the total number of documents in `cache_behavior_docs`.

If count > 75:
```
CB_COUNT_EXCEEDS_LIMIT: Domain "<hostname>" has <count> cache_behavior documents. CloudFront default quota is 75 cache behaviors per distribution (soft limit). Request a quota increase via AWS Support before deploying.
```

This is a CloudFront soft limit. FAIL to prevent deployment errors.

---

#### Check 4 — Every referenced `origin.domain` is a valid hostname

For each cache_behavior document at index `i` that contains an `origin` field:

**4a. `origin.domain` must be present and non-empty** (same rules as V1 Check 2,
since finalizer should have preserved origin fields):

- If `origin.domain` is absent, null, empty, or contains whitespace: append
  the corresponding error (use same error codes as V1 but prefixed with `FIN_`):
  ```
  FIN_ORIGIN_DOMAIN_MISSING[<i>]: ...
  FIN_ORIGIN_DOMAIN_NULL[<i>]: ...
  FIN_ORIGIN_DOMAIN_EMPTY[<i>]: ...
  FIN_ORIGIN_DOMAIN_WHITESPACE[<i>]: ...
  ```

**4b. `origin.domain` must pass hostname format validation:**
- Must match pattern: only `[a-zA-Z0-9\-.]` characters
- Must not start or end with `"-"` or `"."`
- Must not contain `".."`
- Must not contain `"://"`

If invalid:
```
FIN_ORIGIN_DOMAIN_INVALID[<i>]: cache_behavior at index <i> has origin.domain="<value>" which fails hostname format validation. Hostnames must contain only alphanumeric characters, hyphens, and dots, with no protocol or path components.
```

---

#### Check 5 — No duplicate `path_pattern` values

Collect all `path_pattern` values from `cache_behavior_docs`.

Build a map of `pattern → [list of document indices]`.

For any pattern that appears more than once:
```
DUPLICATE_PATH_PATTERN["<pattern>"]: path_pattern="<pattern>" appears in cache_behavior documents at indices [<i1>, <i2>, ...]. Each cache behavior in a domain must have a unique path_pattern.
```

This check must run even when Check 1 also found duplicates — they are
independent.

---

#### Check 6 — `dedup_manifest.json` is valid (if readable)

Skip this check if Step 3a found the manifest missing or invalid.

Validate the manifest structure:

**6a. Required top-level keys:**
The manifest must contain `"policies"` key as a JSON object.

If `"policies"` key is absent:
```
MANIFEST_MISSING_POLICIES_KEY: dedup_manifest.json does not contain a "policies" key at the top level.
```

**6b. Each policy entry must have required fields:**
For each `policy_id` in `manifest.policies`:
- Must have `"hash"` field (non-empty string)
- Must have `"type"` field (one of: `"cache_policy"`, `"origin_request_policy"`,
  `"response_headers_policy"`)
- Must have `"count"` field (positive integer)
- Must have `"sample_hostname"` field (non-empty string)
- Must have `"config"` field (a JSON object, not null, not array)

For any missing or invalid field:
```
MANIFEST_POLICY_INVALID["<policy_id>"].<field>: Policy entry "<policy_id>" has missing or invalid "<field>" field. Found: <observed value or "absent">.
```

---

#### Check 7 — Every `policy_id` reference in the finalized IR resolves

Skip this check if Step 3a found the manifest missing or invalid.

For each cache_behavior document at index `i`, check for keys matching the
pattern `*_policy_id` (i.e., `cache_policy_id`, `origin_request_policy_id`,
`response_headers_policy_id`):

For each such field with value `V`:

If `V` is not a key in `manifest.policies`:
```
POLICY_ID_NOT_IN_MANIFEST[<i>]["<field>"]: cache_behavior at index <i> references <field>="<V>" but this policy_id does not exist in dedup_manifest.json. Every *_policy_id reference must have a corresponding entry in the manifest.
```

Also check the reverse: for every `policy_id` in `manifest.policies` with
`count > 0`, verify it is referenced by at least one cache behavior across the
current domain's finalized IR.

If a policy is in the manifest but not referenced by this domain (this is a
warning, not an error — the policy may be used by other domains):
```
WARN: Policy "<policy_id>" in dedup_manifest.json is not referenced by any cache_behavior in domain "<hostname>". It may be shared with other domains.
```

---

### Step 6 — Write Validation Output

After all 8 checks complete:

1. Determine `status`:
   - `"FAIL"` if `errors` list is non-empty (including global file checks
     from Step 3)
   - `"PASS"` if `errors` list is empty

2. Ensure output directory exists:
   ```
   cloudflare-to-aws-cdn/ir/validation/final/
   ```

3. Write JSON file to:
   ```
   cloudflare-to-aws-cdn/ir/validation/final/<hostname>-v2.json
   ```

4. Pretty-print with 2-space indent.

5. Include every error and every warning. Do not truncate.

---

### Step 7 — Report Result to User

**If status is PASS:**

```
[cf-cdn-ir-final-validator] <hostname>: PASS (0 errors)
```

**If status is FAIL:**

```
[cf-cdn-ir-final-validator] FAILURE — <hostname>: <N> error(s) found.
Validation report written to: cloudflare-to-aws-cdn/ir/validation/final/<hostname>-v2.json

Errors:
  1. <error 1>
  2. <error 2>
  ...

Do NOT proceed to CloudFront template generation until all errors are resolved.
```

Do NOT attempt to fix errors. Do NOT re-run the finalizer. Do NOT modify any
files other than the validation output JSON.

---

## CloudFront Path Pattern Specificity Check — Quick Reference

This section provides concrete test cases the executing agent must use to
verify its specificity ordering logic before applying it to input files.

### Superset / Coverage Matrix

| Pattern A (earlier) | Pattern B (later) | A covers B? | Ordering Correct? |
|---------------------|-------------------|-------------|-------------------|
| `/api/*`            | `/*`              | No          | ✓ Correct (specific before general) |
| `/*`                | `/api/*`          | Yes         | ✗ **VIOLATION** |
| `*`                 | `/api/*`          | Yes         | ✗ **VIOLATION** (default must be last) |
| `/api/v2/*`         | `/api/*`          | No          | ✗ **VIOLATION** (v2 is more specific, should be first) |
| `/api/*`            | `/api/v2/*`       | Yes         | ✓ Correct |
| `/exact/path`       | `/exact/*`        | No          | ✓ Correct (exact before wildcard) |
| `/exact/*`          | `/exact/path`     | Yes         | ✗ **VIOLATION** |

### Precedence Ordering Rules Summary

```
Lower precedence number = higher priority = evaluated first in CloudFront
More specific pattern   = lower precedence number = appears first in file

Correct file order (ascending precedence):
  precedence=1   /api/v2/users    (most specific, exact match)
  precedence=2   /api/v2/*        (specific prefix)
  precedence=3   /api/*           (broad prefix)
  precedence=4   /static/*        (different prefix)
  precedence=5   /*               (near-default)
  precedence=999 *                (default, always last)
```

---

## Reference Documents

| Document | Purpose |
|---|---|
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-per-domain-processor/SKILL.md` | IR schema reference |
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md` | V1 checks — do not re-run these |
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-finalizer/SKILL.md` | Sorting algorithm, dedup logic, output format |
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-final-validator/SKILL.md` | This file — V2 checks |

---

## Check Index

| Check | ID Prefix | Description |
|-------|-----------|-------------|
| 1 | `PRECEDENCE_` | Strictly ascending, no duplicates, positive integers |
| 2 | `DEFAULT_PATTERN_`, `SPECIFICITY_ORDER_` | Sort order correctness, default pattern placement |
| 3 | `CB_COUNT_EXCEEDS_LIMIT` | ≤ 75 behaviors per domain (CloudFront default quota, soft limit) |
| 4 | `FIN_ORIGIN_DOMAIN_` | Origin hostname validity |
| 5 | `DUPLICATE_PATH_PATTERN` | Unique path patterns within domain |
| 6 | `MANIFEST_` | dedup_manifest.json structure validity |
| 7 | `POLICY_ID_NOT_IN_MANIFEST` | Policy ID cross-reference integrity |
| Global | `GLOBAL_` | Required companion files (manifest, report) |

---

## Important Notes for the Executing Agent

- **V2 does not re-run V1 checks.** Do not re-validate `path_pattern` nullity,
  `viewer_request_ops` integrity, or other V1 concerns. Those were checked
  before finalization.
- **V2 validates finalization-specific properties**: sort order, CloudFront
  limits, cross-reference consistency, and required output files.
- **Global file checks (Step 3) apply once per invocation** but contribute
  to the current domain's validation output. If the manifest is missing, it
  is an error for every domain being validated.
- **Precedence 999 is a valid and required value** for the default `"*"` pattern.
  Do not flag it as invalid.
- **An empty `conversion_report.md` is acceptable.** Only its absence is an
  error.
- **Policy ID references may be absent** from some cache behaviors (those with
  no policy configured). Check 7 only applies to behaviors that *do* have a
  `*_policy_id` field.
- **Do not infer that a missing `*_policy_id` field means the policy was
  inline** — absence of the field means no policy was configured for that
  behavior. This is valid.
