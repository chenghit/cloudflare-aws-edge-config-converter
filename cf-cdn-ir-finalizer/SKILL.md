---
name: cf-cdn-ir-finalizer
description: >
  Finalizer for the Cloudflare → CloudFront migration pipeline.
  Runs after ALL domains have passed V1 validation (cf-cdn-ir-chunk-validator).
  Reads all ir/accumulator/*.yaml files, sorts cache behaviors by specificity,
  deduplicates shared policies, detects shadowed rules, and writes finalized
  IR files plus a conversion report.
---

# cf-cdn-ir-finalizer

**IR Finalizer — Cross-Domain Sorting, Deduplication, and Report Generation**

This skill transforms validated per-domain IR accumulator files into finalized
IR files ready for CloudFront template generation. It operates across all
domains simultaneously to enable cross-domain policy deduplication. It writes
one finalized YAML per domain, a shared deduplication manifest, and a human-
readable conversion report.

This skill must only run after **all** domains have received a `PASS` from
`cf-cdn-ir-chunk-validator`. Running it against unvalidated or failed inputs
produces undefined behavior.

---

## Path Resolution

All paths are resolved relative to the **project output root**:

```
cloudflare-to-aws-cdn/
```

| Logical path              | Resolved path                                                      |
|---------------------------|--------------------------------------------------------------------|
| IR accumulator input glob | `cloudflare-to-aws-cdn/ir/accumulator/*.yaml`                  |
| V1 validation results     | `cloudflare-to-aws-cdn/ir/validation/chunk/*.json`                 |
| Finalized IR output       | `cloudflare-to-aws-cdn/ir/final/<hostname>.yaml`                  |
| Dedup manifest            | `cloudflare-to-aws-cdn/shared/dedup_manifest.json`                |
| Conversion report         | `cloudflare-to-aws-cdn/conversion_report.md`                      |

---

## Output Directory

The following directories must be created if they do not exist:

```
cloudflare-to-aws-cdn/ir/final/
cloudflare-to-aws-cdn/shared/
```

The conversion report is written at the project root level:

```
cloudflare-to-aws-cdn/conversion_report.md
```

---

## Workflow

### Step 0 — Read Reference Documents First

Before executing any logic, read the following reference documents in order:

1. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-per-domain-processor/SKILL.md` — authoritative IR
   schema. Know what fields exist in cache_behavior and metadata documents.
2. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md` — understand what
   validations have already passed. Do not re-validate; trust the V1 pass.
3. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-finalizer/SKILL.md` (this file) — finalization
   logic and algorithms.

Proceeding without reading these documents may produce incorrect finalized IR.

---

### Step 1 — Verify Prerequisites

**1a. Confirm all domains passed V1 validation:**

Read all JSON files in `cloudflare-to-aws-cdn/ir/validation/chunk/`.

For each file, check `status`. If any file has `status: "FAIL"`:
- Output an error:
  ```
  PREREQUISITE_FAILED: Domain <hostname> has not passed V1 validation.
  Validation report: cloudflare-to-aws-cdn/ir/validation/chunk/<hostname>-v1.json
  Run cf-cdn-ir-chunk-validator for this domain and resolve all errors before running the finalizer.
  ```
- **Stop. Do not proceed.**

If no V1 validation files exist at all:
- Output:
  ```
  PREREQUISITE_MISSING: No V1 validation reports found in cloudflare-to-aws-cdn/ir/validation/chunk/.
  Run cf-cdn-ir-chunk-validator for all domains before running the finalizer.
  ```
- **Stop.**

**1b. Confirm at least one accumulator file exists:**

List all `*.yaml` files in `cloudflare-to-aws-cdn/ir/accumulator/`.

If none found:
- Output:
  ```
  NO_INPUT_FILES: No YAML files found in cloudflare-to-aws-cdn/ir/accumulator/. Nothing to finalize.
  ```
- **Stop.**

---

### Step 2 — Load All IR Accumulator Files

For each `*.yaml` file in `cloudflare-to-aws-cdn/ir/accumulator/`:

1. Parse the multi-document YAML file.
2. Separate documents by `document_type`:
   - `cache_behavior` documents → `cache_behavior_docs`
   - `metadata` document → `metadata_doc`
3. Extract the hostname from the metadata document's `hostname` field.
4. Store in an in-memory domain map:
   ```
   domain_map[hostname] = {
     metadata: metadata_doc,
     cache_behaviors: [list of cache_behavior documents],
     source_file: <filename>
   }
   ```

If a file fails to parse, output a warning and skip it:
```
WARN: Could not parse cloudflare-to-aws-cdn/ir/accumulator/<filename>. Skipping.
```

---

### Step 3 — Sort Cache Behaviors by Specificity

For each domain in `domain_map`, sort its `cache_behaviors` list using the
**Cache Behavior Precedence Sorting Algorithm** defined below.

#### Cache Behavior Precedence Sorting Algorithm

**Purpose:** Assign `precedence` values such that more-specific path patterns
receive lower precedence numbers (higher priority in CloudFront's evaluation
order, which processes behaviors from lowest to highest precedence).

**Scoring function — `specificity_score(path_pattern)`:**

```
function specificity_score(pattern):
  if pattern == "*":
    return 0                          # bare wildcard: lowest specificity

  # Count literal characters before the first wildcard
  wildcard_pos = index of first '*' or '?' in pattern
  
  if wildcard_pos == -1:              # no wildcard found → exact match
    literal_chars = len(pattern)
    return (literal_chars * 10) + 100  # exact match bonus
  else:
    literal_chars = wildcard_pos       # chars before first wildcard
    return literal_chars * 10
```

**Examples (for reference and agent verification):**

| Pattern         | Literal chars | Has wildcard | Score calculation          | Score |
|-----------------|---------------|--------------|----------------------------|-------|
| `*`             | 0             | yes          | special case               | 0     |
| `/*`            | 1             | yes          | 1 × 10                     | 10    |
| `/api/*`        | 4             | yes          | 4 × 10                     | 40    |
| `/static/*`     | 7             | yes          | 7 × 10                     | 70    |
| `/api/v2/users` | 12            | no           | 12 × 10 + 100              | 220   |
| `/api/v2/*`     | 7             | yes          | 7 × 10                     | 70    |

> Note: The task specification listed `/api/v2/users` score as 120 (12 × 10),
> but with the exact-match bonus of 100 the score is 220. The agent must apply
> the exact-match bonus consistently. The example in the spec used score=120
> without the bonus; use the bonus formula as the authoritative rule since the
> spec text defines it separately from the example.

**Assigning precedence after scoring:**

1. Compute `specificity_score` for every cache behavior's `path_pattern`.
2. Sort behaviors in **descending score order** (highest score first).
3. Assign `precedence` values starting at `1`, incrementing by `1` for each
   behavior in sorted order.
4. **Exception:** The default catch-all pattern `"*"` always receives
   `precedence = 999` regardless of sort position. It must be placed last.
5. If two patterns have equal scores (tie), break the tie by lexicographic
   order of `path_pattern` (ascending). This ensures deterministic output.
6. Overwrite the `precedence` field in each cache behavior document with the
   newly computed value.

**Shadowed rule detection during sorting (pre-dedup):**

After sorting, scan for shadowing within `redirect` and `origin_override` rule
types (first-match-wins semantics):

For each pair of behaviors `(A, B)` where `precedence(A) < precedence(B)`:
- If both have at least one `viewer_request_ops` entry of type `redirect` or
  `origin_override`:
  - Evaluate whether the condition of A is a **strict superset** of B's
    condition, meaning every request matching B also matches A.
  - A condition is a strict superset of B if:
    - A's `path_pattern` is a prefix wildcard that covers B's `path_pattern`
      (e.g., A=`/api/*` covers B=`/api/v2/*`)
    - OR A's `path_pattern` is `*` or `/*` (covers everything)

  If A shadows B:
  - Add `shadowed: true` to B's document.
  - Add an entry to B's `non_convertible` list (append, do not replace):
    ```yaml
    - type: shadowed_rule
      reason: "Rule shadowed by cache_behavior with path_pattern='<A.path_pattern>' (precedence=<A.precedence>). This rule will never be evaluated in CloudFront."
      original_rule_type: "<type>"
    ```
  - Record a warning for the conversion report.

---

### Step 4 — Policy Deduplication

This step detects identical policies used across multiple domains and assigns
shared policy identifiers.

#### What gets deduplicated

For each cache behavior in each domain, extract these policy objects if present:
- `cache_policy`
- `origin_request_policy`
- `response_headers_policy`

#### Deduplication algorithm

For each policy object found:

1. **Normalize** the policy object:
   - Serialize to JSON with **sorted keys** and no extra whitespace.
   - This ensures structurally identical objects produce identical hashes
     regardless of key ordering.

2. **Hash** the normalized JSON string using SHA256.

3. **Assign policy_id:**
   ```
   policy_id = "policy-" + first_8_chars(sha256_hex_digest)
   ```
   Example: if SHA256 = `a3f7b291c4d5e6...`, then `policy_id = "policy-a3f7b291`

4. **Record in dedup_manifest:**
   - Key: `policy_id`
   - Value:
     ```json
     {
       "hash": "<full sha256 hex>",
       "type": "cache_policy" | "origin_request_policy" | "response_headers_policy",
       "count": <number of cache behaviors referencing this policy>,
       "sample_hostname": "<first hostname encountered with this policy>",
       "config": { <the original policy object> }
     }
     ```
   - If a `policy_id` already exists (same hash, different domain), increment
     `count` and do not overwrite `sample_hostname` or `config`.

5. **Replace inline policy with reference** in the cache behavior document:
   - Remove the inline policy object key (`cache_policy`, etc.)
   - Add a reference key:
     ```yaml
     cache_policy_id: "policy-a3f7b291"
     ```
   - Naming convention: `<original_key>_id`

   So:
   - `cache_policy` → replaced by `cache_policy_id: "<policy_id>"`
   - `origin_request_policy` → replaced by `origin_request_policy_id: "<policy_id>"`
   - `response_headers_policy` → replaced by `response_headers_policy_id: "<policy_id>"`

#### Hash collision handling

If two different `policy_id` values (different first-8-chars of hash) share
the same hash (impossible with SHA256 in practice but guard anyway): this is
a FATAL error:
```
HASH_COLLISION_FATAL: Two distinct policies produced the same policy_id "<policy_id>". This should never happen. Aborting finalization.
```

If two distinct policy objects produce the same first-8-char prefix but
different full hashes (truncation collision):
- Append a suffix: `policy-a3f7b291-2`, `policy-a3f7b291-3`, etc.
- Record a warning in the conversion report.

---

### Step 5 — Write Finalized IR Files

For each domain in `domain_map`:

1. Reconstruct a multi-document YAML with:
   - First document: the metadata document — pass through **all** fields
     verbatim (`document_type`, `hostname`, `sanitized_name`, `apex_domain`,
     `cert_arn_mode`, `cert_arn`, `kvs_requirements`, `kvs_data`,
     `custom_error_responses`, `lambda_edge`, and any other fields present).
     Update `finalized_at` timestamp if that field exists, or add it.
   - Subsequent documents: the sorted, deduplicated cache_behavior documents,
     in order of ascending `precedence`.

2. Write to:
   ```
   cloudflare-to-aws-cdn/ir/final/<hostname>.yaml
   ```

3. The output YAML must:
   - Use `---` document separators.
   - Preserve all original fields from input documents (minus replaced inline
     policies).
   - Include the updated `precedence` values from Step 3.
   - Include `shadowed: true` flags where applicable (from Step 3).
   - Replace inline policy objects with `*_policy_id` references (from Step 4).

4. Do NOT write a file for any domain that failed Step 1's prerequisite check
   (this case should have already halted execution, but guard here as well).

---

### Step 6 — Write Dedup Manifest

Write the complete deduplication manifest to:

```
cloudflare-to-aws-cdn/shared/dedup_manifest.json
```

Format:

```json
{
  "generated_at": "<ISO 8601 timestamp>",
  "total_policies": <count of unique policy_ids>,
  "policies": {
    "policy-a3f7b291": {
      "hash": "a3f7b291c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
      "type": "cache_policy",
      "count": 3,
      "sample_hostname": "cdn.example.com",
      "config": { ... }
    },
    "policy-99abc123": {
      ...
    }
  }
}
```

Pretty-print with 2-space indent. Ensure keys in `policies` are sorted
lexicographically for deterministic output.

---

### Step 7 — Write Conversion Report

Write a human-readable Markdown report to:

```
cloudflare-to-aws-cdn/conversion_report.md
```

The report must include the following sections. If a section has no entries,
include the section header with a note: `_No items in this category._`

#### Report Structure

```markdown
# Cloudflare → CloudFront Conversion Report

Generated: <ISO 8601 timestamp>
Domains processed: <count>
Total cache behaviors: <total count across all domains>
Total unique policies: <count from dedup manifest>

---

## Shadowed Rules

Rules that will never be evaluated in CloudFront because a higher-priority
rule (lower precedence number) has a condition that is a strict superset.

| Domain | Path Pattern | Shadowed By | Rule Type |
|--------|-------------|-------------|-----------|
| ... | ... | ... | ... |

_If none: "No shadowed rules detected."_

---

## Non-Convertible Items

Rules or configurations that could not be directly mapped to CloudFront and
were excluded from the finalized IR.

| Domain | Cache Behavior | Type | Reason |
|--------|---------------|------|--------|
| ... | ... | ... | ... |

_If none: "No non-convertible items."_

---

## Policy Deduplication Summary

Policies shared across multiple domains.

| Policy ID | Type | Used By (count) | Sample Domain |
|-----------|------|-----------------|---------------|
| ... | ... | ... | ... |

---

## Warnings

<list of all warnings generated during finalization>

_If none: "No warnings."_

---

## Domain Summary

| Domain | Cache Behaviors | Shadowed | Non-Convertible | Status |
|--------|----------------|----------|-----------------|--------|
| ... | ... | ... | ... | Finalized |
```

Write this file even if it contains only empty sections. An absent
`conversion_report.md` will cause V2 validation to fail.

---

### Step 8 — Output Summary to User

After all files are written, output a summary:

```
[cf-cdn-ir-finalizer] Finalization complete.

Domains finalized: <N>
Total cache behaviors across all domains: <total>
Unique policies identified: <count>
Shadowed rules detected: <count>
Non-convertible items: <count>

Output files:
  cloudflare-to-aws-cdn/ir/final/<hostname1>.yaml
  cloudflare-to-aws-cdn/ir/final/<hostname2>.yaml
  ...
  cloudflare-to-aws-cdn/shared/dedup_manifest.json
  cloudflare-to-aws-cdn/conversion_report.md

Next step: run cf-cdn-ir-final-validator for each domain.
```

---

## Reference Documents

| Document | Purpose |
|---|---|
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-per-domain-processor/SKILL.md` | IR schema — field definitions for cache_behavior and metadata documents |
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md` | V1 validation rules — understand what has already been checked |
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-finalizer/SKILL.md` | This file — sorting, dedup, and finalization algorithms |

---

## Algorithm Reference Card

### Specificity Score Quick Reference

```
pattern = "*"             → score 0     (special: precedence 999)
pattern starts with "/*"  → score 10    (one literal char '/')
pattern = "/api/*"        → score 40    (4 literal chars: /api)
pattern = "/static/*"     → score 70    (7 literal chars: /static)
pattern = "/api/v2/*"     → score 70    (7 literal chars: /api/v2)
pattern = "/api/v2/users" → score 220   (12 chars × 10 + 100 exact bonus)
```

### Precedence Assignment Summary

```
1. Compute score for each pattern
2. Sort descending by score (higher score = more specific = lower precedence number)
3. Assign precedence 1, 2, 3, ... in sorted order
4. Force "*" to precedence 999, placed last
5. Tie-break by lexicographic order of path_pattern (ascending)
```

### Policy ID Generation

```
normalized_json = JSON.stringify(policy_obj, sorted_keys)
sha256_hex = sha256(normalized_json)
policy_id = "policy-" + sha256_hex[0:8]
```

### Shadowing Detection Criteria

A rule B is shadowed by rule A when all of the following are true:
- `precedence(A) < precedence(B)` (A evaluated first)
- Both involve a first-match-wins rule type (`redirect` or `origin_override`)
- A's `path_pattern` is a strict superset of B's `path_pattern`

Superset examples:
- `/*` shadows `/api/*` ✓
- `/api/*` shadows `/api/v2/*` ✓
- `/api/*` does NOT shadow `/static/*` ✗
- `*` shadows everything ✓

---

## Important Constraints

- **Do not run if any domain failed V1 validation.** Check Step 1 rigorously.
- **Do not modify input files** in `ir/accumulator/`. All writes go to `ir/final/`.
- **Preserve all non-policy fields** from input documents verbatim.
- **The dedup manifest must be complete** — every `*_policy_id` reference in
  any `ir/final/*.yaml` file must have a corresponding entry in
  `dedup_manifest.json`. V2 validation checks this cross-reference.
- **The conversion_report.md must always be written**, even if empty. Its
  absence is a V2 validation failure.
- **Precedence 999 is reserved** for the default `"*"` pattern. No other
  pattern may receive precedence 999.

---

## Final Response

After completing all steps, end your response with a `---RESULT---` block so the orchestrator can parse the outcome:

```
---RESULT---
STATUS: COMPLETE
DOMAINS_PROCESSED: 5
FILES_WRITTEN: ir/final/*.yaml, shared/dedup_manifest.json, conversion_report.md
---
```

Or on failure:

```
---RESULT---
STATUS: ERROR
ISSUE: No V1 validation reports found in ir/validation/chunk/
---
```
