---
name: cf-cdn-ir-chunk-validator
description: >
  Validator V1 for the Cloudflare → CloudFront migration pipeline.
  Runs after cf-cdn-per-domain-processor for each domain.
  Validates a single ir/accumulator/<hostname>.yaml file using an
  adversarial checking posture: default assumption is the input is WRONG.
  Produces a structured JSON validation report and halts on any failure.
metadata:
  author: chenghit
---

# cf-cdn-ir-chunk-validator

**Validator V1 — Per-Domain IR Chunk Validation**

This skill performs rigorous structural and semantic validation of a single
intermediate-representation (IR) accumulator file produced by
`cf-cdn-per-domain-processor`. It enforces the adversarial posture: the input
is assumed incorrect until every check passes. Findings are reported as
machine-readable JSON. The agent must never attempt to fix errors — only
detect and report them.

---

## Adversarial Checking Posture

> These rules govern every decision made during validation. They override any
> impulse toward leniency or interpretation.

- **Default assumption: the input is WRONG** until every explicit check passes.
- **Find failures. Do not confirm success** — success is the absence of
  detected failures, not a positive finding.
- **Ambiguous results → FAIL** with a precise explanation of the ambiguity.
  Do not guess intent.
- **Missing field = missing.** Do not infer a default value. Do not assume the
  author intended something. If the field is absent, it is absent.
- **Do NOT suggest fixes.** Write the error. Stop. Output errors only.
- **A false negative (missed error) is worse than a false positive.**
  When uncertain whether a rule is violated, FAIL.
- **Whitespace-only strings are not valid strings.** Any field requiring a
  non-empty string must contain at least one non-whitespace character.

---

## Path Resolution

All paths are resolved relative to the **project output root**:

```
cloudflare-to-aws-cdn/
```

This directory is located at:

```
<workspace>/cloudflare-to-aws-cdn/
```

where `<workspace>` is the current working directory when the skill is invoked.

| Logical path           | Resolved path                                               |
|------------------------|-------------------------------------------------------------|
| IR accumulator input   | `cloudflare-to-aws-cdn/ir/accumulator/<sanitized_hostname>.yaml`  |
| Validation output      | `cloudflare-to-aws-cdn/ir/validation/chunk/<hostname>-v1.json` |

The `<sanitized_hostname>` token is the hostname with every `.` and `-` replaced by `_`
(e.g., `cdn.c.example.com` → `cdn_c_example_com`).
The `<hostname>` token in the validation output is the **raw** hostname (e.g., `cdn.c.example.com`)
read from the `hostname` field inside the YAML.

---

## Output Directory

```
cloudflare-to-aws-cdn/ir/validation/chunk/
```

Create this directory if it does not exist. Write one JSON file per validated
domain. Do not write any other files. Do not modify the input YAML.

---

## Output Format

Every run — pass or fail — produces a JSON file at:

```
cloudflare-to-aws-cdn/ir/validation/chunk/<hostname>-v1.json
```

Schema:

```json
{
  "hostname": "<hostname>",
  "validator": "cf-cdn-ir-chunk-validator",
  "status": "PASS" | "FAIL",
  "errors": [
    "<check_id>: <detailed description of the specific failure>"
  ],
  "warnings": [
    "<optional informational messages that do not cause FAIL>"
  ]
}
```

Rules:
- `status` is `"FAIL"` if `errors` array is non-empty; `"PASS"` otherwise.
- `errors` entries must be specific: include the document index, field path,
  and observed value where applicable.
- `warnings` are informational only and do not affect `status`.
- Do not omit either `errors` or `warnings` keys — use empty arrays if none.

---

## Workflow

### Step 0 — Read Reference Documents First

Before beginning any validation, read the following reference files in order:

1. `references/behavior-assembly.md` — the
   IR output schema (metadata document and cache_behavior document field definitions).
2. `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md` (this file) — confirm
   the checks to perform.

Do not skip this step. The IR schema definition is authoritative; if the
input file deviates from it, that deviation is an error.

---

### Step 1 — Identify the Target Hostname

Determine the hostname being validated. This is provided as the skill input
parameter (e.g., `cdn.c.example.com`). Derive:

- **Sanitized name:** replace every `.` and `-` with `_` (e.g., `cdn_c_example_com`)
- **Input file path:** `cloudflare-to-aws-cdn/ir/accumulator/<sanitized_name>.yaml`
- **Output file path:** `cloudflare-to-aws-cdn/ir/validation/chunk/<hostname>-v1.json`
  (raw hostname in the output filename, consistent with all other validation outputs)

If no hostname parameter is provided, FAIL immediately with:

```
SETUP_ERROR: No hostname parameter supplied. Cannot determine input file.
```

---

### Step 2 — Verify Input File Exists

Check that the input YAML file exists at the resolved path.

If the file does not exist:
- Write the validation JSON with `status: "FAIL"` and error:
  ```
  FILE_NOT_FOUND: Expected input file does not exist: cloudflare-to-aws-cdn/ir/accumulator/<sanitized_hostname>.yaml
  ```
- Output a clear FAILURE message to the user.
- **Stop. Do not proceed.**

---

### Step 3 — Parse the YAML File

Load the YAML file. It may be a **multi-document YAML file** (documents
separated by `---`). Parse all documents into an ordered list.

If parsing fails (invalid YAML syntax):
- Write validation JSON with `status: "FAIL"` and error:
  ```
  PARSE_ERROR: YAML parsing failed. <parser error message>
  ```
- Output FAILURE message to user.
- **Stop.**

After parsing, separate documents by their `document_type` field:
- `document_type: cache_behavior` → collected into `cache_behavior_docs` list
- `document_type: metadata` → assigned to `metadata_doc` (expect exactly one)
- Any document without `document_type` → record warning:
  ```
  WARN: Document at index <n> has no document_type field. It will not be validated by type-specific checks.
  ```

---

### Step 4 — Run All Validation Checks

Execute every check below in sequence. Collect ALL errors before writing
output — do not short-circuit after the first failure. Each check that fails
appends to the `errors` list.

---

#### Check 1 — `path_pattern` and `precedence` on every cache_behavior

For each document in `cache_behavior_docs` (index `i`, 0-based):

**1a. `path_pattern` must be present and non-null:**
- If `path_pattern` key is absent: append error
  ```
  CB_MISSING_PATH_PATTERN[<i>]: cache_behavior document at index <i> is missing the path_pattern field.
  ```
- If `path_pattern` value is `null`: append error
  ```
  CB_NULL_PATH_PATTERN[<i>]: cache_behavior document at index <i> has path_pattern=null.
  ```
- If `path_pattern` value is not a string type (e.g., integer, list): append error
  ```
  CB_INVALID_PATH_PATTERN_TYPE[<i>]: cache_behavior document at index <i> has path_pattern of type <type>, expected string.
  ```

**1b. `precedence` must be present and be an integer:**
- If `precedence` key is absent: append error
  ```
  CB_MISSING_PRECEDENCE[<i>]: cache_behavior document at index <i> is missing the precedence field.
  ```
- If `precedence` value is `null`: append error
  ```
  CB_NULL_PRECEDENCE[<i>]: cache_behavior document at index <i> has precedence=null.
  ```
- If `precedence` is a float (e.g., `1.0`) rather than a strict integer: append error
  ```
  CB_FLOAT_PRECEDENCE[<i>]: cache_behavior document at index <i> has precedence=<value> which is a float, not an integer.
  ```
- If `precedence` is any other non-integer type: append error
  ```
  CB_INVALID_PRECEDENCE_TYPE[<i>]: cache_behavior document at index <i> has precedence of type <type>, expected integer.
  ```

---

#### Check 2 — `origin.domain` validity

For each cache_behavior document at index `i` that contains an `origin` field:

**2a. `origin` field must be a mapping (dict), not null, not a string:**
- If `origin` is null or absent: append error
  ```
  ORIGIN_NULL[<i>]: cache_behavior document at index <i> has null or missing origin field.
  ```

**2b. `origin.domain` must be present and non-empty:**
- If `origin.domain` key is absent: append error
  ```
  ORIGIN_DOMAIN_MISSING[<i>]: cache_behavior document at index <i> has no origin.domain field.
  ```
- If `origin.domain` is null: append error
  ```
  ORIGIN_DOMAIN_NULL[<i>]: cache_behavior document at index <i> has origin.domain=null.
  ```
- If `origin.domain` is an empty string `""`: append error
  ```
  ORIGIN_DOMAIN_EMPTY[<i>]: cache_behavior document at index <i> has origin.domain="" (empty string).
  ```
- If `origin.domain` contains any whitespace character (space, tab, newline): append error
  ```
  ORIGIN_DOMAIN_WHITESPACE[<i>]: cache_behavior document at index <i> has origin.domain="<value>" which contains whitespace characters.
  ```
- If `origin.domain` does not match a basic hostname pattern (letters, digits,
  hyphens, dots only; no protocol prefix like `https://`; no path component):
  append error
  ```
  ORIGIN_DOMAIN_INVALID[<i>]: cache_behavior document at index <i> has origin.domain="<value>" which is not a valid hostname. Hostnames must contain only alphanumeric characters, hyphens, and dots, with no protocol or path components.
  ```

For the purposes of this check, a valid hostname:
- Contains only `[a-zA-Z0-9\-.]`
- Does not start or end with `-` or `.`
- Does not contain consecutive dots `..`
- Does not contain `://`
- Is not empty

---

#### Check 3 — `viewer_request_ops` entry integrity

For each cache_behavior document at index `i`:

If `viewer_request_ops` is present and is a list, iterate over each entry at
sub-index `j` (0-based):

**3a. `type` must not be null:**
- If `type` key is absent: append error
  ```
  VRO_TYPE_MISSING[<i>][<j>]: viewer_request_ops[<j>] in cache_behavior[<i>] is missing the type field.
  ```
- If `type` is null: append error
  ```
  VRO_TYPE_NULL[<i>][<j>]: viewer_request_ops[<j>] in cache_behavior[<i>] has type=null.
  ```

**3b. `params` must be present (not absent, not null) — except for `origin_override`:**

For entries where `type == "origin_override"`, skip the `params` check and instead
verify `conditions`:
- If `conditions` key is absent: append error
  ```
  VRO_CONDITIONS_MISSING[<i>][<j>]: viewer_request_ops[<j>] in cache_behavior[<i>] has type="origin_override" but is missing the conditions field.
  ```
- If `conditions` is null or empty list: append error
  ```
  VRO_CONDITIONS_EMPTY[<i>][<j>]: viewer_request_ops[<j>] in cache_behavior[<i>] has type="origin_override" but conditions is null or empty. At least one condition entry is required.
  ```

For all other types:
- If `params` key is absent: append error
  ```
  VRO_PARAMS_MISSING[<i>][<j>]: viewer_request_ops[<j>] in cache_behavior[<i>] is missing the params field.
  ```
- If `params` is null: append error
  ```
  VRO_PARAMS_NULL[<i>][<j>]: viewer_request_ops[<j>] in cache_behavior[<i>] has params=null. An empty object {} is required at minimum.
  ```

If `viewer_request_ops` is present but is not a list type: append error
```
VRO_NOT_A_LIST[<i>]: viewer_request_ops in cache_behavior[<i>] is not a list (found type: <type>).
```

---

#### Check 4 — `non_convertible` reason strings

For each cache_behavior document at index `i`:

If `non_convertible` is present and is a list, iterate over each entry at
sub-index `j`:

**4a. `reason` must be a non-empty, non-whitespace string:**
- If `reason` key is absent: append error
  ```
  NC_REASON_MISSING[<i>][<j>]: non_convertible[<j>] in cache_behavior[<i>] is missing the reason field.
  ```
- If `reason` is null: append error
  ```
  NC_REASON_NULL[<i>][<j>]: non_convertible[<j>] in cache_behavior[<i>] has reason=null.
  ```
- If `reason` is an empty string: append error
  ```
  NC_REASON_EMPTY[<i>][<j>]: non_convertible[<j>] in cache_behavior[<i>] has reason="" (empty string).
  ```
- If `reason` consists entirely of whitespace characters: append error
  ```
  NC_REASON_WHITESPACE[<i>][<j>]: non_convertible[<j>] in cache_behavior[<i>] has reason that is whitespace-only: "<value>".
  ```

---

#### Check 5 — No duplicate `precedence` values

Collect all `precedence` values from all `cache_behavior_docs` that have a
valid integer precedence (skip documents that already failed Check 1b).

Build a map of `precedence_value → [list of document indices]`.

For any precedence value that appears more than once: append error for each
duplicate:

```
DUPLICATE_PRECEDENCE[<value>]: precedence=<value> is used by cache_behavior documents at indices: [<i1>, <i2>, ...]. Precedence values must be unique within a domain.
```

---

#### Check 6 — `viewer_request_ops` type ordering

For each cache_behavior document at index `i` where `viewer_request_ops` is a
valid, non-empty list:

The required order is:
1. `redirect` (all redirects first)
2. `rewrite` (all rewrites second)
3. `origin_override` (third)
4. `bulk_redirect` (fourth)
5. Header operations: `add_header`, `set_header`, `remove_header`,
   `override_header` (last group)

Define an ordering rank:
```
redirect       → rank 1
rewrite        → rank 2
origin_override → rank 3
bulk_redirect  → rank 4
add_header     → rank 5
set_header     → rank 5
remove_header  → rank 5
override_header → rank 5
```

Any type not in this list → rank 99 (treat as unknown — append warning, do
NOT fail on unknown types alone unless order is violated).

Iterate through `viewer_request_ops` in order. Track `last_rank`. If the rank
of entry `j` is less than `last_rank`:

```
VRO_ORDER_VIOLATION[<i>][<j>]: viewer_request_ops ordering violation in cache_behavior[<i>]. Entry [<j>] has type="<type>" (rank <rank>) which appears after type="<prev_type>" (rank <prev_rank>). Required order: redirect → rewrite → origin_override → bulk_redirect → header ops.
```

If a type is `null` or missing (already caught by Check 3), skip the ordering
check for that entry (it is already an error).

---

#### Check 7 — `hostname` field matches filename

**7a.** The parsed YAML must contain a top-level `hostname` field (in the
metadata document, or as a top-level key in the first document).

Locate the `hostname` field:
- First look in `metadata_doc` if it exists.
- If not found there, look in the first document of the file.
- If still not found: append error
  ```
  HOSTNAME_MISSING: No hostname field found in any document in the file.
  ```

**7b.** Compare the found `hostname` value to the input hostname parameter:

The sanitized filename is derived from the raw hostname by replacing every `.` and `-`
with `_` (e.g., `cdn.c.example.com` → `cdn_c_example_com`).

The `hostname` field inside the YAML must equal the **raw** hostname (e.g.,
`cdn.c.example.com`), not the sanitized form. The filename uses the sanitized form,
but the YAML content uses the raw form.

To verify: derive the expected sanitized filename from the input hostname parameter,
then check that the file exists at that path. Then check that the `hostname` field
inside the YAML equals the raw input hostname parameter.

If `hostname` value in YAML does not match the raw input hostname:
```
HOSTNAME_MISMATCH: hostname field in YAML is "<yaml_value>" but expected "<raw_hostname>". The hostname field must contain the raw FQDN, not the sanitized filename stem.
```

---

#### Check 8 — KVS requirements consistency

Locate the `kvs_requirements` and `kvs_data` fields in the metadata document
(or the first document as fallback).

**8a. needs_redirects consistency:**

If `kvs_requirements.needs_redirects` is exactly `true` (boolean):

Scan ALL `cache_behavior_docs` for any `viewer_request_ops` entry with
`type == "bulk_redirect"`.

If no such entry is found:
```
KVS_REDIRECT_MISSING: kvs_requirements.needs_redirects=true but no viewer_request_ops entry with type="bulk_redirect" was found in any cache_behavior document. At least one bulk_redirect op is required.
```

**8b. needs_continent consistency:**

If `kvs_requirements.needs_continent` is exactly `true` (boolean):

Check that `kvs_data` contains at least one entry whose `key` starts with `continent:`.

If no such entry is found:
```
KVS_CONTINENT_MISSING: kvs_requirements.needs_continent=true but no kvs_data entry with key prefix "continent:" was found. Continent-to-country mappings are required for CF Function KVS lookup.
```

**8c. needs_eu consistency:**

If `kvs_requirements.needs_eu` is exactly `true` (boolean):

Check that `kvs_data` contains at least one entry whose `key` starts with `eu:`.

If no such entry is found:
```
KVS_EU_MISSING: kvs_requirements.needs_eu=true but no kvs_data entry with key prefix "eu:" was found. EU country entries are required for CF Function KVS lookup.
```

**8d. Reverse consistency (WARN, not FAIL):**

If `kvs_data` contains entries with `continent:` prefix but `needs_continent` is not `true`:
```
WARN: kvs_data contains continent: entries but kvs_requirements.needs_continent is not true. The data will not be used.
```

If `kvs_data` contains entries with `eu:` prefix but `needs_eu` is not `true`:
```
WARN: kvs_data contains eu: entries but kvs_requirements.needs_eu is not true. The data will not be used.
```

If `kvs_requirements` is absent or all flags are `false`/absent, and `kvs_data`
is empty or absent, skip this check entirely.

---

#### Check 9 — Metadata document existence and required fields

**9a. Exactly one metadata document must exist:**

If `metadata_doc` is `null` (no document with `document_type: metadata` was found):
```
META_MISSING: No document with document_type="metadata" found in the YAML file. The metadata document is required by downstream skills (finalizer, tf-domain).
```

If more than one document has `document_type: metadata`:
```
META_DUPLICATE: Found <N> documents with document_type="metadata". Exactly one is expected.
```

**9b. Required fields in metadata document:**

If `metadata_doc` exists, check the following fields:

- `hostname` must be a non-empty string:
  ```
  META_HOSTNAME_MISSING: metadata document is missing the hostname field.
  ```
- `sanitized_name` must be a non-empty string:
  ```
  META_SANITIZED_NAME_MISSING: metadata document is missing the sanitized_name field.
  ```
- `apex_domain` must be a non-empty string:
  ```
  META_APEX_DOMAIN_MISSING: metadata document is missing the apex_domain field.
  ```
- `kvs_requirements` must be present and be a mapping (dict):
  ```
  META_KVS_REQUIREMENTS_MISSING: metadata document is missing the kvs_requirements field. An empty mapping {} is required at minimum.
  ```
- `cert_arn_mode` must be present and equal `"explicit"` or `"data_source"`:
  ```
  META_CERT_ARN_MODE_INVALID: metadata document has cert_arn_mode="<value>". Must be "explicit" or "data_source".
  ```
- `origin_type` must be present and equal `"s3"`, `"object_storage"`, or `"server"`:
  ```
  META_ORIGIN_TYPE_INVALID: metadata document has origin_type="<value>". Must be "s3", "object_storage", or "server".
  ```

---

### Step 5 — Write Validation Output

After all 9 checks complete:

1. Determine `status`:
   - `"FAIL"` if `errors` list is non-empty
   - `"PASS"` if `errors` list is empty

2. Ensure output directory exists:
   ```
   cloudflare-to-aws-cdn/ir/validation/chunk/
   ```

3. Write JSON file to:
   ```
   cloudflare-to-aws-cdn/ir/validation/chunk/<hostname>-v1.json
   ```

4. JSON must be pretty-printed (2-space indent).

5. Do NOT truncate the errors list. Include every error found.

---

### Step 6 — Report Result to User

**If status is PASS:**
Output a single-line confirmation:

```
[cf-cdn-ir-chunk-validator] <hostname>: PASS (0 errors)
```

**If status is FAIL:**
Output a clear FAILURE message:

```
[cf-cdn-ir-chunk-validator] FAILURE — <hostname>: <N> error(s) found.
Validation report written to: cloudflare-to-aws-cdn/ir/validation/chunk/<hostname>-v1.json

Errors:
  1. <error 1>
  2. <error 2>
  ...

Do NOT proceed to cf-cdn-ir-finalizer until all errors are resolved.
```

Do NOT attempt to fix the errors. Do NOT re-run the processor. Do NOT modify
any files other than the validation output JSON.

---

## Reference Documents

Before executing this skill, read the following documents:

| Document | Purpose |
|---|---|
| `references/behavior-assembly.md` | IR output schema — metadata and cache_behavior document field definitions |
| `~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md` | This file — defines all validation rules |

If any reference document is missing or unreadable, FAIL with:
```
SETUP_ERROR: Required reference document not found: <path>. Cannot proceed with validation.
```

---

## Notes for the Executing Agent

- **Never modify the input YAML.** This validator is read-only with respect to
  input files.
- **Collect all errors before writing output.** A partial error list is worse
  than a complete one.
- **Do not infer schema version.** If the YAML does not declare a schema or
  version and the upstream processor SKILL.md indicates one is required, treat
  absence as an error.
- **YAML boolean traps:** `yes`, `no`, `on`, `off` may parse as booleans in
  some YAML parsers. If a field expected to be a string parses as boolean, this
  is a type error — record it.
- **Numeric string traps:** A hostname like `"1.2.3.4"` (IP address) is
  technically a valid hostname for these checks. Do not fail IP-address-format
  origins unless they fail the character-set check.
- **Precedence 999 is a valid integer.** Do not flag it as an error in Check 1.
  Do not assign special meaning to it in V1 validation (V2 handles ordering).
- **Check 9 runs even if no cache_behavior documents exist.** A file with only
  a metadata document and no cache behaviors is structurally valid (though
  unusual). A file with only cache behaviors and no metadata is invalid.
