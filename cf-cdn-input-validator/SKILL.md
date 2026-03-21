---
name: cf-cdn-input-validator
description: >
  Validate operator-filled user_input.csv against dns_manifest.yaml, enforce data
  integrity (all proxied hostnames accounted for, valid Y/N flags, correct ACM ARN
  format), and produce domain_scope.json — the authoritative per-domain configuration
  file consumed by cdn-preprocess.py.
metadata:
  author: chenghit
---

# Skill: cf-cdn-input-validator


## Purpose

This skill is **Step 2** of the Cloudflare → CloudFront CDN migration pipeline.

After the operator fills in `user_input_template.csv` (renamed to `user_input.csv`),
this skill:

1. Reads `user_input.csv` (operator-provided) and `dns_manifest.yaml` (from Step 1).
2. Validates completeness and correctness of operator input.
3. Enriches each domain entry with data from the manifest (apex domain, origin content).
4. Determines `cert_arn_mode` for each domain (explicit ARN vs. Terraform data source).
5. Writes `domain_scope.json` — the single source of truth consumed by all downstream
   processing steps.

This skill is the **validation gate** between human input and automated code generation.
Be strict: fail loudly on any validation error rather than silently continuing with
potentially wrong configuration.

---

## Path Resolution

All paths are relative to the **output directory** (`cloudflare-to-aws-cdn/`) under
the current working directory when the skill is invoked.

| Alias            | Resolved Path                                                                 |
|------------------|-------------------------------------------------------------------------------|
| `OUTPUT_DIR`     | `cloudflare-to-aws-cdn/` (relative to current working directory)              |
| `MANIFEST`       | `OUTPUT_DIR/dns_manifest.yaml`                                                |
| `USER_INPUT`     | `OUTPUT_DIR/user_input.csv`                                                   |
| `DOMAIN_SCOPE`   | `OUTPUT_DIR/domain_scope.json`                                                |
| `BACKUP_PATH`    | Read from context or ask operator — same backup directory used in Step 1      |

---

## Output Directory

`OUTPUT_DIR` (`cloudflare-to-aws-cdn/`) must already exist from Step 1. If it does not
exist, abort with:

```
ERROR: Output directory not found at <OUTPUT_DIR>.
       Please run cf-cdn-dns-parser first.
```

---

## Workflow

Follow every step in order. Do not skip steps or reorder them.

### Step 1 — Verify Prerequisites

Check that the following files exist before doing anything else:

1. `OUTPUT_DIR/dns_manifest.yaml` — created by cf-cdn-dns-parser
2. `OUTPUT_DIR/user_input.csv` — filled by operator from template

If `dns_manifest.yaml` is missing:
```
ERROR: dns_manifest.yaml not found. Please run cf-cdn-dns-parser first.
```

If `user_input.csv` is missing (only the template exists):
```
ERROR: user_input.csv not found.
       Did you rename user_input_template.csv to user_input.csv after filling it in?
       Expected location: <OUTPUT_DIR>/user_input.csv
```

### Step 2 — Read dns_manifest.yaml

Parse `dns_manifest.yaml`. Extract:

- `zone_name` — top-level zone name string
- `backup_timestamp` — timestamp string
- `proxied_domains` — list of all proxied hostnames with their metadata
- `apex_groups` — apex domain groupings with suggested cert domains
- `saas_detected` — must be `false`; if `true`, abort with:
  ```
  ERROR: dns_manifest.yaml has saas_detected=true.
         This backup contains SaaS configuration which is not supported.
         Please re-run cf-cdn-dns-parser to verify.
  ```

Build a lookup map: `{ hostname → {apex_domain, record_type, origin_content, origin_type} }` for
quick access during validation.

Also record the expected set of hostnames: every `hostname` in `proxied_domains`.

### Step 3 — Read and Parse user_input.csv

Parse `user_input.csv` as a CSV file.

**Encoding:** Strip UTF-8 BOM (`\xEF\xBB\xBF`) from the beginning of the file if
present — Excel and some editors add this when saving CSV files.

**Expected columns (exact header names, case-sensitive):**
```
hostname,apply_default_cache_behavior,cert_arn
```

If the header row is missing or has different column names, abort with:
```
ERROR: user_input.csv has unexpected column headers.
       Expected: hostname,apply_default_cache_behavior,cert_arn
       Found:    <actual header>
```

Parse every data row, trimming whitespace from all field values.
Skip empty rows (rows where all fields are empty or whitespace-only).

Build a list of parsed input entries:
```
[
  { hostname, apply_default_cache_behavior_raw, cert_arn_raw },
  ...
]
```

### Step 4 — Validate Each Row

For each row in `user_input.csv`, perform the following validations.
Collect ALL errors before reporting — do not abort on the first error.

#### 4a. Hostname existence check

The `hostname` value must exist in the manifest's `proxied_domains` list.

**Error if not found:**
```
VALIDATION ERROR [row <N>]: Hostname "<hostname>" is not in dns_manifest.yaml.
  This hostname was not in the original proxied DNS records.
  Either remove this row or re-run cf-cdn-dns-parser.
```

#### 4b. apply_default_cache_behavior value check

Must be exactly `Y` or `N` (case-insensitive — normalize to uppercase internally,
but flag if the user typed lowercase with a warning, not an error).

**Error if value is anything other than Y/N/y/n:**
```
VALIDATION ERROR [row <N>]: apply_default_cache_behavior for "<hostname>" is "<value>".
  Must be Y or N.
```

#### 4c. cert_arn format check (if provided)

If `cert_arn` is non-empty, it must match this exact pattern:
```
arn:aws:acm:<region>:<account-id>:certificate/<uuid>
```

Where:
- `<region>` is a valid AWS region string (e.g., `us-east-1`, `eu-west-1`)
- `<account-id>` is a 12-digit number
- `<uuid>` is a standard UUID (8-4-4-4-12 hex format)

Regex for validation:
```
^arn:aws:acm:[a-z]{2}-[a-z]+-\d+:\d{12}:certificate/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$
```

**Error if format does not match:**
```
VALIDATION ERROR [row <N>]: cert_arn for "<hostname>" does not match ACM ARN format.
  Provided: "<value>"
  Expected: arn:aws:acm:<region>:<12-digit-account-id>:certificate/<uuid>
  Example:  arn:aws:acm:us-east-1:<ACCOUNT_ID>:certificate/<CERTIFICATE_ID>
```

**Important:** CloudFront requires ACM certificates to be in **us-east-1** regardless
of the CloudFront distribution's edge location. If a cert_arn is provided with a
region other than `us-east-1`, add a **warning** (not an error):
```
WARNING [row <N>]: cert_arn for "<hostname>" is in region "<region>".
  CloudFront distributions require ACM certificates in us-east-1.
  This may cause a Terraform apply error unless you are using a non-standard setup.
```

### Step 5 — Check for Missing Hostnames

Compare the set of hostnames in `user_input.csv` against the expected set from
`dns_manifest.yaml`.

If any proxied hostname from the manifest is **not present** in `user_input.csv`, add
an error for each missing hostname:
```
VALIDATION ERROR: Hostname "<hostname>" from dns_manifest.yaml is missing from user_input.csv.
  All proxied domains must be accounted for.
  Add a row for this hostname to user_input.csv.
```

If there are duplicate hostname rows in `user_input.csv`, add an error:
```
VALIDATION ERROR: Hostname "<hostname>" appears <N> times in user_input.csv.
  Each hostname must appear exactly once.
```

### Step 6 — Report Validation Results

If any errors were collected:

```
❌ Validation failed. Found <N> error(s):

  1. <error message>
  2. <error message>
  ...

Warnings:
  1. <warning message>
  ...

Please fix user_input.csv and re-run cf-cdn-input-validator.
```

**Abort. Do not write domain_scope.json.**

If validation passes (zero errors, warnings may exist):

```
✅ Validation passed. <N> hostname(s) validated.
   <W> warning(s) noted (see above).
```

Continue to Step 7.

### Step 7 — Build domain_scope.json

Construct the `domain_scope.json` object as follows:

#### Top-level fields:

```json
{
  "zone_name": "<from manifest>",
  "backup_path": "<absolute path to backup directory>",
  "domains": [...],
  "apex_cert_groups": {...},
  "global_rules_note": "Rules without http.host condition will be applied to ALL domains during per-domain processing"
}
```

**`backup_path`**: Ask for the backup directory path if not already known from context.
This should be the same directory path used in Step 1 (cf-cdn-dns-parser). It is
stored here so that cdn-preprocess.py can locate all rule files without
needing to ask the operator again.

#### Building `domains` array:

For each row in `user_input.csv` (in the same order as `proxied_domains` in the
manifest — sort alphabetically by hostname):

```json
{
  "hostname": "<hostname>",
  "apex_domain": "<from manifest lookup>",
  "apply_default_cache_behavior": <true if Y, false if N>,
  "cert_arn_mode": "<explicit | data_source>",
  "cert_arn": "<ARN string or null>",
  "origin_content": "<from manifest lookup>",
  "origin_type": "<from manifest lookup: s3 | object_storage | server>"
}
```

**`cert_arn_mode` logic:**
- If `cert_arn` column is non-empty → `"explicit"`, and `cert_arn` = the provided ARN
- If `cert_arn` column is empty → `"data_source"`, and `cert_arn` = `null`

**`apply_default_cache_behavior` logic:**
- `"Y"` (case-insensitive) → `true`
- `"N"` (case-insensitive) → `false`

#### Building `apex_cert_groups`:

Copy directly from `apex_groups` in `dns_manifest.yaml`, transforming the YAML
structure to JSON. Only include apex groups that have at least one hostname in the
validated `user_input.csv`.

```json
"apex_cert_groups": {
  "c.example.com": {
    "suggested_cert_domain": "*.c.example.com",
    "hostnames": ["cdn.c.example.com", "www.c.example.com"]
  }
}
```

### Step 8 — Write domain_scope.json

Write `domain_scope.json` to `OUTPUT_DIR`.

Use 2-space JSON indentation. Do not minify.

**Full example output:**

```json
{
  "zone_name": "c.example.com",
  "backup_path": "/home/operator/cloudflare-backups/c.example.com/2026-02-05 12-09-04",
  "domains": [
    {
      "hostname": "cdn.c.example.com",
      "apex_domain": "c.example.com",
      "apply_default_cache_behavior": true,
      "cert_arn_mode": "explicit",
      "cert_arn": "arn:aws:acm:us-east-1:<ACCOUNT_ID>:certificate/<CERTIFICATE_ID>",
      "origin_content": "httpecho.a.letsmakeit.link",
      "origin_type": "server"
    },
    {
      "hostname": "www.c.example.com",
      "apex_domain": "c.example.com",
      "apply_default_cache_behavior": true,
      "cert_arn_mode": "data_source",
      "cert_arn": null,
      "origin_content": "httpecho.a.letsmakeit.link",
      "origin_type": "server"
    },
    {
      "hostname": "cors1.c.example.com",
      "apex_domain": "c.example.com",
      "apply_default_cache_behavior": false,
      "cert_arn_mode": "data_source",
      "cert_arn": null,
      "origin_content": "httpecho.a.letsmakeit.link",
      "origin_type": "server"
    }
  ],
  "apex_cert_groups": {
    "c.example.com": {
      "suggested_cert_domain": "*.c.example.com",
      "hostnames": [
        "cdn.c.example.com",
        "www.c.example.com",
        "cors1.c.example.com"
      ]
    }
  },
  "global_rules_note": "Rules without http.host condition will be applied to ALL domains during per-domain processing"
}
```

### Step 9 — Print Summary and Next Steps

```
✅ domain_scope.json written successfully.

Summary:
  Zone: <zone_name>
  Total domains: <N>
    - With default cache behavior (Y): <count>
    - Without default cache behavior (N): <count>
    - With explicit cert_arn: <count>
    - Using Terraform data source for cert: <count>
  Apex cert groups: <M>

Output:
  <OUTPUT_DIR>/domain_scope.json

Next steps:
  Run cdn-preprocess.py to process all domains at once:

    python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-preprocess.py \
      <backup_dir> cloudflare-to-aws-cdn

  Or process a single domain:

    python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-preprocess.py \
      <backup_dir> cloudflare-to-aws-cdn --domain cdn.c.example.com
```

---

## Validation Rules Reference

| Check                          | Severity | Condition                                                       |
|-------------------------------|----------|-----------------------------------------------------------------|
| Missing user_input.csv         | ABORT    | File not found before parsing                                   |
| Missing dns_manifest.yaml      | ABORT    | File not found before parsing                                   |
| saas_detected=true in manifest | ABORT    | Manifest has saas_detected flag set                             |
| Wrong CSV headers              | ABORT    | Header row doesn't match expected columns                       |
| Unknown hostname               | ERROR    | Row hostname not in manifest proxied_domains                    |
| Missing hostname               | ERROR    | Manifest hostname absent from user_input.csv                    |
| Duplicate hostname             | ERROR    | Same hostname appears more than once in CSV                     |
| Invalid Y/N value              | ERROR    | apply_default_cache_behavior not Y or N                         |
| Malformed cert_arn             | ERROR    | cert_arn provided but doesn't match ACM ARN regex               |
| cert_arn not in us-east-1      | WARNING  | cert_arn region is not us-east-1                                |
| Lowercase y/n                  | WARNING  | apply_default_cache_behavior is lowercase (normalized silently) |

---

## domain_scope.json Schema

```
{
  zone_name: string
  backup_path: string (absolute filesystem path)
  domains: Array<{
    hostname: string (FQDN)
    apex_domain: string
    apply_default_cache_behavior: boolean
    cert_arn_mode: "explicit" | "data_source"
    cert_arn: string | null
    origin_content: string (IP or hostname)
    origin_type: "s3" | "object_storage" | "server"
  }>
  apex_cert_groups: {
    [apex_domain: string]: {
      suggested_cert_domain: string
      hostnames: string[]
    }
  }
  global_rules_note: string
}
```

Note: Fields like `geo_restriction`, `price_class`, `waf_acl_arn`, `http_version`,
and `ipv6_enabled` are **not** in `domain_scope.json`. They are derived from
Cloudflare configuration rules during per-domain processing and written into the
IR accumulator's `distribution_settings` block. `cf-cdn-tf-domain` reads them
from the IR, not from `domain_scope.json`.

---

## Reference Documents

No reference files are required for this skill. All validation logic is
self-contained in the workflow steps above.

---

## Notes and Constraints

- This skill performs **data validation only** — it does not read any Cloudflare rule
  files. Rule processing is entirely in cdn-preprocess.py.
- `domain_scope.json` is the **single source of truth** for all downstream steps.
  Never modify it manually after this point.
- The `global_rules_note` field is a reminder to cdn-preprocess.py that
  rules without `http.host` conditions apply to every domain — this is documented
  here for traceability, not because this skill handles those rules.
- If the operator wants to add a hostname that was NOT proxied in Cloudflare (e.g.,
  a new domain they want on CloudFront), that is out of scope for this toolchain.
  This tool only migrates existing Cloudflare-proxied records.
- If `dns_manifest.yaml` is regenerated (re-running cf-cdn-dns-parser), `domain_scope.json`
  must be regenerated too. Warn the operator if `dns_manifest.yaml` is newer than
  `domain_scope.json` (if both exist).

---

## Final Response

After completing all steps, end your response with a `---RESULT---` block so the orchestrator can parse the outcome:

```
---RESULT---
STATUS: PASS
FILES_WRITTEN: domain_scope.json
DOMAINS: 5
---
```

Or on failure:

```
---RESULT---
STATUS: ERRORS
ISSUES:
- Row 3: cert_arn format invalid
- Row 5: hostname not found in dns_manifest.yaml
---
```

Or for unrecoverable issues:

```
---RESULT---
STATUS: CANNOT_FIX
ISSUES:
- dns_manifest.yaml is missing
---
```
