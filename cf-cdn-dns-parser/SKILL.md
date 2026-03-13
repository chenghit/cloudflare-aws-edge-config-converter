---
name: cf-cdn-dns-parser
description: >
  Parse a Cloudflare DNS backup file to identify all proxied (orange-cloud) DNS records
  that will become CloudFront distributions. Detects SaaS configuration and aborts if
  found. Groups hostnames by apex domain for ACM certificate grouping. Produces
  dns_manifest.yaml and user_input_template.csv as outputs for downstream skills.
---

# Skill: cf-cdn-dns-parser

## Purpose

This skill is **Step 1** of the Cloudflare → CloudFront CDN migration pipeline.

It reads the raw Cloudflare DNS backup file (`DNS.txt`), identifies every hostname that
is currently proxied through Cloudflare (the "orange cloud" records), and produces two
structured output files:

1. **`dns_manifest.yaml`** — machine-readable inventory of all proxied domains, grouped
   by apex domain, with suggested ACM certificate domains.
2. **`user_input_template.csv`** — a CSV template the operator fills in before running
   the next stage (cf-cdn-input-validator).

> **Safety gate:** If any SaaS-related configuration is detected, this skill **aborts
> immediately** with a clear error message. SaaS migration is not supported by this
> toolchain.

---

## Path Resolution

All paths below are relative to the **base directory** of this skill:

```
/home/chencch/.openclaw/workspace/cf-converter/
```

| Alias              | Resolved Path                                                                 |
|--------------------|-------------------------------------------------------------------------------|
| `BASE`             | `/home/chencch/.openclaw/workspace/cf-converter`                              |
| `REF_DIR`          | `BASE/cf-cdn-analyzer/references/`                                            |
| `OUTPUT_DIR`       | `BASE/cloudflare-to-aws-cdn/`                                                 |
| `DNS_MANIFEST`     | `OUTPUT_DIR/dns_manifest.yaml`                                                |
| `INPUT_TEMPLATE`   | `OUTPUT_DIR/user_input_template.csv`                                          |
| `BACKUP_PATH`      | User-supplied at runtime (e.g. `/path/to/backup/DNS.txt`)                     |
| `SAAS_FALLBACK`    | Same directory as `BACKUP_PATH`: `<backup_dir>/SaaS-Fallback-Origin.txt`      |

---

## Output Directory

Create `cloudflare-to-aws-cdn/` under `BASE` if it does not already exist before
writing any output files. Do **not** overwrite existing files without warning the
operator.

---

## Workflow

Follow every step in order. Do not skip steps or reorder them.

### Step 1 — Read Reference Documentation

Before touching any backup data, read the following reference document:

```
BASE/cf-cdn-analyzer/references/cloudflare-rule-execution-order.md
```

This document explains Cloudflare's rule execution model, which provides essential
context for understanding how proxied records interact with downstream rules. Even
though this skill only parses DNS records, understanding the execution model ensures
you interpret record metadata (e.g., proxied vs. DNS-only) correctly.

If the reference file does not exist, log a warning but continue — it is informational
context for this step only.

### Step 2 — Ask for Backup Path (if not provided)

If the user has not specified the Cloudflare backup directory or `DNS.txt` path,
ask for it now:

> "Please provide the full path to your Cloudflare backup directory (the folder
> containing DNS.txt, Cache-Rules.txt, etc.)."

Construct the `DNS.txt` path as: `<backup_dir>/DNS.txt`

Verify the file exists. If it does not, abort with:

```
ERROR: DNS.txt not found at <path>. Please check the backup directory.
```

### Step 3 — Parse DNS.txt

Cloudflare exports DNS records as a JSON array inside `DNS.txt`. The file format is:

```json
[
  {
    "id": "...",
    "zone_id": "...",
    "zone_name": "c.example.com",
    "name": "cdn.c.example.com",
    "type": "CNAME",
    "content": "httpecho.a.letsmakeit.link",
    "proxiable": true,
    "proxied": true,
    "ttl": 1,
    "locked": false,
    "meta": { ... },
    "created_on": "...",
    "modified_on": "..."
  },
  ...
]
```

**Parsing rules:**

- Read the entire file and parse as JSON.
- Extract `zone_name` from the first record's `zone_name` field.
- Extract `backup_timestamp` from the filename or directory name if available (e.g.,
  a directory named `2026-02-05 12-09-04` → use that string). If not determinable,
  use the file's modification time in `YYYY-MM-DD HH-mm-ss` format.
- Filter records where `proxied: true` — these are the orange-cloud records that are
  routed through Cloudflare and will become CloudFront distributions.
- Ignore records where `proxied: false` or `proxiable: false` — these are DNS-only
  records that do not go through Cloudflare's proxy and should not become CloudFront
  distributions.
- For each proxied record, extract:
  - `hostname` = `name` field (fully qualified hostname)
  - `record_type` = `type` field (A, CNAME, AAAA, etc.)
  - `origin_content` = `content` field (the actual origin: IP address or hostname)
  - `apex_domain` = derived from `hostname` by stripping the leftmost label(s) until
    only 2 labels remain (e.g., `cdn.c.example.com` → `c.example.com`). For
    second-level domains (e.g., `example.com` with no subdomain), use the zone name
    directly.

**Edge cases:**

- If `DNS.txt` contains no proxied records, abort with:
  ```
  ERROR: No proxied DNS records found in DNS.txt. Nothing to migrate.
  ```
- If `DNS.txt` is empty or malformed JSON, abort with:
  ```
  ERROR: DNS.txt could not be parsed as JSON. File may be corrupted or in wrong format.
  ```

### Step 4 — SaaS Detection Check

**This is a hard safety gate. Abort the entire task if SaaS is detected.**

Perform both checks:

#### Check A: SaaS subdomain pattern in proxied records

Scan all proxied DNS records for SaaS-related patterns:

- Any record whose `name` matches `saas.*` (e.g., `saas.c.example.com`)
- Any CNAME record whose `content` contains `cloudfront.net` (a common pattern when
  Cloudflare is acting as a SaaS provider sitting in front of a CloudFront origin —
  migrating this would create a loop)
- Any record tagged with `"type": "CNAME"` pointing to a domain ending in
  `.cloudflaressl.com`, `.cloudflare.com`, or similar Cloudflare SaaS endpoints

#### Check B: SaaS-Fallback-Origin.txt

Look for `SaaS-Fallback-Origin.txt` in the same directory as `DNS.txt`. If the file:
- Does not exist → no SaaS fallback configured (pass)
- Exists and is empty (0 bytes or only whitespace) → no SaaS (pass)
- Exists and contains any non-whitespace content → SaaS is configured (fail)

**If either check fails, abort immediately with this exact message:**

```
ABORT: SaaS configuration detected. This tool does not support SaaS migration. Aborting.

Details:
- SaaS-Fallback-Origin.txt: <exists and non-empty / not found>
- SaaS subdomain records: <list any matching hostnames, or "none">

Please handle SaaS domain migration manually before using this toolchain.
```

Do not write any output files. Do not proceed.

### Step 5 — Group Hostnames by Apex Domain

For each proxied hostname, determine its apex domain (Step 3 logic applies).

Build `apex_groups`:

- Key: apex domain string (e.g., `"c.example.com"`)
- Value:
  - `hostnames`: sorted list of all proxied hostnames under this apex
  - `suggested_cert_domain`: wildcard cert suggestion
    - If there is only **one** hostname matching the apex and it equals the apex
      itself → suggest the exact domain (e.g., `"c.example.com"`)
    - Otherwise → suggest `"*.c.example.com"` (wildcard covers all subdomains)
    - If hostnames span more than 2 levels deep (e.g., `deep.sub.c.example.com`) →
      suggest both `"*.c.example.com"` and note that a SAN cert may be needed for
      deeper subdomains, adding a `cert_note` field

### Step 6 — Write dns_manifest.yaml

Create `OUTPUT_DIR` if it does not exist.

Write `dns_manifest.yaml` with the following structure:

```yaml
zone_name: "c.example.com"
backup_timestamp: "2026-02-05 12-09-04"
proxied_domains:
  - hostname: "cdn.c.example.com"
    apex_domain: "c.example.com"
    record_type: "CNAME"
    origin_content: "httpecho.a.letsmakeit.link"
  - hostname: "www.c.example.com"
    apex_domain: "c.example.com"
    record_type: "CNAME"
    origin_content: "httpecho.a.letsmakeit.link"
apex_groups:
  "c.example.com":
    hostnames:
      - "cdn.c.example.com"
      - "www.c.example.com"
      - "cors1.c.example.com"
    suggested_cert_domain: "*.c.example.com"
saas_detected: false
```

**Formatting rules:**
- Use 2-space indentation.
- Quote all string values containing dots or special characters.
- Sort `proxied_domains` alphabetically by `hostname`.
- Sort `hostnames` within each `apex_groups` entry alphabetically.
- Sort top-level `apex_groups` keys alphabetically.
- `saas_detected` must always be `false` at this point (if it were true, we would have
  aborted in Step 4).

### Step 7 — Write user_input_template.csv

Write `user_input_template.csv` with the following structure:

```csv
hostname,apply_default_cache_behavior,cert_arn
cdn.c.example.com,Y,
www.c.example.com,Y,
cors1.c.example.com,N,arn:aws:acm:us-east-1:123456789:certificate/abc123
```

**Column definitions:**

| Column                        | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| `hostname`                    | Fully qualified hostname (from proxied_domains). **Do not edit.**           |
| `apply_default_cache_behavior`| `Y` or `N`. Pre-fill `Y` as the default for all rows.                      |
| `cert_arn`                    | Leave **blank** for all rows. User fills in ACM certificate ARN, or leaves  |
|                               | blank to let the code generator use a Terraform `data` source lookup.       |

**Formatting rules:**
- No header comments or blank rows — just the header line and data rows.
- Pre-fill `apply_default_cache_behavior` with `Y` for every row.
- Leave `cert_arn` empty for every row (the example ARN in the schema above is for
  illustration only — do not pre-fill with example data).
- Order rows alphabetically by `hostname` (same order as `proxied_domains` in manifest).
- Do not add trailing commas.

Include a `## Instructions` comment block at the top of the CSV file? **No.** CSV files
must not have comments. Instead, print instructions to stdout after writing the file
(see Step 8).

### Step 8 — Print Summary and Instructions

After successfully writing both files, print the following summary to the operator:

```
✅ DNS parsing complete.

Summary:
  Zone: <zone_name>
  Backup timestamp: <backup_timestamp>
  Proxied domains found: <N>
  Apex domain groups: <M>
  SaaS detected: false

Output files written:
  <OUTPUT_DIR>/dns_manifest.yaml
  <OUTPUT_DIR>/user_input_template.csv

Next steps:
  1. Open user_input_template.csv and review each hostname.
  2. Change apply_default_cache_behavior to N for any domain that should NOT use
     Cloudflare's default static-asset caching behavior (images, JS, CSS, etc.).
  3. Optionally fill in cert_arn with an existing ACM certificate ARN. If left blank,
     the Terraform code generator will use a data source lookup by domain name.
  4. Save the filled file as user_input.csv (same directory).
  5. Run cf-cdn-input-validator to validate your input and generate domain_scope.json.

column definitions:
  apply_default_cache_behavior=Y  →  Cache ~70 common static file extensions (2h TTL)
  apply_default_cache_behavior=N  →  No automatic caching; rely entirely on Cache-Rules
  cert_arn (blank)                →  Terraform will look up cert by domain name
  cert_arn (filled)               →  Use this specific ACM certificate ARN
```

---

## Reference Documents

The following reference files provide background context. Read them as specified in the
Workflow steps above.

| File                                               | When to Read     | Purpose                                              |
|----------------------------------------------------|------------------|------------------------------------------------------|
| `cf-cdn-analyzer/references/cloudflare-rule-execution-order.md` | Step 1 (required) | Cloudflare execution model context        |

---

## Error Reference

| Error Code / Condition          | Message                                                                          | Action     |
|---------------------------------|----------------------------------------------------------------------------------|------------|
| DNS.txt not found               | `ERROR: DNS.txt not found at <path>.`                                            | Abort      |
| DNS.txt malformed               | `ERROR: DNS.txt could not be parsed as JSON.`                                    | Abort      |
| No proxied records              | `ERROR: No proxied DNS records found in DNS.txt.`                                | Abort      |
| SaaS detected (either check)   | `ABORT: SaaS configuration detected. This tool does not support SaaS migration.` | Abort      |
| Output dir not writable         | `ERROR: Cannot create output directory at <path>. Check permissions.`            | Abort      |

---

## Output File Schemas

### dns_manifest.yaml

```yaml
# Top-level fields
zone_name: string           # e.g. "c.example.com"
backup_timestamp: string    # e.g. "2026-02-05 12-09-04"
saas_detected: boolean      # always false if we reach this point

proxied_domains:            # list, sorted by hostname
  - hostname: string        # FQDN
    apex_domain: string     # 2-label apex
    record_type: string     # A | CNAME | AAAA | etc.
    origin_content: string  # IP or hostname of actual origin

apex_groups:                # map keyed by apex domain
  "<apex>":
    hostnames: [string]     # sorted list of FQDNs
    suggested_cert_domain: string  # e.g. "*.c.example.com"
    cert_note: string       # optional, only if deep subdomains present
```

### user_input_template.csv

```
hostname,apply_default_cache_behavior,cert_arn
<fqdn>,Y,
```

---

## Notes and Constraints

- This skill does **not** read any rule files (Cache-Rules.txt, etc.). Rule processing
  is handled by cf-cdn-per-domain-processor.
- This skill does **not** validate ACM certificate ARNs — that is cf-cdn-input-validator's
  responsibility.
- A hostname with `record_type: A` pointing to an IP address can still become a
  CloudFront distribution; the IP address becomes the custom origin.
- Wildcard DNS records (e.g., `*.c.example.com`) should be included if proxied, but
  flag them in the manifest with `is_wildcard: true` and add a note that wildcard
  CloudFront distributions require careful path-pattern planning.
- Do not attempt to resolve DNS or make any network requests during this skill.
