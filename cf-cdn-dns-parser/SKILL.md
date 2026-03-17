---
name: cf-cdn-dns-parser
description: >
  Parse a Cloudflare DNS backup file to identify all proxied (orange-cloud) DNS records
  that will become CloudFront distributions. Detects SaaS configuration and aborts if
  found. Groups hostnames by apex domain for ACM certificate grouping. Produces
  dns_manifest.yaml and user_input_template.csv as outputs for downstream skills.
metadata:
  author: chenghit
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

All paths below are relative to the **output directory** created by this skill.
The output directory is `cloudflare-to-aws-cdn/` under the current working directory
when the skill is invoked (i.e., the Cloudflare backup directory or the directory
specified by the orchestrator).

| Alias              | Resolved Path                                                                 |
|--------------------|-------------------------------------------------------------------------------|
| `OUTPUT_DIR`       | `cloudflare-to-aws-cdn/` (relative to current working directory)              |
| `DNS_MANIFEST`     | `OUTPUT_DIR/dns_manifest.yaml`                                                |
| `INPUT_TEMPLATE`   | `OUTPUT_DIR/user_input_template.csv`                                          |
| `BACKUP_PATH`      | User-supplied at runtime (e.g. `/path/to/backup/`)                            |
| `SAAS_FALLBACK`    | Same directory as `BACKUP_PATH`: `<backup_dir>/SaaS-Fallback-Origin.txt`      |

---

## Output Directory

Create `cloudflare-to-aws-cdn/` under the current working directory if it does not already exist before
writing any output files. Do **not** overwrite existing files without warning the
operator.

---

## Workflow

Follow every step in order. Do not skip steps or reorder them.

### Step 1 — Ask for Backup Path (if not provided)

If the user has not specified the Cloudflare backup directory or `DNS.txt` path,
ask for it now:

> "Please provide the full path to your Cloudflare backup directory (the folder
> containing DNS.txt, Cache-Rules.txt, etc.)."

Construct the `DNS.txt` path as: `<backup_dir>/DNS.txt`

Verify the file exists. If it does not, abort with:

```
ERROR: DNS.txt not found at <path>. Please check the backup directory.
```

### Step 2 — Parse DNS.txt

Cloudflare exports DNS records as a Cloudflare API response object inside `DNS.txt`.
The file format is:

```json
{
  "result": [
    {
      "id": "...",
      "name": "cdn.c.example.com",
      "type": "CNAME",
      "content": "httpecho.a.letsmakeit.link",
      "proxiable": true,
      "proxied": true,
      "ttl": 1,
      "settings": { ... },
      "meta": { ... },
      "comment": "...",
      "tags": [],
      "created_on": "...",
      "modified_on": "..."
    },
    ...
  ],
  "success": true,
  "errors": [],
  "messages": [],
  "result_info": { ... }
}
```

**Parsing rules:**

- Read the entire file and parse as JSON.
- The DNS records are in the `.result` array (not the top-level object).
- Derive `zone_name` from the **backup directory path**, NOT from the DNS records
  (records do not contain a `zone_name` field). The CloudflareBackup tool creates
  directories as `<zone_name>/<timestamp>/DNS.txt`, so `zone_name` is the grandparent
  directory name of `DNS.txt`. For example, if `DNS.txt` is at
  `/path/to/c.example.com/2026-02-05 12-09-04/DNS.txt`, then `zone_name = "c.example.com"`.
- Extract `backup_timestamp` from the parent directory name of `DNS.txt` (e.g.,
  `2026-02-05 12-09-04`). If the directory name does not look like a timestamp,
  fall back to the file's modification time in `YYYY-MM-DD HH-mm-ss` format.
- Filter records where `proxied: true` — these are the orange-cloud records that are
  routed through Cloudflare and will become CloudFront distributions.
- Ignore records where `proxied: false` or `proxiable: false` — these are DNS-only
  records that do not go through Cloudflare's proxy and should not become CloudFront
  distributions.
- For each proxied record, extract:
  - `hostname` = `name` field (fully qualified hostname)
  - `record_type` = `type` field (A, CNAME, AAAA, etc.)
  - `origin_content` = `content` field (the actual origin: IP address or hostname)
  - `is_wildcard` = `true` if `hostname` starts with `*.` (e.g., `*.c.example.com`)
  - `origin_type` = classify `origin_content` by matching against known object storage
    hostname patterns (case-insensitive):
    - `"s3"` — AWS S3 REST API endpoint (supports OAC): matches
      `*.s3.amazonaws.com`, `*.s3.<region>.amazonaws.com`,
      `s3.amazonaws.com`, `s3.<region>.amazonaws.com`.
      Does NOT include S3 website endpoints (`*s3-website*`) — those are `"object_storage"`.
    - `"object_storage"` — cloud object storage that does NOT support CloudFront OAC:
      - AWS S3 website endpoints: `*.s3-website.<region>.amazonaws.com`,
        `*.s3-website-<region>.amazonaws.com`
      - GCP GCS: `*.storage.googleapis.com`, `storage.googleapis.com`
      - Azure Blob: `*.blob.core.windows.net`, `*.web.core.windows.net`
      - Alibaba OSS: `*.oss*.aliyuncs.com`
      - Tencent COS: `*.cos.*.myqcloud.com`
      - Huawei OBS: `*.obs.*.myhuaweicloud.com`
      - CTYun OOS: `*.oos*.ctyunapi.cn`
    - `"server"` — anything else (IP address, custom hostname, etc.)
  - `apex_domain` = the `zone_name` derived from the directory path (Step 3 parsing
    rules above). All records in the same `DNS.txt` file share the same `apex_domain`.

**Edge cases:**

- If `DNS.txt` contains no proxied records, abort with:
  ```
  ERROR: No proxied DNS records found in DNS.txt. Nothing to migrate.
  ```
- If `DNS.txt` is empty or malformed JSON, abort with:
  ```
  ERROR: DNS.txt could not be parsed as JSON. File may be corrupted or in wrong format.
  ```

### Step 3 — SaaS Detection Check

**This is a hard safety gate. Abort the entire task if SaaS is detected.**

Perform both checks:

#### Check A: SaaS-related patterns in proxied records

Scan all **proxied** DNS records for SaaS-related patterns:

- Any record whose `name` matches `saas.*` (e.g., `saas.c.example.com`)
- Any record tagged with `"type": "CNAME"` pointing to a domain ending in
  `.cloudflaressl.com`, `.cloudflare.com`, or similar Cloudflare SaaS endpoints

#### Check C: CloudFront origin loop detection

Separately, scan all **proxied** CNAME records whose `content` contains `cloudfront.net`.

These hostnames are already pointing to CloudFront as their origin — migrating them
would create a routing loop. **Exclude** them from `proxied_domains` and the CSV
template, and print a warning in the Step 8 summary:

```
⚠️  Excluded: The following proxied hostnames already point to CloudFront origins
   and were excluded from migration (routing loop risk):
  - <hostname> → <content>
```

#### Check B: SaaS-Fallback-Origin.txt

Look for `SaaS-Fallback-Origin.txt` in the same directory as `DNS.txt`. This file
contains a raw Cloudflare API response (same `{"result":...,"success":...}` envelope
as DNS.txt). Parse it as JSON and check:
- Does not exist → no SaaS fallback configured (pass)
- Exists but `success` is `false` (e.g., error code 1551 "Resource not found") → no SaaS (pass)
- Exists, `success` is `true`, and `result.origin` is a non-empty string → SaaS fallback
  origin is configured (fail)

**If either check fails, abort immediately with this exact message:**

```
ABORT: SaaS configuration detected. This tool does not support SaaS migration. Aborting.

Details:
- SaaS-Fallback-Origin.txt: <origin hostname from result.origin / not configured / not found>
- SaaS subdomain records: <list any matching hostnames, or "none">

Please handle SaaS domain migration manually before using this toolchain.
```

Do not write any output files. Do not proceed.

### Step 4 — Group Hostnames by Apex Domain

For each proxied hostname, `apex_domain` = the `zone_name` derived from the directory
path (as described in Step 3). All records in a single `DNS.txt` share the same apex.

Build `apex_groups`:

- Key: apex domain string (e.g., `"c.example.com"`)
- Value:
  - `hostnames`: sorted list of all proxied hostnames under this apex
  - `suggested_cert_domain`: wildcard cert suggestion
    - If there is only **one** hostname and it equals the apex itself → suggest the exact domain
    - Otherwise → suggest `"*.<apex_domain>"` (wildcard covers all direct subdomains)
    - If any hostname has more labels than `<subdomain>.<apex_domain>` (i.e., deeper than one level below the zone) → add a `cert_note` field noting that a SAN cert covering deeper subdomains may be needed

### Step 5 — Write dns_manifest.yaml

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
    is_wildcard: false
    origin_type: "server"
  - hostname: "www.c.example.com"
    apex_domain: "c.example.com"
    record_type: "CNAME"
    origin_content: "httpecho.a.letsmakeit.link"
    is_wildcard: false
    origin_type: "server"
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

### Step 6 — Write user_input_template.csv

Write `user_input_template.csv` with the following structure:

```csv
hostname,apply_default_cache_behavior,cert_arn
cdn.c.example.com,Y,
www.c.example.com,Y,
cors1.c.example.com,N,arn:aws:acm:us-east-1:<ACCOUNT_ID>:certificate/<CERTIFICATE_ID>
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

### Step 7 — Print Summary and Instructions

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

No reference files are required for this skill. All parsing logic is
self-contained in the workflow steps above.

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
    apex_domain: string     # derived from directory path (e.g. "c.example.com" or "example.com")
    record_type: string     # A | CNAME | AAAA | etc.
    origin_content: string  # IP or hostname of actual origin
    is_wildcard: boolean    # true if hostname starts with "*."
    origin_type: string     # "s3" | "object_storage" | "server"
    is_wildcard: boolean    # true if hostname starts with "*."

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

- **Single-zone only**: This skill processes exactly one zone's DNS backup. The
  orchestrator is responsible for ensuring the provided path points to a single
  zone's backup directory (the directory containing `DNS.txt`). If `DNS.txt` is
  not found at the expected path, abort — do not search parent or sibling
  directories for other zones.
- This skill does **not** read any rule files (Cache-Rules.txt, etc.). Rule processing
  is handled by cdn-preprocess.py.
- This skill does **not** validate ACM certificate ARNs — that is cf-cdn-input-validator's
  responsibility.
- A hostname with `record_type: A` pointing to an IP address can still become a
  CloudFront distribution; the IP address becomes the custom origin.
- Wildcard DNS records (e.g., `*.c.example.com`) should be included if proxied, but
  flag them in the manifest with `is_wildcard: true` and add a note that wildcard
  CloudFront distributions require careful path-pattern planning.
- Do not attempt to resolve DNS or make any network requests during this skill.
