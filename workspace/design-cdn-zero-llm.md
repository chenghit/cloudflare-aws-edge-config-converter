# Design: Replace CDN Stage 1-2 LLM Subagents with Python Scripts

Author: chenghit
Date: 2026-04-16
Status: Draft (v3)

## Problem

CDN pipeline Stages 1 (DNS parsing) and 2 (input validation) use LLM subagents (`cf-cdn-dns-parser`, `cf-cdn-input-validator`). These are the only remaining LLM invocations in the entire tool. Both stages perform purely structural operations — JSON/CSV/YAML parsing, field validation, regex matching — that require zero judgment.

LLM subagents for these stages cause:
- ~4 minutes of unnecessary latency (2 min per stage)
- Non-deterministic output (YAML formatting, field ordering)
- Fragile execution (subagents may skip tool calls, requiring retry logic in orchestrator)
- Model dependency (CDN pipeline requires claude-sonnet-4.6-1m minimum)

## Solution

Replace both subagents with Python scripts. After this change, the entire tool (WAF + CDN) is zero LLM.

### New scripts

| Script | Replaces | Input | Output |
|--------|----------|-------|--------|
| `cdn-parse-dns.py` | `cf-cdn-dns-parser` subagent | `{config_path}/**/DNS.txt` | `dns_manifest.yaml` + `user_input_template.csv` |
| `cdn-validate-input.py` | `cf-cdn-input-validator` subagent | `user_input.csv` + `dns_manifest.yaml` | `domain_scope.json` |

### What gets deleted

| Item | Type |
|------|------|
| `cf-cdn-dns-parser/` | Subagent directory (SKILL.md) |
| `cf-cdn-input-validator/` | Subagent directory (SKILL.md) |
| `subagents/cf-cdn-dns-parser.json` | Agent config |
| `subagents/cf-cdn-input-validator.json` | Agent config |

### Pipeline flow change

```
Before: Stage 1 (LLM) → pause → Stage 2 (LLM) → Stage 3-9 (Python)
After:  Stage 1 (Python) → pause → Stage 2 (Python) → Stage 3-9 (Python)
```

The user pause between Stage 1 and 2 remains — user must fill in `user_input.csv`.

## Detailed Design

### cdn-parse-dns.py

Input: `config_path` (Cloudflare backup root), `output_dir`

Steps:
1. Find `DNS.txt` via glob
2. Derive `zone_name` from directory path (grandparent of DNS.txt)
3. Derive `backup_timestamp` from parent directory name
4. Parse JSON, extract proxied A/AAAA/CNAME records
5. SaaS detection:
   - Check for `saas.*` hostnames in proxied records
   - Check `SaaS-Fallback-Origin.txt` for active SaaS config
   - Exclude proxied CNAMEs pointing to `*.cloudfront.net` (loop risk)
6. Classify `origin_type` per record: `s3` / `object_storage` / `server`
7. Group by apex domain, suggest cert domains
8. Write `dns_manifest.yaml` (YAML) + `user_input_template.csv` (CSV)

Origin type classification patterns:
```python
S3_PATTERNS = [
    r'\.s3\.amazonaws\.com$',
    r'\.s3\.[a-z0-9-]+\.amazonaws\.com$',
    r'^s3\.amazonaws\.com$',
    r'^s3\.[a-z0-9-]+\.amazonaws\.com$',
]
OBJECT_STORAGE_PATTERNS = [
    r's3-website',                          # S3 website endpoints
    r'\.storage\.googleapis\.com$',         # GCS
    r'\.blob\.core\.windows\.net$',         # Azure Blob
    r'\.web\.core\.windows\.net$',          # Azure Static Web
    r'\.oss.*\.aliyuncs\.com$',             # Alibaba OSS
    r'\.cos\..*\.myqcloud\.com$',           # Tencent COS
    r'\.obs\..*\.myhuaweicloud\.com$',      # Huawei OBS
    r'\.oos.*\.ctyunapi\.cn$',              # CTYun OOS
]
```

**IP address origin handling** (CRITICAL):

CloudFront does NOT support IP addresses as origins — all origins must be publicly resolvable FQDNs. Proxied A/AAAA records whose `content` is an IP address are **non-convertible**:

1. Exclude from `proxied_domains` in `dns_manifest.yaml`
2. Exclude from `user_input_template.csv`
3. Record in a `non_convertible_origins` list in the manifest:
   ```yaml
   non_convertible_origins:
     - hostname: "cdn.example.com"
       record_type: "A"
       origin_content: "13.218.55.172"
       reason: "CloudFront requires FQDN origins; IP address not supported"
   ```
4. Print warning during Stage 1:
   ```
   ⚠️  Non-convertible: The following domains have IP address origins
      (CloudFront requires FQDN origins):
     - cdn.example.com → 13.218.55.172 (A record)
   ```
5. Downstream scripts ignore these domains entirely. The conversion report includes them as non-convertible items with remediation: "Create a DNS hostname for the IP (e.g., Route 53 A record `origin-cdn.example.com → 13.218.55.172`), then manually create a CloudFront distribution using that hostname as origin."

Only CNAME records have hostname origins and are convertible. A/AAAA records with IP origins are excluded.

Detection: if `record_type` is `A` or `AAAA`, the `content` is always an IP address → non-convertible. No regex needed.

### Additional clarifications

**CNAME content vs name for origin classification** (#5): Origin type is classified from the CNAME record's `content` field (the target hostname), not the `name` field (the domain being proxied). Example: `name: "cdn.example.com"`, `content: "bucket.s3.amazonaws.com"` → `origin_type: "s3"`.

**Non-proxied records** (#6): Not included in `dns_manifest.yaml`. The manifest only contains convertible proxied CNAME records. Non-proxied records are DNS-only and irrelevant to CDN migration.

**Wildcard domains** (#4): Proxied wildcard CNAME records (e.g., `*.example.com`) are included normally with `is_wildcard: true`. CloudFront supports wildcard alternate domain names. No special handling needed.

**apply_default_cache_behavior** (#1): Transparent pass-through field. `Y` → `true` in domain_scope.json, `N` → `false`. Controls whether cdn-preprocess.py creates a default cache behavior with ~70 common static file extensions (2h TTL). If `N`, the domain relies entirely on Cloudflare Cache Rules for caching configuration.

**cert_arn_mode logic** (#2):
- User fills in `cert_arn` column → `cert_arn_mode: "explicit"`, `cert_arn: "<ARN>"`
- User leaves `cert_arn` empty → `cert_arn_mode: "data_source"`, `cert_arn: null` (Terraform uses `data.aws_acm_certificate` to look up an ISSUED cert by domain name)

**backup_path** (#3): The absolute path of `config_path` argument passed to `cdn-validate-input.py`. Stored so `cdn-preprocess.py` can locate rule files without asking the user again.

**global_rules_note** (#5): Informational string only. No downstream script reads it. Included for human readability of domain_scope.json.

**subagents/ directory** (#7): After deleting the two JSON files, `subagents/` is empty. Remove the directory from the repo. Update `install.sh` to skip the subagent copy section entirely and only do cleanup of old configs.

Output format — `---RESULT---` block:
```
---RESULT---
SPEC: 1
STATUS: OK
OUTPUT_FILE: cloudflare-to-aws-cdn/dns_manifest.yaml
DOMAINS: 14
```

Fatal cases:
- DNS.txt not found → `STATUS: FATAL`
- No proxied records → `STATUS: FATAL`
- SaaS detected → `STATUS: FATAL`, `CONTEXT: SaaS configuration detected`

#### dns_manifest.yaml schema

Only consumed by `cdn-validate-input.py` (Stage 2, also being replaced). No other script reads it. Schema must be internally consistent between our two new scripts.

```yaml
zone_name: "c.example.com"                    # from directory path
backup_timestamp: "2026-02-05 12-09-04"        # from parent dir name
saas_detected: false                           # always false (aborted if true)
proxied_domains:                               # sorted by hostname, CNAME only
  - hostname: "cdn.c.example.com"
    apex_domain: "c.example.com"
    record_type: "CNAME"
    origin_content: "httpecho.a.letsmakeit.link"
    is_wildcard: false
    origin_type: "server"                      # s3 | object_storage | server
apex_groups:
  "c.example.com":
    hostnames: ["cdn.c.example.com", "www.c.example.com"]
    suggested_cert_domain: "*.c.example.com"
    cert_note: null                            # optional, for deep subdomains
non_convertible_origins:                       # A/AAAA records with IP origins
  - hostname: "direct.c.example.com"
    record_type: "A"
    origin_content: "13.218.55.172"
    reason: "CloudFront requires FQDN origins; IP address not supported"
cloudfront_loop_excluded:                      # proxied CNAMEs → *.cloudfront.net
  - hostname: "saas.c.example.com"
    origin_content: "d2b6zm1ze1oihf.cloudfront.net"
```

#### user_input_template.csv schema

```csv
hostname,apply_default_cache_behavior,cert_arn
cdn.c.example.com,Y,
www.c.example.com,Y,
```

- `hostname`: FQDN, from proxied_domains (CNAME only)
- `apply_default_cache_behavior`: pre-filled `Y`
- `cert_arn`: empty (user fills in)
- Sorted alphabetically by hostname
- No comments, no BOM

### cdn-validate-input.py

Input: `output_dir` (containing `dns_manifest.yaml` + `user_input.csv`), `config_path`

Steps:
1. Verify `dns_manifest.yaml` and `user_input.csv` exist
2. Parse manifest YAML, build hostname lookup map
3. Parse CSV (handle BOM, trim whitespace, skip empty rows)
4. Validate each row:
   - Hostname exists in manifest
   - `apply_default_cache_behavior` is Y/N
   - `cert_arn` matches ACM ARN regex (if provided)
   - Warn if cert region ≠ us-east-1
5. Check completeness: all manifest hostnames present in CSV, no duplicates
6. Build `domain_scope.json`:
   - Enrich each domain with manifest data (apex, origin, origin_type)
   - Determine `cert_arn_mode` (explicit vs data_source)
   - Copy `apex_cert_groups` from manifest
7. Write `domain_scope.json`

Output format — `---RESULT---` block:
```
---RESULT---
SPEC: 1
STATUS: OK
OUTPUT_FILE: cloudflare-to-aws-cdn/domain_scope.json
DOMAINS: 14
```

Error cases:
- Missing files → `STATUS: FATAL`
- Validation errors → `STATUS: ERROR`, `ACTION: FIX`, list errors
- SaaS flag in manifest → `STATUS: FATAL`

#### domain_scope.json schema

Consumed by `cdn-preprocess.py` (Stage 3) and `cdn-generate-shared-policies.py` (Stage 7). Fields must match exactly.

```json
{
  "zone_name": "c.example.com",
  "backup_path": "/absolute/path/to/backup",
  "domains": [
    {
      "hostname": "cdn.c.example.com",
      "apex_domain": "c.example.com",
      "apply_default_cache_behavior": true,
      "cert_arn_mode": "explicit | data_source",
      "cert_arn": "arn:aws:acm:... | null",
      "origin_content": "httpecho.a.letsmakeit.link",
      "origin_type": "s3 | object_storage | server"
    }
  ],
  "apex_cert_groups": {
    "c.example.com": {
      "suggested_cert_domain": "*.c.example.com",
      "hostnames": ["cdn.c.example.com", "www.c.example.com"]
    }
  },
  "global_rules_note": "Rules without http.host condition will be applied to ALL domains during per-domain processing"
}
```

**Downstream field usage** (verified from code):
- `cdn-preprocess.py`: `domains[].hostname`, `domains[].apex_domain`, `domains[].origin_type`, `domains[].cert_arn_mode`, `domains[].cert_arn`, `domains[].origin_content`
- `cdn-generate-shared-policies.py`: `zone_name` (extracts TLD for CORS wildcard)

### Downstream dependency summary

| File | Reads dns_manifest.yaml? | Reads domain_scope.json? |
|------|--------------------------|--------------------------|
| `cdn-validate-input.py` (Stage 2) | ✅ Yes (we write both) | ❌ No (we write it) |
| `cdn-preprocess.py` (Stage 3) | ❌ No | ✅ Yes |
| `cdn-generate-shared-policies.py` (Stage 7) | ❌ No | ✅ Yes (zone_name only) |
| All other scripts | ❌ No | ❌ No |

**Key insight**: `dns_manifest.yaml` is only consumed by our own Stage 2 script. No external dependency. `domain_scope.json` is the real contract — its schema must be exact.

### Orchestrator SKILL.md changes

Stage 1 and 2 change from LLM subagent invocations to Python script calls:

**Stage 1:**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-parse-dns.py "{config_path}" "cloudflare-to-aws-cdn"
```
Parse `---RESULT---`. On OK → pause for user input (same as before).

**Stage 2:**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-validate-input.py "cloudflare-to-aws-cdn" "{config_path}"
```
Parse `---RESULT---`. On OK → proceed to Stage 3.

Remove:
- All subagent invocation logic (retry, skill-loading prefix, output verification)
- References to `cf-cdn-dns-parser` and `cf-cdn-input-validator`

Update:
- Pipeline description: "0 LLM stages + 11 Python scripts"
- Remove model requirement for CDN pipeline

### install.sh changes

Remove:
```bash
cp -r cf-cdn-dns-parser "$SKILLS_DIR/"
cp -r cf-cdn-input-validator "$SKILLS_DIR/"
cp subagents/cf-cdn-dns-parser.json "$AGENTS_DIR/"
cp subagents/cf-cdn-input-validator.json "$AGENTS_DIR/"
```

Add cleanup:
```bash
rm -rf "$SKILLS_DIR/cf-cdn-dns-parser"
rm -rf "$SKILLS_DIR/cf-cdn-input-validator"
rm -f "$AGENTS_DIR/cf-cdn-dns-parser.json"
rm -f "$AGENTS_DIR/cf-cdn-input-validator.json"
```

Add new scripts (already covered by existing `cp -r cloudflare-aws-converter/scripts`).

### README changes

- "2 LLM stages + 9 Python scripts" → "0 LLM stages + 11 Python scripts"
- Remove model requirement for CDN pipeline
- Update benchmark: CDN pipeline time drops from ~7 min to ~1 min (Stage 1-2 go from ~4 min to <1 second)
- Update Mermaid diagram: Stage 1 and 2 get 🐍 prefix

## Files Changed

| File | Change |
|------|--------|
| `cdn-parse-dns.py` | **NEW** — Python DNS parser |
| `cdn-validate-input.py` | **NEW** — Python input validator |
| `SKILL.md` (orchestrator) | Stage 1-2 use Python scripts, remove subagent logic |
| `install.sh` | Remove subagent copy, add cleanup |
| `README.md` | 0 LLM, update benchmark |
| `README_CN.md` | Same |
| `CHANGELOG.md` | New entry |

## Files Deleted

| File | Reason |
|------|--------|
| `cf-cdn-dns-parser/SKILL.md` | Replaced by `cdn-parse-dns.py` |
| `cf-cdn-input-validator/SKILL.md` | Replaced by `cdn-validate-input.py` |
| `subagents/cf-cdn-dns-parser.json` | No longer needed |
| `subagents/cf-cdn-input-validator.json` | No longer needed |

## Impact

After this change:
- **Zero LLM dependency** — entire tool runs without any model
- **CDN pipeline time**: ~7 min → ~1 min (user input pause is the bottleneck)
- **No model requirement** — works with any Kiro CLI version, no model selection needed
- **Fully deterministic** — same input always produces same output
- **No retry logic** — Python scripts either succeed or fail with clear errors
- **`subagents/` directory becomes empty** — can be deleted entirely
