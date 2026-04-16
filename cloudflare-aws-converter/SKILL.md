---
name: cloudflare-aws-converter
description: Orchestrates Cloudflare-to-AWS conversion and analysis by delegating to specialized subagents. Use when the user mentions Cloudflare and any of: CDN, WAF, CloudFront, AWS, migration, conversion, analysis, configuration, rules, cache, redirect, firewall, security. Also triggers on Chinese equivalents: Cloudflare 配置分析、CDN 迁移、WAF 转换、转换到 AWS、迁移到 CloudFront. The user may or may not provide a config directory path in their initial message.
metadata:
  author: chenghit
---

# Cloudflare to AWS Converter

Orchestrate conversion of Cloudflare configurations to AWS by delegating to specialized subagents. Do NOT read config files yourself — pass the config directory path directly to each subagent.

**Language Adaptation**: Respond to the user in the same language as their message. However, **always write subagent queries in English** — subagents rely on English keywords to correctly parse paths and instructions. Pass the output language as an explicit instruction within the query (e.g., `"Generate output files in Chinese"`).

## Available Subagents

### WAF Pipeline

| Component | Type | Description |
|-----------|------|-------------|
| `waf-pipeline.sh` | Bash script | Single entry point — runs all steps below in sequence |
| `waf-analyze-ip.py` | Python | IP Lists + IP Access Rules → IR JSON |
| `waf-analyze-custom.py` | Python | Custom Rules → IR JSON (expression parser + convertibility + host scope) |
| `waf-analyze-rate.py` | Python | Rate-Limiting Rules → IR JSON (rate calculation + host scope) |
| `waf-merge-ir.py` | Python | Merge 3 batch IR files |
| `waf-count-validate.py` | Python | Verify rule counts match source |
| `waf-validate-ir.py` | Python | Round-trip validation + consistency checks |
| `waf-check-split.py` | Python | Auto-decide: legacy (2 WebACLs) vs per-domain split based on IP set count |
| `waf-split-by-host.py` | Python | Split IR by domain — strip host conditions, re-derive scope-down |
| `waf-generate-cfn.py` | Python | IR JSON → CloudFormation template (legacy or per-domain WebACLs) |

**No LLM subagents are used in the WAF pipeline.** All analysis, validation, and generation is deterministic Python.

**Auto-split**: If total IP sets > 50, the pipeline automatically switches to per-domain WebACLs. Use `--force-split` flag to force per-domain mode for testing.

### CDN Pipeline

| Component | Type | Description |
|-----------|------|-------------|
| `cdn-parse-dns.py` | Python | DNS.txt → dns_manifest.yaml + domain_scope.json (no user input needed) |

| Component | Type | Description |
|-----------|------|-------------|
| `cdn-generate-js.py` | Python | IR → CloudFront Function JS + Lambda@Edge handlers (all domains) |
| `cdn-validate-js.py` | Python | Validates generated JS files (all domains) |

**All CDN stages are deterministic Python scripts.** No LLM subagents are used.

## Workflow

### Step 1: Identify intent and scope

Determine what the user wants from their message. There are two dimensions:

**Dimension 1 — Scope (what to process):**
- **WAF only**: user mentions WAF, security rules, firewall, rate limiting, IP rules
- **CDN only**: user mentions CDN, cache, origin rules, CloudFront, redirects, URL rewrites, header transforms
- **Both / Everything**: user says "convert everything", "full migration", "all configs", or scope is unclear → run **WAF first, then CDN**. WAF pipeline is <1 second (zero LLM), so running both in one session is fine.

**Dimension 2 — Depth (how far to go):**
- **Analyze**: user says "analyze", "分析" → run analyzer + validator only, stop before generator/converter
- **Convert**: user says "convert", "migrate", "转换", "迁移" → run full pipeline including generator/converter
- **Default**: if user doesn't specify, assume **convert** (the most common intent)

**Intent matrix:**

| Scope | Depth: Analyze | Depth: Convert |
|-------|---------------|----------------|
| WAF only | waf-pipeline.sh | waf-pipeline.sh |
| CDN only | CDN full pipeline | CDN full pipeline |
| Both | WAF pipeline → CDN pipeline | WAF pipeline → CDN pipeline |

**Both pipelines in one session is supported.** Both WAF and CDN pipelines are zero LLM, <1 second each. Run WAF first, then CDN — fully automated, no user interaction.

### Step 2: Extract config path and validate single-zone

Extract the Cloudflare config directory path from the user's message. This is the path to pass to each subagent. Do not read or analyze the files yourself.

**Multi-zone detection (CRITICAL — must check before invoking any subagent):**

This tool only supports converting ONE zone at a time. The CloudflareBackup tool creates directories as `<zone_name>/<timestamp>/`, so a backup directory containing multiple zones will have multiple zone subdirectories.

Before proceeding, check the structure of the provided path:
1. Use `glob` or `fs_read` (directory mode) to list the contents of the provided path.
2. Look for `DNS.txt` files. The expected layout is `<config_path>/DNS.txt` (single zone) or `<config_path>/<zone_name>/<timestamp>/DNS.txt` (CloudflareBackup structure).
3. If the path directly contains `DNS.txt`, it is a single zone — proceed normally.
4. If the path contains multiple subdirectories that each contain timestamped subdirectories with `DNS.txt`, this is a multi-zone backup. **Abort immediately** with:
   > "This backup directory contains multiple zones: [list zone names]. This tool can only convert one zone at a time. Please specify which zone to convert by providing the path to a specific zone's backup directory (e.g., `{config_path}/<zone_name>/<timestamp>/`)."
5. If the path contains exactly one zone subdirectory, auto-resolve to that zone's latest timestamped backup and inform the user:
   > "Detected single zone: {zone_name}. Using backup at {resolved_path}."

**When passing the path to subagents**, always pass the original `{config_path}` (backup root). Both WAF and CDN subagents use recursive glob to find files — WAF needs `account/IP-Lists.txt`, CDN needs `account/List-Items-redirect-*.txt` for bulk redirects. Do NOT resolve to the zone subdirectory before passing to subagents.

**Account directory check**: Verify that `{config_path}` contains an `account/` subdirectory. If not found, warn the user: "No `account/` directory found under the provided path. IP lists and bulk redirect lists may not be found. CloudflareBackup always creates an `account/` directory — make sure you provided the backup root directory, not a zone subdirectory."

If the user requests CDN full pipeline (Terraform generation), also check for:
- `cloudflare-to-aws-cdn/domain_scope.json` — if it exists, pipeline can start from Stage 3

### Step 2b: Initialize CDN output directory (CDN pipeline only)

Before dispatching any CDN subagent, run the initialization script to create the
output directory structure and copy static Terraform modules:

```bash
bash ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-init.sh "$(pwd)"
```

This creates `cloudflare-to-aws-cdn/` under the **current working directory** (where all
skills expect it) and copies the CloudFront distribution Terraform module. Subagents
can then write directly to their output paths without needing to create directories.

**IMPORTANT**: The output directory is always `$(pwd)/cloudflare-to-aws-cdn/`, NOT inside
the Cloudflare config backup directory. Do NOT look for or use `cloudflare-to-aws-cdn/`
under the config path — that would be a leftover from a previous run in a different
working directory.

Skip this step if `cloudflare-to-aws-cdn/` already exists **in the current working directory** (resuming a previous run).

### Step 3: Run pipeline scripts

No LLM subagents are used. All stages are Python scripts invoked via `execute_bash`.

---

#### WAF pipeline:

**The entire WAF pipeline is a single deterministic script. No LLM subagents are invoked.**

1. Check if `cloudflare-to-aws-waf/waf-cloudformation.json` already exists.
   - If it exists → ask the user: "Found existing WAF output. Do you want to overwrite and re-run, or keep the existing files?"
     - User says overwrite → `rm -rf cloudflare-to-aws-waf`, then proceed.
     - User says keep → skip to Step 4 (report results).
   - If it does not exist → proceed.

2. Check IR version compatibility: if `cloudflare-to-aws-waf/waf_ir.json` exists, check for `conditions` field in the first custom rule. If absent (old format), delete the directory and re-run.

3. Run the pipeline:
   ```bash
   bash ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-pipeline.sh "{config_path}" "cloudflare-to-aws-waf"
   ```
   If the user explicitly requests per-domain WebACL splitting (e.g., "force split", "split per domain"):
   ```bash
   bash ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-pipeline.sh "{config_path}" "cloudflare-to-aws-waf" --force-split
   ```
   Parse the `---RESULT---` block:
   - `STATUS: OK` → proceed to Step 4.
   - `STATUS: ERROR` → report the `CONTEXT` field to the user and stop.

---

#### CDN full pipeline (0 LLM stages + 10 Python scripts — runs when user wants Terraform output for CloudFront):

All stages are deterministic Python scripts. No LLM subagents. No user interaction required.

**Stage 1: DNS Parsing + Domain Scope** (Python script, no LLM)
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-parse-dns.py "{config_path}" "cloudflare-to-aws-cdn"
```
Parse the `---RESULT---` block:
- `STATUS: OK` → proceed directly to Stage 3.
  If the result includes WARNINGS about non-convertible origins or CloudFront loop exclusions, report them to the user.
- `STATUS: FATAL` → report the `CONTEXT` field to the user and stop.

**Stage 3–6: Preprocess → Validate → Finalize → Validate Final** (Python scripts, no LLM)

These four stages are fully deterministic Python scripts. Run them in sequence:

**Stage 3: Preprocess**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-preprocess.py "{config_path}" "cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → all domains processed, proceed to Stage 4
- 1 → partial failure. Read stderr for failed domain names. Retry failed domains:
  ```bash
  python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-preprocess.py "{config_path}" "cloudflare-to-aws-cdn" --domain {failed_domain}
  ```
  If retry also fails → mark domain as SKIPPED, continue with remaining domains.
- 2 → total failure, stop pipeline

**Stage 4: V1 Chunk Validation**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-validate-chunk.py "cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → all PASS, proceed to Stage 5
- 1 → some FAIL. Read the validation reports at `cloudflare-to-aws-cdn/ir/validation/chunk/{hostname}-v1.json`.
  - If >50% of domains fail with the same error type → preprocess bug, stop pipeline
  - Otherwise → delete failed domain's accumulator and validation files, re-run Stage 3 for that domain with `--domain`, then re-run Stage 4
  - If second attempt also FAILs → mark domain as SKIPPED

**Stage 5: Finalize**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-finalize.py "cloudflare-to-aws-cdn" [skipped_domains.json]
```
If there are SKIPPED domains, write a JSON file with `[{"hostname": "...", "reason": "..."}]` and pass it as the second argument.

Check exit code:
- 0 → proceed to Stage 6
- 1 → stop pipeline, report error

**Stage 6: V2 Final Validation**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-validate-final.py "cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → all PASS, proceed to Stage 7
- 1 → some FAIL. Read `cloudflare-to-aws-cdn/ir/validation/final/{hostname}-v2.json`:
  - If ALL errors are about missing `dedup_manifest.json` or `conversion_report.md` → re-run Stage 5
  - Otherwise → pipeline bug, stop and tell user to file a GitHub issue

**Stage 7: Shared Terraform Policies** (Python script, no LLM)
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-shared-policies.py "cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → proceed to Stage 7.5
- 1 → stop pipeline, report error

**Stage 7.5: Generate Terraform Scaffold** (Python script, no LLM)
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tf-scaffold.py "cloudflare-to-aws-cdn"
```
Generates main.tf, functions.tf, outputs.tf, kvs.tf, kvs-data.json for each domain. These are deterministic template files — no LLM needed.

**Stage 7.5b: Terraform Validate** (shared policies only)
1. Validate shared policies:
   ```bash
   cd cloudflare-to-aws-cdn/terraform/shared && terraform init -backend=false && terraform validate
   ```
2. If validation fails → stop pipeline and report errors. These are Python script bugs — the user should file a GitHub issue.
3. If validation passes → proceed to Stage 7.6.

**Stage 7.6: Generate Test Scripts** (Python script, no LLM)
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tests.py "cloudflare-to-aws-cdn"
```
Generates `test-cdn-rules.py` per domain for post-deployment validation. Proceed to Stage 8.

**Stage 8: JS Generation** (Python script, no LLM)
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-js.py "cloudflare-to-aws-cdn"
```
Parse the `---RESULT---` block:
- `STATUS: OK` → proceed to Stage 9
- `STATUS: PARTIAL` → some domains exceeded 10KB CFF size limit (`SIZE_EXCEEDED`). Report failed domains to user. Remaining domains proceed.
- `STATUS: FATAL` → stop pipeline, report error

**Stage 9: JS Validation** (Python script, no LLM)
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-validate-js.py "cloudflare-to-aws-cdn"
```
Parse the `---RESULT---` block:
- `STATUS: OK` → all domains passed, proceed to Step 4 (final reporting)
- `STATUS: ERROR` → some domains failed validation. Report failed domains and their check failures to user.

---

---

### Step 4: Report results

After the pipeline completes, summarize what was done and where output files were generated.

**For the WAF pipeline**, report:
- Number of rules converted (custom + rate-limiting + IP access)
- Number of non-convertible rules (list each with reason)
- WCU total and whether it exceeds 1,500 (extra charges) or 5,000 (hard limit)
- Path to generated CloudFormation template
- Any warnings from the generator

After the summary, include deployment instructions:
```
## Next Steps: Deploy

1. Set your AWS profile (must have WAFv2 and CloudFormation permissions):
   export AWS_PROFILE=<your-profile-name>

2. Deploy the CloudFormation stack:
   cd cloudflare-to-aws-waf
   aws cloudformation deploy \
     --template-file waf-cloudformation.json \
     --stack-name cloudflare-waf-migration \
     --region us-east-1

3. Check deployment status:
   aws cloudformation describe-stacks --stack-name cloudflare-waf-migration --region us-east-1

4. Associate WebACLs with your CloudFront distributions in the AWS Console or CLI.
```

**Step 4b: Translate deployment README (non-English users)**

**CRITICAL — do NOT skip this step if the user's message is not in English.**

If the user's message is not in English, read `cloudflare-to-aws-waf/README_aws-waf-deployment.md`, translate it to the user's language, and save as `cloudflare-to-aws-waf/README_aws-waf-deployment_{lang}.md` (e.g., `_CN.md`, `_JA.md`). Keep the original English version as-is.

**For the CDN full pipeline**, include a summary table showing:
- Number of domains processed successfully
- Number of domains SKIPPED (V1 failure after retry) — list each with failure reason
- Number of domains with SIZE_EXCEEDED (JS exceeded 10KB CFF limit) — list each
- Number of CloudFront distributions generated
- Number of shared policies created (cache, origin request, response headers)
- Number of CloudFront Functions generated
- Any domains or rules that could not be automatically converted (link to `conversion_report.md`)
- Path to generated Terraform files

After the summary table, include deployment instructions:
```
## Next Steps: Deploy

1. Set your AWS profile (must have CloudFront, Lambda, IAM, and ACM permissions):
   export AWS_PROFILE=<your-profile-name>

2. Deploy shared policies first:
   cd cloudflare-to-aws-cdn/terraform/shared && terraform init && terraform apply

3. Deploy each domain:
   cd cloudflare-to-aws-cdn/terraform/domains/<domain>/ && terraform init && terraform apply

See docs/deployment-guide.md for the full deployment order and DNS cutover steps.
```

**Step 4c: Translate CDN deployment guide (non-English users)**

**CRITICAL — do NOT skip this step if the user's message is not in English.**

If the user's message is not in English, read `cloudflare-to-aws-cdn/conversion_report.md`, translate it to the user's language, and save as `cloudflare-to-aws-cdn/conversion_report_{lang}.md` (e.g., `_CN.md`, `_JA.md`). Keep the original English version as-is.

## Important Rules

- **Never read config files yourself** — always delegate to scripts (both WAF and CDN pipelines)
- **Pass the exact path** the user provided; do not modify or resolve it
- **WAF pipeline**: single `waf-pipeline.sh` call, no LLM subagents, no retry logic needed
- **CDN pipeline**: serial execution for pipeline stages. All 10 stages are Python script invocations (no LLM subagents, no parallelization needed, no user interaction).
