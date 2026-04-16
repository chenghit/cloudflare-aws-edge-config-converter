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
| `waf-analyze-custom.py` | Python | Custom Rules → IR JSON (expression parser + convertibility) |
| `waf-analyze-rate.py` | Python | Rate-Limiting Rules → IR JSON (rate calculation) |
| `waf-merge-ir.py` | Python | Merge 3 batch IR files |
| `waf-count-validate.py` | Python | Verify rule counts match source |
| `waf-validate-ir.py` | Python | Round-trip validation + consistency checks |
| `waf-generate-cfn.py` | Python | IR JSON → CloudFormation template |

**No LLM subagents are used in the WAF pipeline.** All analysis, validation, and generation is deterministic Python.

### CDN Pipeline

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-cdn-dns-parser` | DNS export → domain manifest + input template | CDN, full migration, domains, DNS |
| `cf-cdn-input-validator` | Validates user_input.csv → domain_scope.json | (invoked automatically after user fills input) |
| `cf-cdn-tf-domain` | Per-domain final IR → JS files for CloudFront distribution | (invoked once per domain, parallelizable) |
| `cf-cdn-js-validator` | Validates each domain's CloudFront Function JS | (invoked once per domain, parallelizable) |

## Workflow

### Step 1: Identify intent and scope

Determine what the user wants from their message. There are two dimensions:

**Dimension 1 — Scope (what to process):**
- **WAF only**: user mentions WAF, security rules, firewall, rate limiting, IP rules
- **CDN only**: user mentions CDN, cache, origin rules, CloudFront, redirects, URL rewrites, header transforms
- **Everything / Ambiguous**: user says "convert everything", "full migration", "all configs", or scope is unclear → **do NOT guess**. Ask the user to pick one of the following prompts (replace `{path}` with the backup path they already provided):
  > Which pipeline do you need? Copy one of these:
  >
  > **WAF** (security rules → AWS WAF Terraform):
  > `Convert Cloudflare WAF rules in {path} to AWS WAF`
  >
  > **CDN** (cache/redirect/origin rules → CloudFront Terraform):
  > `Convert CDN configuration in {path} to CloudFront`
  >
  > To run both, run them in separate sessions to avoid token limits.

**Dimension 2 — Depth (how far to go):**
- **Analyze**: user says "analyze", "分析" → run analyzer + validator only, stop before generator/converter
- **Convert**: user says "convert", "migrate", "转换", "迁移" → run full pipeline including generator/converter
- **Default**: if user doesn't specify, assume **convert** (the most common intent)

**Intent matrix:**

| Scope | Depth: Analyze | Depth: Convert |
|-------|---------------|----------------|
| WAF only | waf-pipeline.sh (full pipeline, outputs CloudFormation) | waf-pipeline.sh (same — pipeline always generates CloudFormation) |
| CDN only | CDN full pipeline | CDN full pipeline |

**One pipeline per session.** Running both WAF and CDN in a single session risks hitting token limits. If the user explicitly asks for both, warn them and recommend separate sessions.

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
- `cloudflare-to-aws-cdn/user_input.csv` — if it exists, CDN pipeline can start from Stage 2
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

### Step 3: Invoke subagents

**CRITICAL: Every subagent query MUST start with a skill-loading instruction.** Subagents may not automatically load their skill file when invoked via `use_subagent`. Prefix every query with:

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/{subagent-name}/SKILL.md and follow its workflow. You MUST use tools to read input files and write output files — do NOT generate output from memory or skip tool calls. "`

Where `{subagent-name}` matches the subagent directory name (e.g., `cf-cdn-dns-parser`, `cf-cdn-tf-domain`).

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
   Parse the `---RESULT---` block:
   - `STATUS: OK` → proceed to Step 4.
   - `STATUS: ERROR` → report the `CONTEXT` field to the user and stop.

---

#### CDN full pipeline (4 LLM stages + 7 Python scripts — runs when user wants Terraform output for CloudFront):

Stages 3–7.6 are deterministic Python scripts (no LLM). Stages 1, 2, 8, 9 are LLM subagents.

**Stage 1: DNS Parsing**
1. Invoke `cf-cdn-dns-parser` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-dns-parser/SKILL.md and follow its workflow. You MUST use tools (glob, fs_read, fs_write) to read DNS.txt and write output files — do NOT generate output from memory. The Cloudflare backup directory is {config_path}. Parse DNS.txt to identify all proxied domains. Detect any Cloudflare for SaaS configurations. Group domains by apex domain for ACM certificate planning. Write dns_manifest.yaml and user_input_template.csv to the cloudflare-to-aws-cdn/ output directory. Generate output files in {user_language}."`
2. **Verify output files exist** (CRITICAL — subagents may skip tool calls):
   ```bash
   ls cloudflare-to-aws-cdn/dns_manifest.yaml cloudflare-to-aws-cdn/user_input_template.csv
   ```
   - If both files exist → **pause and tell the user**:
     > "DNS parsing complete. I found N proxied domains. Please fill in `cloudflare-to-aws-cdn/user_input_template.csv` with your ACM certificate ARNs (or leave blank for auto-lookup), then save it as `cloudflare-to-aws-cdn/user_input.csv`. Let me know when it's ready to proceed."
   - If either file is missing → **re-invoke the subagent once** with the same query. If the second attempt also fails to produce files → stop and tell the user: "DNS parser failed to write output files after 2 attempts. Please file a GitHub issue."
   - Wait for the user to confirm before continuing.

**Stage 2: Input Validation**
1. Invoke `cf-cdn-input-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-input-validator/SKILL.md and follow its workflow. You MUST use tools to read and write files. The Cloudflare backup directory is {config_path}. Validate cloudflare-to-aws-cdn/user_input.csv against cloudflare-to-aws-cdn/dns_manifest.yaml. On success, write cloudflare-to-aws-cdn/domain_scope.json. Report any validation errors with remediation hints. Generate output files in {user_language}."`
2. **Verify output**: run `ls cloudflare-to-aws-cdn/domain_scope.json`. If missing after subagent claims PASS → re-invoke once.
3. Check the `---RESULT---` block:
   - `STATUS: PASS` → proceed to Stage 3
   - `STATUS: ERRORS` → show the user the list of errors and ask them to fix `user_input.csv`, then re-invoke Stage 2
   - `STATUS: CANNOT_FIX` → stop and tell the user which fields require manual correction

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

**Stage 8: Per-Domain JS Generation** (parallelizable — invoke once per domain)
1. For each domain `{domain}`, invoke `cf-cdn-tf-domain` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-domain/SKILL.md and follow its workflow. You MUST use tools to read IR files and write JS output — do NOT skip tool calls. The Cloudflare backup directory is {config_path}. Generate JavaScript files for domain {domain} using the final IR at cloudflare-to-aws-cdn/ir/final/{domain}.json. Terraform scaffold files (main.tf, functions.tf, etc.) have already been generated at cloudflare-to-aws-cdn/terraform/domains/. Only generate JS files (viewer_request.js, viewer_response.js, Lambda@Edge handlers if needed). If Lambda@Edge files are generated, update functions.tf by replacing the LAMBDA_EDGE_PLACEHOLDER comment with L@E resource blocks. Do NOT modify main.tf. Generate output files in {user_language}."`
2. **Verify output** (CRITICAL — run this exact script, do NOT simplify or omit the lambda check):
   ```bash
   for d in cloudflare-to-aws-cdn/terraform/domains/*/; do
     san=$(basename "$d")
     echo -n "$san/functions: "; ls "$d/functions/" 2>/dev/null | tr '\n' ' '; echo
     echo -n "$san/lambda: "; ls "$d/lambda/" 2>/dev/null | tr '\n' ' '; echo
   done
   ```
   For each domain:
   - `functions/` must contain at least `*_viewer_request.js`. If missing → re-invoke once.
   - If the domain's IR has `lambda_edge.origin_response` non-null, `lambda/` must contain `default_cache_origin_response.js`. If missing → re-invoke once.
   - If `lambda/origin_request_handler.js` exists (CFF overflow), verify `functions.tf` contains `origin_request` (PLACEHOLDER was replaced). If not → re-invoke once.
3. Wait for all domains to complete.

**Stage 9: CloudFront Function JS Validation** (parallelizable — invoke once per domain)
1. For each domain `{domain}` that has a `functions/` directory, invoke `cf-cdn-js-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-js-validator/SKILL.md and follow its workflow. You MUST use tools to read JS files and write validation report. The Cloudflare backup directory is {config_path}. Validate all CloudFront Function AND Lambda@Edge JavaScript files for domain {domain} — check both the functions/ and lambda/ directories (the skill will derive the sanitized directory name from the hostname). Output a validation report to cloudflare-to-aws-cdn/ir/validation/js/{domain}-v3.json. Generate output files in {user_language}."`
2. **Verify output**: check that `cloudflare-to-aws-cdn/ir/validation/js/{domain}-v3.json` exists. If missing → re-invoke once.
3. Check the `overall_status` field in the written JSON report:
   - `"PASS"` → domain JS is valid
   - `"FAIL"` → **auto-retry once** with the following procedure:
     a. Use `fs_read` to read `cloudflare-to-aws-cdn/ir/validation/js/{hostname}-v3.json` and extract the failed checks (entries where `status == "FAIL"`).
     b. Derive the sanitized hostname (replace every `.` and `-` with `_`, e.g., `cdn.c.example.com` → `cdn_c_example_com`). Use `execute_bash` to delete the JS output and regenerate scaffold (to restore LAMBDA_EDGE_PLACEHOLDER in functions.tf):
        ```bash
        rm -rf cloudflare-to-aws-cdn/terraform/domains/{sanitized}/functions/ cloudflare-to-aws-cdn/terraform/domains/{sanitized}/lambda/
        python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tf-scaffold.py "cloudflare-to-aws-cdn"
        ```
     c. Re-invoke `cf-cdn-tf-domain` with the error hint: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-domain/SKILL.md and follow its workflow. You MUST use tools to read IR files and write JS output — do NOT skip tool calls. The Cloudflare backup directory is {config_path}. Generate JavaScript files for domain {domain} using the final IR at cloudflare-to-aws-cdn/ir/final/{domain}.json. IMPORTANT: A previous generation attempt produced JavaScript validation errors. Pay special attention to these issues: {failed_checks}. Generate all JS files from scratch — do NOT read any existing JS files. Generate output files in {user_language}."`
     d. Re-invoke `cf-cdn-js-validator` for this domain.
     e. If the second attempt also FAILs → mark this domain as `JS_VALIDATION_FAILED` (record the errors), continue processing other domains.
3. Once all domains have completed (PASS or JS_VALIDATION_FAILED), proceed to Step 4 (final reporting).

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
- Number of domains with JS_VALIDATION_FAILED (V3 failure after retry) — list each with failure reason
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

## Important Rules

- **Never read config files yourself** — always delegate to subagents (CDN pipeline) or scripts (WAF pipeline)
- **Pass the exact path** the user provided; do not modify or resolve it
- **WAF pipeline**: single `waf-pipeline.sh` call, no LLM subagents, no retry logic needed
- **CDN pipeline**: serial execution for pipeline stages; parallel execution where the same LLM stage runs across multiple domains (Stages 8, 9). Stages 3–6 are single Python script invocations (no parallelization needed).
- **Parallel batch size: 2** (default, CDN pipeline only). For parallelizable stages, dispatch at most 2 subagents at a time.
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
- **When re-invoking the same subagent** (CDN pipeline), always explicitly state what action to perform and what inputs to use. Never assume the subagent remembers a previous invocation.
- **CDN full pipeline requires a user pause at Stage 1** — always wait for the user to fill in `user_input.csv` before invoking Stage 2. Do not attempt to auto-fill the CSV.
- **Domain list for parallelizable stages** — always extract the domain list from `domain_scope.json` or the finalized IR directory listing, not from earlier intermediate state that may have changed.
