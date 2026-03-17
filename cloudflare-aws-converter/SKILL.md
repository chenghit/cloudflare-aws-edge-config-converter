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

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-waf-analyzer` | Security rules → IR JSON (3 batches) | WAF, firewall, rate limiting, IP rules, security rules |
| `cf-waf-analyzer-validator` | Validates IR JSON in parallel batches (V1/V2/V3/V4) | (invoked automatically after merge) |
| `cf-waf-terraform-generator` | Validated IR JSON → AWS WAF Terraform | (invoked automatically after validator passes) |

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
- **Everything**: user says "convert everything", "full migration", "all configs", or mentions Cloudflare config without specifying a type **and** without mentioning a specific AWS target service (e.g., CloudFront → CDN only, WAF → WAF only)

**Dimension 2 — Depth (how far to go):**
- **Analyze**: user says "analyze", "分析" → run analyzer + validator only, stop before generator/converter
- **Convert**: user says "convert", "migrate", "转换", "迁移" → run full pipeline including generator/converter
- **Default**: if user doesn't specify, assume **convert** (the most common intent)

**Intent matrix:**

| Scope | Depth: Analyze | Depth: Convert |
|-------|---------------|----------------|
| WAF only | waf-analyzer → waf-validator | waf-analyzer → waf-validator → waf-terraform-generator |
| CDN only | CDN full pipeline | CDN full pipeline |
| Everything | WAF convert → CDN full pipeline | WAF convert → CDN full pipeline |

**Execution order for "Everything":**
1. WAF pipeline first (analyzer → validator → generator)
2. CDN full pipeline second

This order matters because WAF and CDN analysis are independent, but running WAF first avoids context confusion.

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

This creates `cloudflare-to-aws-cdn/` under the current working directory (where all
skills expect it) and copies the CloudFront distribution Terraform module. Subagents
can then write directly to their output paths without needing to create directories.

Skip this step if `cloudflare-to-aws-cdn/` already exists (resuming a previous run).

### Step 3: Invoke subagents

**CRITICAL: Every subagent query MUST start with a skill-loading instruction.** Subagents may not automatically load their skill file when invoked via `use_subagent`. Prefix every query with:

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/{subagent-name}/SKILL.md and follow its workflow. "`

Where `{subagent-name}` matches the subagent directory name (e.g., `cf-waf-analyzer`, `cf-cdn-dns-parser`).

---

#### WAF pipeline:

**Stage 0: Initialize**
1. Run `bash ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-init.sh "$(pwd)"` to create the output directory and pre-written Terraform files.

**Stage 1: Analyze (3 batches, serial)**

1. Before invoking the analyzer, check if `cloudflare-to-aws-waf/waf_ir.json` already exists.
   - If it exists → ask the user: "Found existing IR files. Do you want to overwrite them and re-run the analysis, or use the existing files and proceed to validation?"
     - User says overwrite → delete the entire `cloudflare-to-aws-waf/` directory (`rm -rf cloudflare-to-aws-waf`), then re-run `waf-init.sh` to recreate it with fresh pre-written files. Then proceed to invoke analyzer below.
     - User says use existing → skip to Stage 2
   - If it does not exist → proceed to invoke analyzer below

2. Invoke analyzer 3 times in sequence (A1 → A2 → extract skip labels → A3):

   **A1**: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. Analyze batch A1: IP Lists and IP Access Rules. The Cloudflare backup directory is {config_path}. Generate output files in {user_language}."`

   **A2**: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. Analyze batch A2: WAF Custom Rules. The Cloudflare backup directory is {config_path}. Generate output files in {user_language}."`

   **Extract skip labels** (between A2 and A3):
   ```bash
   skip_labels=$(python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-extract-skip-labels.py "cloudflare-to-aws-waf/waf_ir_custom.json")
   ```
   - If exit code 1 → re-invoke A2 once. If second attempt also fails → stop and report.
   - If exit code 0 → capture the stdout line (e.g., `http_ratelimit=true all_remaining_custom_rules=true http_request_firewall_managed=true`)

   **A3**: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. Analyze batch A3: Rate Limiting Rules. Skip labels from custom rules: {skip_labels}. The Cloudflare backup directory is {config_path}. Generate output files in {user_language}."`

3. If any batch fails → stop and report the error. Do not proceed to Stage 2.

**Stage 2: Validate (merge → count → chunk → parallel V1/V2/V3 → V4)**

**Step 2a: Merge IR + Count validation + JSON chunking**
1. Set `validation_round = 1`.
2. Merge batch JSONs: `python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-merge-ir.py "cloudflare-to-aws-waf"`
   - If exit code 1 → stop and report.
3. Run count validation: `python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-count-validate.py "{config_path}" "cloudflare-to-aws-waf"`
   - If exit code 1 (mismatch) → re-invoke the mismatched batch(es) from Stage 1, then re-merge and re-validate. If second attempt also mismatches → stop and report.
   - If exit code 0 → proceed.
4. Run JSON chunking: `python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-chunk-rules.py "{config_path}" "cloudflare-to-aws-waf" 50`
   - Capture the output lines (chunk file paths) for use in V2 dispatch.
   - If output is `NO_RULES` (0 custom rules), skip all V2 dispatches in Step 2b.
5. Read `cloudflare-to-aws-waf/waf_ir.json` to check rule counts:
   - If `ip_access_rules.count == 0`, skip V1 in Step 2b.
   - If `rate_limiting_rules.count == 0`, skip V3 in Step 2b.

**Step 2b: Parallel validation (V1 + V2 chunks + V3)**

Dispatch all validation batches in parallel (respecting batch size 2):

- **V1**: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. Mode: V1 (IP Lists + IP Access Rules). The Cloudflare backup directory is {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`

- **V2** (one per chunk): `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. Mode: V2 (Custom Rules chunk). The Cloudflare backup directory is {config_path}. Chunk file: cloudflare-to-aws-waf/chunks/custom-rules-{start}-{end}.json (positions {start}-{end}). This is validation round {validation_round}. Generate output files in {user_language}."`

- **V3**: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. Mode: V3 (Rate Limiting Rules). The Cloudflare backup directory is {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`

Wait for all batches to complete.

**Step 2c: V4 Global validation**

Invoke: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. Mode: V4 (Global validation). This is validation round {validation_round}. Generate output files in {user_language}."`

Check the `---RESULT---` block:
- `STATUS: PASS` → if depth is "analyze", proceed to Step 4. If depth is "convert", proceed to Stage 3.
- `STATUS: FIXED` → increment `validation_round`. If `validation_round > 3`, stop and tell the user manual review is required. Otherwise, delete `cloudflare-to-aws-waf/validation/` and `cloudflare-to-aws-waf/chunks/`, then re-run Stage 2 from Step 2a **but skip the merge step** (V4 already applied fixes to waf_ir.json — re-merging from batch JSONs would overwrite those fixes). Start from count validation instead.
- `STATUS: CANNOT_FIX` → stop and tell the user which issues require manual intervention.

**Stage 3: Generate Terraform** (only if depth is "convert")
1. Invoke `cf-waf-terraform-generator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-terraform-generator/SKILL.md and follow its workflow. Generate AWS WAF Terraform configuration from the validated IR JSON. Generate output files in {user_language}."`
2. Check the `---RESULT---` block:
   - `STATUS: COMPLETE` → proceed to Step 3b.

**Step 3b: Terraform validate**
1. Run: `cd cloudflare-to-aws-waf && terraform init -backend=false && terraform validate`
2. If validation passes → proceed to Step 4.
3. If validation fails → re-invoke generator with error details: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-terraform-generator/SKILL.md and follow its workflow. Generate AWS WAF Terraform configuration from the validated IR JSON. IMPORTANT: The previous generation had terraform validate errors. Fix these specific issues and regenerate all affected files: {terraform_validate_error_output}. Generate output files in {user_language}."`
4. Run terraform validate again. If it fails a second time → stop and tell the user: "Terraform validation failed after retry. Please manually fix the errors in cloudflare-to-aws-waf/ and run `terraform validate` to verify. Errors: {error_output}"

---

#### CDN full pipeline (5 LLM stages + 4 Python scripts — runs when user wants Terraform output for CloudFront):

Stages 3–6 are deterministic Python scripts (no LLM). Stages 1, 2, 7, 8, 9 are LLM subagents.

**Stage 1: DNS Parsing**
1. Invoke `cf-cdn-dns-parser` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-dns-parser/SKILL.md and follow its workflow. The Cloudflare backup directory is {config_path}. Parse DNS.txt to identify all proxied domains. Detect any Cloudflare for SaaS configurations. Group domains by apex domain for ACM certificate planning. Write dns_manifest.yaml and user_input_template.csv to the cloudflare-to-aws-cdn/ output directory. Generate output files in {user_language}."`
2. Check the response:
   - If `dns_manifest.yaml` and `user_input_template.csv` were written successfully → **pause and tell the user**:
     > "DNS parsing complete. I found N proxied domains. Please fill in `cloudflare-to-aws-cdn/user_input_template.csv` with your ACM certificate ARNs (or leave blank for auto-lookup), then save it as `cloudflare-to-aws-cdn/user_input.csv`. Let me know when it's ready to proceed."
   - Wait for the user to confirm before continuing.

**Stage 2: Input Validation**
1. Invoke `cf-cdn-input-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-input-validator/SKILL.md and follow its workflow. The Cloudflare backup directory is {config_path}. Validate cloudflare-to-aws-cdn/user_input.csv against cloudflare-to-aws-cdn/dns_manifest.yaml. On success, write cloudflare-to-aws-cdn/domain_scope.json. Report any validation errors with remediation hints. Generate output files in {user_language}."`
2. Check the `---RESULT---` block:
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
Generates main.tf, functions.tf, outputs.tf, kvs.tf, kvs-data.json for each domain. These are deterministic template files — no LLM needed. Proceed to Stage 8.

**Stage 8: Per-Domain JS Generation** (parallelizable — invoke once per domain)
1. For each domain `{domain}`, invoke `cf-cdn-tf-domain` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-domain/SKILL.md and follow its workflow. The Cloudflare backup directory is {config_path}. Generate JavaScript files for domain {domain} using the final IR at cloudflare-to-aws-cdn/ir/final/{domain}.json. Terraform scaffold files (main.tf, functions.tf, etc.) have already been generated at cloudflare-to-aws-cdn/terraform/domains/. Only generate JS files (viewer_request.js, viewer_response.js, Lambda@Edge handlers if needed). If Lambda@Edge files are generated, update functions.tf by replacing the LAMBDA_EDGE_PLACEHOLDER comment with L@E resource blocks. Do NOT modify main.tf. Generate output files in {user_language}."`
2. Wait for all domain Terraform generators to complete.

**Stage 9: CloudFront Function JS Validation** (parallelizable — invoke once per domain)
1. For each domain `{domain}` that has a `functions/` directory, invoke `cf-cdn-js-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-js-validator/SKILL.md and follow its workflow. The Cloudflare backup directory is {config_path}. Validate all CloudFront Function JavaScript files for domain {domain} (the skill will derive the sanitized directory name from the hostname). Output a validation report to cloudflare-to-aws-cdn/ir/validation/js/{domain}-v3.json. Generate output files in {user_language}."`
2. Check the `overall_status` field in the written JSON report:
   - `"PASS"` → domain JS is valid
   - `"FAIL"` → **auto-retry once** with the following procedure:
     a. Use `fs_read` to read `cloudflare-to-aws-cdn/ir/validation/js/{hostname}-v3.json` and extract the failed checks (entries where `status == "FAIL"`).
     b. Derive the sanitized hostname (replace every `.` and `-` with `_`, e.g., `cdn.c.example.com` → `cdn_c_example_com`). Use `execute_bash` to delete the JS output and regenerate scaffold (to restore LAMBDA_EDGE_PLACEHOLDER in functions.tf):
        ```bash
        rm -rf cloudflare-to-aws-cdn/terraform/domains/{sanitized}/functions/ cloudflare-to-aws-cdn/terraform/domains/{sanitized}/lambda/
        python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tf-scaffold.py "cloudflare-to-aws-cdn"
        ```
     c. Re-invoke `cf-cdn-tf-domain` with the error hint: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-domain/SKILL.md and follow its workflow. The Cloudflare backup directory is {config_path}. Generate JavaScript files for domain {domain} using the final IR at cloudflare-to-aws-cdn/ir/final/{domain}.json. IMPORTANT: A previous generation attempt produced JavaScript validation errors. Pay special attention to these issues: {failed_checks}. Generate all JS files from scratch — do NOT read any existing JS files. Generate output files in {user_language}."`
     d. Re-invoke `cf-cdn-js-validator` for this domain.
     e. If the second attempt also FAILs → mark this domain as `JS_VALIDATION_FAILED` (record the errors), continue processing other domains.
3. Once all domains have completed (PASS or JS_VALIDATION_FAILED), proceed to Step 4 (final reporting).

---

---

### Step 4: Report results

After all subagents complete, summarize what was done and where output files were generated.

For "Everything" scope, report results for each pipeline separately.

**For the CDN full pipeline**, include a summary table showing:
- Number of domains processed successfully
- Number of domains SKIPPED (V1 failure after retry) — list each with failure reason
- Number of domains with JS_VALIDATION_FAILED (V3 failure after retry) — list each with failure reason
- Number of CloudFront distributions generated
- Number of shared policies created (cache, origin request, response headers)
- Number of CloudFront Functions generated
- Any domains or rules that could not be automatically converted (link to `conversion_report.md`)
- Path to generated Terraform files

## Important Rules

- **Never read config files yourself** — always delegate to subagents
- **Pass the exact path** the user provided; do not modify or resolve it
- **Serial execution** for pipeline stages; **parallel execution** where the same LLM stage runs across multiple domains (Stages 8, 9 of the CDN pipeline). Stages 3–6 are single Python script invocations (no parallelization needed — they process all domains internally).
- **Parallel batch size: 2** (default). For parallelizable stages, dispatch at most 2 subagents at a time. Wait for the batch to complete before dispatching the next. This avoids hitting LLM API rate limits on most platforms (Anthropic Tier 1, AWS Bedrock default quotas). Users with higher API quotas can increase this — see the project README.
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
- **When re-invoking the same subagent**, always explicitly state what action to perform and what inputs to use. Never assume the subagent remembers a previous invocation. Each call is a fresh session with no context. A vague re-invoke query (e.g. "run again") may cause the subagent to skip all tool calls and return immediately.
- **CDN full pipeline requires a user pause at Stage 1** — always wait for the user to fill in `user_input.csv` before invoking Stage 2. Do not attempt to auto-fill the CSV.
- **Domain list for parallelizable stages** — always extract the domain list from `domain_scope.json` or the finalized IR directory listing, not from earlier intermediate state that may have changed.
