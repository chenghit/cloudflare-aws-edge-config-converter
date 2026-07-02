---
name: cloudflare-aws-converter
description: Orchestrates Cloudflare-to-AWS conversion by running deterministic Python scripts. Use when the user mentions Cloudflare and any of: CDN, WAF, CloudFront, AWS, migration, conversion, analysis, configuration, rules, cache, redirect, firewall, security. Also triggers on Chinese equivalents: Cloudflare 配置分析、CDN 迁移、WAF 转换、转换到 AWS、迁移到 CloudFront. The user may or may not provide a config directory path in their initial message.
metadata:
  author: chenghit
---

# Cloudflare to AWS Converter

Orchestrate conversion of Cloudflare configurations to AWS by running deterministic Python scripts. Do NOT read config files yourself — pass the config directory path to scripts.

**Language Adaptation**: Respond to the user in the same language as their message.

## Setup: repo layout and path conventions

This repository has two parts:

- `backup/` — the CloudflareBackup tool (a bash script). The user runs it to export their Cloudflare config to disk. It is the **input producer** for the converter.
- `converter/` — this skill: `SKILL.md` (this file) plus `scripts/`, `references/`, and the Terraform module under `references/modules/`. All conversion logic lives here.

**There is no install step.** The scripts self-locate (bash via `dirname`, Python via `__file__`), so they run correctly from wherever the repo is cloned. Before running anything, establish three shell variables and use them in every command. This keeps script location, output location, and input location all absolute and independent of the current directory.

```bash
mkdir -p ~/cf-migration && cd ~/cf-migration   # pick a working dir for the output; cd once
REPO=/path/to/cloudflare-aws-edge-config-converter   # where this repo is cloned
OUT="$(pwd)"                                    # output lands here (NOT inside the repo)
```

- **`$REPO`** — absolute path to the cloned repo. Every script is invoked as `python3 "$REPO/converter/scripts/X.py"` or `bash "$REPO/converter/scripts/X.sh"`. Never a relative path.
- **`$OUT`** — absolute path to the working directory chosen above. All output (`cloudflare-to-aws-waf/`, `cloudflare-to-aws-cdn/`) is written under `$OUT`. Do NOT write output inside `$REPO`.
- **`$CONFIG_PATH`** — absolute path to the user's CloudflareBackup output directory (see Step 2).
- **Do not `cd` again after the initial `cd`** for the rest of the session. Output paths are passed as absolute `$OUT/...` so this is a safety net, not the primary guard — but staying put avoids surprises. When a command genuinely needs a different directory (e.g. `terraform`), wrap it in a subshell `( cd "$OUT/..." && ... )` so the working directory is restored automatically.

## Credential safety (HARD RULES — never violate)

The backup step requires a Cloudflare API Token or Global API Key. These are the user's secrets. You:

- **MUST NOT** ask the user to paste, type, or send their API token / key / email in the conversation.
- **MUST NOT** read, open, or cat the `backup/config` file (or any file containing credentials).
- **MUST** only tell the user *how* to create `backup/config` themselves (copy `config.example`, edit it in their own editor) and how to run the backup script. The credentials stay entirely on the user's machine, never in the conversation.

## Backup step (only if the user has no backup yet)

If the user already has a CloudflareBackup output directory, skip straight to conversion. If they don't, guide them to produce one (without ever touching their credentials — see Credential safety above):

1. `cd "$REPO/backup"`
2. `cp config.example config`, then edit `config` to add their API Token (or Global API Key) and domains. Point them at `backup/README.md` for details. **You do not read or edit this file for them.**
3. Run `./cloudflare_backup.sh` (macOS/Linux; Windows users run it via WSL — see `backup/README.md`).
4. The output directory (`<zone>/<timestamp>/` plus `account/<timestamp>/`) becomes `$CONFIG_PATH`.

## Available Components

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
| `waf-split-by-host.py` | Python | Split IR by domain — strip host conditions, re-derive scope-down |
| `waf-generate-cfn.py` | Python | IR JSON → CloudFormation template (legacy or per-domain WebACLs) |

**No LLM subagents are used in the WAF pipeline.** All analysis, validation, and generation is deterministic Python.

**Default mode**: Legacy (1-2 WebACLs, no split). If IP set references exceed 50, the pipeline continues and outputs a `POST_ACTION` warning for the user. Use `--force-split` to generate per-domain WebACLs instead.

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

### Step 2: Locate and validate the backup root

Do not read or analyze config files yourself — you only locate the correct directory and pass it to scripts.

**If the user did not give a path**, ask them where their CloudflareBackup output is (the directory produced by the backup script). Do not guess.

**Why this matters:** the scripts recursively glob **downward** from `$CONFIG_PATH` — WAF needs `account/IP-Lists.txt`, CDN needs `account/List-Items-redirect-*.txt` for bulk redirects. Those `account/` files live *outside* the zone directory. If you pass a zone subdir (a natural mistake), `account/` is above it and the glob finds nothing — WAF silently loses all IP lists and CDN silently loses all bulk redirects. So you must resolve to the true root first.

**The backup root** is the directory that contains an `account/` subdirectory alongside one or more `<zone_name>/<timestamp>/DNS.txt`. `DNS.txt` never sits directly in the root — always at `<root>/<zone>/<timestamp>/DNS.txt`.

**Resolve the true root.** Take the user-given path `P`, list it (glob / directory read), and normalize:
1. If `P` contains an `account/` subdir → `P` is the backup root. Use it.
2. Else if `P` contains `DNS.txt` directly → `P` is a *zone timestamp dir*. The root is `P/../..`. Verify `account/` exists there; if so, use that root.
3. Else if `P` contains `<zone>/<timestamp>/DNS.txt` but no `account/` → walk up to 2 levels from `P` looking for a directory that contains `account/`; if found, use it.
4. If no directory containing `account/` can be found near `P` → do NOT proceed. Tell the user the path doesn't look like a CloudflareBackup root, show what you found, and ask them to point at the directory that contains both `account/` and the zone folders.

Store the resolved root as `$CONFIG_PATH` (absolute). **Always pass the resolved root to scripts — never a zone subdir.**

**Multi-zone check (CRITICAL — run on the resolved root before any script):**

This tool converts ONE zone at a time, and the scripts glob for a single `DNS.txt` under the root. Count the zone directories in the resolved root (subdirectories other than `account/` that contain `<timestamp>/DNS.txt`):
- **Exactly one zone** → proceed. Inform the user: "Detected single zone: {zone_name}."
- **More than one zone** → **abort immediately**. Passing this root would make the scripts match multiple zones' `DNS.txt`, and there is no way to isolate one zone while keeping the shared `account/` files. Tell the user:
  > "This backup contains multiple zones: [list zone names]. This tool converts one zone at a time. Please provide a backup root that contains a single zone plus its `account/` directory — re-run the backup tool for just one domain if needed."

If the user requests CDN full pipeline (Terraform generation), also check for:
- `$OUT/cloudflare-to-aws-cdn/domain_scope.json` — if it exists, pipeline can start from Stage 3

### Step 2b: Initialize CDN output directory (CDN pipeline only)

Before running any CDN script, run the initialization script to create the
output directory structure and copy static Terraform modules:

```bash
bash "$REPO/converter/scripts/cdn-init.sh" "$OUT"
```

This creates `$OUT/cloudflare-to-aws-cdn/` and copies the CloudFront distribution
Terraform module. Scripts can then write directly to their output paths without
needing to create directories.

**IMPORTANT**: The output directory is always `$OUT/cloudflare-to-aws-cdn/`, NOT inside
the Cloudflare config backup directory. Do NOT look for or use `cloudflare-to-aws-cdn/`
under the config path — that would be a leftover from a previous run in a different
working directory.

Skip this step if `$OUT/cloudflare-to-aws-cdn/` already exists (resuming a previous run).

### Step 3: Run pipeline scripts

No LLM subagents are used. All stages are Python scripts invoked via `execute_bash`.

---

#### WAF pipeline:

**The entire WAF pipeline is a single deterministic script. No LLM subagents are invoked.**

1. Check if `$OUT/cloudflare-to-aws-waf/waf-cloudformation.json` already exists.
   - If it exists → ask the user: "Found existing WAF output. Do you want to overwrite and re-run, or keep the existing files?"
     - User says overwrite → `rm -rf "$OUT/cloudflare-to-aws-waf"`, then proceed.
     - User says keep → skip to Step 4 (report results).
   - If it does not exist → proceed.

2. Check IR version compatibility: if `$OUT/cloudflare-to-aws-waf/waf_ir.json` exists, check for `conditions` field in the first custom rule. If absent (old format), delete the directory and re-run.

3. Run the pipeline:
   ```bash
   bash "$REPO/converter/scripts/waf-pipeline.sh" "$CONFIG_PATH" "$OUT/cloudflare-to-aws-waf"
   ```
   If the user explicitly requests per-domain split, add `--force-split` to the command.

   Parse the `---RESULT---` block:
   - `STATUS: OK` → proceed to Step 4.
   - `STATUS: ERROR` → report the `CONTEXT` field to the user and stop.
   - `POST_ACTION` field → if present, follow the instruction. Multi-line values use 2-space indented continuation lines. If the instruction says "exactly as-is", print the content verbatim without translation or modification. A single `POST_ACTION` may instruct multiple steps (e.g. print a warning AND translate the README for non-English users) — perform all of them.

---

#### CDN full pipeline (0 LLM stages + 10 Python scripts — runs when user wants Terraform output for CloudFront):

All stages are deterministic Python scripts. No LLM subagents. No user interaction required.

**Stage 1: DNS Parsing + Domain Scope** (Python script, no LLM)
```bash
python3 "$REPO/converter/scripts/cdn-parse-dns.py" "$CONFIG_PATH" "$OUT/cloudflare-to-aws-cdn"
```
Parse the `---RESULT---` block:
- `STATUS: OK` → proceed directly to Stage 3.
  If the result includes WARNINGS about non-convertible origins or CloudFront loop exclusions, report them to the user.
- `STATUS: FATAL` → report the `CONTEXT` field to the user and stop.

**Stage 3–6: Preprocess → Validate → Finalize → Validate Final** (Python scripts, no LLM)

These four stages are fully deterministic Python scripts. Run them in sequence:

**Stage 3: Preprocess**
```bash
python3 "$REPO/converter/scripts/cdn-preprocess.py" "$CONFIG_PATH" "$OUT/cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → all domains processed, proceed to Stage 4
- 1 → partial failure. Read stderr for failed domain names. Retry failed domains:
  ```bash
  python3 "$REPO/converter/scripts/cdn-preprocess.py" "$CONFIG_PATH" "$OUT/cloudflare-to-aws-cdn" --domain {failed_domain}
  ```
  If retry also fails → mark domain as SKIPPED, continue with remaining domains.
- 2 → total failure, stop pipeline

**Stage 4: V1 Chunk Validation**
```bash
python3 "$REPO/converter/scripts/cdn-validate-chunk.py" "$OUT/cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → all PASS, proceed to Stage 5
- 1 → some FAIL. Read the validation reports at `$OUT/cloudflare-to-aws-cdn/ir/validation/chunk/{hostname}-v1.json`.
  - If >50% of domains fail with the same error type → preprocess bug, stop pipeline
  - Otherwise → delete failed domain's accumulator and validation files, re-run Stage 3 for that domain with `--domain`, then re-run Stage 4
  - If second attempt also FAILs → mark domain as SKIPPED

**Stage 5: Finalize**
```bash
python3 "$REPO/converter/scripts/cdn-finalize.py" "$OUT/cloudflare-to-aws-cdn" [skipped_domains.json]
```
If there are SKIPPED domains, write a JSON file with `[{"hostname": "...", "reason": "..."}]` and pass it as the second argument.

Check exit code:
- 0 → proceed to Stage 6
- 1 → stop pipeline, report error

**Stage 6: V2 Final Validation**
```bash
python3 "$REPO/converter/scripts/cdn-validate-final.py" "$OUT/cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → all PASS, proceed to Stage 7
- 1 → some FAIL. Read `$OUT/cloudflare-to-aws-cdn/ir/validation/final/{hostname}-v2.json`:
  - If ALL errors are about missing `dedup_manifest.json` or `conversion_report.md` → re-run Stage 5
  - Otherwise → pipeline bug, stop and tell user to file a GitHub issue

**Stage 7: Shared Terraform Policies** (Python script, no LLM)
```bash
python3 "$REPO/converter/scripts/cdn-generate-shared-policies.py" "$OUT/cloudflare-to-aws-cdn"
```
Check exit code:
- 0 → proceed to Stage 7.5
- 1 → stop pipeline, report error

**Stage 7.5: Generate Terraform Scaffold** (Python script, no LLM)
```bash
python3 "$REPO/converter/scripts/cdn-generate-tf-scaffold.py" "$OUT/cloudflare-to-aws-cdn"
```
Generates main.tf, functions.tf, outputs.tf, kvs.tf, kvs-data.json for each domain. These are deterministic template files — no LLM needed.

**Stage 7.5b: Terraform Validate** (shared policies only)
1. Validate shared policies (subshell keeps the working directory unchanged):
   ```bash
   ( cd "$OUT/cloudflare-to-aws-cdn/terraform/shared" && terraform init -backend=false && terraform validate )
   ```
2. If validation fails → stop pipeline and report errors. These are Python script bugs — the user should file a GitHub issue.
3. If validation passes → proceed to Stage 7.6.

**Stage 7.6: Generate Test Scripts** (Python script, no LLM)
```bash
python3 "$REPO/converter/scripts/cdn-generate-tests.py" "$OUT/cloudflare-to-aws-cdn"
```
Generates `test-cdn-rules.py` per domain for post-deployment validation. Proceed to Stage 8.

**Stage 8: JS Generation** (Python script, no LLM)
```bash
python3 "$REPO/converter/scripts/cdn-generate-js.py" "$OUT/cloudflare-to-aws-cdn"
```
Parse the `---RESULT---` block:
- `STATUS: OK` → proceed to Stage 9
- `STATUS: PARTIAL` → some domains exceeded 10KB CFF size limit (`SIZE_EXCEEDED`). Report failed domains to user. Remaining domains proceed.
- `STATUS: FATAL` → stop pipeline, report error

**Stage 9: JS Validation** (Python script, no LLM)
```bash
python3 "$REPO/converter/scripts/cdn-validate-js.py" "$OUT/cloudflare-to-aws-cdn"
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

After the summary, refer the user to the generated deployment README for deployment instructions:

> See `$OUT/cloudflare-to-aws-waf/README_aws-waf-deployment.md` for deployment steps, quota usage, and post-deployment checklist.

The README contains deployment commands adapted to the template size (direct upload vs S3 bucket vs multi-stack split). Do NOT hardcode deployment commands — always refer to the README.

**Step 4b: Translate deployment README (non-English users)**

**CRITICAL — do NOT skip this step if the user's message is not in English.**

If the user's message is not in English, read `$OUT/cloudflare-to-aws-waf/README_aws-waf-deployment.md`, translate it to the user's language, and save as `$OUT/cloudflare-to-aws-waf/README_aws-waf-deployment_{lang}.md` (e.g., `_CN.md`, `_JA.md`). Keep the original English version as-is.

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

> **Note on deploy paths**: the generated deployment README and `conversion_report.md` contain example commands with relative paths (e.g. `cd cloudflare-to-aws-cdn/terraform/shared`). These assume the user runs them from `$OUT`. When you show deploy steps, tell the user to run them from `$OUT` (the working directory chosen at Setup), or prefix with the absolute `$OUT` path.

**Step 4c: Translate CDN deployment guide (non-English users)**

**CRITICAL — do NOT skip this step if the user's message is not in English.**

If the user's message is not in English, read `$OUT/cloudflare-to-aws-cdn/conversion_report.md`, translate it to the user's language, and save as `$OUT/cloudflare-to-aws-cdn/conversion_report_{lang}.md` (e.g., `_CN.md`, `_JA.md`). Keep the original English version as-is.

## Important Rules

- **Never read config files yourself** — always delegate to scripts (both WAF and CDN pipelines)
- **Never read or ask for credentials** — see Credential safety above
- **Pass the exact path** the user provided; do not modify or resolve it
- **Always use `$REPO`, `$OUT`, `$CONFIG_PATH`** — never hardcode script or output paths, never `cd` mid-session
- **WAF pipeline**: single `waf-pipeline.sh` call, no LLM subagents, no retry logic needed
- **CDN pipeline**: serial execution for pipeline stages. All 10 stages are Python script invocations (no LLM subagents, no parallelization needed, no user interaction).
