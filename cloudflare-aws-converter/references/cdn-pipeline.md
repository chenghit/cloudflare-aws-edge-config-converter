# CDN Pipeline

CDN conversion: Cloudflare cache/redirect/origin rules → CloudFront Terraform.

4 LLM stages + 7 Python scripts. All scripts output `---RESULT---` blocks per SCRIPT_STANDARDS.md.

## Stage 0: Initialize

```bash
bash ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-init.sh "$(pwd)"
```

Output directory is always `$(pwd)/cloudflare-to-aws-cdn/`, NOT inside the config backup directory. Skip if already exists in current working directory.

## Stage 1: DNS Parsing (LLM)

Invoke `cf-cdn-dns-parser`:
`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-dns-parser/SKILL.md and follow its workflow. You MUST use tools (glob, fs_read, fs_write) to read DNS.txt and write output files — do NOT generate output from memory. The Cloudflare backup directory is {config_path}. Parse DNS.txt to identify all proxied domains. Detect any Cloudflare for SaaS configurations. Group domains by apex domain for ACM certificate planning. Write dns_manifest.yaml and user_input_template.csv to the cloudflare-to-aws-cdn/ output directory. Generate output files in {user_language}."`

Verify: `ls cloudflare-to-aws-cdn/dns_manifest.yaml cloudflare-to-aws-cdn/user_input_template.csv`
- Both exist → pause and tell user to fill in `user_input_template.csv`, save as `user_input.csv`.
- Missing → re-invoke once. Second failure → stop.

**Wait for user confirmation before continuing.**

## Stage 2: Input Validation (LLM)

Invoke `cf-cdn-input-validator`:
`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-input-validator/SKILL.md and follow its workflow. You MUST use tools to read and write files. The Cloudflare backup directory is {config_path}. Validate cloudflare-to-aws-cdn/user_input.csv against cloudflare-to-aws-cdn/dns_manifest.yaml. On success, write cloudflare-to-aws-cdn/domain_scope.json. Report any validation errors with remediation hints. Generate output files in {user_language}."`

Verify: `ls cloudflare-to-aws-cdn/domain_scope.json`. Missing after PASS claim → re-invoke once.

Check `---RESULT---`:
- `STATUS: PASS` → Stage 3
- `STATUS: ERRORS` → show errors, ask user to fix CSV, re-invoke Stage 2
- `STATUS: CANNOT_FIX` → stop

## Stages 3–6: Python Scripts (no LLM)

Run in sequence. For each script, parse the `---RESULT---` block and follow the ACTION field on failure.

**Stage 3: Preprocess**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-preprocess.py "{config_path}" "cloudflare-to-aws-cdn"
```
- `STATUS: OK` → Stage 4
- `STATUS: PARTIAL` → read `FAILED_ITEMS` and `COMMAND` fields. Run the retry command. If retry also fails → mark failed domains as SKIPPED.
- `STATUS: FATAL` → stop pipeline

**Stage 4: V1 Chunk Validation**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-validate-chunk.py "cloudflare-to-aws-cdn"
```
- `STATUS: OK` → Stage 5
- `STATUS: ERROR` → read `FAILED_ITEMS`. If >50% fail with same error → preprocess bug, stop. Otherwise delete failed domain's accumulator + validation files, re-run Stage 3 with `--domain`, re-run Stage 4. Second failure → mark as SKIPPED.

**Stage 5: Finalize**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-finalize.py "cloudflare-to-aws-cdn" [skipped_domains.json]
```
If SKIPPED domains exist, write `[{"hostname": "...", "reason": "..."}]` to a JSON file and pass as second arg.

- `STATUS: OK` → note `DOMAINS`, `UNIQUE_POLICIES`, `SHARED_POLICIES`, `SHADOW_WARNINGS` for final report. Stage 6.
- Error → follow ACTION.

**Stage 6: V2 Final Validation**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-validate-final.py "cloudflare-to-aws-cdn"
```
- `STATUS: OK` → Stage 7
- `STATUS: ERROR` → read `FAILED_ITEMS`. If all errors are about missing manifest/report → re-run Stage 5. Otherwise → pipeline bug, stop.

## Stage 7: Shared Policies

```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-shared-policies.py "cloudflare-to-aws-cdn"
```
- `STATUS: OK` → note `TOTAL_POLICIES`, `CACHE_POLICIES`, `ORIGIN_REQUEST_POLICIES`, `RESPONSE_HEADERS_POLICIES`. Stage 7.5.

## Stage 7.5: Terraform Scaffold

```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tf-scaffold.py "cloudflare-to-aws-cdn"
```
- `STATUS: OK` → Stage 7.5b.

**Stage 7.5b: Terraform Validate** (shared policies only)
```bash
cd cloudflare-to-aws-cdn/terraform/shared && terraform init -backend=false && terraform validate
```
Fail → stop, report (script bug). Pass → Stage 7.6.

## Stage 7.6: Test Scripts

```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tests.py "cloudflare-to-aws-cdn"
```
- `STATUS: OK` → Stage 8.

## Stage 8: Per-Domain JS Generation (LLM, parallelizable)

For each domain from `domain_scope.json`, invoke `cf-cdn-tf-domain` (batch size 2):

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-domain/SKILL.md and follow its workflow. You MUST use tools to read IR files and write JS output — do NOT skip tool calls. The Cloudflare backup directory is {config_path}. Generate JavaScript files for domain {domain} using the final IR at cloudflare-to-aws-cdn/ir/final/{domain}.json. Terraform scaffold files (main.tf, functions.tf, etc.) have already been generated at cloudflare-to-aws-cdn/terraform/domains/. Only generate JS files (viewer_request.js, viewer_response.js, Lambda@Edge handlers if needed). If Lambda@Edge files are generated, update functions.tf by replacing the LAMBDA_EDGE_PLACEHOLDER comment with L@E resource blocks. Do NOT modify main.tf. Generate output files in {user_language}."`

Verify: `functions/` directory exists under domain's terraform dir. If domain IR has `lambda_edge.origin_response` non-null, also check `lambda/` exists. Missing → re-invoke once.

## Stage 9: JS Validation (LLM, parallelizable)

For each domain with `functions/`, invoke `cf-cdn-js-validator` (batch size 2):

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-js-validator/SKILL.md and follow its workflow. You MUST use tools to read JS files and write validation report. The Cloudflare backup directory is {config_path}. Validate all CloudFront Function JavaScript files for domain {domain} (the skill will derive the sanitized directory name from the hostname). Output a validation report to cloudflare-to-aws-cdn/ir/validation/js/{domain}-v3.json. Generate output files in {user_language}."`

Verify: `{domain}-v3.json` exists. Missing → re-invoke once.

Check `overall_status` in report:
- `"PASS"` → done
- `"FAIL"` → auto-retry once:
  a. Read failed checks from `{hostname}-v3.json`.
  b. Derive sanitized hostname (replace `.` and `-` with `_`). Delete JS output and regenerate scaffold:
     ```bash
     rm -rf cloudflare-to-aws-cdn/terraform/domains/{sanitized}/functions/ cloudflare-to-aws-cdn/terraform/domains/{sanitized}/lambda/
     python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/cdn-generate-tf-scaffold.py "cloudflare-to-aws-cdn"
     ```
  c. Re-invoke `cf-cdn-tf-domain` with error hint.
  d. Re-invoke `cf-cdn-js-validator`.
  e. Second FAIL → mark as `JS_VALIDATION_FAILED`, continue other domains.

After all domains complete → Step 4 (report).
