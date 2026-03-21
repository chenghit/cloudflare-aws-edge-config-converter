# WAF Pipeline

WAF conversion: Cloudflare security rules → IR JSON → AWS WAF Terraform.

All Python scripts output `---RESULT---` blocks per SCRIPT_STANDARDS.md. Parse STATUS and ACTION fields to decide next step. Do not hardcode exit code logic — let the script tell you what to do.

## Stage 0: Initialize

```bash
bash ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-init.sh "$(pwd)"
```

Parse `---RESULT---`: if `SKIPPED: true`, output directory already exists. Check if `cloudflare-to-aws-waf/waf_ir.json` exists:
- If yes → ask user: "Found existing IR files. Overwrite and re-analyze, or use existing and proceed to validation?"
  - Overwrite → `rm -rf cloudflare-to-aws-waf`, re-run init, proceed to Stage 1.
  - Use existing → skip to Stage 2.
- If no → proceed to Stage 1.

## Stage 1: Analyze (3 batches, serial)

**A1** (Python, no LLM):
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-analyze-ip.py "{config_path}" "cloudflare-to-aws-waf"
```
On `STATUS: OK` → proceed. On error → follow ACTION field.

**A2** (LLM subagent):
`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. You MUST use tools to read config files and write output JSON — do NOT skip tool calls. Analyze batch A2: WAF Custom Rules. The Cloudflare backup directory is {config_path}. Generate output files in {user_language}."`

**Extract skip labels** (between A2 and A3):
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-extract-skip-labels.py "cloudflare-to-aws-waf/waf_ir_custom.json"
```
On `STATUS: OK` → read `SKIP_LABELS` field. On error → re-invoke A2 once, then re-run. If second attempt also fails → stop and report.

**A3** (LLM subagent):
`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. You MUST use tools to read config files and write output JSON — do NOT skip tool calls. Analyze batch A3: Rate Limiting Rules. Skip labels from custom rules: {skip_labels}. The Cloudflare backup directory is {config_path}. Generate output files in {user_language}."`

If any batch fails → stop and report. Do not proceed to Stage 2.

## Stage 2: Validate

**Step 2a: Merge + Count + Chunk**

1. Set `validation_round = 1`.

2. Merge:
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-merge-ir.py "cloudflare-to-aws-waf"
```
On `STATUS: OK` → note `IP_RULES`, `CUSTOM_RULES`, `RATE_RULES`. On error → follow ACTION.

3. Count validation:
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-count-validate.py "{config_path}" "cloudflare-to-aws-waf"
```
On `STATUS: OK` → proceed. On `STATUS: ERROR` → read `RETRY_BATCHES` field (e.g., `A2,A3`), re-invoke those batches from Stage 1, re-merge, re-validate. If second attempt also mismatches → stop and report.

4. Chunk:
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-chunk-rules.py "{config_path}" "cloudflare-to-aws-waf" 50
```
On `STATUS: OK` → read `CHUNK_FILES` (multi-line, one path per line) for V2 dispatch. If `NO_RULES: true` → skip all V2 dispatches.

5. Use merge output to determine skips:
   - `IP_RULES == 0` → skip V1.
   - `RATE_RULES == 0` → skip V3.

**Step 2b: Parallel validation (V1 + V2 chunks + V3)**

Dispatch in parallel (batch size 2):

- **V1**: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. You MUST use tools to read IR and config files and write validation reports. Mode: V1 (IP Lists + IP Access Rules). The Cloudflare backup directory is {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`

- **V2** (one per chunk): `"... Mode: V2 (Custom Rules chunk). ... Chunk file: {chunk_path} (positions {start}-{end}). ..."`

- **V3**: `"... Mode: V3 (Rate Limiting Rules). ..."`

Wait for all to complete.

**Step 2c: V4 Global validation**

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. You MUST use tools to read IR files and write validation reports. Mode: V4 (Global validation). This is validation round {validation_round}. Generate output files in {user_language}."`

Check `---RESULT---`:
- `STATUS: PASS` → if depth is "analyze", go to Step 4 (report). If "convert", go to Stage 3.
- `STATUS: FIXED` → increment `validation_round`. If > 3 → stop, manual review needed. Otherwise delete `cloudflare-to-aws-waf/validation/` and `cloudflare-to-aws-waf/chunks/`, re-run Stage 2 from count validation (skip merge — V4 already fixed waf_ir.json).
- `STATUS: CANNOT_FIX` → stop, tell user which issues need manual intervention.

## Stage 3: Generate Terraform (convert depth only)

1. Invoke `cf-waf-terraform-generator`:
`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-terraform-generator/SKILL.md and follow its workflow. You MUST use tools to read IR and write Terraform files — do NOT skip tool calls. Generate AWS WAF Terraform configuration from the validated IR JSON. Generate output files in {user_language}."`

2. Check `---RESULT---`: `STATUS: COMPLETE` → proceed.

**Step 3b: Terraform validate**
```bash
cd cloudflare-to-aws-waf && terraform init -backend=false && terraform validate
```
Pass → Step 3c. Fail → re-invoke generator with error details. Second fail → stop, tell user to fix manually.

**Step 3c: Generate README**
```bash
python3 ~/.kiro/skills/cloudflare-aws-converter/scripts/waf-generate-readme.py "cloudflare-to-aws-waf"
```
On `STATUS: OK` → note `NON_CONVERTIBLE` and `PARTIAL_RULES` counts for the final report. Proceed to Step 4.
