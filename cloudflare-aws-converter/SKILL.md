---
name: cloudflare-aws-converter
description: Orchestrates Cloudflare-to-AWS conversion and analysis by delegating to specialized subagents. Use when the user mentions Cloudflare and any of: CDN, WAF, CloudFront, AWS, migration, conversion, analysis, configuration, rules, cache, redirect, firewall, security. Also triggers on Chinese equivalents: Cloudflare 配置分析、CDN 迁移、WAF 转换、转换到 AWS、迁移到 CloudFront. The user may or may not provide a config directory path in their initial message.
---

# Cloudflare to AWS Converter

Orchestrate conversion of Cloudflare configurations to AWS by delegating to specialized subagents. Do NOT read config files yourself — pass the config directory path directly to each subagent.

**Language Adaptation**: Respond to the user in the same language as their message. However, **always write subagent queries in English** — subagents rely on English keywords to correctly parse paths and instructions. Pass the output language as an explicit instruction within the query (e.g., `"Generate output files in Chinese"`).

## Available Subagents

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-waf-analyzer` | Security rules → analysis summary | WAF, firewall, rate limiting, IP rules, security rules |
| `cf-waf-analyzer-validator` | Validates WAF analysis summary | (invoked automatically after cf-waf-analyzer) |
| `cf-waf-terraform-generator` | Validated summary → AWS WAF Terraform | (invoked automatically after validator passes) |
| `cf-functions-converter` | Transformation rules → CloudFront Functions (JS) | redirects, URL rewrites, header transforms, transformation rules |
| `cf-cdn-analyzer` | CDN config → hostname-based summary | CDN, cache, origin, full migration, all configs |
| `cf-cdn-analyzer-validator` | Validates CDN analyzer output | (invoked automatically after cf-cdn-analyzer) |

## Workflow

### Step 1: Identify intent and scope

Determine what the user wants from their message. There are two dimensions:

**Dimension 1 — Scope (what to process):**
- **WAF only**: user mentions WAF, security rules, firewall, rate limiting, IP rules
- **CDN only**: user mentions CDN, cache, origin rules
- **Functions only**: user mentions transformation rules, redirects, URL rewrites, header transforms
- **Everything**: user says "convert everything", "full migration", "all configs", or mentions Cloudflare config without specifying a type

**Dimension 2 — Depth (how far to go):**
- **Analyze**: user says "analyze", "分析" → run analyzer + validator only, stop before generator/converter
- **Convert**: user says "convert", "migrate", "转换", "迁移" → run full pipeline including generator/converter
- **Default**: if user doesn't specify, assume **convert** (the most common intent)

**Intent matrix:**

| Scope | Depth: Analyze | Depth: Convert |
|-------|---------------|----------------|
| WAF only | waf-analyzer → waf-validator | waf-analyzer → waf-validator → waf-terraform-generator |
| CDN only | cdn-analyzer → cdn-validator | cdn-analyzer → cdn-validator (no generator yet) |
| Functions only | N/A (no separate analyzer) | cf-functions-converter |
| Everything | WAF analyze → CDN analyze | WAF convert → CDN convert → Functions convert |

**Execution order for "Everything":**
1. WAF pipeline first (analyzer → validator → generator)
2. CDN pipeline second (analyzer → validator)
3. Functions converter last

This order matters because WAF and CDN analysis are independent, but running WAF first avoids context confusion.

### Step 2: Extract config path

Extract the Cloudflare config directory path from the user's message. This is the path to pass to each subagent. Do not read or analyze the files yourself.

### Step 3: Invoke subagents

**CRITICAL: Every subagent query MUST start with a skill-loading instruction.** Subagents may not automatically load their skill file when invoked via `use_subagent`. Prefix every query with:

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/{subagent-name}/SKILL.md and follow its workflow. "`

Where `{subagent-name}` matches the subagent directory name (e.g., `cf-waf-analyzer`, `cf-cdn-analyzer-validator`).

#### WAF pipeline (analyzer → validator → generator):

**Stage 1: Analyze**
1. Invoke `cf-waf-analyzer` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. Analyze Cloudflare security rules in {config_path}. Generate output files in {user_language}."`
2. Check the analyzer's response:
   - If analyzer reports existing summary files found → ask the user: "Found existing analysis files. Do you want to overwrite them and re-run the analysis, or use the existing files and proceed to validation?"
     - User says overwrite → invoke analyzer again with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer/SKILL.md and follow its workflow. Analyze Cloudflare security rules in {config_path}. Overwrite existing summary files. Generate output files in {user_language}."`
     - User says use existing → skip to Stage 2
   - If analyzer completed successfully → proceed to Stage 2

**Stage 2: Validate**
1. Set `validation_round = 1`
2. Invoke `cf-waf-analyzer-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. Validate WAF analysis in {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`
3. Check the `---RESULT---` block in the validator's response:
   - `STATUS: PASS` → if depth is "analyze", proceed to Step 4. If depth is "convert", proceed to Stage 3.
   - `STATUS: FIXED` → increment `validation_round`. If `validation_round > 3`, stop and tell the user manual review is required. Otherwise invoke validator again with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-analyzer-validator/SKILL.md and follow its workflow. Validate WAF analysis in {config_path}. This is validation round {validation_round}. The previous round had STATUS: FIXED. Re-run all validation checks against the current cloudflare-security-rules-summary.md to confirm all issues are resolved. Generate output files in {user_language}."`
   - `STATUS: CANNOT_FIX` → stop and tell the user which issues require manual intervention (from the ISSUES section)

**Stage 3: Generate Terraform** (only if depth is "convert")
1. Invoke `cf-waf-terraform-generator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-waf-terraform-generator/SKILL.md and follow its workflow. Generate AWS WAF Terraform configuration from the validated summary. Generate output files in {user_language}."`
2. Check the `---RESULT---` block in the generator's response:
   - `STATUS: COMPLETE` → proceed to Step 4

#### CDN pipeline (analyzer → validator):

1. Invoke `cf-cdn-analyzer` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-analyzer/SKILL.md and follow its workflow. Analyze CDN configuration in {config_path}. Generate output files in {user_language}."`
2. Check the analyzer's response:
   - If analyzer reports existing summary files found → ask the user (same as WAF flow above)
   - If analyzer completed successfully (`STATUS: COMPLETE` in `---RESULT---` block) → proceed to validator loop
3. Set `validation_round = 1`
4. Invoke `cf-cdn-analyzer-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-analyzer-validator/SKILL.md and follow its workflow. Validate CDN analysis in {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`
5. Check the `---RESULT---` block in the validator's response:
   - `STATUS: PASS` → proceed to Step 4 (or next pipeline if "Everything")
   - `STATUS: FIXED` → increment `validation_round`. If `validation_round > 3`, stop and tell the user manual review is required. Otherwise invoke validator again with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-analyzer-validator/SKILL.md and follow its workflow. Validate CDN analysis in {config_path}. This is validation round {validation_round}. The previous round had STATUS: FIXED. Re-run all validation checks against the current hostname-based-config-summary.md to confirm all issues are resolved. Generate output files in {user_language}."`
   - `STATUS: CANNOT_FIX` → stop and tell the user which issues require manual intervention (from the ISSUES section)

#### Functions pipeline:

Invoke `cf-functions-converter` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-functions-converter/SKILL.md and follow its workflow. Convert Cloudflare transformation rules in {config_path} to CloudFront Functions. Generate output files in {user_language}."`

### Step 4: Report results

After all subagents complete, summarize what was done and where output files were generated.

For "Everything" scope, report results for each pipeline separately.

## Important Rules

- **Never read config files yourself** — always delegate to subagents
- **Pass the exact path** the user provided; do not modify or resolve it
- **Serial execution only** — wait for each subagent to finish before starting the next
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
- **When re-invoking the same subagent**, always explicitly state what action to perform and what inputs to use. Never assume the subagent remembers a previous invocation. Each call is a fresh session with no context. A vague re-invoke query (e.g. "run again") may cause the subagent to skip all tool calls and return immediately.
