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

### Step 1: Identify tasks from user request

Determine which subagents are needed based on what the user wants to convert:
- Security/WAF rules → `cf-waf-analyzer` → `cf-waf-analyzer-validator` → `cf-waf-terraform-generator`
- Transformation/redirect/header rules → `cf-functions-converter`
- CDN/cache/origin config or full migration → `cf-cdn-analyzer` → `cf-cdn-analyzer-validator`

If the user says "convert everything" or "full migration", invoke all conversion paths.

### Step 2: Extract config path

Extract the Cloudflare config directory path from the user's message. This is the path to pass to each subagent. Do not read or analyze the files yourself.

### Step 3: Invoke subagents

#### For WAF/security rules requests:

Run the analyzer → validator → generator pipeline:

**Stage 1: Analyze**
1. Invoke `cf-waf-analyzer` with: `"Analyze Cloudflare security rules in {config_path}. Generate output files in {user_language}."`
2. Check the analyzer's response:
   - If analyzer reports existing summary files found → ask the user: "Found existing analysis files. Do you want to overwrite them and re-run the analysis, or use the existing files and proceed to validation?"
     - User says overwrite → invoke analyzer again with: `"Analyze Cloudflare security rules in {config_path}. Overwrite existing summary files. Generate output files in {user_language}."`
     - User says use existing → skip to Stage 2
   - If analyzer completed successfully → proceed to Stage 2

**Stage 2: Validate**
1. Set `validation_round = 1`
2. Invoke `cf-waf-analyzer-validator` with: `"Validate WAF analysis in {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`
3. Check the `---RESULT---` block in the validator's response:
   - `STATUS: PASS` → proceed to Stage 3
   - `STATUS: FIXED` → increment `validation_round`. If `validation_round > 3`, stop and tell the user manual review is required. Otherwise invoke validator again with: `"Validate WAF analysis in {config_path}. This is validation round {validation_round}. The previous round had STATUS: FIXED. Re-run all validation checks against the current cloudflare-security-rules-summary.md to confirm all issues are resolved. Generate output files in {user_language}."`
   - `STATUS: CANNOT_FIX` → stop and tell the user which issues require manual intervention (from the ISSUES section)

**Stage 3: Generate Terraform**
1. Invoke `cf-waf-terraform-generator` with: `"Generate AWS WAF Terraform configuration from the validated summary. Generate output files in {user_language}."`

#### For CDN analysis requests:

Run the analyzer → validator loop:

1. Invoke `cf-cdn-analyzer` with: `"Analyze CDN configuration in {config_path}. Generate output files in {user_language}."`
2. Check the analyzer's response:
   - If analyzer reports existing summary files found → ask the user (same as WAF flow above)
   - If analyzer completed successfully → proceed to validator loop
3. Set `validation_round = 1`
4. Invoke `cf-cdn-analyzer-validator` with: `"Validate CDN analysis in {config_path}. This is validation round {validation_round}. Generate output files in {user_language}."`
5. Check the `---RESULT---` block in the validator's response:
   - `STATUS: PASS` → proceed to Step 4
   - `STATUS: FIXED` → increment `validation_round`. If `validation_round > 3`, stop and tell the user manual review is required. Otherwise invoke validator again with: `"Validate CDN analysis in {config_path}. This is validation round {validation_round}. The previous round had STATUS: FIXED. Re-run all validation checks against the current hostname-based-config-summary.md to confirm all issues are resolved. Generate output files in {user_language}."`
   - `STATUS: CANNOT_FIX` → stop and tell the user which issues require manual intervention (from the ISSUES section)

#### For Functions/transformation requests:

Invoke `cf-functions-converter` with: `"Convert Cloudflare transformation rules in {config_path} to CloudFront Functions. Generate output files in {user_language}."`

### Step 4: Report results

After all subagents complete, summarize what was done and where output files were generated.

## Important Rules

- **Never read config files yourself** — always delegate to subagents
- **Pass the exact path** the user provided; do not modify or resolve it
- **Serial execution only** — wait for each subagent to finish before starting the next
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
- **When re-invoking the same subagent**, always explicitly state what action to perform and what inputs to use. Never assume the subagent remembers a previous invocation. Each call is a fresh session with no context. A vague re-invoke query (e.g. "run again") may cause the subagent to skip all tool calls and return immediately.
