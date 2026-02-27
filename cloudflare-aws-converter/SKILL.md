---
name: cloudflare-aws-converter
description: Orchestrates Cloudflare-to-AWS conversion and analysis by delegating to specialized subagents. Use when the user wants to analyze, convert, or migrate Cloudflare configurations (WAF, CloudFront Functions, or CDN) and provides a Cloudflare config directory path. This skill determines which subagents to invoke and in what order based on the user's request, then passes the config path directly to each subagent. Triggers on requests like "analyze my Cloudflare CDN config", "convert my Cloudflare config to AWS", "migrate Cloudflare WAF and CDN to AWS", or any combination of WAF/Functions/CDN analysis or conversion tasks.
---

# Cloudflare to AWS Converter

Orchestrate conversion of Cloudflare configurations to AWS by delegating to specialized subagents. Do NOT read config files yourself — pass the config directory path directly to each subagent.

## Available Subagents

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-waf-converter` | Security rules → AWS WAF (Terraform) | WAF, firewall, rate limiting, IP rules, security rules |
| `cf-functions-converter` | Transformation rules → CloudFront Functions (JS) | redirects, URL rewrites, header transforms, transformation rules |
| `cf-cdn-analyzer` | CDN config → hostname-based summary | CDN, cache, origin, full migration, all configs |
| `cf-cdn-analyzer-validator` | Validates analyzer output, fixes errors in-place | (invoked automatically after cf-cdn-analyzer) |

## Workflow

### Step 1: Identify tasks from user request

Determine which subagents are needed based on what the user wants to convert:
- Security/WAF rules → `cf-waf-converter`
- Transformation/redirect/header rules → `cf-functions-converter`
- CDN/cache/origin config or full migration → `cf-cdn-analyzer` (followed by validator loop)

If the user says "convert everything" or "full migration", invoke all three conversion paths.

### Step 2: Extract config path

Extract the Cloudflare config directory path from the user's message. This is the path to pass to each subagent. Do not read or analyze the files yourself.

### Step 3: Invoke subagents

#### For CDN analysis requests:

Run the analyzer → validator loop:

1. Invoke `cf-cdn-analyzer` with: `"Analyze CDN configuration in {config_path}"`
2. Set `validation_round = 1`
3. Invoke `cf-cdn-analyzer-validator` with: `"Validate CDN analysis in {config_path}. This is validation round {validation_round}."`
4. Check the `---RESULT---` block in the validator's response:
   - `STATUS: PASS` → proceed to Step 4
   - `STATUS: FIXED` → increment `validation_round`. If `validation_round > 3`, stop and tell the user manual review is required. Otherwise go back to step 3.
   - `STATUS: CANNOT_FIX` → stop and tell the user which issues require manual intervention (from the ISSUES section)

#### For WAF and Functions requests:

Invoke in this order (when multiple are needed):
1. `cf-waf-converter`
2. `cf-functions-converter`

For each subagent, pass a clear instruction with the conversion task and the exact config directory path.

### Step 4: Report results

After all subagents complete, summarize what was done and where output files were generated.

## Important Rules

- **Never read config files yourself** — always delegate to subagents
- **Pass the exact path** the user provided; do not modify or resolve it
- **Serial execution only** — wait for each subagent to finish before starting the next
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
