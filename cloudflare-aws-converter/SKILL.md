---
name: cloudflare-aws-converter
description: Orchestrates Cloudflare-to-AWS conversion by delegating to specialized subagents. Use when the user wants to convert Cloudflare configurations to AWS (WAF, CloudFront Functions, or CDN analysis) and provides a Cloudflare config directory path. This skill determines which subagents to invoke and in what order based on the user's request, then passes the config path directly to each subagent. Triggers on requests like "convert my Cloudflare config to AWS", "migrate Cloudflare WAF and CDN to AWS", or any combination of WAF/Functions/CDN conversion tasks.
---

# Cloudflare to AWS Converter

Orchestrate conversion of Cloudflare configurations to AWS by delegating to specialized subagents. Do NOT read config files yourself — pass the config directory path directly to each subagent.

## Available Subagents

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-waf-converter` | Security rules → AWS WAF (Terraform) | WAF, firewall, rate limiting, IP rules, security rules |
| `cf-functions-converter` | Transformation rules → CloudFront Functions (JS) | redirects, URL rewrites, header transforms, transformation rules |
| `cf-cdn-analyzer` | CDN config → hostname-based summary | CDN, cache, origin, full migration, all configs |

## Workflow

### Step 1: Identify tasks from user request

Determine which subagents are needed based on what the user wants to convert:
- Security/WAF rules → `cf-waf-converter`
- Transformation/redirect/header rules → `cf-functions-converter`
- CDN/cache/origin config or full migration → `cf-cdn-analyzer`

If the user says "convert everything" or "full migration", invoke all three.

### Step 2: Extract config path

Extract the Cloudflare config directory path from the user's message. This is the path to pass to each subagent. Do not read or analyze the files yourself.

### Step 3: Invoke subagents serially

Invoke each required subagent one at a time in this order (when multiple are needed):
1. `cf-cdn-analyzer` (analysis first, output informs subsequent steps)
2. `cf-waf-converter`
3. `cf-functions-converter`

For each subagent, use `use_subagent` with a clear instruction that includes:
- The conversion task
- The exact config directory path from the user

**Example invocation message to subagent:**
> "Convert security rules in /path/to/cloudflare-config to AWS WAF"

### Step 4: Report results

After all subagents complete, summarize what was done and where output files were generated.

## Important Rules

- **Never read config files yourself** — always delegate to subagents
- **Pass the exact path** the user provided; do not modify or resolve it
- **Serial execution only** — wait for each subagent to finish before starting the next
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
