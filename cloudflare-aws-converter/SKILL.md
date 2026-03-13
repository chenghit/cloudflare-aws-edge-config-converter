---
name: cloudflare-aws-converter
description: Orchestrates Cloudflare-to-AWS conversion and analysis by delegating to specialized subagents. Use when the user mentions Cloudflare and any of: CDN, WAF, CloudFront, AWS, migration, conversion, analysis, configuration, rules, cache, redirect, firewall, security. Also triggers on Chinese equivalents: Cloudflare 配置分析、CDN 迁移、WAF 转换、转换到 AWS、迁移到 CloudFront. The user may or may not provide a config directory path in their initial message.
---

# Cloudflare to AWS Converter

Orchestrate conversion of Cloudflare configurations to AWS by delegating to specialized subagents. Do NOT read config files yourself — pass the config directory path directly to each subagent.

**Language Adaptation**: Respond to the user in the same language as their message. However, **always write subagent queries in English** — subagents rely on English keywords to correctly parse paths and instructions. Pass the output language as an explicit instruction within the query (e.g., `"Generate output files in Chinese"`).

## Available Subagents

### WAF Pipeline

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-waf-analyzer` | Security rules → analysis summary | WAF, firewall, rate limiting, IP rules, security rules |
| `cf-waf-analyzer-validator` | Validates WAF analysis summary | (invoked automatically after cf-waf-analyzer) |
| `cf-waf-terraform-generator` | Validated summary → AWS WAF Terraform | (invoked automatically after validator passes) |

### CDN Pipeline (New)

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-cdn-dns-parser` | DNS export → domain manifest + input template | CDN, full migration, domains, DNS |
| `cf-cdn-input-validator` | Validates user_input.csv → domain_scope.json | (invoked automatically after user fills input) |
| `cf-cdn-per-domain-processor` | Per-domain CDN rules → IR accumulator YAML | (invoked once per domain, parallelizable) |
| `cf-cdn-ir-chunk-validator` | Validates each domain's IR accumulator | (invoked once per domain, parallelizable) |
| `cf-cdn-ir-finalizer` | Merges all accumulators → final IR + dedup manifest + report | (invoked after all chunks validated) |
| `cf-cdn-ir-final-validator` | Validates each domain's final IR | (invoked once per domain, parallelizable) |
| `cf-cdn-tf-shared-policies` | Final IR → shared Terraform policies | (invoked after all final IRs validated) |
| `cf-cdn-tf-domain` | Per-domain final IR → Terraform distribution config | (invoked once per domain, parallelizable) |
| `cf-cdn-js-validator` | Validates each domain's CloudFront Function JS | (invoked once per domain, parallelizable) |

### Functions Pipeline

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-functions-converter` | Transformation rules → CloudFront Functions (JS) | redirects, URL rewrites, header transforms, transformation rules |

### Shared CDN Analysis

| Subagent | Handles | Trigger when user mentions |
|----------|---------|---------------------------|
| `cf-cdn-analyzer` | CDN config → hostname-based summary | CDN, cache, origin, full migration, all configs |
| `cf-cdn-analyzer-validator` | Validates CDN analyzer output | (invoked automatically after cf-cdn-analyzer) |

## Workflow

### Step 1: Identify intent and scope

Determine what the user wants from their message. There are two dimensions:

**Dimension 1 — Scope (what to process):**
- **WAF only**: user mentions WAF, security rules, firewall, rate limiting, IP rules
- **CDN only**: user mentions CDN, cache, origin rules, CloudFront distributions
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
| CDN only (analyze) | cdn-analyzer → cdn-validator | cdn-analyzer → cdn-validator (no deep CDN generator) |
| CDN only (full TF) | N/A | CDN full pipeline (9 stages, see below) |
| Functions only | N/A (no separate analyzer) | cf-functions-converter |
| Everything | WAF analyze → CDN analyze | WAF convert → CDN full pipeline → Functions convert |

**Execution order for "Everything":**
1. WAF pipeline first (analyzer → validator → generator)
2. CDN full pipeline second (all 9 stages)
3. Functions converter last

This order matters because WAF and CDN analysis are independent, but running WAF first avoids context confusion.

### Step 2: Extract config path

Extract the Cloudflare config directory path from the user's message. This is the path to pass to each subagent. Do not read or analyze the files yourself.

If the user requests CDN full pipeline (Terraform generation), also check for:
- `{config_path}/user_input.csv` — if it exists, CDN pipeline can start from Stage 2
- `{config_path}/domain_scope.json` — if it exists, pipeline can start from Stage 3

### Step 3: Invoke subagents

**CRITICAL: Every subagent query MUST start with a skill-loading instruction.** Subagents may not automatically load their skill file when invoked via `use_subagent`. Prefix every query with:

`"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/{subagent-name}/SKILL.md and follow its workflow. "`

Where `{subagent-name}` matches the subagent directory name (e.g., `cf-waf-analyzer`, `cf-cdn-dns-parser`).

---

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

---

#### CDN full pipeline (9 stages — runs when user wants Terraform output for CloudFront):

**Stage 1: DNS Parsing**
1. Invoke `cf-cdn-dns-parser` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-dns-parser/SKILL.md and follow its workflow. Parse the Cloudflare DNS export in {config_path} to identify all proxied domains that need CloudFront distributions. Detect any Cloudflare for SaaS custom hostname configurations. Group domains by apex domain for ACM certificate planning. Write dns_manifest.yaml and user_input_template.csv to {config_path}/cdn/. Generate output files in {user_language}."`
2. Check the response:
   - If `dns_manifest.yaml` and `user_input_template.csv` were written successfully → **pause and tell the user**:
     > "DNS parsing complete. I found N proxied domains. Please fill in `{config_path}/cdn/user_input_template.csv` with the origin URL, cache policy, and routing settings for each domain, then save it as `{config_path}/cdn/user_input.csv`. Let me know when it's ready to proceed."
   - Wait for the user to confirm before continuing.

**Stage 2: Input Validation**
1. Invoke `cf-cdn-input-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-input-validator/SKILL.md and follow its workflow. Validate the operator-filled {config_path}/cdn/user_input.csv against {config_path}/cdn/dns_manifest.yaml. Ensure all required columns are present, origin URLs are valid, cache policy names are recognized, and ACM certificate groupings are consistent. On success, write {config_path}/cdn/domain_scope.json. Report any validation errors with remediation hints. Generate output files in {user_language}."`
2. Check the `---RESULT---` block:
   - `STATUS: PASS` → proceed to Stage 3
   - `STATUS: ERRORS` → show the user the list of errors and ask them to fix `user_input.csv`, then re-invoke Stage 2
   - `STATUS: CANNOT_FIX` → stop and tell the user which fields require manual correction

**Stage 3: Per-Domain Processing** (parallelizable — invoke once per domain)
1. Read `{config_path}/cdn/domain_scope.json` to get the list of domains (or extract from the Stage 2 response).
2. For each domain `{domain}` in the list, invoke `cf-cdn-per-domain-processor` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-per-domain-processor/SKILL.md and follow its workflow. Process the Cloudflare CDN configuration for domain {domain} from the config directory {config_path}. Read domain_scope.json at {config_path}/cdn/domain_scope.json for this domain's settings. Translate all page rules, cache rules, origin rules, redirect rules, response header rules, and transform rules into an intermediate representation (IR) accumulator. Write the output to {config_path}/cdn/ir/accumulator/{domain}.yaml. Generate output files in {user_language}."`
3. If there are many domains (> 5), invoke subagents concurrently where the orchestration environment supports it. Otherwise invoke serially.
4. Wait for all per-domain processors to complete before proceeding.

**Stage 4: IR Chunk Validation** (parallelizable — invoke once per domain)
1. For each domain `{domain}`, invoke `cf-cdn-ir-chunk-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-chunk-validator/SKILL.md and follow its workflow. Validate the IR accumulator for domain {domain} at {config_path}/cdn/ir/accumulator/{domain}.yaml. Check structural correctness, cache behavior path conflicts, origin compatibility, CloudFront Function syntax, and policy reference validity. Output a validation report. If issues are fixable, fix them in-place and mark STATUS: FIXED. If not fixable, mark STATUS: CANNOT_FIX with details. Generate output files in {user_language}."`
2. Collect results. For any domain with `STATUS: CANNOT_FIX`, report the issues to the user and ask whether to skip that domain or pause the entire pipeline.
3. For any domain with `STATUS: FIXED`, note that it was auto-corrected.
4. Once all validations pass (PASS or FIXED), proceed to Stage 5.

**Stage 5: IR Finalization**
1. Invoke `cf-cdn-ir-finalizer` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-finalizer/SKILL.md and follow its workflow. Merge and finalize all validated IR accumulator YAMLs from {config_path}/cdn/ir/accumulator/. Deduplicate shared cache policies, origin request policies, and response headers policies across all domains. Write per-domain final IR files to {config_path}/cdn/ir/final/{domain}.yaml for each domain. Write the shared deduplication manifest to {config_path}/cdn/shared/dedup_manifest.json. Generate a human-readable conversion report at {config_path}/cdn/conversion_report.md summarizing domains processed, rules translated, policies created, feature-parity gaps, and rules requiring manual attention. Generate output files in {user_language}."`
2. Check the `---RESULT---` block:
   - `STATUS: COMPLETE` → proceed to Stage 6
   - `STATUS: ERROR` → report the error to the user and stop

**Stage 6: Final IR Validation** (parallelizable — invoke once per domain)
1. For each domain `{domain}`, invoke `cf-cdn-ir-final-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-ir-final-validator/SKILL.md and follow its workflow. Validate the final IR for domain {domain} at {config_path}/cdn/ir/final/{domain}.yaml. Verify all shared policy references exist in {config_path}/cdn/shared/dedup_manifest.json, cache behavior path patterns are valid CloudFront patterns, ACM certificate ARN placeholders follow the expected format, CloudFront Function code is complete and not just snippets, and no Cloudflare-specific features remain untranslated. Mark the domain as PASS or report issues. Generate output files in {user_language}."`
2. Collect results. Handle `STATUS: CANNOT_FIX` domains the same as Stage 4.
3. Once all validations pass, proceed to Stage 7.

**Stage 7: Shared Terraform Policies**
1. Invoke `cf-cdn-tf-shared-policies` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-shared-policies/SKILL.md and follow its workflow. Read the shared deduplication manifest at {config_path}/cdn/shared/dedup_manifest.json. Generate Terraform resources for all shared CloudFront policies (cache policies, origin request policies, response headers policies, and shared CloudFront Functions). Write the output to {config_path}/cdn/terraform/shared/policies.tf and {config_path}/cdn/terraform/shared/outputs.tf. Use AWS managed policy data sources where applicable. Generate output files in {user_language}."`
2. Check the `---RESULT---` block:
   - `STATUS: COMPLETE` → proceed to Stage 8
   - `STATUS: ERROR` → report the error and stop

**Stage 8: Per-Domain Terraform Generation** (parallelizable — invoke once per domain)
1. For each domain `{domain}`, invoke `cf-cdn-tf-domain` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-tf-domain/SKILL.md and follow its workflow. Generate Terraform configuration for domain {domain} using the final IR at {config_path}/cdn/ir/final/{domain}.yaml and the shared policy manifest at {config_path}/cdn/shared/dedup_manifest.json. Write main.tf, variables.tf, and outputs.tf to {config_path}/cdn/terraform/domains/{domain}/. If this domain has domain-specific CloudFront Functions (not in shared), also write the JS source files to {config_path}/cdn/terraform/domains/{domain}/functions/. Generate output files in {user_language}."`
2. Wait for all domain Terraform generators to complete.

**Stage 9: CloudFront Function JS Validation** (parallelizable — invoke once per domain)
1. For each domain `{domain}` that has a `functions/` directory, invoke `cf-cdn-js-validator` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-cdn-js-validator/SKILL.md and follow its workflow. Validate all CloudFront Function JavaScript files for domain {domain} in {config_path}/cdn/terraform/domains/{domain}/functions/. Check for: correct handler signature, CloudFront Functions runtime API compliance, 10KB compressed size limit, no Node.js built-ins, correct HTTP status codes in redirects, and no syntax errors. Fix any auto-fixable issues in-place. Output a per-domain validation report. Generate output files in {user_language}."`
2. Also validate shared functions in `{config_path}/cdn/terraform/shared/` the same way (invoke once for shared).
3. Collect results. For any domain with unfixable JS issues, report to the user with specific error details.
4. Once all JS is validated, proceed to Step 4 (final reporting).

---

#### CDN analyze-only pipeline (runs when user says "analyze CDN" without wanting Terraform output):

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

---

#### Functions pipeline:

Invoke `cf-functions-converter` with: `"FIRST read your skill file at ~/.kiro/skills/cloudflare-aws-converter/cf-functions-converter/SKILL.md and follow its workflow. Convert Cloudflare transformation rules in {config_path} to CloudFront Functions. Generate output files in {user_language}."`

---

### Step 4: Report results

After all subagents complete, summarize what was done and where output files were generated.

For "Everything" scope, report results for each pipeline separately.

**For the CDN full pipeline**, include a summary table showing:
- Number of domains processed
- Number of CloudFront distributions generated
- Number of shared policies created (cache, origin request, response headers)
- Number of CloudFront Functions generated
- Any domains or rules that could not be automatically converted (link to `conversion_report.md`)
- Path to generated Terraform files

## Important Rules

- **Never read config files yourself** — always delegate to subagents
- **Pass the exact path** the user provided; do not modify or resolve it
- **Serial execution** for pipeline stages within a domain group; **parallel execution** where the same stage runs across multiple domains (Stages 3, 4, 6, 8, 9 of the CDN full pipeline)
- If the user's request is ambiguous about which conversion is needed, infer from context rather than asking
- **When re-invoking the same subagent**, always explicitly state what action to perform and what inputs to use. Never assume the subagent remembers a previous invocation. Each call is a fresh session with no context. A vague re-invoke query (e.g. "run again") may cause the subagent to skip all tool calls and return immediately.
- **CDN full pipeline requires a user pause at Stage 1** — always wait for the user to fill in `user_input.csv` before invoking Stage 2. Do not attempt to auto-fill the CSV.
- **Domain list for parallelizable stages** — always extract the domain list from `domain_scope.json` or the finalized IR directory listing, not from earlier intermediate state that may have changed.
