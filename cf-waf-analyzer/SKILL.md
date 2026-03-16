---
name: cf-waf-analyzer
description: Analyzes Cloudflare security configurations (WAF custom rules, rate limiting rules, IP access rules, IP/ASN lists) and generates a structured summary for AWS WAF migration. Use this skill when you need to analyze Cloudflare security rules, understand WAF rule convertibility, or prepare security configuration summary before converting to AWS WAF. This skill reads CloudflareBackup configuration files, parses rule expressions, determines convertibility status, and generates a Markdown summary grouped by rule type. This skill does NOT generate Terraform code - it only analyzes and summarizes Cloudflare security configurations.
---

# Cloudflare WAF Config Analyzer

Analyze Cloudflare security configurations and generate a structured summary for AWS WAF migration planning.

**CRITICAL: When activated, your FIRST action is:**
1. Read the reference documents specified for your batch (Step 0 in Workflow)
2. Then follow Workflow steps sequentially

**DO NOT:**
- Generate Terraform code
- Skip reading reference documents
- Deviate from the Workflow

**Language Adaptation**: Generate output files in the language specified in the query (e.g., "Generate output files in Chinese"). If no language is specified, default to English.

## Path Resolution

Reference files in `references/` directory. User data from path provided by user.

## Output Directory

**All output files will be written to**: `cloudflare-to-aws-waf/` in current working directory.

**File Structure:**
```
cloudflare-to-aws-waf/
└── cloudflare-security-rules-summary.md    # Step 4: Rule summary
```

**CRITICAL**: The output directory `cloudflare-to-aws-waf/` is pre-created by the orchestrator (waf-init.sh). Do NOT create it yourself. All file write operations use this directory as base path.

## Scope

**⚠️ CRITICAL: ALL rate-based rules are ALWAYS convertible.** If marking as "cannot convert" due to limit < 10, you're wrong. Read `references/common-mistakes.md` Mistake 0.

**In Scope:** WAF custom rules, rate limiting rules, IP access rules, IP/ASN lists

**Out of Scope:** Redirect/rewrite rules, header transforms, bulk redirects, page rules, Terraform code generation

## Workflow

### 0. Read Reference Documents (CRITICAL - Must be first)

**Before starting any analysis, read the reference documents specified for your batch.**

The orchestrator invokes this skill in 3 batches. Each batch processes specific rule types and writes specific summary sections. The batch is specified in the invocation query.

**Batch A1 (IP Lists + IP Access Rules):**
- Read: `references/field-conversions.md`, `references/non-convertible-rules.md`
- Process: IP-Lists.txt, List-Items-*.txt, IP-Access-Rules.txt
- Write: Summary Section 1 (IP Lists) + Section 2 (IP Access Rules)
- Use `fs_write` create mode (creates new file)

**Batch A2 (WAF Custom Rules):**
- Read: ALL 5 reference documents
- Process: WAF-Custom-Rules.txt, IP-Lists.txt, List-Items-*.txt
- Write: Summary Section 3 (WAF Custom Rules) + Section 5 (Manual Intervention notes)
- Use `fs_write` append mode (appends to file created by A1)

**Batch A3 (Rate Limiting Rules):**
- Read: `references/action-conversions.md`, `references/common-mistakes.md`, `references/non-convertible-rules.md`
- Process: Rate-limits.txt
- Write: Summary Section 4 (Rate Limiting Rules) + append to Section 5 if any partial/non-convertible rate limiting rules
- Use `fs_write` append mode (appends to file created by A1+A2)

**After reading the required references for your batch, proceed to Step 1.**

1. `references/non-convertible-rules.md` - Which rules cannot be converted and why
2. `references/action-conversions.md` - Rate limiting conversion algorithm (CRITICAL for rate-based rules)
3. `references/field-conversions.md` - IP/ASN/field mapping rules
4. `references/nesting-and-splitting.md` - Rule splitting strategy (to understand which rules will be split)
5. `references/common-mistakes.md` - Common errors to avoid (read this LAST)

**Read only the references listed for your batch above, then proceed to Step 1.**

### 1. Validate Input

**CRITICAL: Configuration path must be provided by main agent in the initial query.**

Extract the config path from the query — look for any absolute path (starting with `/` or `~`) in the query. The path format may vary; extract the directory path regardless of surrounding text.

**If no path found in query:**
- STOP immediately
- Return error: "Configuration directory path is required. Please provide the path to CloudflareBackup output directory."

### 2. Discover and Read Configuration Files

**CRITICAL: Search entire directory tree, don't assume locations.**

**Step 2.1:** Based on your batch, use glob to find the relevant files:
- **Batch A1**: `**/IP-Lists.txt`, `**/List-Items-*.txt`, `**/IP-Access-Rules.txt`
- **Batch A2**: `**/WAF-Custom-Rules.txt`, `**/IP-Lists.txt`, `**/List-Items-*.txt`
- **Batch A3**: `**/Rate-limits.txt`

**Step 2.2:** **MANDATORY VALIDATION - If NO relevant configuration files found for this batch, STOP immediately:**

Return error: "No configuration files found for this batch. Expected: {list files relevant to your batch}. Please provide the correct CloudflareBackup output directory."

**Step 2.3:** If duplicate files found (same filename in multiple locations):
- STOP immediately
- Return error: "Found duplicate configuration files: [list files]. Please remove duplicates and specify which directory to use."

**Step 2.4:** Read all discovered files. For each list in `IP-Lists.txt`, read corresponding `List-Items-ip-<name>.txt` or `List-Items-asn-<name>.txt`.

**Step 2.5:** Missing files = assume no rules of that type. Missing list items = mark rules using that list as "partially convertible".

### 3. Parse Cloudflare Configuration

Parse JSON to Cloudflare rule expressions. Process ALL rules in the file — `managed_challenge` is a valid action to convert (→ AWS WAF `challenge {}`), not a managed ruleset. Cloudflare Managed Rulesets (OWASP etc.) are in a separate phase and not present in WAF-Custom-Rules.txt.

**Non-convertible fields** (require manual intervention): Client Certificate Verified, MIME Type, European Union, bot fields (`cf.verified_bot_category`, `cf.bot_management.*`), fraud fields (`cf.waf.credential_check.*`), attack score fields (`cf.waf.score*`)

**Conversion strategy:**
- Only non-convertible fields: Fully non-convertible
- Convertible OR non-convertible: Partial (convert convertible parts)
- Convertible AND non-convertible: Fully non-convertible (AND requires both conditions)

### 4. Generate Markdown Summary

**CRITICAL: Preserve Rule Order**

Both Cloudflare and AWS WAF execute rules sequentially. **Maintain the exact order from original configuration files** in all sections.

**Batch-specific output:**

- **Batch A1**: Use `fs_write` **create** mode to write the summary file. Include a title heading, then Section 1 (IP Lists) and Section 2 (IP Access Rules).
- **Batch A2**: Use `fs_write` **append** mode. Write Section 3 (WAF Custom Rules) and Section 5 (Manual Intervention notes).
- **Batch A3**: Use `fs_write` **append** mode. Write Section 4 (Rate Limiting Rules). If any rate limiting rules are partial or non-convertible, also append their notes to Section 5.

**For skip action rules:** Extract and document the COMPLETE `action_parameters` JSON from Cloudflare configuration:
- Copy the entire `action_parameters` object verbatim in a code block
- Explicitly list which `phases` array values are present
- Note if `ruleset: "current"` is present
- **CRITICAL**: Only document phases that actually exist in the configuration - do NOT assume or add phases
- Explicitly state which phases are NOT being skipped to prevent errors
- This information is critical for correct AWS WAF RuleLabels generation by the downstream Terraform generator

**Example format for skip rule documentation:**

```markdown
### Rule: `skip-example`
- **Action**: `skip`
- **Expression**: `(ip.src.country eq "US")`
- **Action Parameters** (complete):
  ```json
  {
    "phases": ["http_request_firewall_managed"],
    "ruleset": "current"
  }
  ```
- **Phases Being Skipped**: `http_request_firewall_managed` ONLY (does NOT skip `http_ratelimit`)
- **Convertible**: ✓ Yes
  - Will be converted to COUNT action with RuleLabels:
    - `skip:http_request_firewall_managed` (because `"http_request_firewall_managed"` is in phases)
    - `skip:all_remaining_custom_rules` (because `"ruleset": "current"` is present)
  - **Note**: Does NOT add `skip:http_ratelimit` RuleLabel because `"http_ratelimit"` is NOT in phases
```

Output a Markdown file with five sections:

1. **IP Lists and their items**
2. **IP Access Rules** - Zone-level IP access rules (execute before WAF custom rules in Cloudflare)
3. **WAF Custom Rules** - Preserve array order from `WAF-Custom-Rules.txt`
4. **Rate limiting rules** - Preserve array order from `Rate-limits.txt`
   - **CRITICAL: For each rate-limiting rule, you MUST calculate the AWS WAF Limit and EvaluationWindowSec using this exact algorithm:**
     1. For EACH window in [60, 120, 300, 600] seconds, calculate: `limit = requests_per_period × (window / period)`
     2. Use the FIRST window where limit ≥ 10
     3. If ALL four windows produce limit < 10: use mandatory fallback `Limit=10, EvaluationWindowSec=600`
     4. **Show the calculation for ALL four windows in the summary** so the validator can verify
   - Example: 1 req/10s → 60s: 6 < 10 ❌, 120s: 12 ≥ 10 ✓ → `Limit=12, EvaluationWindowSec=120`
   - **AWS WAF minimum Limit is 10. NEVER output a Limit below 10.**
5. **Notes on Rules Requiring Manual Intervention** - For rules that cannot be automatically converted or are partially convertible, use the information from non-convertible-rules.md to provide detailed explanations. Clearly state: **"These rules require manual intervention because AWS WAF implements these features differently from Cloudflare, requiring manual configuration of managed rule groups. This is NOT because AWS WAF lacks these capabilities."**

**CRITICAL**: IP Access Rules must be in a separate section before WAF Custom Rules because they execute earlier in Cloudflare's request processing pipeline and should NOT be affected by skip rules from WAF Custom Rules.

**For each rule, mark convertibility status:**

- **✓ Yes** - Fully convertible
- **⚠️ Partial** - Partially convertible (some conditions can be converted, others require manual intervention)
  - Document which parts are convertible and which require manual intervention
  - Example: Rate limit rule with `(path match) OR (bot field)` → Convert path match, document bot field in Section 5
- **❌ No** - Not convertible (entire rule requires manual intervention)

For each non-convertible or partially convertible rule found, explain:
- What Cloudflare feature it uses
- What AWS WAF equivalent exists
- Why automatic conversion is not feasible (or only partial)
- What manual configuration is needed

Save the summary as `cloudflare-security-rules-summary.md` to avoid conflicts with other Cloudflare conversion skills.

### Return Result

After the summary sections for this batch are written, end your response with this exact block:

```
---RESULT---
STATUS: COMPLETE
BATCH: <A1|A2|A3>
OUTPUT_FILES:
  - cloudflare-to-aws-waf/cloudflare-security-rules-summary.md
---END---
```
