---
name: cf-waf-terraform-generator
description: Generates AWS WAF Terraform configuration from a validated security rules summary. Use this skill after cf-waf-analyzer and cf-waf-analyzer-validator have produced and validated cloudflare-security-rules-summary.md. This skill reads the summary, generates a conversion plan, produces Terraform modules with proper nesting and splitting strategies, and validates the output. It does NOT read original Cloudflare configuration files — it only reads the summary.
---

# Cloudflare to AWS WAF Terraform Generator

Generate AWS WAF Terraform configuration from a validated security rules summary.

**CRITICAL: When activated, your FIRST action is:**
1. Read ALL reference documents (Step 0 in Workflow)
2. Then follow Workflow steps sequentially

**DO NOT:**
- Read original Cloudflare configuration files
- Re-analyze or re-classify rules
- Skip reading reference documents
- Deviate from the Workflow

**Language Adaptation**: Generate output files in the language specified in the query (e.g., "Generate output files in Chinese"). If no language is specified, default to English.

## Path Resolution

Reference files in `references/` directory. Summary file in `cloudflare-to-aws-waf/` relative to current working directory.

## Output Directory

**All output files will be written to**: `cloudflare-to-aws-waf/` in current working directory.

**⚠️ CRITICAL: Output path is `cloudflare-to-aws-waf/`, NOT any other directory. Do NOT create `aws-waf-terraform/` or any other custom directory name.**

**File Structure (MUST follow exactly):**
```
cloudflare-to-aws-waf/
├── cloudflare-security-rules-summary.md    # INPUT (already exists, do not modify)
├── versions.tf                              # PRE-WRITTEN by waf-init.sh (do not modify)
├── ip_sets.tf                               # Root: shared IP sets (YOU generate this)
├── main.tf                                  # Root: locals + two module calls (YOU generate this)
├── modules/
│   └── waf/
│       ├── main.tf                          # Module: Web ACL resource (YOU generate this)
│       ├── variables.tf                     # PRE-WRITTEN by waf-init.sh (do not modify)
│       └── outputs.tf                       # PRE-WRITTEN by waf-init.sh (do not modify)
└── README_aws-waf-terraform-deployment.md   # Deployment guide (YOU generate this)
```

**⚠️ CRITICAL: You MUST create the `modules/waf/` subdirectory and place module files there. The root `main.tf` calls the module twice (website + api-and-file). Do NOT put all files flat in one directory.**

## How to Read the Summary File

The summary file (`cloudflare-security-rules-summary.md`) is your ONLY input. It contains all information needed to generate Terraform. Here is how to extract what you need:

### Section 1: IP Lists and Their Items
- Each list has a name, kind (ip or asn), and items table
- **"AWS WAF conversion"** line tells you what to create:
  - "Create two IP sets — `name-ipv4` and `name-ipv6`" → create `aws_wafv2_ip_set` resources
  - "Use `asn_match_statement`" → use inline ASN list, no IP set resource needed
  - "Empty list" → skip
  - "Out of scope — redirect lists" → skip

### Section 2: IP Access Rules
- Each rule has: Mode (action), Target (condition), Convertible status, and conversion notes
- These rules are NEVER affected by skip rule labels (they execute before skip rules)

### Section 3: WAF Custom Rules
- Each rule has: Action, Expression, Convertible status, and conversion plan
- **"Splitting required"** block tells you exactly how to split:
  - Phase 1 branches, Phase 2 IPv4/IPv6 variants, final rule count
  - Each branch's planned AWS WAF statement
- **"IP Sets to create"** block lists inline IP sets with names and addresses
- **Skip rules** have: Action Parameters JSON, Phases Being Skipped, RuleLabels list
  - Use the RuleLabels list verbatim — do not re-derive from action_parameters

### Section 4: Rate Limiting Rules
- Each rule has: Expression, Rate limit config, Convertible status, AWS WAF calculation
- **"Mandatory fallback applied"** or **"AWS configuration"** tells you the Limit and EvaluationWindowSec
- **"Scope-down statement"** tells you which conditions to include (convertible only)
- Rate-limiting rules are NEVER split

### Section 5: Notes on Rules Requiring Manual Intervention
- Lists non-convertible rules with explanations
- Referenced when generating the deployment README (Step 5) — not used for Terraform generation

## Workflow

### 0. Read All Reference Documents (CRITICAL - Must be first)

1. `references/terraform-architecture.md` - Module structure and IP set sharing pattern
2. `references/nesting-and-splitting.md` - Terraform nesting constraints and De Morgan's Law
3. `references/field-conversions.md` - IP/ASN/field mapping to Terraform statements
4. `references/action-conversions.md` - Action conversions and skip rule implementation
5. `references/aws-managed-rules.md` - AWS managed rules Terraform templates
6. `references/common-mistakes.md` - Common Terraform generation errors (read LAST)

**After reading all 6 references, proceed to Step 1.**

### 1. Read and Validate Summary

Read `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md`.

**If file does not exist:** STOP. Return error: "Summary file not found. Run cf-waf-analyzer and cf-waf-analyzer-validator first."

Extract from the summary:
- All IP set definitions (from Section 1 and inline IP sets in Section 3)
- All rules with their conversion plans
- All skip rule RuleLabels
- All rate-limit calculations

### 2. Generate Conversion Plan

**CRITICAL**: Process rules in this exact order to match Cloudflare execution sequence:
1. IP Access Rules (if any)
2. WAF Custom Rules
3. Rate Limiting Rules

For each rule, extract the conversion plan directly from the summary — do NOT re-derive it. The summary already contains:
- Split strategy and final rule count
- AWS WAF statement types
- IP set names and contents
- RuleLabels
- Scope-down statement content

**Assign priorities:**
- Priority 0: Anti-DDoS managed rule
- Priority 1+: IP Access Rules (count split rules individually)
- Next: WAF Custom Rules (count split rules individually)
- Next: Rate Limiting Rules
- Last 4: AWS managed rule groups

**CRITICAL**: When counting priorities, each split variant is a separate rule with its own priority. Example: a rule that splits into 5 variants occupies priorities N through N+4.

**Determine scope-down from skip rule labels:**

Read each skip rule's RuleLabels from the summary. For rules positioned AFTER skip rules, add label-based scope-down ONLY if the corresponding label exists:

- **IP Access Rules**: NEVER add skip-label scope-down (they execute before skip rules in Cloudflare)
- **Skip rules themselves**: NEVER add skip-label scope-down (skip rules are not affected by other skip rules — they always evaluate their own match conditions independently)
- **Custom rules (non-skip, non-rate-based)**: Add `NOT label_match(skip:all_remaining_custom_rules)` if that label exists
- **Rate-based rules**: Add `NOT label_match(skip:http_ratelimit)` if that label exists. NEVER use `skip:all_remaining_custom_rules` (Cloudflare rate-limiting is a separate phase)
- **Managed rules**: Add `NOT label_match(skip:http_request_firewall_managed)` if that label exists

Present the plan as a summary in your response, then proceed directly to generating Terraform. Do NOT wait for user confirmation — this skill runs as a subagent with no interactive access to the user.

### 3. Generate Terraform Files

**Pre-written files (DO NOT generate — already created by waf-init.sh):**
- `versions.tf`
- `modules/waf/variables.tf`
- `modules/waf/outputs.tf`

**Step 1: Generate `ip_sets.tf`** (root directory)

Create all IP set resources here — shared between both Web ACLs. Include:
- Named IP lists from Section 1 (split into IPv4/IPv6)
- Inline IP sets from Section 3 splitting annotations

**Step 2: Generate `modules/waf/main.tf`**

Web ACL resource with rules in priority order. Reference IP sets via `var.ip_set_arns["set_name"]`.

**Nesting rules:**
- Max 3 nesting levels
- No AND-in-AND or OR-in-OR (flatten as siblings)
- De Morgan's Law: `NOT (A OR B)` → `NOT A AND NOT B` (siblings in one `and_statement`)

**Skip action implementation:**
- Skip rules → `count` action with `rule_label` blocks. The rule's own match condition is its normal statement (NOT wrapped in any skip-label scope-down).
- Subsequent custom rules → wrap in `and_statement { not_statement { label_match(skip:all_remaining_custom_rules) }, original_statement }`
- Subsequent rate-based rules → `scope_down_statement { and_statement { not_statement { label_match(skip:http_ratelimit) }, original_conditions } }`
- Subsequent managed rules → `scope_down_statement { not_statement { label_match(skip:http_request_firewall_managed) } }`

**Challenge action conversion:**
- `interactive_challenge` → `captcha {}`
- `js_challenge`, `managed_challenge` → `challenge {}`

**All AWS managed rules use `override_action { count {} }` for monitoring.**

See `references/aws-managed-rules.md` for complete templates.

**Step 3: Generate root `main.tf`**

Create `locals.ip_set_arns` map and call module twice:
- `waf_website`: challenge enabled, basic Anti-DDoS
- `waf_api_file`: challenge disabled, advanced Anti-DDoS

### 4. Validate Generated Terraform

**File Structure Verification:**
- [ ] `ip_sets.tf` exists with all IP set resources
- [ ] `main.tf` exists with locals and two module calls
- [ ] `modules/waf/main.tf` exists (Web ACL only, no IP sets)
- [ ] Pre-written files untouched: `versions.tf`, `modules/waf/variables.tf`, `modules/waf/outputs.tf`

**Self-Check Checklist:**
- [ ] IP sets in root `ip_sets.tf`, referenced via `var.ip_set_arns` in module
- [ ] Nesting depth ≤ 3 for all rules
- [ ] No AND-in-AND or OR-in-OR
- [ ] Geo rules use `geo_match_statement`
- [ ] ASN rules use `asn_match_statement` with inline list
- [ ] Skip rules have correct RuleLabels (matching summary verbatim)
- [ ] Skip rules are NOT wrapped in skip-label scope-down (they evaluate their own conditions independently)
- [ ] IP Access Rules are NOT wrapped in skip-label scope-down
- [ ] Rate-based rules NEVER check `skip:all_remaining_custom_rules`
- [ ] Priorities sequential with no gaps (counting all split variants)
- [ ] Rule order: Anti-DDoS → IP Access → WAF Custom → Rate Limiting → Managed
- [ ] Rate-based rules use Limit and EvaluationWindowSec from summary
- [ ] Challenge actions correctly mapped
- [ ] All managed rules use `override_action { count {} }`

### 5. Generate Deployment README

Create `README_aws-waf-terraform-deployment.md` with:
- Prerequisites: Terraform >= 1.8.0, AWS Provider >= 6.2.0
- Deployment: `terraform init && terraform apply`
- CloudFront association instructions
- Two Web ACLs: website (challenge enabled) vs api-and-file (challenge disabled)
- IP sets quota note
- Non-converted rules from summary Section 5 (rule name, Cloudflare feature, AWS equivalent, why manual)

### 6. Return Result

After all files are generated, end your response with this exact block:

```
---RESULT---
STATUS: COMPLETE
OUTPUT_FILES:
  - cloudflare-to-aws-waf/ip_sets.tf
  - cloudflare-to-aws-waf/main.tf
  - cloudflare-to-aws-waf/modules/waf/main.tf
  - cloudflare-to-aws-waf/README_aws-waf-terraform-deployment.md
---END---
```

## Reference

- `references/terraform-architecture.md` - Module architecture and IP set sharing
- `references/nesting-and-splitting.md` - Nesting constraints and cascading split strategy
- `references/field-conversions.md` - Field mapping and conversion rules
- `references/action-conversions.md` - Action conversions and rate limiting
- `references/aws-managed-rules.md` - Managed rules templates and ordering
- `references/common-mistakes.md` - Common Terraform generation errors
