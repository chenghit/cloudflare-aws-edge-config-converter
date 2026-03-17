---
name: cf-waf-terraform-generator
description: Generates AWS WAF Terraform configuration from a validated IR JSON. Use this skill after cf-waf-analyzer and cf-waf-analyzer-validator have produced and validated waf_ir.json. This skill reads the IR JSON, generates a conversion plan, produces Terraform modules with proper nesting and splitting strategies, and validates the output. It does NOT read original Cloudflare configuration files — it only reads the IR JSON.
metadata:
  author: chenghit
---

# Cloudflare to AWS WAF Terraform Generator

Generate AWS WAF Terraform configuration from a validated IR JSON.

**CRITICAL: When activated, your FIRST action is:**
1. Read ALL reference documents (Step 0 in Workflow)
2. Then follow Workflow steps sequentially

**DO NOT:**
- Read original Cloudflare configuration files
- Re-analyze or re-classify rules
- Skip reading reference documents

**Language Adaptation**: Generate output files in the language specified in the query. Default to English.

## Path Resolution

Reference files in `references/` directory. IR file in `cloudflare-to-aws-waf/` relative to current working directory.

## Output Directory

**All output files will be written to**: `cloudflare-to-aws-waf/` in current working directory.

**File Structure (MUST follow exactly):**
```
cloudflare-to-aws-waf/
├── waf_ir.json                              # INPUT (already exists, do not modify)
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

## How to Read the IR JSON

The IR file (`waf_ir.json`) is your ONLY input. It contains structured data — read JSON fields directly, no parsing needed.

### Top-level structure
```json
{
  "ip_lists": [...],
  "ip_access_rules": { "count": N, "rules": [...] },
  "custom_rules": { "count": N, "skip_labels_present": {...}, "rules": [...] },
  "rate_limiting_rules": { "count": N, "rules": [...] },
  "non_convertible_notes": [...]
}
```

### ip_lists
Each entry has `name`, `kind`, `conversion`, and items:
- `conversion: "ip_set"` → create `aws_wafv2_ip_set` resources (use `items_ipv4` and `items_ipv6`)
- `conversion: "asn_inline"` → use inline ASN list in statements, no IP set resource
- `conversion: "empty"` or `"out_of_scope"` → skip

### ip_access_rules.rules
Each rule has `mode` (action), `target`, `value`, `aws_statement_type`, `split_count`.
- `split_count > 1` → use `ip_sets` array for separate IPv4/IPv6 resources
- These rules are NEVER affected by skip rule labels

### custom_rules.rules
Each rule has `action`, `expression`, `convertibility`, `aws_statement_type`, `split`, `scope_down`.
- `split.required: true` → read `split.branches` for per-branch statement types and IP set names
- `split.total_aws_rules` → number of AWS WAF rules this generates
- `scope_down.skip_all_remaining_custom_rules: true` → wrap in NOT label_match scope-down
- `aws_action` (if present) → use instead of `action` for Terraform action block (`"challenge"` → `challenge {}`, `"captcha"` → `captcha {}`)
- Skip rules have `labels` array → use verbatim for `rule_label` blocks
- Partial rules have `convertible_expression` + `aws_statement_type` → generate statement from these
- `ip_sets` array (if present) → create IP set resources

### custom_rules.skip_labels_present
Tells you which skip labels exist globally:
- `all_remaining_custom_rules: true` → some custom rules need scope-down
- `http_ratelimit: true` → rate-limiting rules need scope-down
- `http_request_firewall_managed: true` → managed rules need scope-down

### rate_limiting_rules.rules
Each rule has `aws_limit`, `aws_evaluation_window_sec`, `mandatory_fallback`, `scope_down`, `aws_statement_type`.
- `scope_down.skip_http_ratelimit: true` → add NOT label_match in scope_down_statement
- Rate-limiting rules are NEVER split
- NEVER use `skip:all_remaining_custom_rules` for rate-limiting rules

### non_convertible_notes
Array of notes for the deployment README. Each has `rule`, `field`, `reason`, `aws_equivalent`, `manual_action`.

## Workflow

### 0. Read All Reference Documents (CRITICAL - Must be first)

1. `references/terraform-architecture.md` - Module structure and IP set sharing pattern
2. `references/nesting-and-splitting.md` - Terraform nesting constraints and De Morgan's Law
3. `references/field-conversions.md` - IP/ASN/field mapping to Terraform statements
4. `references/action-conversions.md` - Action conversions and skip rule implementation
5. `references/aws-managed-rules.md` - AWS managed rules Terraform templates
6. `references/common-mistakes.md` - Common Terraform generation errors (read LAST)

### 1. Read and Validate IR

Read `cloudflare-to-aws-waf/waf_ir.json`.

**If file does not exist:** STOP. Return error: "IR file not found. Run cf-waf-analyzer and validator first."

Extract from the IR:
- All IP set definitions (from `ip_lists` and inline `ip_sets` in rules)
- All rules with their conversion plans
- All skip rule labels (from `custom_rules.rules` where `action == "skip"`)
- All rate-limit calculations
- `skip_labels_present` for scope-down decisions

### 2. Generate Conversion Plan

Process rules in this exact order:
1. IP Access Rules
2. WAF Custom Rules
3. Rate Limiting Rules

For each rule, read the conversion plan directly from IR fields — do NOT re-derive.

**Assign priorities:**
- Priority 0: Anti-DDoS managed rule
- Priority 1+: IP Access Rules (count split rules individually)
- Next: WAF Custom Rules (count split rules individually — use `split.total_aws_rules`)
- Next: Rate Limiting Rules
- Last 4: AWS managed rule groups

**Scope-down from skip labels:**
- **IP Access Rules**: NEVER add skip-label scope-down
- **Skip rules themselves**: NEVER add skip-label scope-down
- **Custom rules** (non-skip): if `scope_down.skip_all_remaining_custom_rules: true` → add `NOT label_match(skip:all_remaining_custom_rules)`
- **Rate-based rules**: if `scope_down.skip_http_ratelimit: true` → add `NOT label_match(skip:http_ratelimit)`. NEVER use `skip:all_remaining_custom_rules`
- **Managed rules**: if `skip_labels_present.http_request_firewall_managed: true` → add `NOT label_match(skip:http_request_firewall_managed)`

Proceed directly to generating Terraform. Do NOT wait for user confirmation.

### 3. Generate Terraform Files

**Pre-written files (DO NOT generate):** `versions.tf`, `modules/waf/variables.tf`, `modules/waf/outputs.tf`

**Step 1: Generate `ip_sets.tf`** (root directory)

Create all IP set resources — shared between both Web ACLs. Collect from THREE sources:
1. `ip_lists` where `conversion == "ip_set"` → create `<name>-ipv4` and `<name>-ipv6` resources
2. `ip_access_rules.rules[].ip_sets` → inline IP sets from mixed IPv4/IPv6 access rules
3. `custom_rules.rules[].ip_sets` → inline IP sets from split custom rules

**Step 2: Generate `modules/waf/main.tf`**

Web ACL resource with rules in priority order. Reference IP sets via `var.ip_set_arns["set_name"]`.

**Nesting rules:**
- Max 3 nesting levels
- No AND-in-AND or OR-in-OR (flatten as siblings)
- De Morgan's Law: `NOT (A OR B)` → `NOT A AND NOT B`

**Skip action implementation:**
- Skip rules → `count` action with `rule_label` blocks (use `labels` array from IR verbatim)
- Subsequent custom rules → wrap in `and_statement { not_statement { label_match }, original_statement }`
- Subsequent rate-based rules → `scope_down_statement { and_statement { not_statement { label_match }, original_conditions } }`
- Subsequent managed rules → `scope_down_statement { not_statement { label_match } }`

**Challenge action conversion:**
- If rule has `aws_action` field → use it: `"challenge"` → `challenge {}`, `"captcha"` → `captcha {}`
- If no `aws_action` field → use `action` directly: `block` → `block {}`, `allow` → `allow {}`, `count` → `count {}`

**All AWS managed rules use `override_action { count {} }` for monitoring.**

**Step 3: Generate root `main.tf`**

Create `locals.ip_set_arns` map and call module twice:
- `waf_website`: challenge enabled, basic Anti-DDoS
- `waf_api_file`: challenge disabled, advanced Anti-DDoS

### 4. Validate Generated Terraform

**File Structure:**
- [ ] `ip_sets.tf` exists with all IP set resources
- [ ] `main.tf` exists with locals and two module calls
- [ ] `modules/waf/main.tf` exists (Web ACL only)
- [ ] Pre-written files untouched

**Self-Check:**
- [ ] IP sets in root, referenced via `var.ip_set_arns` in module
- [ ] Nesting depth ≤ 3
- [ ] No AND-in-AND or OR-in-OR
- [ ] Skip rules have correct labels (from IR `labels` array)
- [ ] Skip rules NOT wrapped in skip-label scope-down
- [ ] IP Access Rules NOT wrapped in skip-label scope-down
- [ ] Rate-based rules NEVER check `skip:all_remaining_custom_rules`
- [ ] Priorities sequential with no gaps
- [ ] Rule order: Anti-DDoS → IP Access → WAF Custom → Rate Limiting → Managed
- [ ] Rate-based rules use `aws_limit` and `aws_evaluation_window_sec` from IR
- [ ] Challenge actions correctly mapped
- [ ] All managed rules use `override_action { count {} }`

### 5. Generate Deployment README

Create `README_aws-waf-terraform-deployment.md` with:
- Prerequisites: Terraform >= 1.8.0, AWS Provider >= 6.2.0
- Deployment: `terraform init && terraform apply`
- CloudFront association instructions
- Two Web ACLs: website (challenge enabled) vs api-and-file (challenge disabled)
- IP sets quota note
- Non-converted rules from `non_convertible_notes` (rule name, field, reason, AWS equivalent, manual action)

### 6. Return Result

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

- `references/terraform-architecture.md`
- `references/nesting-and-splitting.md`
- `references/field-conversions.md`
- `references/action-conversions.md`
- `references/aws-managed-rules.md`
- `references/common-mistakes.md`
