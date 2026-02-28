---
name: cf-waf-analyzer-validator
description: Validates the output of cf-waf-analyzer by cross-checking cloudflare-security-rules-summary.md against the original Cloudflare configuration files. Use this skill after cf-waf-analyzer has generated its summary. Fixes errors directly in the summary file. Triggers on requests like "validate WAF analysis" or "validate WAF analyzer output".
---

# Cloudflare WAF Analyzer Validator

Validate `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md` by cross-checking it against the original Cloudflare configuration files. Fix errors directly in the summary. Do NOT re-run the full analysis workflow.

**Language Adaptation**: Write output files in the language specified in the query (e.g., "Generate output files in Chinese"). If no language is specified, default to English.

## Input

- `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md` — the file to validate and fix
- Cloudflare configuration directory path (provided in the invocation prompt)
- Validation round number (provided in the invocation prompt)

## Output Directory

All output files written to `cloudflare-to-aws-waf/`.

```
cloudflare-to-aws-waf/
├── cloudflare-security-rules-summary.md   # Modified in-place if issues found
└── validator-report.md                    # Validation report (overwrite each round)
```

## Workflow

### 0. Read All Reference Documents (CRITICAL - Must be first)

**Before starting any validation, you MUST read ALL reference documents:**

1. `references/non-convertible-rules.md` - Which rules cannot be converted and why
2. `references/action-conversions.md` - Rate limiting conversion algorithm (CRITICAL for rate-based rules)
3. `references/field-conversions.md` - IP/ASN/field mapping rules
4. `references/nesting-and-splitting.md` - Rule splitting strategy
5. `references/common-mistakes.md` - Common errors to avoid (read this LAST)

**After reading all 5 references, proceed to Step 1.**

### 1. Read Inputs

**CRITICAL: The Cloudflare configuration directory path must be provided in the invocation prompt.**

Extract the config path from the prompt — look for any absolute path (starting with `/` or `~`). The path format may vary; extract the directory path regardless of surrounding text.

1. Read `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md`
2. Use glob to find all original Cloudflare configuration files under the provided config path:
   - `**/IP-Lists.txt`, `**/List-Items-*.txt`, `**/IP-Access-Rules.txt`, `**/WAF-Custom-Rules.txt`, `**/Rate-limits.txt`
3. Read all found configuration files
4. Note the validation round number from the prompt (default: 1 if not specified)

**If config path not provided in prompt:** Stop immediately. Return error: "Cloudflare configuration directory path is required."

**If `cloudflare-security-rules-summary.md` does not exist:** Stop immediately. Return error: "cloudflare-security-rules-summary.md not found in cloudflare-to-aws-waf/. Run cf-waf-analyzer first."

**If no original configuration files found:** Stop immediately. Return error: "Original Cloudflare configuration files not found."

### 2. Run Validation Checks

Run all checks below. Collect all issues before fixing anything.

---

#### Check 1: Rule Coverage (No Missing or Extra Rules)

For each rule type file (WAF-Custom-Rules.txt, Rate-limits.txt, IP-Access-Rules.txt), go through every rule in the original file and verify it appears in the summary.

**Excluded from this check:**
- Managed rules and DDoS protection rules in the original files (these are out of scope)
- IP Lists (verified separately in Check 2)

For each rule in the original file:
1. Find the corresponding entry in the summary by matching the rule's name or expression
2. Verify the rule is in the correct section (IP Access Rules / WAF Custom Rules / Rate Limiting Rules)

Then check the reverse: for each rule in the summary, verify it corresponds to a rule in the original file.

**Pass condition:** Every in-scope original rule has a corresponding summary entry; every summary entry corresponds to an original rule.

**Fail:** Record which rules are missing from the summary, or which summary entries have no corresponding original rule.

---

#### Check 2: IP Lists and List Items

For each list in `IP-Lists.txt`, verify:
1. The list appears in the summary's "IP Lists and their items" section
2. The corresponding `List-Items-ip-<name>.txt` or `List-Items-asn-<name>.txt` items are correctly listed

**Pass condition:** All lists and their items are present and correct.

**Fail:** Record missing lists or incorrect items.

---

#### Check 3: Convertibility Classification Spot-Check

For each rule type, sample up to 5 rules (or all rules if fewer than 5). For each sampled rule, verify the convertibility status:

**Non-convertible fields** (require manual intervention): Client Certificate Verified, MIME Type, European Union, bot fields (`cf.verified_bot_category`, `cf.bot_management.*`), fraud fields (`cf.waf.credential_check.*`), attack score fields (`cf.waf.score*`)

**Conversion strategy — apply in this exact order (specific before general):**
1. **Rate-based rules are ALWAYS convertible** — at minimum ⚠️ Partial. If any rate-based rule is marked ❌ No due to low calculated limit, that is an error. See `references/common-mistakes.md` Mistake 0.
2. **Convertible OR non-convertible** → must be marked ⚠️ Partial (convert the convertible parts, document the rest). This is the most commonly missed case — if a rule has ANY convertible condition joined by OR, it is Partial, NOT ❌ No.
3. **Convertible AND non-convertible** → must be marked ❌ No (AND requires both conditions to match)
4. **Only non-convertible fields** → must be marked ❌ No

**Pass condition:** Each sampled rule has the correct convertibility status.

**Fail:** Record the rule, its current status, and what it should be.

---

#### Check 4: Rule Order and Skip Rule Positioning

**Part A — Section order:**
Verify the summary sections appear in Cloudflare execution order:
1. IP Access Rules (execute first)
2. WAF Custom Rules (execute second)
3. Rate Limiting Rules (execute last)

**Part B — Intra-section order:**
Within each section, verify rules maintain the exact array order from the original configuration files.

**Part C — Skip rule positioning and downstream impact (CRITICAL):**
Skip rules only affect rules that execute **after** them. Verify:

1. For each skip rule in the WAF Custom Rules section, identify its position (e.g., Rule 2 of 5)
2. Verify the summary correctly identifies which subsequent rules are affected:
   - `skip:all_remaining_custom_rules` → affects WAF Custom Rules **after** this skip rule only (not before, not IP Access Rules, not rate-limit rules)
   - `skip:http_ratelimit` → affects ALL rate-limiting rules (they always execute after all custom rules)
   - `skip:http_request_firewall_managed` → affects ALL managed rules (they always execute after all custom rules)
3. If there are multiple skip rules, verify the summary accounts for the cumulative effect:
   - A custom rule positioned after TWO skip rules with `skip:all_remaining_custom_rules` needs scope-down for BOTH labels
   - But in practice, since both labels have the same key (`skip:all_remaining_custom_rules`), one scope-down check suffices — verify the summary does not incorrectly suggest multiple scope-down checks for the same label

**Pass condition:** Sections are in correct order, rules within sections are in correct order, and skip rule positioning correctly determines downstream impact.

**Fail:** Record ordering errors and any incorrect skip rule impact descriptions.

---

#### Check 5: Skip Rule Action Parameters and Scope-Down Implications

For each skip action rule in the summary, verify:

**Part A — Action Parameters Accuracy:**
1. The `action_parameters` JSON is complete and matches the original configuration verbatim
2. The `phases` array values are correctly listed
3. If `"ruleset": "current"` is present, it is noted

**Part B — RuleLabels Correctness (CRITICAL — most error-prone area):**

For each skip rule, verify the RuleLabels description follows these exact rules:
- `phases` contains `"http_ratelimit"` → must list `skip:http_ratelimit` label
- `phases` contains `"http_request_firewall_managed"` → must list `skip:http_request_firewall_managed` label
- `"ruleset": "current"` exists → must list `skip:all_remaining_custom_rules` label
- **No extra labels**: If a phase is NOT in the `phases` array, the corresponding label must NOT be listed

**Part C — Scope-Down Impact Description (prevents downstream generator errors):**

Verify the summary accurately describes which downstream rules are affected:
1. If skip rule has `skip:all_remaining_custom_rules` but NOT `skip:http_ratelimit`:
   - Summary must explicitly state "Does NOT skip rate-limiting rules" (or equivalent)
   - If summary says or implies rate-limiting rules will be skipped, that is an error
2. If skip rule has `skip:http_ratelimit` but NOT `skip:all_remaining_custom_rules`:
   - Summary must explicitly state "Does NOT skip remaining custom rules" (or equivalent)
3. If skip rule has `skip:http_request_firewall_managed`:
   - Summary must explicitly state this only affects managed rules
4. Skip rules themselves are NEVER affected by other skip rules — if summary implies otherwise, that is an error

**Pass condition:** All skip rules have complete action_parameters, correct RuleLabels, and accurate scope-down impact descriptions.

**Fail:** Record which skip rules have errors and what specifically is wrong.

---

#### Check 6: Splitting Annotations and Conversion Plan

For each WAF Custom Rule and IP Access Rule in the summary, verify the splitting strategy AND conversion plan:

**Part A — Top-level OR splitting (Phase 1):**
- If the rule expression has top-level OR branches (e.g., `(A) or (B)`), the summary must note that this rule will be split into separate AWS WAF rules (one per OR branch)
- Verify the branch count matches the actual number of top-level OR branches in the expression

**Part B — IPv4/IPv6 splitting (Phase 2):**
- For each branch from Phase 1, check if it references an IP list or inline IPs with both IPv4 and IPv6 addresses
- Check the actual IP list contents (from `List-Items-ip-<name>.txt`) to determine if mixed
- If mixed, the summary must note IPv4/IPv6 split for that branch
- Branches that only use ASN, geo, user-agent, or other non-IP fields must NOT be split by IPv4/IPv6

**Part C — Cascading split count:**
- Verify the final rule count = sum of (branches that need IPv4/IPv6 split × 2) + (branches that don't need split × 1)
- Example: 3 OR branches, 2 with mixed IP, 1 with ASN only → 2×2 + 1 = 5 rules

**Part D — Inline IP Set definitions:**
- For each branch that uses inline IPs (not named IP lists), verify:
  1. Separate IP sets are defined for each branch (NEVER combined across branches)
  2. IPv4 and IPv6 addresses are correctly separated
  3. IP set names follow the pattern `<rule-name>-branch-<N>-<context>-ipv4/ipv6`
  4. All IP addresses from the original expression are present (none missing, none extra)

**Part E — AWS WAF statement type:**
- For each rule/branch, verify the planned AWS WAF statement type is correct:
  - `ip.src in $list` or inline IPs → `ip_set_reference_statement`
  - `ip.src.asnum in $list` or inline ASNs → `asn_match_statement`
  - `ip.src.country eq "XX"` → `geo_match_statement`
  - `http.user_agent` → `byte_match_statement` on `single_header { name = "user-agent" }`
  - `http.request.uri.path` → `byte_match_statement` on `uri_path`
  - `not` conditions → `not_statement` wrapping the inner statement

**Rate-limiting rules are excluded from Parts A-D** — they are NEVER split (splitting causes independent rate tracking).

**Pass condition:** All splitting annotations, IP set definitions, and statement types are correct.

**Fail:** Record which rules have errors and what specifically is wrong.

---

#### Check 7: Rate-Limit Calculation Verification

For each rate-limiting rule in the summary, verify:

1. **Evaluation window selection**: Re-calculate using the algorithm from `references/action-conversions.md`:
   - For each window in [60, 120, 300, 600]s: `limit = requests_per_period × (window / period)`
   - Use the first window where limit ≥ 10
   - If all windows produce limit < 10: must use fallback `Limit=10, EvaluationWindowSec=600`
2. **Verify the summary shows the correct Limit and EvaluationWindowSec values**
3. **If fallback was applied**: Verify the summary includes the fallback note

**Pass condition:** All rate-limit calculations are correct.

**Fail:** Record which rules have incorrect calculations and what the correct values should be.

---

#### Check 8: Scope-Down Statement Content (Partial Rules)

For each rule marked ⚠️ Partial in the summary, verify:

1. **Convertible conditions only**: The planned scope-down statement (or main statement for non-rate-based rules) includes ONLY the convertible conditions, not the non-convertible ones
2. **Non-convertible conditions excluded**: The non-convertible conditions (bot fields, fraud fields, attack score, etc.) are NOT included in the planned AWS WAF statement
3. **Non-convertible conditions documented**: The non-convertible conditions are listed in Section 5 with manual intervention guidance
4. **OR logic preserved**: If the original rule has `(convertible_A) or (convertible_B) or (non_convertible_C)`, the planned statement should include `convertible_A OR convertible_B` only

**Pass condition:** All partial rules correctly separate convertible and non-convertible conditions.

**Fail:** Record which rules have incorrect scope-down content.

---

#### Check 9: Skip Rule Scope-Down Impact on Rule Types

Verify the summary correctly describes which rule types are affected by each skip rule:

1. **IP Access Rules**: Must NEVER be affected by any skip rule (they execute before skip rules in Cloudflare). If the summary implies IP Access Rules have scope-down statements, that is an error.
2. **Rate-limiting rules**: Must ONLY be affected by `skip:http_ratelimit` label. Must NEVER be affected by `skip:all_remaining_custom_rules` (Cloudflare architectural difference — rate-limiting is a separate phase).
3. **Custom rules (non-skip, non-rate-based)**: Must ONLY be affected by `skip:all_remaining_custom_rules` label.
4. **Managed rules**: Must ONLY be affected by `skip:http_request_firewall_managed` label.
5. **Skip rules themselves**: Must NEVER have scope-down statements or be affected by other skip rules.

**Pass condition:** The summary's skip rule descriptions are consistent with these scope-down rules.

**Fail:** Record which rules have incorrect scope-down impact descriptions.

---

### 3. Determine Status

- **PASS**: All checks passed. No changes needed.
- **FIXED**: One or more checks failed. Fix the issues directly in `cloudflare-security-rules-summary.md`, then set status to FIXED.
- **CANNOT_FIX**: Issues found that cannot be resolved by editing the summary (e.g., original config files are ambiguous). List these issues for user review.

### 4. Fix Issues (if FIXED)

For each issue found:

- **Missing or extra rules**: Add missing rules or remove extra entries. Place each rule in the correct section.
- **Missing IP list or items**: Add the list and its items to the IP Lists section.
- **Wrong convertibility status**: Update the status and explanation. Pay special attention to rules with OR logic that should be ⚠️ Partial instead of ❌ No.
- **Wrong rule order**: Reorder entries within the section.
- **Incomplete or incorrect skip rule documentation**: Complete the action_parameters, phases, RuleLabels, and scope-down impact descriptions from the original config. Ensure no extra labels are listed and impact descriptions are accurate.
- **Missing or incorrect splitting annotations**: Add or correct the split strategy, branch count, cascading split count, and inline IP set definitions.
- **Wrong AWS WAF statement type**: Correct the planned statement type for the rule/branch.
- **Incorrect rate-limit calculation**: Correct the Limit and EvaluationWindowSec values. Add fallback note if needed.
- **Incorrect scope-down content for partial rules**: Remove non-convertible conditions from the planned statement. Ensure non-convertible conditions are documented in Section 5.
- **Incorrect skip rule scope-down impact**: Correct which rule types are affected. Ensure IP Access Rules have no scope-down, rate-limit rules only check `skip:http_ratelimit`, etc.

After all fixes, re-read the modified summary and verify the fixed checks pass before writing the report.

### 5. Write Validator Report

Write `cloudflare-to-aws-waf/validator-report.md` (overwrite if exists):

```markdown
# Validator Report
Validation Round: {N}
Status: PASS | FIXED | CANNOT_FIX

## Current Issues
{Empty if PASS. List unresolved issues if CANNOT_FIX.}

## Changes Made This Round
{Empty if PASS. List each fix applied if FIXED.}

## Cannot Fix (Requires User Action)
{Empty unless CANNOT_FIX.}

## Changelog
{Append one line per round, newest first}
- Round {N}: {PASS | FIXED (X issues) | CANNOT_FIX (X issues)} — {one-sentence summary}
```

**CRITICAL**: Preserve the existing Changelog section from the previous report when overwriting. Read the old report first, extract the Changelog, append the new entry, then write the new report.

### 6. Return Result

End your response with this exact block:

```
---RESULT---
STATUS: PASS | FIXED | CANNOT_FIX
OUTPUT_FILES:
  - cloudflare-to-aws-waf/validator-report.md
NEXT_ACTION: Proceed to Terraform generation | Run validator again | Request user input
ISSUES_COUNT: {number of issues found, 0 if PASS}
---END---
```
