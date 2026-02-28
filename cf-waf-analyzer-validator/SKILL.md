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

**Conversion strategy:**
- Only non-convertible fields → must be marked ❌ No
- Convertible OR non-convertible → must be marked ⚠️ Partial
- Convertible AND non-convertible → must be marked ❌ No (AND requires both conditions)

**CRITICAL for rate-based rules:** ALL rate-based rules are ALWAYS convertible (at minimum ⚠️ Partial if they have non-convertible conditions, ✓ Yes otherwise). If any rate-based rule is marked ❌ No due to low calculated limit, that is an error — see `references/common-mistakes.md` Mistake 0.

**Pass condition:** Each sampled rule has the correct convertibility status.

**Fail:** Record the rule, its current status, and what it should be.

---

#### Check 4: Rule Order

Verify that rules within each section maintain the exact order from the original configuration files:
- IP Access Rules section: same order as IP-Access-Rules.txt
- WAF Custom Rules section: same array order as WAF-Custom-Rules.txt
- Rate Limiting Rules section: same array order as Rate-limits.txt

Also verify section order: IP Access Rules → WAF Custom Rules → Rate Limiting Rules.

**Pass condition:** Rules are in correct order within each section, and sections are in correct order.

**Fail:** Record which section has incorrect ordering.

---

#### Check 5: Skip Rule Action Parameters

For each skip action rule in the summary, verify:
1. The `action_parameters` JSON is complete and matches the original configuration verbatim
2. The `phases` array values are correctly listed
3. The "Phases Being Skipped" description is accurate (only lists phases actually in the array)
4. If `"ruleset": "current"` is present, it is noted
5. The RuleLabels description is consistent with the phases

**Pass condition:** All skip rules have complete and accurate action_parameters documentation.

**Fail:** Record which skip rules have incomplete or incorrect documentation.

---

### 3. Determine Status

- **PASS**: All checks passed. No changes needed.
- **FIXED**: One or more checks failed. Fix the issues directly in `cloudflare-security-rules-summary.md`, then set status to FIXED.
- **CANNOT_FIX**: Issues found that cannot be resolved by editing the summary (e.g., original config files are ambiguous). List these issues for user review.

### 4. Fix Issues (if FIXED)

For each issue found:

- **Missing or extra rules**: Add missing rules or remove extra entries. Place each rule in the correct section.
- **Missing IP list or items**: Add the list and its items to the IP Lists section.
- **Wrong convertibility status**: Update the status and explanation.
- **Wrong rule order**: Reorder entries within the section.
- **Incomplete skip rule documentation**: Complete the action_parameters, phases, and RuleLabels documentation from the original config.

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
