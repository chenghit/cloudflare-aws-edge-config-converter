---
name: cf-waf-analyzer-validator
description: Validates WAF analysis summary against original Cloudflare configuration files, fixes errors in-place. Operates in batch mode — each invocation validates a specific rule type or chunk. Use after cf-waf-analyzer has generated its summary and cf-waf-summary-scanner has produced rule_index.yaml.
---

# Cloudflare WAF Analyzer Validator

Validate `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md` by cross-checking it against the original Cloudflare configuration files. Fix errors directly in the summary. Do NOT re-run the full analysis workflow.

**Language Adaptation**: Write output files in the language specified in the query. Default to English.

## Validation Modes

The orchestrator invokes this skill in one of 4 modes, specified in the query:

| Mode | What it validates | Input config files | Checks |
|------|------------------|--------------------|--------|
| **V1** | IP Access Rules | IP-Access-Rules.txt, IP-Lists.txt, List-Items-*.txt | 1, 2, 3, 6 |
| **V2** | Custom Rules chunk | Pre-chunked JSON (bare array) + IP-Lists.txt, List-Items-*.txt | 1, 3, 4B, 5, 6, 8, 9 |
| **V3** | Rate Limiting Rules | Rate-limits.txt | 1, 3, 7, 9 |
| **V4** | Global cross-type | rule_index.yaml + per-batch reports | 4A, cross-type consistency |

## Input

All modes read:
- `cloudflare-to-aws-waf/rule_index.yaml` — structured rule index from V0 scanner
- `cloudflare-to-aws-waf/cloudflare-security-rules-summary.md` — the summary to validate and fix

Mode-specific inputs:
- **V1**: Original IP-Access-Rules.txt, IP-Lists.txt, List-Items-*.txt from config path
- **V2**: `cloudflare-to-aws-waf/chunks/custom-rules-{start}-{end}.json` (bare JSON array, pre-chunked by orchestrator) + IP-Lists.txt, List-Items-*.txt from config path
- **V3**: Original Rate-limits.txt from config path
- **V4**: Validation reports from V1, V2, V3 batches

## Output

Each mode writes a validation report:
- **V1**: `cloudflare-to-aws-waf/validation/v1-ip-access.json`
- **V2**: `cloudflare-to-aws-waf/validation/v2-custom-{start}-{end}.json`
- **V3**: `cloudflare-to-aws-waf/validation/v3-rate-limiting.json`
- **V4**: `cloudflare-to-aws-waf/validator-report.md` (final consolidated report)

Report JSON format (V1/V2/V3):
```json
{
  "mode": "V1|V2|V3",
  "status": "PASS|FIXED|CANNOT_FIX",
  "issues_found": 0,
  "issues_fixed": 0,
  "issues_cannot_fix": 0,
  "details": [
    { "check": "Check 1", "rule": "rule-name", "issue": "...", "action": "fixed|cannot_fix" }
  ]
}
```

## Reference Documents

Read the references relevant to your mode:

- **V1**: `references/field-conversions.md`, `references/non-convertible-rules.md`
- **V2**: `references/action-conversions.md`, `references/field-conversions.md`, `references/non-convertible-rules.md`, `references/nesting-and-splitting.md`
- **V3**: `references/action-conversions.md`, `references/common-mistakes.md`
- **V4**: No references needed

## Workflow

### 0. Read Inputs and References

1. Identify your mode from the query (V1, V2, V3, or V4).
2. Read `cloudflare-to-aws-waf/rule_index.yaml`.
3. Read the reference documents listed for your mode above.
4. Read the summary file. **For V1/V2/V3**: you will read the full summary but only validate rules in your assigned scope — ignore rules outside your range.
5. Read the mode-specific input files:
   - **V1**: Use glob to find IP-Access-Rules.txt, IP-Lists.txt, List-Items-*.txt under the config path.
   - **V2**: Read the chunk file specified in the query (bare JSON array). Also find IP-Lists.txt, List-Items-*.txt if rules in this chunk reference IP lists.
   - **V3**: Use glob to find Rate-limits.txt under the config path.
   - **V4**: Read all validation report JSONs from `cloudflare-to-aws-waf/validation/`.

**For V2 mode:** The chunk file is a bare JSON array of Cloudflare rule objects (not the full CloudflareBackup response). The query specifies the position range (e.g., "custom rules 1-50"). Use rule_index.yaml to identify which rules in the summary correspond to this range, then locate them in the summary by their heading/name.

### 1. Run Validation Checks

Run only the checks relevant to your mode. Collect all issues before fixing anything.

---

#### Check 1: Rule Coverage (No Missing or Extra Rules)

**Modes: V1, V2, V3**

For each rule in the original config (or chunk), verify it appears in the summary. For each summary entry in your scope, verify it corresponds to an original rule.

- **V1**: Check IP Access Rules section against IP-Access-Rules.txt.
- **V2**: Check the chunk's rules against the corresponding entries in Summary Section 3. Use rule_index.yaml positions to identify which summary entries belong to this chunk.
- **V3**: Check Rate Limiting Rules section against Rate-limits.txt.

---

#### Check 2: IP Lists and List Items

**Mode: V1 only**

For each list in IP-Lists.txt, verify the list and its items appear correctly in Summary Section 1.

---

#### Check 3: Convertibility Classification

**Modes: V1, V2, V3**

For each rule in your scope, verify the convertibility status:

**Non-convertible fields** (require manual intervention): Client Certificate Verified, MIME Type, European Union, bot fields (`cf.verified_bot_category`, `cf.bot_management.*`), fraud fields (`cf.waf.credential_check.*`), attack score fields (`cf.waf.score*`)

**Conversion strategy — apply in this exact order:**
1. **Rate-based rules are ALWAYS convertible** — at minimum ⚠️ Partial. The mandatory fallback (Limit=10, EvaluationWindowSec=600) makes ALL rate-based rules convertible.
2. **Convertible OR non-convertible** → ⚠️ Partial
3. **Convertible AND non-convertible** → ❌ No
4. **Only non-convertible fields** → ❌ No

---

#### Check 4B: Intra-Section Rule Order

**Mode: V2 only**

Verify rules within this chunk maintain the exact array order from the original configuration. Compare the chunk's rule order against the summary's rule order for the corresponding positions.

---

#### Check 4A: Section Order

**Mode: V4 only**

Verify the summary sections appear in Cloudflare execution order:
1. IP Access Rules (execute first)
2. WAF Custom Rules (execute second)
3. Rate Limiting Rules (execute last)

---

#### Check 5: Skip Rule Action Parameters and RuleLabels

**Mode: V2 only (when chunk contains skip rules)**

For each skip rule in this chunk:

**Part A — Action Parameters Accuracy:**
- The `action_parameters` JSON matches the original config verbatim
- The `phases` array values are correctly listed
- `"ruleset": "current"` is noted if present

**Part B — RuleLabels Correctness:**
- `phases` contains `"http_ratelimit"` → must list `skip:http_ratelimit`
- `phases` contains `"http_request_firewall_managed"` → must list `skip:http_request_firewall_managed`
- `"ruleset": "current"` exists → must list `skip:all_remaining_custom_rules`
- No extra labels

**Part C — Scope-Down Impact Description:**
- Verify the summary accurately describes which downstream rules are affected

---

#### Check 6: Splitting Annotations

**Modes: V1, V2**

For each rule in your scope, verify splitting strategy:

**Part A — Top-level OR splitting:** If expression has top-level OR, summary must note split.
**Part B — IPv4/IPv6 splitting:** Check actual IP list contents for mixed addresses.
**Part C — Cascading split count:** Verify final rule count.
**Part D — Inline IP Set definitions:** Separate sets per branch, correct IPv4/IPv6 separation.
**Part E — Split skip rules share RuleLabels:** All variants add same labels.
**Part F — AWS WAF statement type:** Correct statement type for each rule/branch.

---

#### Check 7: Rate-Limit Calculation Verification

**Mode: V3 only**

For each rate-limiting rule, **re-calculate from scratch**:

1. Extract `requests_per_period` and `period` from original config
2. Calculate for ALL four windows: 60s, 120s, 300s, 600s
3. Select FIRST window where limit ≥ 10. If none → fallback Limit=10, EvaluationWindowSec=600
4. Compare against summary values

---

#### Check 8: Scope-Down Statement Content (Partial Rules)

**Mode: V2 only**

For each rule marked ⚠️ Partial in this chunk:
- Planned statement includes ONLY convertible conditions
- Non-convertible conditions are excluded and documented in Section 5

For non-skip custom rules: use rule_index.yaml to determine if this rule is positioned after a skip rule with `skip:all_remaining_custom_rules`. If so, verify the summary describes the scope-down.

---

#### Check 9: Skip Rule Scope-Down Impact

**Modes: V2, V3**

- **V2**: Skip rules themselves NEVER have scope-down. Non-skip custom rules after a skip rule with `skip:all_remaining_custom_rules` (check rule_index.yaml positions) should have scope-down noted.
- **V3**: If rule_index.yaml shows `skip_labels_present.http_ratelimit` is true, verify each rate-limit rule has scope-down for `skip:http_ratelimit` noted. Rate-limit rules NEVER check `skip:all_remaining_custom_rules`.

---

### 2. Determine Status

- **PASS**: All checks passed.
- **FIXED**: Issues found that can be fixed.
- **CANNOT_FIX**: Issues that cannot be resolved by editing.

### 3. Fix Issues (if FIXED)

**V4 mode only:** V4 is responsible for applying all fixes. Read the `details` array from each V1/V2/V3 report, and for each issue with `"action": "fixed"`, apply the fix to `cloudflare-security-rules-summary.md` using `fs_write` str_replace. Apply fixes serially to avoid race conditions.

**V1/V2/V3 modes:** Do NOT fix the summary yourself. Record each issue in the JSON report with the `action` field set to `"fixed"` (if fixable) or `"cannot_fix"`. Include enough detail in the `issue` and `fix` fields for V4 to apply the fix. For example:

```json
{
  "check": "Check 3",
  "rule": "rate-limit-api",
  "issue": "Convertibility marked as 'no' but should be 'partial' (rate-based rules are always convertible)",
  "action": "fixed",
  "fix": {
    "old_text": "- **Convertible**: ❌ No",
    "new_text": "- **Convertible**: ⚠️ Partial"
  }
}
```

### 4. Write Validation Report

**V1/V2/V3**: Write the JSON report to the appropriate path.

**V4**: Read all V1/V2/V3 reports from `cloudflare-to-aws-waf/validation/`. Determine global status:
- All PASS → global PASS
- Any FIXED, no CANNOT_FIX → global FIXED (apply all fixes serially to the summary)
- Any CANNOT_FIX → global CANNOT_FIX

**Apply fixes (V4 only):** For each report with status FIXED, iterate through the `details` array. For each entry with `"action": "fixed"`, use `fs_write` str_replace with the `old_text` and `new_text` from the `fix` field. Apply fixes one at a time, serially.

Also verify:
- Check 4A (section order)
- IP Access Rules have no skip-label scope-down
- Rate-limit rules don't check `skip:all_remaining_custom_rules`

Write `cloudflare-to-aws-waf/validator-report.md`:

```markdown
# Validator Report
Validation Round: {N}
Status: PASS | FIXED | CANNOT_FIX

## Batch Results
| Batch | Status | Issues Found | Issues Fixed |
|-------|--------|-------------|-------------|
| V1 (IP Access) | ... | ... | ... |
| V2 (Custom 1-50) | ... | ... | ... |
| V2 (Custom 51-100) | ... | ... | ... |
| V3 (Rate Limiting) | ... | ... | ... |

## Issues Fixed This Round
{list}

## Cannot Fix (Requires User Action)
{list or empty}
```

### 5. Return Result

```
---RESULT---
STATUS: PASS | FIXED | CANNOT_FIX
MODE: <V1|V2|V3|V4>
OUTPUT_FILES:
  - <report path>
ISSUES_COUNT: <number>
---END---
```
