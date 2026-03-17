---
name: cf-waf-analyzer-validator
description: Validates WAF IR JSON against original Cloudflare configuration files. Operates in batch mode — each invocation validates a specific rule type or chunk. V1/V2/V3 modes report issues; V4 mode applies fixes serially to waf_ir.json. Use after cf-waf-analyzer has generated IR JSON files and the orchestrator has merged them into waf_ir.json.
metadata:
  author: chenghit
---

# Cloudflare WAF Analyzer Validator

Validate `cloudflare-to-aws-waf/waf_ir.json` by cross-checking it against the original Cloudflare configuration files. V1/V2/V3 modes only report issues (do NOT modify waf_ir.json). V4 mode applies all fixes serially and writes the final report.

**Language Adaptation**: Write output files in the language specified in the query. Default to English.

## Validation Modes

| Mode | What it validates | Input config files | Checks |
|------|------------------|--------------------|--------|
| **V1** | IP Lists + IP Access Rules | IP-Access-Rules.txt, IP-Lists.txt, List-Items-*.txt | 1, 2, 3, 6 |
| **V2** | Custom Rules chunk | Pre-chunked JSON (bare array) + IP-Lists.txt, List-Items-*.txt | 1, 3, 4B, 5, 6, 8, 9 |
| **V3** | Rate Limiting Rules | Rate-limits.txt | 1, 3, 7, 9 |
| **V4** | Global cross-type | waf_ir.json + per-batch reports | 4A, cross-type consistency |

## Input

All modes read:
- `cloudflare-to-aws-waf/waf_ir.json` — the merged IR to validate and fix

Mode-specific inputs:
- **V1**: Original IP-Access-Rules.txt, IP-Lists.txt, List-Items-*.txt from config path
- **V2**: `cloudflare-to-aws-waf/chunks/custom-rules-{start}-{end}.json` (bare JSON array) + IP-Lists.txt, List-Items-*.txt from config path
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
    {
      "check": "Check 1",
      "rule": "rule-name",
      "issue": "...",
      "action": "fixed|cannot_fix",
      "fix": {
        "old_text": "\"name\": \"rule-name\",\n    \"convertibility\": \"no\"",
        "new_text": "\"name\": \"rule-name\",\n    \"convertibility\": \"partial\""
      }
    }
  ]
}
```

**Fix format for V1/V2/V3 reports:** Each fix uses `old_text`/`new_text` pairs for `fs_write` str_replace on waf_ir.json. Include the rule's `"name"` field as context to ensure unique matching. V4 applies these directly.

## Reference Documents

- **V1**: `references/field-conversions.md`, `references/non-convertible-rules.md`
- **V2**: `references/action-conversions.md`, `references/field-conversions.md`, `references/non-convertible-rules.md`, `references/nesting-and-splitting.md`
- **V3**: `references/action-conversions.md`, `references/common-mistakes.md`
- **V4**: No references needed

## Workflow

### 0. Read Inputs and References

1. Identify your mode from the query (V1, V2, V3, or V4).
2. Read `cloudflare-to-aws-waf/waf_ir.json`.
3. Read the reference documents listed for your mode.
4. Read mode-specific input files:
   - **V1**: glob for IP-Access-Rules.txt, IP-Lists.txt, List-Items-*.txt
   - **V2**: Read chunk file from query. Also find IP-Lists.txt, List-Items-*.txt if rules reference IP lists.
   - **V3**: glob for Rate-limits.txt
   - **V4**: Read all validation report JSONs from `cloudflare-to-aws-waf/validation/`

**For V2 mode:** The chunk file is a bare JSON array of Cloudflare rule objects. The query specifies the position range (e.g., "positions 1-50"). Match rules in waf_ir.json's `custom_rules.rules` array by position.

### 1. Run Validation Checks

Run only the checks relevant to your mode.

---

#### Check 1: Rule Coverage (No Missing or Extra Rules)

**Modes: V1, V2, V3**

For each rule in the original config (or chunk), verify it appears in waf_ir.json. For each IR entry in your scope, verify it corresponds to an original rule.

**Excluded:** Managed rules and DDoS protection rules (out of scope for conversion).

- **V1**: Check `ip_lists` array against IP-Lists.txt. Check `ip_access_rules.rules` against IP-Access-Rules.txt.
- **V2**: Check chunk rules against `custom_rules.rules` by position range.
- **V3**: Check `rate_limiting_rules.rules` against Rate-limits.txt.

---

#### Check 2: IP Lists and List Items

**Mode: V1 only**

For each list in IP-Lists.txt, verify the list appears in `ip_lists` with correct kind, conversion type, and items.

---

#### Check 3: Convertibility Classification

**Modes: V1, V2, V3**

For each rule in your scope, verify the `convertibility` field:

**Non-convertible fields:** Client Certificate Verified, MIME Type, European Union, bot fields (`cf.verified_bot_category`, `cf.bot_management.*`), fraud fields (`cf.waf.credential_check.*`), attack score fields (`cf.waf.score*`)

**Rules:**
1. Rate-based rules are ALWAYS convertible — at minimum `"partial"`
2. Convertible OR non-convertible → `"partial"`
3. Convertible AND non-convertible → `"no"`
4. Only non-convertible fields → `"no"`

---

#### Check 4B: Intra-Section Rule Order

**Mode: V2 only**

Verify rules within this chunk maintain the exact array order from the original configuration. Compare chunk rule order against `custom_rules.rules` positions.

---

#### Check 4A: Section Order

**Mode: V4 only**

Verify waf_ir.json has all expected top-level keys: `ip_lists`, `ip_access_rules`, `custom_rules`, `rate_limiting_rules`, `non_convertible_notes`.

---

#### Check 5: Skip Rule Action Parameters and RuleLabels

**Mode: V2 only (when chunk contains skip rules)**

For each skip rule in this chunk:

**Part A — Action Parameters:** `action_parameters` matches original config verbatim.

**Part B — Labels Correctness:**
- `phases` contains `"http_ratelimit"` → labels must include `"skip:http_ratelimit"`
- `phases` contains `"http_request_firewall_managed"` → labels must include `"skip:http_request_firewall_managed"`
- `"ruleset": "current"` → labels must include `"skip:all_remaining_custom_rules"`
- No extra labels

**Part C — skip_labels_present Consistency:**
- If this chunk has a skip rule with `skip:all_remaining_custom_rules` label → `custom_rules.skip_labels_present.all_remaining_custom_rules` must be `true`
- Same for `http_ratelimit` and `http_request_firewall_managed`
- If skip rule does NOT skip a phase, verify the IR does NOT include that phase's label in the rule's `labels` array

---

#### Check 6: Splitting Annotations

**Modes: V1, V2**

**Rate-limiting rules are excluded** — they are NEVER split.

**Part A — Top-level OR:** If expression has top-level OR, `split.required` must be `true`.
**Part B — IPv4/IPv6:** Check actual IP list contents for mixed addresses. If mixed, verify split accounts for it.
**Part C — Cascading count:** Verify `split.total_aws_rules`.
**Part D — IP Set definitions:** Separate sets per branch, correct IPv4/IPv6 separation.
**Part E — Split skip rules share labels:** All split variants of a skip rule must produce the same labels.
**Part F — AWS WAF statement type:** Correct `aws_statement_type` for each rule/branch.

---

#### Check 7: Rate-Limit Calculation Verification

**Mode: V3 only**

For each rate-limiting rule, re-calculate from scratch:
1. Extract `requests_per_period` and `period` from original config
2. Calculate for ALL four windows: 60s, 120s, 300s, 600s
3. Select FIRST window where limit ≥ 10. If none → fallback 10/600s
4. Compare `aws_limit` and `aws_evaluation_window_sec` against calculated values
5. Verify `mandatory_fallback` flag is correct

---

#### Check 8: Scope-Down Statement Content (Partial Rules)

**Mode: V2 only**

For each rule with `"convertibility": "partial"`:
- `convertible_expression` includes ONLY convertible conditions
- Non-convertible conditions are excluded and documented in `non_convertible_notes`
- `aws_statement_type` matches the convertible expression

For non-skip custom rules: check if this rule's position is after any skip rule with `skip:all_remaining_custom_rules`. If so, `scope_down.skip_all_remaining_custom_rules` must be `true`.

---

#### Check 9: Skip Rule Scope-Down Impact

**Modes: V2, V3**

- **V2**: Skip rules themselves always have `scope_down.skip_all_remaining_custom_rules: false`. Non-skip custom rules after a skip rule with that label must have `scope_down.skip_all_remaining_custom_rules: true`. A rule at position P needs scope-down if ANY skip rule at position < P has that label.
- **V3**: If `custom_rules.skip_labels_present.http_ratelimit` is `true`, every rate-limiting rule must have `scope_down.skip_http_ratelimit: true`. Rate-limit rules NEVER check `skip:all_remaining_custom_rules`.

---

### 2. Determine Status

- **PASS**: All checks passed.
- **FIXED**: Issues found that can be fixed.
- **CANNOT_FIX**: Issues that cannot be resolved by editing.

### 3. Fix Issues

**V1/V2/V3 modes:** Do NOT fix waf_ir.json. Record each issue in the JSON report with `"action": "fixed"` or `"cannot_fix"`. Include enough detail for V4 to apply the fix.

**Fix format:** Each fix specifies what to change in waf_ir.json. Use `old_text`/`new_text` pairs that include the rule's `"name"` field as context for unique matching:

```json
{
  "fix": {
    "old_text": "\"name\": \"rate-limit-api\",\n    \"convertibility\": \"no\"",
    "new_text": "\"name\": \"rate-limit-api\",\n    \"convertibility\": \"partial\""
  }
}
```

Include enough surrounding JSON context (the rule name at minimum) to ensure the old_text is unique in waf_ir.json.

**V4 mode:** Read all V1/V2/V3 reports. For each issue with `"action": "fixed"`, apply `fs_write` str_replace with `old_text`/`new_text` from the fix. Apply fixes one at a time, serially. If a str_replace fails (old_text not found), log as warning and continue.

Also verify:
- Check 4A (all top-level keys present)
- IP Access Rules have no skip-label scope-down (they execute before skip rules)
- Rate-limit rules don't check `skip:all_remaining_custom_rules`

### 4. Write Validation Report

**V1/V2/V3**: Write JSON report to the appropriate path.

**V4**: Determine global status:
- All PASS → global PASS
- Any FIXED, no CANNOT_FIX → global FIXED (apply all fixes)
- Any CANNOT_FIX → global CANNOT_FIX

Write `cloudflare-to-aws-waf/validator-report.md`:

**CRITICAL**: If a previous `validator-report.md` exists, preserve the Changelog section.

```markdown
# Validator Report
Validation Round: {N}
Status: PASS | FIXED | CANNOT_FIX

## Batch Results
| Batch | Status | Issues Found | Issues Fixed |
|-------|--------|-------------|-------------|
| V1 (IP Access) | ... | ... | ... |
| V2 (Custom 1-50) | ... | ... | ... |
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
