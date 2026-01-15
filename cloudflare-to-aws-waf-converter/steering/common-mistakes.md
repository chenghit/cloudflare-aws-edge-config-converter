# Common Mistakes and How to Avoid Them

This document lists common mistakes when converting Cloudflare rules to AWS WAF and how to avoid them.

## Mistake 1: Not Applying Cascading Splits

**WRONG Approach:**

Rule: `(country eq "DZ" and ip in {ipv4, ipv6}) OR (country eq "CO" and NOT ip in {ipv4, ipv6})`

Incorrect split (only splitting by OR):
- Rule 1: `country eq "DZ" and ip in {ipv4, ipv6}` ← Still has mixed IPv4/IPv6!
- Rule 2: `country eq "CO" and NOT ip in {ipv4, ipv6}` ← Still has mixed IPv4/IPv6!

**Problem:** Each rule still contains mixed IPv4/IPv6, which will cause nesting issues when adding scope-down statements.

**CORRECT Approach:**

Phase 1 - Split by OR:
- Branch 1: `country eq "DZ" and ip in {ipv4, ipv6}`
- Branch 2: `country eq "CO" and NOT ip in {ipv4, ipv6}`

Phase 2 - Split EACH branch by IPv4/IPv6:
- Rule 1: `country eq "DZ" and ipv4`
- Rule 2: `country eq "DZ" and ipv6`
- Rule 3: `country eq "CO" and NOT ipv4`
- Rule 4: `country eq "CO" and NOT ipv6`

**Result:** 4 rules, each with single IP version, no nesting issues.

---

## Mistake 2: Forgetting to Split After OR Split

**WRONG Approach:**

Rule: `(A and ip in {ipv4, ipv6}) OR (B and ip in {ipv4, ipv6}) OR (C and asn in {1234})`

Incorrect split:
- Rule 1: `A and ip in {ipv4, ipv6}` ← Forgot to split by IPv4/IPv6!
- Rule 2: `B and ip in {ipv4, ipv6}` ← Forgot to split by IPv4/IPv6!
- Rule 3: `C and asn in {1234}` ← Correct (no IP lists)

**CORRECT Approach:**

Phase 1 - Split by OR (3 branches):
- Branch 1: `A and ip in {ipv4, ipv6}`
- Branch 2: `B and ip in {ipv4, ipv6}`
- Branch 3: `C and asn in {1234}`

Phase 2 - Split branches 1 and 2 by IPv4/IPv6:
- Rule 1: `A and ipv4`
- Rule 2: `A and ipv6`
- Rule 3: `B and ipv4`
- Rule 4: `B and ipv6`
- Rule 5: `C and asn in {1234}` (unchanged)

**Result:** 5 rules total.

---

## Mistake 3: Combining Different Inline IP Lists

**WRONG Approach:**

Rule: `(country eq "DZ" and ip in {200.1.1.1, 200.1.1.2}) OR (country eq "CO" and ip in {100.1.1.1, 100.1.1.2})`

Incorrect IP set creation:
- Create one IP set: `skip-rule-ipv4` with addresses `[200.1.1.1, 200.1.1.2, 100.1.1.1, 100.1.1.2]`

**Problem:** Cannot distinguish between DZ and CO conditions. Logic is broken.

**CORRECT Approach:**

Create separate IP sets for each condition:
- `skip-rule-branch-1-dz-ipv4`: `[200.1.1.1/32, 200.1.1.2/32]`
- `skip-rule-branch-2-co-ipv4`: `[100.1.1.1/32, 100.1.1.1.2/32]`

Then create rules:
- Rule 1: `country eq "DZ" and ip_set(skip-rule-branch-1-dz-ipv4)`
- Rule 2: `country eq "CO" and ip_set(skip-rule-branch-2-co-ipv4)`

---

## Mistake 4: Not Applying De Morgan's Law to Negative IP Matching

**WRONG Approach:**

Rule: `country eq "CO" and NOT ip in {ipv4, ipv6}`

Incorrect Terraform (creates OR-in-OR or exceeds nesting):
```hcl
statement {
  and_statement {
    statement { geo_match { country_codes = ["CO"] } }
    statement {
      not_statement {
        statement {
          or_statement {  # ← Creates nesting issues
            statement { ip_set ipv4 }
            statement { ip_set ipv6 }
          }
        }
      }
    }
  }
}
```

**CORRECT Approach:**

Apply De Morgan's Law: `NOT (ipv4 OR ipv6)` → `NOT ipv4 AND NOT ipv6`

Split into 2 rules:
- Rule 1: `country eq "CO" and NOT ipv4`
- Rule 2: `country eq "CO" and NOT ipv6`

Terraform for Rule 1:
```hcl
statement {
  and_statement {
    statement { geo_match { country_codes = ["CO"] } }
    statement {
      not_statement {
        statement { ip_set_reference_statement { arn = ipv4_arn } }
      }
    }
  }
}
```

---

## Mistake 5: Forgetting RuleLabels on Split Rules

**WRONG Approach:**

Original skip rule: `(A) OR (B)` → Adds RuleLabel `skip:http_ratelimit`

Incorrect split:
- Rule 1: `A` → Adds RuleLabel `skip:http_ratelimit` ✓
- Rule 2: `B` → No RuleLabel ✗

**Problem:** Rule 2 doesn't add the skip label, so subsequent rules won't be skipped correctly.

**CORRECT Approach:**

ALL split rules must add the SAME RuleLabels:
- Rule 1: `A` → Adds RuleLabel `skip:http_ratelimit`
- Rule 2: `B` → Adds RuleLabel `skip:http_ratelimit`

---

## Mistake 6: Adding Scope-Down to Skip Rules

**WRONG Approach:**

Skip rule positioned after another skip rule, incorrectly adds scope-down statement.

**Problem:** Skip rules should always be evaluated independently. They should not skip other skip rules.

**CORRECT Approach:**

Skip rules NEVER have scope-down statements, regardless of their position.

---

## Mistake 7: Rate-Based Rules Checking Wrong RuleLabel

**WRONG Approach:**

Rate-based rule checks `skip:all_remaining_custom_rules` label.

**Problem:** In Cloudflare, rate-limiting is a separate phase from custom rules. The `skip:all_remaining_custom_rules` label should NOT affect rate-based rules.

**CORRECT Approach:**

Rate-based rules ONLY check `skip:http_ratelimit` label (if it exists). They NEVER check `skip:all_remaining_custom_rules`.

---

## Mistake 8: Not Counting Split Rules in Priority Assignment

**WRONG Approach:**

Original rules:
1. skip-rule-1 (will split into 3 branches, each with IPv4/IPv6 = 6 rules)
2. block-rule-2
3. rate-limit-rule-3

Incorrect priority assignment:
- Priority 0: Anti-DDoS
- Priority 1: skip-rule-1 (but this is actually 6 rules!)
- Priority 2: block-rule-2
- Priority 3: rate-limit-rule-3

**CORRECT Approach:**

Count all split rules:
- Priority 0: Anti-DDoS
- Priority 1-6: skip-rule-1 (6 split rules)
- Priority 7: block-rule-2
- Priority 8: rate-limit-rule-3

---

## Mistake 9: Marking Low-Limit Rate Rules as "Cannot Convert"

**WRONG Approach:**

Cloudflare rule: 1 request per 100 seconds

Calculation:
- Try 60s: 1 × (60/100) = 0.6 < 10 ❌
- Try 120s: 1 × (120/100) = 1.2 < 10 ❌
- Try 300s: 1 × (300/100) = 3 < 10 ❌
- Try 600s: 1 × (600/100) = 6 < 10 ❌

**Incorrect conclusion:** "Cannot convert - calculated limit is below AWS WAF minimum of 10 requests"

**Problem:** This ignores the mandatory fallback rule in action-conversions.md.

**CORRECT Approach:**

When all evaluation windows result in limit < 10, YOU MUST apply the fallback:
- **AWS Configuration**: `Limit=10, EvaluationWindowSec=600`
- **Status**: ✓ CONVERTIBLE (using mandatory fallback)
- **Note in summary**: "Converted using fallback configuration (10 req/600s ≈ 1.67 req/100s). This is slightly more permissive than the original Cloudflare configuration (1 req/100s) but provides similar rate limiting protection."

**Key Point:** NEVER mark a rate-based rule as "cannot convert" solely because the calculated limit is below 10. The fallback configuration is MANDATORY and ALWAYS makes the rule convertible.

---

## Quick Checklist Before Generating Terraform

- [ ] Applied Phase 1 split (top-level OR)?
- [ ] Applied Phase 2 split (IPv4/IPv6) to EACH rule from Phase 1?
- [ ] Created separate IP sets for each distinct inline IP list?
- [ ] All split rules from same original rule add SAME RuleLabels?
- [ ] Skip rules have NO scope-down statements?
- [ ] Rate-based rules ONLY check `skip:http_ratelimit` (not `skip:all_remaining_custom_rules`)?
- [ ] Priorities are sequential with no gaps?
- [ ] Counted all split rules when assigning priorities?
- [ ] Applied mandatory fallback (Limit=10, Window=600s) for rate rules with calculated limit < 10?
