# Terraform Nesting Depth and Rule Splitting Strategy

**CRITICAL: Read this file BEFORE generating any Terraform code.**

This document explains Terraform's nesting constraints and the default splitting strategy to avoid errors.

## Terraform Nesting Constraints

**CRITICAL CONSTRAINTS:**

1. **Terraform AWS provider limits statement nesting to maximum 3 levels**
   - Level 1: Top-level statement (or_statement, and_statement, etc.)
   - Level 2: Nested statement inside Level 1
   - Level 3: Nested statement inside Level 2
   - Level 4+: **NOT SUPPORTED** - will cause error: `Unsupported block type`

2. **AWS WAF/Terraform does NOT support same-type logical nesting**
   - `and_statement` **CANNOT** contain another `and_statement` as a direct child
   - `or_statement` **CANNOT** contain another `or_statement` as a direct child
   - This is logically redundant: `A AND (B AND C)` is equivalent to `A AND B AND C`
   - **Solution:** Flatten by adding all conditions as sibling statements in the parent
   - **Note:** `and_statement` CAN contain `or_statement`, `not_statement`, and other statement types

## DEFAULT STRATEGY: Split Rules Instead of Complex Nesting

**CRITICAL: Due to the complexity of managing nested logic and high error rate, the default strategy is to SPLIT rules rather than attempt complex nesting.**

**Splitting must be applied in cascading phases:**

**Phase 1: Split by top-level OR expressions FIRST**
- **ALWAYS split rules with top-level OR expressions** - Each OR branch becomes a separate rule
- This is the PRIMARY splitting strategy

**Phase 2: Split by IPv4/IPv6 SECOND**
- **ALWAYS split rules with mixed IPv4/IPv6 IP lists** - Create separate rules for IPv4 and IPv6
- Apply to EVERY rule, including those already split in Phase 1
- Even if a rule was split by OR, each resulting rule must be further split if it contains mixed IPv4/IPv6

**Phase 3: Verify nesting depth**
- **ALWAYS split when nesting would exceed 3 levels** - Even after Phases 1 and 2

**Critical principle: Splitting strategies are CASCADING, not mutually exclusive**

If a rule has both top-level OR and mixed IPv4/IPv6:
1. First split by OR (creates N rules)
2. Then split each of those N rules by IPv4/IPv6 (creates 2N rules)

**Example:**

Original: `(country eq "DZ" and ip in {ipv4, ipv6}) OR (country eq "CO" and ip in {ipv4, ipv6})`

Phase 1 - Split by OR:
- Branch 1: `country eq "DZ" and ip in {ipv4, ipv6}`
- Branch 2: `country eq "CO" and ip in {ipv4, ipv6}`

Phase 2 - Split each branch by IPv4/IPv6:
- Branch 1 IPv4: `country eq "DZ" and ip in {ipv4}`
- Branch 1 IPv6: `country eq "DZ" and ip in {ipv6}`
- Branch 2 IPv4: `country eq "CO" and ip in {ipv4}`
- Branch 2 IPv6: `country eq "CO" and ip in {ipv6}`

**Result: 4 rules total**

**Benefits of cascading splits:**
- Eliminates nesting depth errors completely
- Eliminates same-type nesting violations (OR-in-OR, AND-in-AND)
- Prevents scope-down statement nesting issues
- Simpler, more maintainable Terraform code
- Easier to debug and modify
- Matches AWS WAF best practices (simple rules are easier to understand)

**How to split:**
- Each split rule gets the same action (block, allow, challenge, count, etc.)
- For skip rules: ALL split rules must add the SAME RuleLabels to maintain skip logic consistency
- Maintain sequential priorities for split rules
- Document in rule names that they are part of a split set (e.g., `rule-name-branch-1-ipv4`, `rule-name-branch-1-ipv6`)

**Only use complex nesting when:**
- Rule is simple (2 levels or less)
- Already verified to not exceed 3 levels
- Cannot be split without changing semantics (rare)

## De Morgan's Law Transformations

Apply De Morgan's Law to flatten NOT(OR) and NOT(AND) patterns.

**Pattern 1: NOT (A OR B) → (NOT A) AND (NOT B)**

```hcl
# After transformation:
statement {
  and_statement {
    statement {
      not_statement {
        statement { condition_a {} }
      }
    }
    statement {
      not_statement {
        statement { condition_b {} }
      }
    }
  }
}
```

**Pattern 2: NOT (A AND B) → (NOT A) OR (NOT B)**

```hcl
# After transformation:
statement {
  or_statement {
    statement {
      not_statement {
        statement { condition_a {} }
      }
    }
    statement {
      not_statement {
        statement { condition_b {} }
      }
    }
  }
}
```

**CRITICAL: Add transformed NOT statements as siblings, NOT nested**

Example: `C AND NOT (A OR B)` → `C AND NOT A AND NOT B`

**CORRECT:**
```hcl
statement {
  and_statement {
    statement { condition_c {} }
    statement { not_statement { statement { condition_a {} } } }
    statement { not_statement { statement { condition_b {} } } }
  }
}
```

**WRONG (creates AND-in-AND):**
```hcl
statement {
  and_statement {
    statement { condition_c {} }
    statement {
      and_statement {  # ← WRONG!
        statement { not_statement { ... } }
        statement { not_statement { ... } }
      }
    }
  }
}
```

### Real-World Example: Negative IP Matching

Cloudflare: `ip.src.country eq "CO" and not ip.src in {100.1.1.1 ... 2001::2}`

Because the IP list contains both IPv4 and IPv6, it splits into two IP sets.

Logical transformation:
1. Original: `country == CO AND NOT (ipv4_set OR ipv6_set)`
2. Apply De Morgan: `country == CO AND (NOT ipv4_set AND NOT ipv6_set)`
3. Flatten: `country == CO AND NOT ipv4_set AND NOT ipv6_set`

**CORRECT Terraform:**
```hcl
statement {
  and_statement {
    statement {
      geo_match_statement {
        country_codes = ["CO"]
      }
    }
    statement {
      not_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.rule_name_co_ipv4.arn
          }
        }
      }
    }
    statement {
      not_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.rule_name_co_ipv6.arn
          }
        }
      }
    }
  }
}
```

**WRONG Terraform (causes "Unsupported block type" error):**
```hcl
statement {
  and_statement {
    statement {
      geo_match_statement {
        country_codes = ["CO"]
      }
    }
    statement {
      and_statement {  # ← WRONG! Unnecessary AND nesting
        statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.rule_name_co_ipv4.arn
              }
            }
          }
        }
        statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.rule_name_co_ipv6.arn
              }
            }
          }
        }
      }
    }
  }
}
```

**Key principle:** `and_statement` and `or_statement` can contain multiple sibling `statement` blocks. Use this to keep the structure flat. Only create nested `and_statement` or `or_statement` when the logical grouping requires a **different** operator (e.g., AND containing OR, or OR containing AND).

## Step-by-Step Conversion Process

**When converting any Cloudflare expression to Terraform:**

1. **Parse the logical structure** of the Cloudflare expression
   - Identify all AND, OR, NOT operators
   - Identify all conditions (geo, IP, header, etc.)

2. **Apply De Morgan's Law** to all NOT(OR) and NOT(AND) patterns:
   - `NOT (A OR B)` → `(NOT A) AND (NOT B)`
   - `NOT (A AND B)` → `(NOT A) OR (NOT B)`

3. **Flatten same-type logical operators**:
   - `A AND (B AND C)` → `A AND B AND C` (all as siblings)
   - `A OR (B OR C)` → `A OR B OR C` (all as siblings)
   - After De Morgan transformation, add resulting statements as siblings, not nested

4. **Build Terraform structure** with flattened logic:
   - Use `and_statement` or `or_statement` as the parent
   - Add all conditions as sibling `statement` blocks
   - Only nest when changing operator type (AND→OR or OR→AND)

5. **Verify nesting depth** does not exceed 3 levels

**Example workflow:**

Cloudflare: `(ip.src.country eq "CO" and not ip.src in {ipv4_list, ipv6_list}) or (http.user_agent contains "Bot")`

Step 1 - Parse:
- Top-level: OR
- Left branch: `country == CO AND NOT (ipv4 OR ipv6)`
- Right branch: `user_agent contains "Bot"`

Step 2 - Apply De Morgan to left branch:
- `NOT (ipv4 OR ipv6)` → `NOT ipv4 AND NOT ipv6`
- Result: `country == CO AND NOT ipv4 AND NOT ipv6`

Step 3 - Flatten:
- Left branch has 3 AND conditions (all siblings)
- Top-level OR has 2 branches

Step 4 - Build Terraform:
```hcl
statement {
  or_statement {
    statement {
      and_statement {
        statement { geo_match { country_codes = ["CO"] } }
        statement { not_statement { ip_set ipv4 } }
        statement { not_statement { ip_set ipv6 } }
      }
    }
    statement {
      byte_match_statement { search_string = "Bot" ... }
    }
  }
}
```

Step 5 - Verify depth:
- Level 1: `or_statement`
- Level 2: `and_statement` and `byte_match_statement`
- Level 3: `geo_match`, `not_statement` (containing `ip_set`)
- ✓ Maximum 3 levels

## Rule Splitting Patterns

**CRITICAL: Splitting is CASCADING - apply Phase 1 first, then Phase 2 to each result**

**Pattern 1: Top-level OR only (Phase 1 only)**

Original: `(A AND B) OR (C AND D)`

Phase 1 - Split by OR:
- Rule N: A AND B
- Rule N+1: C AND D

**Result: 2 rules**

**Pattern 2: Mixed IPv4/IPv6 only (Phase 2 only)**

Original: `ip.src in {ipv4_list, ipv6_list}`

Phase 2 - Split by IPv4/IPv6:
- Rule N: IPv4 variant
- Rule N+1: IPv6 variant

**Result: 2 rules**

**Pattern 3: Top-level OR with mixed IPv4/IPv6 (CASCADING - Phase 1 then Phase 2)**

Original: `(country eq "DZ" and ip.src in {ipv4, ipv6}) OR (country eq "CO" and ip.src in {ipv4, ipv6})`

Phase 1 - Split by OR:
- Branch 1: `country eq "DZ" and ip.src in {ipv4, ipv6}`
- Branch 2: `country eq "CO" and ip.src in {ipv4, ipv6}`

Phase 2 - Split EACH branch by IPv4/IPv6:
- Branch 1 IPv4: `country eq "DZ" and ipv4`
- Branch 1 IPv6: `country eq "DZ" and ipv6`
- Branch 2 IPv4: `country eq "CO" and ipv4`
- Branch 2 IPv6: `country eq "CO" and ipv6`

**Result: 4 rules** (NOT 2!)

**Pattern 4: Top-level OR with one branch having mixed IPv4/IPv6**

Original: `(country eq "CN" and ip.src in {ipv4, ipv6}) OR (user_agent contains "Bot")`

Phase 1 - Split by OR:
- Branch 1: `country eq "CN" and ip.src in {ipv4, ipv6}`
- Branch 2: `user_agent contains "Bot"`

Phase 2 - Split Branch 1 by IPv4/IPv6 (Branch 2 has no IP lists):
- Branch 1 IPv4: `country eq "CN" and ipv4`
- Branch 1 IPv6: `country eq "CN" and ipv6`
- Branch 2: `user_agent contains "Bot"` (unchanged)

**Result: 3 rules**

**Pattern 5: Top-level OR with negative IP matching**

Original: `(country eq "DZ" and ip in {ipv4, ipv6}) OR (country eq "CO" and NOT ip in {ipv4, ipv6})`

Phase 1 - Split by OR:
- Branch 1: `country eq "DZ" and ip in {ipv4, ipv6}`
- Branch 2: `country eq "CO" and NOT ip in {ipv4, ipv6}`

Phase 2 - Split EACH branch by IPv4/IPv6:
- Branch 1 IPv4: `country eq "DZ" and ipv4`
- Branch 1 IPv6: `country eq "DZ" and ipv6`
- Branch 2 IPv4: `country eq "CO" and NOT ipv4` (De Morgan applied)
- Branch 2 IPv6: `country eq "CO" and NOT ipv6` (De Morgan applied)

**Result: 4 rules**

**Pattern 6: Three-way OR with mixed IPv4/IPv6**

Original: `(country eq "DZ" and ip in {ipv4, ipv6}) OR (country eq "CO" and NOT ip in {ipv4, ipv6}) OR (user_agent contains "Bot" and asn in {16001, 16002})`

Phase 1 - Split by OR:
- Branch 1: `country eq "DZ" and ip in {ipv4, ipv6}`
- Branch 2: `country eq "CO" and NOT ip in {ipv4, ipv6}`
- Branch 3: `user_agent contains "Bot" and asn in {16001, 16002}`

Phase 2 - Split branches 1 and 2 by IPv4/IPv6 (Branch 3 has no IP lists):
- Branch 1 IPv4: `country eq "DZ" and ipv4`
- Branch 1 IPv6: `country eq "DZ" and ipv6`
- Branch 2 IPv4: `country eq "CO" and NOT ipv4`
- Branch 2 IPv6: `country eq "CO" and NOT ipv6`
- Branch 3: `user_agent contains "Bot" and asn in {16001, 16002}` (unchanged)

**Result: 5 rules**

## Action Handling After Split

**For skip rules:** ALL split rules add the SAME RuleLabel

```
Original: (A OR B) → skip:http_ratelimit
Split:
  - Rule N: A → skip:http_ratelimit
  - Rule N+1: B → skip:http_ratelimit
```

**For custom rules:** Each split rule uses the SAME action

```
Original: (A OR B) → Block
Split:
  - Rule N: A → Block
  - Rule N+1: B → Block
```

**For rate limiting rules:** Each split rule applies the SAME rate limit

```
Original: (A OR B) → Rate limit 100/min
Split:
  - Rule N: A → Rate limit 100/min
  - Rule N+1: B → Rate limit 100/min
```

Note: Rate limits are tracked separately per rule.

## Non-Splittable Patterns (Rare)

Rules with top-level AND and cross-dependencies cannot be split:

```
(A OR B) AND (C OR D)
```

**Action:** Mark as "Cannot convert - too complex" and recommend user simplify in Cloudflare.

**Example validation report entry:**

```
Rule: complex-skip-rule
Status: Cannot convert
Reason: Rule expression exceeds Terraform's 3-level nesting limit and cannot be split while preserving semantics
Cloudflare expression: (ip.src.country eq "US" and (http.request.uri.path contains "/api" or http.request.uri.path contains "/admin")) and (http.user_agent contains "Bot" or http.user_agent contains "Crawler")
Recommendation: Simplify this rule in Cloudflare by splitting into multiple rules before conversion
```

**Reference:** See [Terraform AWS Provider Issue #14377](https://github.com/hashicorp/terraform-provider-aws/issues/14377) for background on the 3-level nesting limitation.
