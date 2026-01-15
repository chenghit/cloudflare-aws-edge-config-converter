# Action Conversions and Rate Limiting

This document covers how to convert Cloudflare rule actions and rate limiting rules to AWS WAF.

## Challenge Actions

Cloudflare challenge actions convert directly to AWS WAF challenge actions.

**Cloudflare `interactive_challenge` → AWS WAF `Captcha`**

Requires user interaction (solving a CAPTCHA puzzle).

```hcl
action {
  captcha {}
}
```

**Cloudflare `js_challenge`, `managed_challenge` → AWS WAF `Challenge`**

Silent browser challenge (no user interaction required).

```hcl
action {
  challenge {}
}
```

**Note:** These are standalone actions, not requiring Bot Control managed rule group.

## Skip Action

Convert Cloudflare Skip action to AWS WAF Count action with RuleLabels.

**Conversion steps:**

1. **Change action:** `skip` → `count`
2. **Add RuleLabels based on `action_parameters`:**
   - If `phases` contains `"http_ratelimit"` → Add `skip:http_ratelimit`
   - If `phases` contains `"http_request_firewall_managed"` → Add `skip:http_request_firewall_managed`
   - If `"ruleset": "current"` exists → Add `skip:all_remaining_custom_rules`
   - Ignore `"http_request_sbfm"` and `products` array

**Terraform format:**

```hcl
rule {
  name     = "skip-rule-name"
  priority = N
  action { count {} }
  statement { # ... converted expression ... }
  
  rule_label { name = "skip:http_ratelimit" }
  rule_label { name = "skip:http_request_firewall_managed" }
  rule_label { name = "skip:all_remaining_custom_rules" }
  
  visibility_config { # ... }
}
```

### Implementing Skip Logic

Skip rules only affect rules **after** them in execution order.

**For rate-based rules:**
- If `skip:http_ratelimit` exists: Add scope-down statement with NOT logic
- Structure: `rate_based_statement { scope_down_statement { and_statement { not(label), original_conditions } } }`

**For managed rules:**
- If `skip:http_request_firewall_managed` exists: Add scope-down statement with NOT logic
- Structure: `managed_rule_group_statement { scope_down_statement { not_statement { label_match } } }`

**For custom rules (non-rate-based):**
- If `skip:all_remaining_custom_rules` exists: Wrap original statement
- Structure: `and_statement { not_statement { label_match }, original_statement }`

**CRITICAL:** 
- Skip action rules themselves NEVER have scope-down statements
- Use exact RuleLabel names (no `awswaf:` or `aws:` prefix)
- Rate-based rules NEVER check `skip:all_remaining_custom_rules` (Cloudflare architectural difference)

### Detailed Skip Logic Examples

**Example 1: Rate-based rule with skip logic**

```hcl
rule {
  name     = "rate-limit-paths"
  priority = 7

  action {
    block {}
  }

  statement {
    rate_based_statement {
      limit              = 12
      aggregate_key_type = "IP"
      evaluation_window_sec = 120

      scope_down_statement {
        and_statement {
          statement {
            not_statement {
              statement {
                label_match_statement {
                  scope = "LABEL"
                  key   = "skip:http_ratelimit"
                }
              }
            }
          }
          statement {
            or_statement {
              statement {
                byte_match_statement {
                  search_string         = "/rate-limit/"
                  positional_constraint = "CONTAINS"
                  field_to_match {
                    uri_path {}
                  }
                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
              statement {
                byte_match_statement {
                  search_string         = "/rbr/"
                  positional_constraint = "CONTAINS"
                  field_to_match {
                    uri_path {}
                  }
                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "rate-limit-paths"
    sampled_requests_enabled   = true
  }
}
```

**Example 2: Managed rule with skip logic**

```hcl
rule {
  name     = "AWS-AWSManagedRulesCommonRuleSet"
  priority = 10

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesCommonRuleSet"
      
      scope_down_statement {
        not_statement {
          statement {
            label_match_statement {
              scope = "LABEL"
              key   = "skip:http_request_firewall_managed"
            }
          }
        }
      }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesCommonRuleSet"
  }
}
```

**Example 3: Custom rule with skip logic**

```hcl
rule {
  name     = "block-user-agent"
  priority = 5

  action {
    block {}
  }

  statement {
    and_statement {
      statement {
        not_statement {
          statement {
            label_match_statement {
              scope = "LABEL"
              key   = "skip:all_remaining_custom_rules"
            }
          }
        }
      }
      statement {
        byte_match_statement {
          search_string         = "BadBot/1.0.2"
          positional_constraint = "EXACTLY"
          field_to_match {
            single_header {
              name = "user-agent"
            }
          }
          text_transformation {
            priority = 0
            type     = "LOWERCASE"
          }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "block-user-agent"
    sampled_requests_enabled   = true
  }
}
```

## Rate Limiting Rules

### Duration (mitigation_timeout)

Cloudflare supports custom block duration. AWS WAF does not.

**Action:** Ignore duration field, convert other parameters.

### Request Count and Evaluation Window

**Cloudflare configuration:**
- `period`: Time window in seconds
- `requests_per_period`: Request count limit
- `mitigation_timeout`: Block duration (ignored)

**AWS WAF constraints:**
- Request count (limit): 10 to 2,000,000,000
- Evaluation window: 60, 120, 300, or 600 seconds only

**Conversion formula:**

```
AWS_limit = Cloudflare_requests_per_period × (AWS_window / Cloudflare_period)
```

**Evaluation window selection algorithm:**

1. Try windows in order: [60, 120, 300, 600] seconds
2. For each window, calculate: `limit = requests_per_period × (window / period)`
3. Use first window where calculated limit ≥ 10 (AWS minimum)
4. If all windows result in limit < 10, use 600s with limit = 10 (fallback)

**Example 1:**

Cloudflare: 1 request per 10 seconds
- Try 60s: 1 × (60 / 10) = 6 < 10 ❌
- Try 120s: 1 × (120 / 10) = 12 ≥ 10 ✓
- AWS configuration: Limit=12, EvaluationWindowSec=120

**Example 2:**

Cloudflare: 5 requests per 20 seconds
- Try 60s: 5 × (60 / 20) = 15 ≥ 10 ✓
- AWS configuration: Limit=15, EvaluationWindowSec=60

**Example 3:**

Cloudflare: 1 request per 100 seconds
- Try 60s: 1 × (60 / 100) = 0.6 < 10 ❌
- Try 120s: 1 × (120 / 100) = 1.2 < 10 ❌
- Try 300s: 1 × (300 / 100) = 3 < 10 ❌
- Try 600s: 1 × (600 / 100) = 6 < 10 ❌
- AWS configuration: Limit=10, EvaluationWindowSec=600 (fallback, slightly more permissive than original)

**AWS WAF JSON example:**
```json
{
  "Statement": {
    "RateBasedStatement": {
      "Limit": 10,
      "AggregateKeyType": "IP",
      "EvaluationWindowSec": 60
    }
  }
}
```

**Terraform example:**

```hcl
statement {
  rate_based_statement {
    limit              = 12
    aggregate_key_type = "IP"
    evaluation_window_sec = 120
  }
}
```

### Response Matching

AWS WAF rate-based rules don't support Response code or Response headers.

**Action:** Do not convert rate-limiting rules with Response matching.

### Rate-Based Rule Limit and Complexity Constraints

**Constraints:**
- AWS WAF limit: Maximum 10 rate-based rules per web ACL (cannot be increased)
- Terraform limit: Maximum 3 nesting levels in scope_down_statement

**Conversion strategy:**

1. **If ≤10 rate-limiting rules AND all scope_down_statements ≤3 nesting levels**: Convert directly to rate-based rules
   - Preserve original matching logic in scope_down_statement
   - Do NOT split rules (splitting causes independent rate tracking and semantic changes)

2. **If >10 rate-limiting rules OR any scope_down_statement >3 nesting levels**: Mark as "Cannot convert - too complex"
   - Document in summary: "This rate-limiting rule cannot be converted because [reason]"
   - Recommend user simplify rules in Cloudflare before conversion
   - Reasons may include:
     - "More than 10 rate-limiting rules (AWS WAF limit)"
     - "Matching logic exceeds 3 nesting levels (Terraform limit)"
     - "Contains response matching (not supported in AWS WAF)"

**Rationale:** Rate-limiting rules require preserving exact semantic behavior. Complex workarounds (like two-phase labeling) are error-prone and difficult for AI to implement correctly. Users should simplify rules at the source (Cloudflare) rather than rely on complex conversion logic.
