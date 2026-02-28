# AWS WAF Managed Rules Configuration

This document defines the AWS WAF managed rules that must be included in every generated Terraform configuration.

## Rule Ordering Requirements

**CRITICAL**: Rule order matters in AWS WAF. Rules must be added in this exact sequence:

1. **First**: Anti-DDoS managed rule (MUST be first)
2. **Middle**: All converted custom rules and rate-based rules from Cloudflare (sequential priorities)
3. **Last**: 4 AWS managed rule groups in this order (sequential priorities after converted rules)

**Priority Assignment Logic**:
```
priority_counter = 0
1. Anti-DDoS rule → priority = priority_counter++
2. For each converted rule → priority = priority_counter++
3. IP Reputation List → priority = priority_counter++
4. Common Rule Set → priority = priority_counter++
5. Known Bad Inputs → priority = priority_counter++
6. SQLi Rule Set → priority = priority_counter++
```

**Example with 3 converted rules**:
- Priority 0: Anti-DDoS
- Priority 1-3: Converted rules
- Priority 4-7: AWS managed rule groups

**Example with 10 converted rules**:
- Priority 0: Anti-DDoS
- Priority 1-10: Converted rules
- Priority 11-14: AWS managed rule groups

---

## 1. Anti-DDoS Managed Rule (Always First)

**MUST be the first rule in the Web ACL** - needs complete traffic pattern visibility to establish accurate baseline.

**Override Action**: COUNT (for monitoring and false positive evaluation)

**Provider Requirement**: AWS Provider >= 6.2.0 (for `managed_rule_group_configs` support)

### Configuration A: Basic (for Website Web ACL)

Use default configuration without `managed_rule_group_configs`. Suitable for HTML pages and web assets.

```hcl
rule {
  name     = "AWS-AWSManagedRulesAntiDDoSRuleSet"
  priority = 0

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesAntiDDoSRuleSet"
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesAntiDDoSRuleSet"
  }
}
```

### Configuration B: Advanced (for API and File Web ACL)

Disables challenge action, sets block sensitivity to MEDIUM. For API endpoints and file downloads that cannot complete JavaScript challenges.

```hcl
rule {
  name     = "AWS-AWSManagedRulesAntiDDoSRuleSet"
  priority = 0

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesAntiDDoSRuleSet"

      managed_rule_group_configs {
        aws_managed_rules_anti_ddos_rule_set {
          client_side_action_config {
            challenge {
              usage_of_action = "DISABLED"
            }
          }
          sensitivity_to_block = "MEDIUM"
        }
      }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesAntiDDoSRuleSet"
  }
}
```

**Why Two Configurations?**

Binary files and API requests cannot complete JavaScript challenges. During DDoS events, challenge actions may incorrectly block legitimate API/file requests. 

**Best Practice**: Create two Web ACLs:
- Website Web ACL: Uses Configuration A (default challenge enabled)
- API/File Web ACL: Uses Configuration B (challenge disabled, higher block sensitivity)

---

## 2. IP Reputation List (First of 4 Managed Rules at End)

### Terraform HCL Format

```hcl
rule {
  name     = "AWS-AWSManagedRulesAmazonIpReputationList"
  priority = DYNAMIC  # Set to (last_converted_rule_priority + 1)

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesAmazonIpReputationList"
      
      # Optional: Add scope_down_statement here if skip rules exist
      # scope_down_statement {
      #   not_statement {
      #     statement {
      #       label_match_statement {
      #         scope = "LABEL"
      #         key   = "skip:http_request_firewall_managed"
      #       }
      #     }
      #   }
      # }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesAmazonIpReputationList"
  }
}
```

---

## 3. Common Rule Set (Second of 4 Managed Rules at End)

**Special Override**: `SizeRestrictions_BODY` rule is overridden to COUNT to prevent blocking legitimate file uploads.

### Terraform HCL Format

```hcl
rule {
  name     = "AWS-AWSManagedRulesCommonRuleSet"
  priority = DYNAMIC  # Set to (IP_Reputation_priority + 1)

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesCommonRuleSet"

      rule_action_override {
        name = "SizeRestrictions_BODY"
        action_to_use {
          count {}
        }
      }
      
      # Optional: Add scope_down_statement here if skip rules exist
      # scope_down_statement {
      #   not_statement {
      #     statement {
      #       label_match_statement {
      #         scope = "LABEL"
      #         key   = "skip:http_request_firewall_managed"
      #       }
      #     }
      #   }
      # }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesCommonRuleSet"
  }
}
```

---

## 4. Known Bad Inputs Rule Set (Third of 4 Managed Rules at End)

### Terraform HCL Format

```hcl
rule {
  name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
  priority = DYNAMIC  # Set to (CommonRuleSet_priority + 1)

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesKnownBadInputsRuleSet"
      
      # Optional: Add scope_down_statement here if skip rules exist
      # scope_down_statement {
      #   not_statement {
      #     statement {
      #       label_match_statement {
      #         scope = "LABEL"
      #         key   = "skip:http_request_firewall_managed"
      #       }
      #     }
      #   }
      # }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
  }
}
```

---

## 5. SQLi Rule Set (Last of 4 Managed Rules at End)

### Terraform HCL Format

```hcl
rule {
  name     = "AWS-AWSManagedRulesSQLiRuleSet"
  priority = DYNAMIC  # Set to (KnownBadInputs_priority + 1)

  override_action {
    count {}
  }

  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesSQLiRuleSet"
      version     = "Version_2.0"
      
      # Optional: Add scope_down_statement here if skip rules exist
      # scope_down_statement {
      #   not_statement {
      #     statement {
      #       label_match_statement {
      #         scope = "LABEL"
      #         key   = "skip:http_request_firewall_managed"
      #       }
      #     }
      #   }
      # }
    }
  }

  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "AWS-AWSManagedRulesSQLiRuleSet"
  }
}
```

---

## JSON to Terraform Field Mapping Reference

| AWS WAF JSON | Terraform HCL | Notes |
|--------------|---------------|-------|
| `Name` | `name` | Rule name |
| `Priority` | `priority` | Integer, dynamically assigned |
| `OverrideAction.Count` | `override_action { count {} }` | For managed rule groups |
| `Statement.ManagedRuleGroupStatement.VendorName` | `vendor_name` | Always "AWS" |
| `Statement.ManagedRuleGroupStatement.Name` | `name` | Rule group name |
| `Statement.ManagedRuleGroupStatement.Version` | `version` | Optional version |
| `Statement.ManagedRuleGroupStatement.RuleActionOverrides` | `rule_action_override` | Override specific rules |
| `Statement.ManagedRuleGroupStatement.ManagedRuleGroupConfigs` | `managed_rule_group_configs` | Advanced configs |
| `VisibilityConfig.SampledRequestsEnabled` | `sampled_requests_enabled` | Boolean |
| `VisibilityConfig.CloudWatchMetricsEnabled` | `cloudwatch_metrics_enabled` | Boolean |
| `VisibilityConfig.MetricName` | `metric_name` | Metric name string |

---

## Rationale

**Why not convert Cloudflare DDoS/Managed Rules?**
- Cloudflare and AWS WAF managed rules are not apple-to-apple equivalents
- Different detection mechanisms and rule logic
- No meaningful conversion possible
- Better to use AWS native managed rules with proper configuration

**Why COUNT mode for all managed rules?**
- Allows monitoring without blocking legitimate traffic
- Users can evaluate false positives in WAF logs
- Can switch to BLOCK mode after validation period

**Why this specific order?**
- Anti-DDoS first: Needs to see all traffic patterns to build accurate baseline
- Custom rules middle: User-specific logic
- AWS managed rules last: General protection after custom logic
