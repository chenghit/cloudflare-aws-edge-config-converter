# Non-Convertible Rules and Manual Intervention Requirements

This document explains which Cloudflare rules should NOT be automatically converted to AWS WAF and why.

## Important Distinction

**These rules are NOT converted because:**
- AWS WAF implementation differs significantly from Cloudflare
- They require manual configuration of AWS managed rule groups
- Automatic conversion would require complex decision-making about which managed rules to enable
- The configuration details are too nuanced for automated conversion

**NOT because AWS WAF doesn't support these features.**

## Rules Requiring Manual Intervention

### 1. Bot Detection Rules

**Cloudflare Fields:**
- `cf.verified_bot_category`
- `cf.bot_management.score`
- Known bots
- Bot score
- Any bot-related expressions

**Why Not Convert:**
- Cloudflare uses its own bot detection engine with specific categories and scoring
- AWS WAF Bot Control has different detection logic and rule structure
- Requires choosing protection level and potential SDK integration

**Manual Action Required:**
Enable AWS WAF Bot Control managed rule group. Select protection level (Common or Targeted) and implement client-side integration if using Targeted level.

### 2. Fraud Prevention Rules

**Cloudflare Fields:**
- `cf.waf.credential_check.password_leaked`
- `cf.waf.credential_check.username_leaked`
- `cf.waf.credential_check.similar_password_leaked`
- `cf.waf.credential_check.user_and_password_leaked`
- `cf.waf.credential_check.authentication_detected`
- `cf.waf.credential_check.disposable_email`

**Why Not Convert:**
- Cloudflare's credential stuffing detection is integrated into their WAF engine
- AWS WAF Fraud Control (ATP/ACFP) requires:
  - Separate managed rule group configuration
  - Integration with your application's login/registration endpoints
  - Custom request inspection configuration
  - Token acquisition and validation setup
- ATP (Account Takeover Prevention) and ACFP (Account Creation Fraud Prevention) have different implementation models

**Manual Action Required:**
Configure AWS WAF Fraud Control ATP and/or ACFP managed rule groups with proper endpoint mappings and inspection configurations.

### 3. WAF Attack Score Rules

**Cloudflare Fields:**
- `cf.waf.score` (overall attack score)
- `cf.waf.score.sqli` (SQLi attack score)
- `cf.waf.score.xss` (XSS attack score)
- `cf.waf.score.rce` (RCE attack score)

**Why Not Convert:**
- Cloudflare's attack scoring is proprietary
- AWS WAF Common Rule Set uses different detection patterns (signature-based rules)
- No direct mapping between score thresholds and AWS WAF rules

**Manual Action Required:**
The AWS WAF Common Rule Set (AWSManagedRulesCommonRuleSet) is already included in the generated Terraform. Consider enabling AWS WAF Bot Control managed rule group for additional attack detection capabilities.

**Note:** AWS documentation sometimes refers to the Common Rule Set as "Core Rule Set (CRS)" - these are the same managed rule group.

## Summary Table

| Cloudflare Feature | AWS WAF Equivalent | Conversion Status | Reason |
|-------------------|-------------------|-------------------|---------|
| Bot detection | Bot Control managed rule group | ❌ Not converted | Different detection logic, requires level selection and potential SDK integration |
| Fraud prevention | Fraud Control ATP/ACFP | ❌ Not converted | Different implementation model, requires endpoint mapping |
| Attack scores | Common Rule Set (already included) | ❌ Not converted | No direct score mapping, different detection approach |
| Managed rules | AWS managed rule groups | ❌ Not converted | Provider-specific, no direct mapping |
| DDoS protection | Shield + rate-based rules | ❌ Not converted | Different architecture, requires separate configuration |

## Conversion Workflow Impact

When generating the Markdown summary (Step 4), clearly state:

**"These rules require manual intervention because AWS WAF implements these features differently, requiring manual configuration of managed rule groups. This is NOT because AWS WAF lacks these capabilities."**

For each non-convertible rule, explain:
1. Cloudflare feature used
2. AWS WAF equivalent
3. Why automatic conversion is not feasible
4. Manual steps needed
