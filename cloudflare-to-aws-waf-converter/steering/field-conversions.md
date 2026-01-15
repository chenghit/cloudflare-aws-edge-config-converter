# Field Conversions and IP/ASN Handling

This document covers how to convert Cloudflare fields to AWS WAF statements.

## IP Address Handling

### Inline IP Lists

Cloudflare supports inline lists with multiple formats:
- Individual IPs: `ip.src in {198.51.100.1 198.51.100.5}`
- IP ranges: `ip.src in {198.51.100.3..198.51.100.7}`
- CIDR notation: `ip.src in {192.0.2.0/24 2001:0db8::/32}`
- Mixed: `ip.src in {198.51.100.1 198.51.100.3..198.51.100.7 192.0.2.0/24}`

**Conversion steps:**

1. **Expand IP ranges to CIDR blocks:**
   - `198.51.100.3..198.51.100.7` → `198.51.100.3/32, 198.51.100.4/32, 198.51.100.5/32, 198.51.100.6/32, 198.51.100.7/32`
   - Or aggregate to CIDR when possible: `198.51.100.0..198.51.100.255` → `198.51.100.0/24`

2. **Create IP set resource:**
   - **CRITICAL**: Each distinct inline IP list in a rule MUST have its own IP set with a unique, descriptive name
   - Name format for rules with single inline list: `<rule-name-slug>-ipv4` / `<rule-name-slug>-ipv6`
   - Name format for rules with multiple inline lists after cascading split: `<rule-name-slug>-branch-<N>-<context>-ipv4` / `<rule-name-slug>-branch-<N>-<context>-ipv6`
     - `<context>` should describe what the IP list is for (e.g., country code, condition purpose)
     - Example: For a skip rule with DZ and CO conditions (top-level OR), after cascading split:
       - Branch 1: `skip-rule-branch-1-dz-ipv4` and `skip-rule-branch-1-dz-ipv6`
       - Branch 2: `skip-rule-branch-2-co-ipv4` and `skip-rule-branch-2-co-ipv6`
   - For named lists: `<list_name>-ipv4` / `<list_name>-ipv6`
   - **Never reuse the same IP set for different inline lists**, even within the same rule

3. **Reference in rule:**
   ```hcl
   statement {
     ip_set_reference_statement {
       arn = aws_wafv2_ip_set.skip_rule_branch_1_dz_ipv4.arn
     }
   }
   ```

**Example: Rule with top-level OR and multiple inline IP lists (requires cascading split)**

Cloudflare expression:
```
(ip.src.country eq "DZ" and ip.src in {200.1.1.1 200.1.1.2 2000::1 2000::2}) or 
(ip.src.country eq "CO" and not ip.src in {100.1.1.1 100.1.1.2 2001::1 2001::2})
```

Phase 1 - Split by OR:
- Branch 1: `country eq "DZ" and ip in {ipv4, ipv6}`
- Branch 2: `country eq "CO" and NOT ip in {ipv4, ipv6}`

Phase 2 - Split each branch by IPv4/IPv6, create separate IP sets:
- Branch 1 IPv4: `skip-rule-branch-1-dz-ipv4` → `[200.1.1.1/32, 200.1.1.2/32]`
- Branch 1 IPv6: `skip-rule-branch-1-dz-ipv6` → `[2000::1/128, 2000::2/128]`
- Branch 2 IPv4: `skip-rule-branch-2-co-ipv4` → `[100.1.1.1/32, 100.1.1.2/32]`
- Branch 2 IPv6: `skip-rule-branch-2-co-ipv6` → `[2001::1/128, 2001::2/128]`

**Result: 4 rules, 4 IP sets**

**DO NOT** combine different branches into one IP set.

### Inline ASN Lists

Cloudflare: `ip.geoip.asnum in {1234 5678}`

AWS WAF: Use inline `asn_match_statement` (no separate resource):

```hcl
statement {
  asn_match_statement {
    asn_list = [1234, 5678]
  }
}
```

### Named IP/ASN Lists

For lists referenced by name (e.g., `$office_network`):

1. Read list items from `List-Items-ip-<name>.txt` or `List-Items-asn-<name>.txt`
2. Create AWS WAF IP set (for IP lists) or use `asn_match_statement` (for ASN lists)
3. Split mixed IPv4/IPv6 lists into two IP sets

### IPv4 and IPv6 Separation

**CRITICAL: Always split mixed IPv4/IPv6 lists into separate rules.**

AWS WAF IP sets must specify IP version. Cloudflare lists can contain both.

**Strategy:**
- Create 2 IP sets: `<name>-ipv4` and `<name>-ipv6`
- Create 2 AWS WAF rules: one for IPv4, one for IPv6
- Both rules use the same action and RuleLabels (for skip rules)

**Example:**

Cloudflare: `(ip.src.country eq "CN" and ip.src in {ipv4_list, ipv6_list})`

Split into:

```hcl
# Rule 1: IPv4 variant
rule {
  name     = "rule-name-ipv4"
  priority = N
  action { block {} }
  statement {
    and_statement {
      statement { geo_match_statement { country_codes = ["CN"] } }
      statement { ip_set_reference_statement { arn = aws_wafv2_ip_set.list_name_ipv4.arn } }
    }
  }
}

# Rule 2: IPv6 variant
rule {
  name     = "rule-name-ipv6"
  priority = N+1
  action { block {} }
  statement {
    and_statement {
      statement { geo_match_statement { country_codes = ["CN"] } }
      statement { ip_set_reference_statement { arn = aws_wafv2_ip_set.list_name_ipv6.arn } }
    }
  }
}
```

**Benefits:**
- Maximum 2 nesting levels
- No risk of exceeding 3-level limit
- Clear, maintainable code

**For negative matching:**
- Still split into 2 rules
- Each rule applies De Morgan's Law to its own IP set
- Example: `not ip.src in {list}` becomes:
  - Rule 1: `NOT ipv4_set`
  - Rule 2: `NOT ipv6_set`

**WRONG - Do NOT attempt to combine IPv4/IPv6 in one rule:**

```hcl
# This creates nesting depth or same-type nesting errors
statement {
  and_statement {
    statement { geo_match {} }
    statement {
      or_statement {  # ← Creates 4 levels or OR-in-OR
        statement { ip_set ipv4 }
        statement { ip_set ipv6 }
      }
    }
  }
}
```

## ASN Support

AWS WAF supports ASN matching for Cloudflare "AS Num" field.

**Cloudflare format:** ASN lists stored in IP Lists with `kind: "asn"`

**AWS WAF format:** Use AsnMatchStatement

**AWS WAF JSON example:**

```json
{
  "Name": "block-asn",
  "Priority": 7,
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-asn"
  },
  "Statement": {
    "AsnMatchStatement": {
      "AsnList": [1234, 5678]
    }
  }
}
```

**Terraform example:**

```hcl
rule {
  name     = "block-asn"
  priority = 7
  action { block {} }
  statement {
    asn_match_statement {
      asn_list = [1234, 5678]
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "block-asn"
    sampled_requests_enabled   = true
  }
}
```

## Unsupported Fields

### Geographic Fields

- **Continent matching**: Not supported. Workaround: CloudFront Function with lat/long headers
- **European Union**: Not supported. Workaround: CloudFront Function with EU country list

### Connection Fields

- **SSL/HTTPS**: Not supported. Workaround: CloudFront config or Function with `CloudFront-Viewer-TLS`
- **HTTP Version**: Not supported. Workaround: CloudFront Function with `CloudFront-Viewer-Http-Version`

### Security Score Fields

Not supported in AWS WAF:
- SQLi Attack Score
- XSS Attack Score
- RCE Attack Score
- Attack Score

### Bot Detection

**Do not convert** bot-related fields:
- Known bots
- Verified Bot Category
- Bot score

**Workaround:** Use AWS WAF Bot Control managed rule group.

### Fraud Prevention

**Do not convert** these fields:
- Disposable email check
- Authentication detected
- Username/password leaked checks

**Workaround:** Use AWS WAF Fraud Control ATP/ACFP managed rule groups.

### Other Unsupported

- API Abuse (Fallthrough detected)
- Client Certificate Verified
- MIME Type

## Field Mapping Reference

| Cloudflare Field | AWS WAF Support | Notes |
|-----------------|-----------------|-------|
| IP address | ✓ | Use IP sets, separate v4/v6 |
| AS Num | ✓ | Use AsnMatchStatement |
| Country | ✓ | Use GeoMatchStatement |
| Continent | ✗ | Use CloudFront Function |
| URI path | ✓ | Use UriPath match |
| Query string | ✓ | Use QueryString match |
| HTTP method | ✓ | Use Method match |
| Headers | ✓ | Use Headers match |
| Hostname | ✓ | Use SingleHeader match |
| User Agent | ✓ | Use SingleHeader match |
| X-Forward-For | ✓ | Use SingleHeader match |
| Referer | ✓ | Use SingleHeader match |
| Cookie | ✓ | Use Cookies match |
| SSL/HTTPS | ✗ | Use CloudFront config/function |
| HTTP Version | ✗ | Use CloudFront Function |
| Client Certificate Verified | ✗ | Not supported |
| MIME Type | ✗ | Not supported |
| Known bots | ✗ | Use Bot Control managed rule |
| Verified bot category | ✗ | Use Bot Control managed rule |
| Attack scores | ✗ | Not supported |
| Bot score | ✗ | Not supported |
| Fraud prevention fields | ✗ | Use Fraud Control managed rules |
| Response code | ✗ | Not supported |
| Response header | ✗ | Not supported |
