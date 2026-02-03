# Terraform Module Architecture

## Problem: IP Set Name Conflicts

AWS WAF IP set names must be globally unique within the same scope (CLOUDFRONT). When using modules, each module instance tries to create IP sets with the same names, causing `WAFDuplicateItemException` errors.

## Solution: Shared IP Sets at Root Level

IP sets are created once at the root module level and shared between both Web ACL modules via variable passing.

## File Structure

```
waf-terraform/
├── versions.tf           # Terraform and provider versions
├── ip_sets.tf           # All IP set resources (shared)
├── main.tf              # Module calls with IP set ARN map
└── modules/waf/
    ├── main.tf          # Web ACL definition only
    ├── variables.tf     # Includes ip_set_arns variable
    └── outputs.tf       # Web ACL ARN and ID
```

## Data Flow

```
ip_sets.tf
  ↓ (creates IP sets)
  ↓
main.tf (root)
  ↓ (builds locals.ip_set_arns map)
  ↓
  ├─→ module.waf_website (receives ip_set_arns)
  │     ↓ (references via var.ip_set_arns["name"])
  │     └─→ Web ACL 1
  │
  └─→ module.waf_api_file (receives ip_set_arns)
        ↓ (references via var.ip_set_arns["name"])
        └─→ Web ACL 2
```

## Key Implementation Details

### Root `ip_sets.tf`

Contains all IP set resources:

```hcl
resource "aws_wafv2_ip_set" "block_list_1_ipv4" {
  name               = "block-list-1-ipv4"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = ["100.0.0.0/24"]
}
```

### Root `main.tf`

Creates ARN map and passes to modules:

```hcl
locals {
  ip_set_arns = {
    block_list_1_ipv4 = aws_wafv2_ip_set.block_list_1_ipv4.arn
    # ... all other IP sets
  }
}

module "waf_website" {
  source      = "./modules/waf"
  ip_set_arns = local.ip_set_arns
  # ... other variables
}

module "waf_api_file" {
  source      = "./modules/waf"
  ip_set_arns = local.ip_set_arns  # Same map
  # ... other variables
}
```

### Module `variables.tf`

Accepts IP set ARN map:

```hcl
variable "ip_set_arns" {
  type        = map(string)
  description = "Map of IP set names to ARNs"
}
```

### Module `main.tf`

References IP sets via variable:

```hcl
resource "aws_wafv2_web_acl" "main" {
  # ...
  rule {
    statement {
      ip_set_reference_statement {
        arn = var.ip_set_arns["block_list_1_ipv4"]  # Not direct resource reference
      }
    }
  }
}
```

## Benefits

1. **No duplicate IP sets** - Created once, shared by both Web ACLs
2. **Single source of truth** - IP addresses defined in one place
3. **Reduced resource count** - Half the IP sets compared to duplicated approach
4. **Easier maintenance** - Update IP addresses in one file
5. **Cost efficiency** - AWS WAF charges per IP set, this reduces the count
