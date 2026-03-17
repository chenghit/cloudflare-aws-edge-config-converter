[中文](./deployment-guide_CN.md)

# Deployment Guide

This guide explains the output structure and deployment steps for each pipeline.

## WAF Pipeline Output

```
cloudflare-to-aws-waf/
├── waf_ir.json                             # Structured IR (input to generator)
├── versions.tf                             # Provider version constraints
├── ip_sets.tf                              # Shared IP sets (referenced by both ACLs)
├── main.tf                                 # Locals + two module calls (website + api-and-file)
├── modules/
│   └── waf/
│       ├── main.tf                         # Web ACL resource definition
│       ├── variables.tf                    # Module input variables
│       └── outputs.tf                      # Module outputs
└── README_aws-waf-terraform-deployment.md  # Auto-generated deployment notes
```

### WAF deployment

WAF is a single root module — one `terraform apply` deploys everything:

```bash
cd cloudflare-to-aws-waf
terraform init
terraform plan    # Review the plan carefully
terraform apply
```

The root `main.tf` calls the `modules/waf/` module twice — once for the website
Web ACL and once for the API/file Web ACL. Shared IP sets are defined at root
level and passed into both module calls.

### WAF notes

- WAF resources are regional. Set your AWS provider region to match where your
  ALB/API Gateway lives, or use `us-east-1` for CloudFront-associated WAFs.
- Review `ip_sets.tf` — IP addresses from Cloudflare rules are converted
  directly. Verify they are still correct for your AWS environment.
- Check `README_aws-waf-terraform-deployment.md` (auto-generated) for
  rule-specific notes from the conversion.

---

## CDN Pipeline Output

```
cloudflare-to-aws-cdn/
├── user_input_template.csv          # Fill this in, save as user_input.csv
├── dns_manifest.yaml                # Parsed DNS records
├── domain_scope.json                # Validated domain settings
├── conversion_report.md             # Non-convertible rules + warnings
├── ir/                              # Intermediate representation (debug only)
│   ├── accumulator/                 # Per-domain IR before finalization
│   ├── final/                       # Sorted, deduplicated IR
│   └── validation/                  # V1, V2, V3 validator reports
└── terraform/
    ├── modules/
    │   └── cloudfront_distribution/ # Shared module (do not edit)
    ├── shared/
    │   └── policies.tf              # Deduplicated CachePolicy, ORP, RHP resources + outputs
    └── domains/
        └── <sanitized_hostname>/
            ├── main.tf              # Module call to cloudfront_distribution
            ├── outputs.tf           # distribution_id, domain_name, hosted_zone_id
            ├── functions.tf         # aws_cloudfront_function resources
            ├── kvs.tf              # KVS store (only if bulk redirects exist)
            ├── kvs-data.json       # KVS seed data (only if bulk redirects exist)
            ├── functions/
            │   ├── <name>_viewer_request.js
            │   └── <name>_viewer_response.js   # Only if response header ops exist
            └── lambda/             # Only if CloudFront Function exceeded 10KB
                ├── origin_request_handler.js
                └── default_cache_origin_response.js
```

### CDN deployment order

The CDN output uses independent Terraform root modules. **Deploy in this order:**

#### Step 1: Deploy shared policies

```bash
cd cloudflare-to-aws-cdn/terraform/shared
terraform init
terraform plan
terraform apply
```

This creates all deduplicated CloudFront cache policies, origin request policies,
and response headers policies. Domain modules look up these policies by name
using `data` sources — they must exist before any domain is deployed.

#### Step 2: Deploy Lambda@Edge functions (if any)

If any domain has a `lambda/` directory, you must deploy those Lambda functions
to AWS **before** applying the domain's Terraform. Lambda@Edge has special
requirements:

- Must be deployed in **us-east-1** (Lambda@Edge is a global service but
  functions must be created in N. Virginia)
- The Terraform output uses `REPLACE_WITH_DEPLOYED_LAMBDA_ARN` placeholders —
  after deploying each Lambda, replace the placeholder in `main.tf` with the
  actual ARN (including version number, e.g.,
  `arn:aws:lambda:us-east-1:123456789:function:my-func:1`)

If no domain has a `lambda/` directory, skip this step.

#### Step 3: Deploy each domain

Each domain is an independent root module. Deploy them in any order:

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
terraform init
terraform plan    # Review: check origins, cache policies, function associations
terraform apply
```

Repeat for each domain. Domains are independent — deploying or changing one
does not affect others.

#### Step 4: Seed KVS data (if any)

If a domain has `kvs-data.json`, the KVS store is created by Terraform but the
data must be seeded separately. Use the AWS CLI:

```bash
# For each entry in kvs-data.json:
aws cloudfront-keyvaluestore put-key \
  --kvs-arn <kvs_arn_from_terraform_output> \
  --key "redirect:example.com/old-path" \
  --value "301|0|https://example.com/new-path"
```

Or write a script to iterate over `kvs-data.json` entries.

#### Step 5: Update DNS

After verifying each CloudFront distribution is working:

1. Get the distribution domain name from Terraform output (e.g.,
   `d111111abcdef8.cloudfront.net`)
2. Update your DNS records to point to the CloudFront distribution:
   - For apex domains: Route 53 ALIAS record or CNAME flattening
   - For subdomains: CNAME record

### CDN notes

- **Review `conversion_report.md`** before deploying. It lists all rules that
  could not be converted and may need manual attention.
- **The `ir/` directory is for debugging only.** You don't need it for
  deployment. It contains the intermediate representation and validation
  reports used during conversion.
- **The shared module (`modules/cloudfront_distribution/`) should not be
  edited.** It's a generic wrapper — all domain-specific configuration is in
  each domain's `main.tf`.
- **CloudFront Functions have a 10KB size limit.** If a function exceeds this,
  the pipeline splits origin_override logic to Lambda@Edge origin-request.
  Remaining viewer-event ops that still don't fit are marked non-convertible.
  Check the `lambda/` directory in each domain for origin-event handlers.
- **CloudFront KVS has a default quota of 50 stores per account.** If you have
  more than 50 domains using bulk redirects, [request a quota increase](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)
  before deploying.
