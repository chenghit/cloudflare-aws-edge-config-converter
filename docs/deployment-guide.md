[中文](./deployment-guide_CN.md)

# Deployment Guide

This guide explains the output structure and deployment steps for each pipeline.

## WAF Pipeline Output

```
cloudflare-to-aws-waf/
├── waf_ir_ip.json                  # IP lists + access rules IR
├── waf_ir_custom.json              # Custom rules IR
├── waf_ir_rate.json                # Rate-limiting rules IR
├── waf_ir.json                     # Merged IR (all rule types)
├── waf-cloudformation.json         # CloudFormation template (deploy this)
└── README_aws-waf-deployment.md    # Auto-generated deployment notes
```

### WAF deployment

WAF uses CloudFormation — one command deploys everything:

```bash
cd cloudflare-to-aws-waf
aws cloudformation deploy \
  --template-file waf-cloudformation.json \
  --stack-name cloudflare-waf-migration \
  --region us-east-1
```

The template contains all IP sets, two Web ACLs (website + API/file), and
managed rule groups. CloudFormation handles resource ordering automatically.

### WAF notes

- WAF resources with `Scope: CLOUDFRONT` must be in `us-east-1`.
- **Legacy mode** (≤50 ref statements per WebACL): Two Web ACLs — `waf-website` (search engine labeling + Anti-DDoS challenge + always-on challenge) and `waf-api-file` (Anti-DDoS challenge disabled, block sensitivity MEDIUM).
- **Per-domain mode** (auto-fallback when ref statements exceed 50 hard limit): One WebACL per proxied domain. All include search engine labeling, Anti-DDoS, and always-on challenge (Count mode). Customize per-domain after deployment — see the post-deployment checklist in `README_aws-waf-deployment.md`.
- All managed rules use Count mode for initial monitoring. Switch to Block after
  validating no false positives.
- Check `README_aws-waf-deployment.md` (auto-generated) for rule-specific notes,
  WCU summary, and non-convertible items.

---

## CDN Pipeline Output

```
cloudflare-to-aws-cdn/
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
            └── lambda/             # Only if a default-cache-TTL rule needs it
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

#### Step 2: Deploy each domain

Each domain is an independent root module. Deploy them in any order:

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
terraform init
terraform plan    # Review: check origins, cache policies, function associations
terraform apply
```

Repeat for each domain. Domains are independent — deploying or changing one
does not affect others.

The Lambda@Edge origin-response function (for the default cache-behavior TTL) is
fully automated — the scaffold generates the IAM role, archive, Lambda function,
and `qualified_arn` reference in `main.tf`. No manual ARN replacement needed.
That is the only Lambda@Edge this tool emits: there is no origin-request
function and no viewer-event Lambda@Edge — viewer logic is CloudFront-Functions
-only, and a CFF over the 10 KB limit is reported `SIZE_EXCEEDED` for you to
simplify or split the rules, never split to Lambda@Edge.

#### Step 3: Seed KVS data (if any)

If a domain has `kvs-data.json`, the KVS store is created by Terraform but the
data must be seeded separately. Each domain with KVS has a generated
`seed-kvs.py` script:

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
python3 seed-kvs.py
```

The script reads `kvs-data.json` and writes entries in batches of 50 via the
`update-keys` API. Requires `boto3` (`pip install boto3`) and AWS credentials.

#### Step 4: Validate deployment

Each domain has a generated `test-cdn-rules.py` script for post-deployment
validation. Run it against the CloudFront distribution domain:

```bash
cd cloudflare-to-aws-cdn/terraform/domains/cdn_example_com
python3 test-cdn-rules.py d111111abcdef8.cloudfront.net
```

The script tests redirects, error pages, bulk redirects, and response headers
using curl. Items that require manual testing (IP-based rules, geo conditions,
origin overrides) are listed as SKIP with instructions.

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
- **CloudFront Functions have a hard 10KB size limit.** If a function exceeds
  this even after minification, the whole domain is reported `SIZE_EXCEEDED` for
  human intervention — the tool does not split viewer logic to Lambda@Edge
  (viewer events are CloudFront-Functions-only). Simplify or split the Cloudflare
  rules for that host, or drop rules that can't fit.
- **CloudFront KVS has a default quota of 50 stores per account.** If you have
  more than 50 domains using bulk redirects, [request a quota increase](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html)
  before deploying.
- **Lambda@Edge IAM roles may survive `terraform destroy`.** Edge replicas are
  cleaned up asynchronously (can take hours). If you destroy and re-deploy,
  you may need to `terraform import` the existing role. See
  [Troubleshooting](./troubleshooting.md#lambda-at-edge-iam-role-not-destroyed).
