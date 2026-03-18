[中文](./README_CN.md)

# Examples

## Cloudflare Configurations

`cloudflare-configs/` contains sample Cloudflare configurations for testing the migration tool. The configs cover 7 proxied domains with 34 CDN rules + 8 WAF rules across 12 rule types, including regex expressions, OR conditions, geo-based routing, CORS, bulk redirects, and inline error pages.

- `account/` — Account-level configurations (IP lists, bulk redirect lists)
- `c.example.com/` — Zone-level configurations for a sample domain

## How to Use

```bash
kiro-cli chat
```

Then reference the example configs:

```
Convert Cloudflare security rules in ./examples/cloudflare-configs/ to AWS WAF
Convert CDN configuration in ./examples/cloudflare-configs/ to CloudFront Terraform
```

## Before You Deploy

These example configs use `c.example.com` as the zone name, with subdomains like `cdn.c.example.com`, `www.c.example.com`, etc. If you only want to run the conversion pipeline and inspect the generated Terraform/JS output, you can use them as-is — no changes needed.

However, if you want to actually deploy the generated CloudFront distributions to AWS, you must replace the domain names with a real public domain you own:

1. Rename the zone directory and replace all domain references:
   ```bash
   cd examples/cloudflare-configs
   mv c.example.com yourdomain.com
   find yourdomain.com -name "*.txt" -exec sed -i '' 's/c\.example\.com/yourdomain.com/g' {} +
   ```
   On Linux, use `sed -i` instead of `sed -i ''`.
2. Make sure you have a valid ACM certificate for `*.yourdomain.com` in `us-east-1`, provide the cert ARN to the tool or leave it blank in the CSV to let Terraform auto-discover it.

The `account/` directory does not contain domain-specific data and does not need modification.
