# Example Cloudflare Configurations

This directory contains sample Cloudflare configurations for testing the migration tool. The configs cover 7 proxied domains with 34 CDN rules + 8 WAF rules across 12 rule types, including regex expressions, OR conditions, geo-based routing, CORS, bulk redirects, and inline error pages.

## Before You Deploy

These example configs use `c.example.com` as the apex domain. If you only want to run the conversion pipeline and inspect the generated Terraform/JS output, you can use them as-is — no changes needed.

However, if you want to actually deploy the generated CloudFront distributions to AWS, you must replace the domain names with a real public domain you own:

1. Rename the zone directory: `c.example.com` → `c.yourdomain.com`
2. Replace `example.com` with `yourdomain.com` in all `.txt` files under the zone directory:
   ```bash
   cd examples/cloudflare-configs
   mv c.example.com c.yourdomain.com
   find c.yourdomain.com -name "*.txt" -exec sed -i '' 's/example\.com/yourdomain.com/g' {} +
   ```
   On Linux, use `sed -i` instead of `sed -i ''`.
3. Make sure you have a valid ACM certificate for `*.yourdomain.com` in `us-east-1`, or leave the cert ARN blank in the CSV to let Terraform auto-discover it.

The `account/` directory (IP lists, bulk redirect lists) does not contain domain-specific data and does not need modification.
