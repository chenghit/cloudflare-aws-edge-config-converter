[中文](./README_CN.md)

# Examples

## Cloudflare Configurations

`cloudflare-configs/` contains sample Cloudflare configurations for testing the migration tool. The configs cover 54 proxied domains with CDN rules (cache, redirect, rewrite, origin, header transform, compression, custom error, cloud connector, bulk redirects) + WAF rules (custom rules, rate limiting, IP access) across 12+ rule types, including regex expressions, OR conditions, geo-based routing, CORS, bulk redirects, inline error pages, and KV store data.

- `account/` — Account-level configurations (IP lists, ASN lists, hostname lists, bulk redirect lists, KV namespaces and data)
- `example.com/` — Zone-level configurations for a sample domain

All domain names, Cloudflare IDs, and IP addresses have been sanitized. IP addresses use RFC 5737 (`198.51.100.x`, `203.0.113.x`) and RFC 3849 (`2001:db8::x`) documentation ranges.

## How to Use

```bash
kiro-cli chat
```

Then reference the example configs:

```
Convert Cloudflare security rules in ./examples/cloudflare-configs/ to AWS WAF
Convert CDN configuration in ./examples/cloudflare-configs/ to CloudFront Terraform
Convert all Cloudflare configuration in ./examples/cloudflare-configs/ to AWS
```

## Before You Deploy

These example configs use `example.com` as the zone name, with subdomains like `cdn.c.example.com`, `www.c.example.com`, etc. If you only want to run the conversion pipeline and inspect the generated Terraform/JS output, you can use them as-is — no changes needed.

However, if you want to actually deploy the generated CloudFront distributions to AWS, you must replace the domain names with a real public domain you own:

1. Rename the zone directory and replace all domain references:
   ```bash
   cd examples/cloudflare-configs
   mv example.com yourdomain.com
   find . -name "*.txt" -exec sed -i '' 's/c\.example\.com/yourdomain.com/g' {} +
   find . -name "*.txt" -exec sed -i '' 's/example\.com/yourdomain.com/g' {} +
   ```
   On Linux, use `sed -i` instead of `sed -i ''`.
2. Make sure you have a valid ACM certificate for `*.yourdomain.com` in `us-east-1`. Terraform auto-discovers existing ISSUED certs via data source lookup.

The `account/` directory contains bulk redirect lists that reference domain names — the `find` commands above will update those as well.
