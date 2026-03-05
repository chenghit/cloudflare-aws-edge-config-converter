# Limitations and Caveats

## Content Not Converted

* **Managed Rules** — Cloudflare-specific managed rules (e.g., API Abuse Detection) have no direct equivalent in AWS WAF. Use AWS WAF's own managed rule groups instead (Anti-DDoS, Core Rule Set, Bot Control, etc.). These standardized configurations don't require AI conversion.

* **Page Rules (Deprecated)** — Cloudflare has deprecated Page Rules. First migrate to modern rule types in Cloudflare (Redirect Rules, URL Rewrite Rules, etc.), then use this tool.

* **Snippets and Workers** — Custom JavaScript/TypeScript functions, not configuration rules. Manual conversion required — review logic and rewrite as CloudFront Functions or Lambda@Edge.

* **SaaS and mTLS Configurations** — Complex multi-tenant and certificate management configurations require manual architecture design. Cloudflare Custom Hostnames and CloudFront SaaS have fundamentally different implementation models.

* **Image Optimization and Advanced Features** — CloudFront doesn't natively support Cloudflare's Image Optimization, Zaraz, etc. Deploy AWS solutions separately (e.g., Dynamic Image Transformation for Amazon CloudFront).

* **Some Advanced Transformation Rules** — Cloudflare and CloudFront features are not one-to-one. Tool will list unconvertible rules and alternatives in generated documentation.

## Large-Scale Configurations

* **Token Consumption** — Increases significantly with > 100 rules. Use `claude-sonnet-4.6-1m` model, or convert in batches.
* **Conversion Time** — More rules = longer time. Typical: ~5-10 minutes for 50 rules.

## Conversion Accuracy

* **Manual Review Required** — AI-generated configurations require manual review, especially for complex conditional logic and regular expressions. Validate in test environment first.
* **Edge Cases** — Some complex nested conditions may require manual adjustment. Tool will mark areas requiring attention.
