#!/usr/bin/env python3
"""waf-generate-readme.py — Generate WAF deployment README.

Reads waf_ir.json for non-convertible notes and partial/no-convert rules,
generates README_aws-waf-terraform-deployment.md with deployment steps
and manual action items.

Usage:
    python3 waf-generate-readme.py <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os


def main():
    if len(sys.argv) < 2:
        print("Usage: waf-generate-readme.py <output_dir>", file=sys.stderr)
        sys.exit(1)

    output_dir = sys.argv[1]
    ir_path = os.path.join(output_dir, "waf_ir.json")

    if not os.path.exists(ir_path):
        print(f"ERROR: {ir_path} not found", file=sys.stderr)
        sys.exit(1)

    with open(ir_path) as f:
        ir = json.load(f)

    # Collect non-convertible notes
    nc_notes = ir.get("non_convertible_notes", [])

    # Collect partial/no rules across all sections
    partial_rules = []
    for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        s = ir.get(section, {})
        if not isinstance(s, dict):
            continue
        for rule in s.get("rules", []):
            conv = rule.get("convertibility", "yes")
            if conv == "partial":
                partial_rules.append({
                    "name": rule.get("name", ""),
                    "convertibility": conv,
                    "reason": rule.get("non_convertible_reason", ""),
                    "section": section,
                })

    # Count rules
    ip_count = ir.get("ip_access_rules", {}).get("count", 0)
    custom_count = ir.get("custom_rules", {}).get("count", 0)
    rate_count = ir.get("rate_limiting_rules", {}).get("count", 0)
    ip_lists_count = len([l for l in ir.get("ip_lists", [])
                          if l.get("conversion") == "ip_set"])

    lines = [
        "# AWS WAF Terraform Deployment Guide",
        "",
        "## Overview",
        "",
        f"- IP lists converted: {ip_lists_count}",
        f"- IP access rules: {ip_count}",
        f"- Custom rules: {custom_count}",
        f"- Rate limiting rules: {rate_count}",
        f"- Non-convertible items: {len(nc_notes)}",
        f"- Partially converted rules: {len([r for r in partial_rules if r['convertibility'] == 'partial'])}",
        "",
        "## Prerequisites",
        "",
        "- Terraform >= 1.8.0",
        "- AWS Provider >= 6.0",
        "- AWS credentials with WAF, IAM, and CloudFront permissions",
        "",
        "## Deployment Steps",
        "",
        "### 1. Set AWS credentials",
        "```bash",
        "export AWS_PROFILE=<your-profile-name>",
        "```",
        "",
        "### 2. Initialize and deploy",
        "```bash",
        f"cd {output_dir}",
        "terraform init",
        "terraform plan    # Review changes before applying",
        "terraform apply",
        "```",
        "",
        "### 3. Associate Web ACL with CloudFront",
        "",
        "After deployment, associate the Web ACL with your CloudFront distribution:",
        "```bash",
        "# Get the Web ACL ARN from terraform output",
        "terraform output",
        "",
        "# Associate via AWS Console or CLI:",
        "aws wafv2 associate-web-acl \\",
        '  --web-acl-arn "<WEB_ACL_ARN>" \\',
        '  --resource-arn "<CLOUDFRONT_DISTRIBUTION_ARN>"',
        "```",
        "",
        "Or add to your CloudFront distribution Terraform:",
        "```hcl",
        'web_acl_id = "<WEB_ACL_ARN>"',
        "```",
        "",
        "## Important Notes",
        "",
        "- **Two Web ACLs** are generated: one for website traffic (challenge actions enabled) "
        "and one for API/file traffic (challenge actions disabled, using block instead). "
        "Associate the appropriate ACL based on your traffic type.",
        "- **IP sets quota**: Default 100 IP sets per account per region. "
        "Request increase via AWS Service Quotas if needed.",
        "- **Rate-based rules**: AWS WAF minimum rate limit is 10 requests per evaluation window. "
        "Rules with very low Cloudflare thresholds are adjusted to meet this minimum.",
        "",
    ]

    # Non-convertible items
    if nc_notes or partial_rules:
        lines += [
            "## Items Requiring Manual Action",
            "",
        ]

    if nc_notes:
        lines += [
            "### Non-Convertible Rules",
            "",
            "These Cloudflare features have no direct AWS WAF equivalent and were not "
            "included in the generated Terraform. Manual configuration is required.",
            "",
            "| Rule | Field | Reason | AWS Equivalent | Manual Action |",
            "|------|-------|--------|----------------|---------------|",
        ]
        for n in nc_notes:
            lines.append(
                f"| {n.get('rule', '')} "
                f"| `{n.get('field', '')}` "
                f"| {n.get('reason', '')} "
                f"| {n.get('aws_equivalent', '')} "
                f"| {n.get('manual_action', '')} |"
            )
        lines.append("")

    if partial_rules:
        lines += [
            "### Partially Converted Rules",
            "",
            "These rules were converted but some conditions were removed because they "
            "reference Cloudflare-specific fields. Review the generated Terraform and "
            "add equivalent AWS WAF conditions where possible.",
            "",
            "| Rule | Section | Convertibility | Removed Condition |",
            "|------|---------|---------------|-------------------|",
        ]
        for r in partial_rules:
            section_label = r["section"].replace("_", " ").title()
            lines.append(
                f"| {r['name']} "
                f"| {section_label} "
                f"| {r['convertibility']} "
                f"| {r['reason']} |"
            )
        lines.append("")

    out_path = os.path.join(output_dir, "README_aws-waf-terraform-deployment.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"OK: {out_path} → {len(nc_notes)} non-convertible, "
          f"{len(partial_rules)} partial rules")


if __name__ == "__main__":
    main()
