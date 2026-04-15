#!/usr/bin/env python3
"""waf-generate-readme.py — Generate WAF deployment README.

Reads waf_ir.json and waf-cloudformation.json for deployment guide,
non-convertible notes, and WCU summary.

Usage:
    python3 waf-generate-readme.py <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os


def main():
    if len(sys.argv) < 2:
        print("Usage: waf-generate-readme.py <output_dir>", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
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
        "# AWS WAF CloudFormation Deployment Guide",
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
        "- AWS CLI v2",
        "- AWS credentials with WAFv2 and CloudFormation permissions",
        "- Region: `us-east-1` (required for CloudFront-scoped WAF resources)",
        "",
        "## Deployment Steps",
        "",
        "### 1. Set AWS credentials",
        "```bash",
        "export AWS_PROFILE=<your-profile-name>",
        "```",
        "",
        "### 2. Deploy the CloudFormation stack",
        "```bash",
        f"cd {output_dir}",
        "aws cloudformation deploy \\",
        "  --template-file waf-cloudformation.json \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1",
        "```",
        "",
        "### 3. Check deployment status",
        "```bash",
        "aws cloudformation describe-stacks \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1 \\",
        '  --query "Stacks[0].StackStatus"',
        "```",
        "",
        "### 4. Associate Web ACL with CloudFront",
        "",
        "After deployment, get the Web ACL ARNs from stack outputs:",
        "```bash",
        "aws cloudformation describe-stacks \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1 \\",
        '  --query "Stacks[0].Outputs"',
        "```",
        "",
        "Associate the appropriate Web ACL with your CloudFront distribution:",
        "```bash",
        "aws wafv2 associate-web-acl \\",
        '  --web-acl-arn "<WEB_ACL_ARN>" \\',
        '  --resource-arn "arn:aws:cloudfront::<ACCOUNT_ID>:distribution/<DIST_ID>"',
        "```",
        "",
        "### 5. Update or destroy",
        "```bash",
        "# Update (re-run after regenerating template)",
        "aws cloudformation deploy \\",
        "  --template-file waf-cloudformation.json \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1",
        "",
        "# Destroy all resources",
        "aws cloudformation delete-stack \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1",
        "```",
        "",
        "## Important Notes",
        "",
        "- **Region**: All WAFv2 resources with `Scope: CLOUDFRONT` must be in `us-east-1`.",
        "- **Two Web ACLs** are generated:",
        "  - `waf-website`: For website traffic (Anti-DDoS challenge enabled)",
        "  - `waf-api-file`: For API/file traffic (Anti-DDoS challenge disabled, block sensitivity MEDIUM)",
        "  - Rules with `challenge` or `captcha` actions apply to both — review whether these are appropriate for your API endpoints.",
        "- **All managed rules use Count mode** for initial monitoring. Switch to Block after validating no false positives.",
        "- **IP sets quota**: Default 100 IP sets per account per region.",
        "- **Rate-based rules**: AWS WAF minimum rate limit is 10 requests per evaluation window.",
        "",
        "## Migration from Terraform",
        "",
        "If you previously deployed WAF resources with the Terraform version of this tool:",
        "1. Run `terraform destroy` in the old `cloudflare-to-aws-waf/` directory to remove old resources",
        "2. Then deploy with CloudFormation using the steps above",
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
            "included in the generated CloudFormation template. Manual configuration is required.",
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
            "reference Cloudflare-specific fields. Review the generated CloudFormation template and "
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

    out_path = os.path.join(output_dir, "README_aws-waf-deployment.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"OK: {out_path} → {len(nc_notes)} non-convertible, "
          f"{len(partial_rules)} partial rules")


if __name__ == "__main__":
    main()
