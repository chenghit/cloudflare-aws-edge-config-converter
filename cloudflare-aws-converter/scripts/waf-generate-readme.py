#!/usr/bin/env python3
"""waf-generate-readme.py — Generate WAF deployment README.

Reads waf_ir.json (or waf_ir_split.json), waf_split_decision.json,
and waf-cloudformation.json for deployment guide.

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

    # Check split mode
    decision_path = os.path.join(output_dir, "waf_split_decision.json")
    mode = "legacy"
    dedup = False
    if os.path.exists(decision_path):
        with open(decision_path) as f:
            decision = json.load(f)
        mode = decision.get("mode", "legacy")
        dedup = decision.get("dedup", False)

    # Read CloudFormation template for WebACL names
    cfn_path = os.path.join(output_dir, "waf-cloudformation.json")
    webacl_names = []
    if os.path.exists(cfn_path):
        with open(cfn_path) as f:
            cfn = json.load(f)
        for lid, res in cfn.get("Resources", {}).items():
            if res.get("Type") == "AWS::WAFv2::WebACL":
                webacl_names.append(res["Properties"]["Name"])

    # Collect non-convertible notes and partial rules
    nc_notes = ir.get("non_convertible_notes", [])
    partial_rules = []
    for section in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        s = ir.get(section, {})
        if not isinstance(s, dict):
            continue
        for rule in s.get("rules", []):
            if rule.get("convertibility") == "partial":
                partial_rules.append({
                    "name": rule.get("name", ""),
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
        f"- Mode: **{'per-domain WebACLs' if mode == 'split' else 'legacy (2 WebACLs)'}**",
        f"- WebACLs: {len(webacl_names)}",
        f"- IP lists converted: {ip_lists_count}",
        f"- IP access rules: {ip_count}",
        f"- Custom rules: {custom_count}",
        f"- Rate limiting rules: {rate_count}",
        f"- Non-convertible items: {len(nc_notes)}",
        f"- Partially converted rules: {len(partial_rules)}",
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
        f"cd cloudflare-to-aws-waf",
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
        "### 4. Associate Web ACLs with CloudFront distributions",
        "",
        "Get the Web ACL ARNs from stack outputs:",
        "```bash",
        "aws cloudformation describe-stacks \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1 \\",
        '  --query "Stacks[0].Outputs"',
        "```",
        "",
    ]

    if mode == "split":
        lines += [
            "Associate each domain's Web ACL with its CloudFront distribution:",
            "```bash",
            "aws wafv2 associate-web-acl \\",
            '  --web-acl-arn "<DOMAIN_WEB_ACL_ARN>" \\',
            '  --resource-arn "arn:aws:cloudfront::<ACCOUNT_ID>:distribution/<DIST_ID>"',
            "```",
            "",
            "WebACL → domain mapping:",
            "",
            "| WebACL Name | Domain |",
            "|-------------|--------|",
        ]
        for name in sorted(webacl_names):
            domain = name.replace("_", ".")
            lines.append(f"| `{name}` | {domain} |")
        lines.append("")
    else:
        lines += [
            "Associate the appropriate Web ACL with your CloudFront distribution:",
            "```bash",
            "aws wafv2 associate-web-acl \\",
            '  --web-acl-arn "<WEB_ACL_ARN>" \\',
            '  --resource-arn "arn:aws:cloudfront::<ACCOUNT_ID>:distribution/<DIST_ID>"',
            "```",
            "",
        ]

    lines += [
        "### 5. Update or destroy",
        "```bash",
        "# Update",
        "aws cloudformation deploy \\",
        "  --template-file waf-cloudformation.json \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1",
        "",
        "# Destroy",
        "aws cloudformation delete-stack \\",
        "  --stack-name cloudflare-waf-migration \\",
        "  --region us-east-1",
        "```",
        "",
    ]

    # Post-deployment checklist
    lines += [
        "## ⚠️ Post-Deployment Checklist",
        "",
        "### always-on-challenge rule",
        "",
        "The `always-on-challenge` rule is deployed with **Count action** (monitoring only). "
        "It does NOT protect against DDoS until you change it.",
        "",
        "1. **Web-facing domains**: Change the `always-on-challenge` rule's action from "
        "Count to **Challenge**. Add your landing page paths (e.g., `/pricing`, `/about`, "
        "`/register`) to the rule's URI list.",
        "2. **Mixed domains** (web frontend + API backend): Same as #1, but also ensure "
        "all API paths are excluded from challenge rules. API clients cannot solve "
        "challenges — unexcluded API paths will return 202 challenge responses.",
        "3. **Pure API / static file domains** (no web frontend): Delete the "
        "`search-engine-label` rule and the `always-on-challenge` rule from the WebACL. "
        "In the Anti-DDoS AMR, disable challenge and set block sensitivity to medium.",
        "",
        "### Managed rules",
        "",
        "All managed rules (CRS, Known Bad Inputs, SQLi, IP Reputation) use **Count mode** "
        "for initial monitoring. Switch to Block after validating no false positives.",
        "",
    ]

    # Rate-limiting note for split mode
    if mode == "split":
        lines += [
            "### Rate-limiting behavioral difference",
            "",
            "Cloudflare counts rate limits across all domains in a zone. With per-domain "
            "WebACLs, each domain's rate counter is independent. This means a client hitting "
            "multiple domains will have separate rate counters per domain, not a shared one.",
            "",
        ]

    # IP set dedup warning
    if dedup:
        lines += [
            "### IP set deduplication",
            "",
            "Some inline IP sets with identical addresses were merged to stay within the "
            "100 IP set per-region limit. If you need to maintain separate lists for "
            "different rules in the future, duplicate the IP set in the AWS WAF console "
            "and update the rule references.",
            "",
        ]

    # Important notes
    lines += [
        "## Important Notes",
        "",
        "- **Region**: All WAFv2 resources with `Scope: CLOUDFRONT` must be in `us-east-1`.",
    ]

    if mode == "legacy":
        lines += [
            "- **Two Web ACLs** are generated:",
            "  - `waf-website`: For website traffic (search engine labeling + Anti-DDoS "
            "challenge enabled + always-on challenge)",
            "  - `waf-api-file`: For API/file traffic (Anti-DDoS challenge disabled, "
            "block sensitivity MEDIUM)",
        ]
    else:
        lines += [
            f"- **{len(webacl_names)} per-domain Web ACLs** are generated, one per proxied domain.",
            "- All WebACLs include search engine labeling, Anti-DDoS with challenge enabled, "
            "and always-on challenge (Count mode). Customize per-domain after deployment.",
        ]

    lines += [
        "- **IP sets quota**: Default 100 IP sets per account per region.",
        "- **WebACL quota**: Default 100 WebACLs per account per region.",
        "- **Rate-based rules**: AWS WAF minimum rate limit is 10 requests per evaluation window.",
        "",
        "## Migration from Terraform",
        "",
        "If you previously deployed WAF resources with the Terraform version of this tool:",
        "1. Run `terraform destroy` in the old `cloudflare-to-aws-waf/` directory",
        "2. Then deploy with CloudFormation using the steps above",
        "",
    ]

    # Non-convertible items
    if nc_notes:
        lines += [
            "## Non-Convertible Rules",
            "",
            "These Cloudflare features have no direct AWS WAF equivalent.",
            "",
            "| Rule | Field | AWS Equivalent | Manual Action |",
            "|------|-------|----------------|---------------|",
        ]
        for n in nc_notes:
            lines.append(
                f"| {n.get('rule', '')} "
                f"| `{n.get('field', '')}` "
                f"| {n.get('aws_equivalent', '')} "
                f"| {n.get('manual_action', '')} |"
            )
        lines.append("")

    if partial_rules:
        lines += [
            "## Partially Converted Rules",
            "",
            "| Rule | Section | Removed Condition |",
            "|------|---------|-------------------|",
        ]
        for r in partial_rules:
            section_label = r["section"].replace("_", " ").title()
            lines.append(f"| {r['name']} | {section_label} | {r['reason']} |")
        lines.append("")

    out_path = os.path.join(output_dir, "README_aws-waf-deployment.md")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"OK: {out_path} → {len(nc_notes)} non-convertible, "
          f"{len(partial_rules)} partial rules")
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nOUTPUT_DIR: {output_dir}\n"
          f"TEMPLATE: {os.path.join(output_dir, 'waf-cloudformation.json')}")


if __name__ == "__main__":
    main()
