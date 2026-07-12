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

    # Detect mode, dedup, and quota data from metadata written by generate-cfn
    meta_path = os.path.join(output_dir, "waf_metadata.json")
    mode = "legacy"
    dedup = False
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        mode = meta.get("mode", "legacy")
        dedup = meta.get("dedup", False)

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

    ip_sets_total = meta.get("ip_sets_total", 0)
    compact_size = meta.get("compact_size", 0)

    # Actual post-pack reference-statement count per WebACL (overflow refs are
    # offloaded into rule groups, so this is always ≤50 — the cap can't force a
    # split anymore).
    max_ref = meta.get("max_ref_per_webacl", 0)
    ref_count_display = f"{max_ref}/50 max per WebACL" if max_ref else ""

    lines = [
        "# AWS WAF CloudFormation Deployment Guide",
        "",
    ]

    lines += [
        "## Overview",
        "",
        f"- Mode: **{'per-domain WebACLs' if mode == 'split' else 'legacy (2 WebACLs)'}**",
        f"- WebACLs: {len(webacl_names)}",
        f"- IP sets: {ip_sets_total}",
        f"- IP access rules: {ip_count}",
        f"- Custom rules: {custom_count}",
        f"- Rate limiting rules: {rate_count}",
        f"- Non-convertible items: {len(nc_notes)}",
        f"- Partially converted rules: {len(partial_rules)}",
        f"- Reference statements: {ref_count_display}",
        "",
    ]

    # Quota usage summary (right after Overview for visibility)
    lines += [
        "## Quota Usage",
        "",
        "| Resource | Used | Limit | Notes |",
        "|----------|------|-------|-------|",
        f"| IP sets | {ip_sets_total} | 100 per region | Soft limit, can request increase |",
        f"| WebACLs | {len(webacl_names)} | 100 per region | Soft limit, can request increase |",
    ]

    webacl_refs = meta.get("ref_counts_per_webacl", {})
    if webacl_refs:
        max_ref = meta.get("max_ref_per_webacl", 0)
        max_name = max(webacl_refs, key=webacl_refs.get)
        lines.append(f"| Ref statements (max per WebACL) | {max_ref} | 50 | "
                     f"**Hard limit** — highest: {max_name}. Overflow auto-packed "
                     f"into rule groups to stay ≤50 |")

    lines += [
        "",
    ]

    # Per-WebACL detail (collapsible for large configs). Counts are the actual
    # post-pack direct reference statements per WebACL (always ≤50).
    if webacl_refs:
        lines += [
            "<details>",
            "<summary>Per-WebACL reference statement detail</summary>",
            "",
            "| WebACL | Ref Statements | Status |",
            "|--------|---------------|--------|",
        ]
        for name in sorted(webacl_refs):
            count = webacl_refs[name]
            status = "⚠️ Near limit" if count > 40 else "✅ OK"
            lines.append(f"| {name} | {count}/50 | {status} |")
        lines += ["", "</details>", ""]

    lines += [
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
    ]

    # Deployment instructions based on template count and size
    template_count = meta.get("template_count", 1)
    compact_size = meta.get("compact_size", 0)
    template_files = meta.get("template_files", ["waf-cloudformation.json"])

    if template_count == 1:
        if compact_size <= 51200:
            # Small enough for direct upload
            lines += [
                "### 2. Deploy the CloudFormation stack",
                "```bash",
                f"cd cloudflare-to-aws-waf",
                "aws cloudformation deploy \\",
                f"  --template-file {template_files[0]} \\",
                "  --stack-name cloudflare-waf-migration \\",
                "  --region us-east-1",
                "```",
            ]
        else:
            # Needs S3 bucket
            lines += [
                "### 2. Deploy the CloudFormation stack",
                "",
                f"Template size ({compact_size // 1024} KB) exceeds the 51 KB direct upload limit. "
                "An S3 bucket is required for deployment.",
                "",
                "```bash",
                f"cd cloudflare-to-aws-waf",
                "aws cloudformation deploy \\",
                f"  --template-file {template_files[0]} \\",
                "  --stack-name cloudflare-waf-migration \\",
                "  --s3-bucket <your-cfn-templates-bucket> \\",
                "  --region us-east-1",
                "```",
            ]
    else:
        # Multi-stack deployment
        lines += [
            "### 2. Deploy CloudFormation stacks",
            "",
            f"The template was split into {template_count} stacks due to the 1 MB CloudFormation size limit. "
            "Deploy in order — IP sets first, then WebACL stacks.",
            "",
            "```bash",
            f"cd cloudflare-to-aws-waf",
            "",
            "# Step 1: Deploy IP sets",
            "aws cloudformation deploy \\",
            f"  --template-file {template_files[0]} \\",
            "  --stack-name cloudflare-waf-ipsets \\",
            "  --s3-bucket <your-cfn-templates-bucket> \\",
            "  --region us-east-1",
            "",
            "# Step 2: Deploy WebACL stacks (auto-resolves IP set ARNs via ImportValue)",
        ]
        for tf in template_files[1:]:
            stack_name = tf.replace(".json", "").replace("waf-cloudformation-", "cloudflare-waf-")
            lines += [
                "aws cloudformation deploy \\",
                f"  --template-file {tf} \\",
                f"  --stack-name {stack_name} \\",
                "  --s3-bucket <your-cfn-templates-bucket> \\",
                "  --region us-east-1",
                "",
            ]
        lines += ["```"]

    lines += [
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

    if template_count == 1:
        update_lines = [
            "### 5. Update or destroy",
            "```bash",
            "# Update (re-run deploy with same stack name)",
            "aws cloudformation deploy \\",
            f"  --template-file {template_files[0]} \\",
            "  --stack-name cloudflare-waf-migration \\",
        ]
        if compact_size > 51200:
            update_lines.append("  --s3-bucket <your-cfn-templates-bucket> \\")
        update_lines += [
            "  --region us-east-1",
            "",
            "# Destroy",
            "aws cloudformation delete-stack \\",
            "  --stack-name cloudflare-waf-migration \\",
            "  --region us-east-1",
            "```",
            "",
        ]
        lines += update_lines
    else:
        lines += [
            "### 5. Destroy (reverse order)",
            "```bash",
        ]
        for tf in reversed(template_files[1:]):
            stack_name = tf.replace(".json", "").replace("waf-cloudformation-", "cloudflare-waf-")
            lines += [
                "aws cloudformation delete-stack \\",
                f"  --stack-name {stack_name} \\",
                "  --region us-east-1",
            ]
        lines += [
            "# Delete IP sets last (WebACL stacks depend on them via ImportValue)",
            "aws cloudformation delete-stack \\",
            "  --stack-name cloudflare-waf-ipsets \\",
            "  --region us-east-1",
            "```",
            "",
        ]

    # Post-deployment checklist
    lines += [
        "## ⚠️ Post-Deployment Checklist",
        "",
        "### Anti-DDoS managed rule group",
        "",
        "The Anti-DDoS AMR is deployed with **Override Action: Count** (monitoring only). "
        "Review WAF logs before activating.",
        "",
        "- **Web-facing domains**: Change Override Action from Count to **None** to activate. "
        "The default config enables Challenge with HIGH sensitivity and exempts `/api/` paths "
        "and static file extensions. Adjust `ExemptUriRegularExpressions` if your API paths "
        "differ from the default pattern.",
        "- **Pure API / static file domains** (no web frontend): Change Override Action from "
        "Count to **None**, then edit the Anti-DDoS config: disable Challenge and set Block "
        "sensitivity to MEDIUM. Also delete the `search-engine-label` and `always-on-challenge` "
        "rules from the WebACL (they are not useful for API-only domains).",
        "",
        "### always-on-challenge rule",
        "",
        "The `always-on-challenge` rule is deployed with **Count action** (monitoring only). "
        "It automatically excludes requests labeled `custom:search-engine` (from the "
        "`search-engine-label` rule) to protect SEO.",
        "",
        "1. **Web-facing domains**: Change the action from Count to **Challenge**. "
        "Add your landing page paths (e.g., `/pricing`, `/about`, `/register`) to the "
        "rule's URI list.",
        "2. **Mixed domains** (web frontend + API backend): Same as #1, but also ensure "
        "all API paths are excluded. API clients cannot solve challenges — unexcluded API "
        "paths will return 202 challenge responses.",
        "3. **Pure API / static file domains**: Delete this rule (see Anti-DDoS section above).",
        "",
        "### Managed rules (CRS, Known Bad Inputs, SQLi, IP Reputation)",
        "",
        "All managed rules are deployed with "
        "**Override Action: Count** (monitoring only). To activate blocking:",
        "",
        "1. Monitor WAF logs for 1-2 weeks to identify false positives.",
        "2. For each managed rule group, change the Override Action from `Count` to `None` "
        "(this lets the rule group's default actions — Block — take effect).",
        "3. In the AWS Console: WAF → Web ACL → Rules → select the managed rule group → "
        "Edit → set \"Override rule group action\" to **No override**.",
        "4. Or update the CloudFormation template: change `\"OverrideAction\": {\"Count\": {}}` "
        "to `\"OverrideAction\": {\"None\": {}}` and redeploy.",
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
        "- **Reference statements per WebACL**: 50 (**hard limit** — counts IP-set + "
        "regex-set + rule-group + AWS-managed-rule-group references). Overflow (IP-set "
        "refs and rate-based rules) is automatically offloaded into referenced rule "
        "groups, so a WebACL stays ≤50 without a per-host split.",
        "- **Rate-based rules per WebACL**: 10 (**hard limit**). Overflow is packed into "
        "rule groups (≤4 rate-based rules each), which don't count against this 10.",
        "- **WCU per WebACL**: 5000 (**hard limit**). Over 1500 incurs extra charges. If a "
        "WebACL exceeds 5000 the tool reports `STATUS: BLOCKED` — simplify rules and re-run.",
        "- **IP sets per account per region**: 100 (soft limit, can request increase).",
        "- **WebACLs per account per region**: 100 (soft limit, can request increase).",
        "- **Rate-based rules**: AWS WAF minimum rate limit is 10 requests per evaluation window.",
        "",
        "### Optional: verify WCU against AWS before deploying",
        "",
        "The generated rule-group `Capacity` values come from a local calculator that is "
        "exact against AWS `CheckCapacity`. To reconcile them against your account before "
        "deploying (needs an AWS profile), run:",
        "",
        "```bash",
        "python3 waf-verify-wcu.py <output_dir> --profile <your-aws-profile>",
        "```",
        "",
        "It only ever corrects the integer `Capacity` field (never rule logic) and refreshes "
        "managed-rule-group WCU numbers. Without a profile, deploy as-is — a rule group's "
        "declared `Capacity` can only ever be slightly high, which still deploys.",
        "",
    ]

    lines += [
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
