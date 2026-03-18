#!/usr/bin/env python3
"""cdn-finalize.py — Stage 5: Sort, dedup, and finalize IR.

Usage:
    python3 cdn-finalize.py <output_dir> [skipped_domains_json]

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, hashlib, copy, re
from datetime import datetime, timezone


def specificity_score(pattern):
    """Compute specificity score for a CloudFront path pattern."""
    if pattern == "*":
        return 0
    if pattern == "/*":
        return 1
    # Extension pattern: *.jpg, *.css (no slash)
    if pattern.startswith("*.") and "/" not in pattern:
        return 5
    # Find first wildcard
    wc_pos = -1
    for i, ch in enumerate(pattern):
        if ch in ("*", "?"):
            wc_pos = i
            break
    if wc_pos == -1:
        # Exact match
        return len(pattern) * 10 + 100
    return wc_pos * 10


def sort_behaviors(behaviors):
    """Sort cache behaviors by specificity (descending) and assign precedence."""
    # Separate default from rest
    default = None
    rest = []
    for b in behaviors:
        if b["path_pattern"] == "*":
            default = b
        else:
            rest.append(b)

    # Sort by score descending, then lexicographic ascending for ties
    rest.sort(key=lambda b: (-specificity_score(b["path_pattern"]), b["path_pattern"]))

    # Assign precedence
    for i, b in enumerate(rest):
        b["precedence"] = i + 1

    if default:
        default["precedence"] = 999
        rest.append(default)

    return rest


def detect_shadows(behaviors):
    """Detect shadowed rules. Returns list of warning strings."""
    warnings = []
    for i, a in enumerate(behaviors):
        for j, b in enumerate(behaviors):
            if i >= j:
                continue
            if a["precedence"] >= b["precedence"]:
                continue
            # Check if A's path_pattern covers B's
            a_types = {op["type"] for op in a.get("viewer_request_ops", [])}
            b_types = {op["type"] for op in b.get("viewer_request_ops", [])}
            shadow_types = {"redirect", "origin_override"}
            if not (a_types & shadow_types) or not (b_types & shadow_types):
                continue
            if _path_covers(a["path_pattern"], b["path_pattern"]):
                b["shadowed"] = True
                b.setdefault("non_convertible", []).append({
                    "type": "shadowed_rule",
                    "reason": (
                        f"Rule potentially shadowed by cache_behavior with "
                        f"path_pattern='{a['path_pattern']}' (precedence={a['precedence']}). "
                        f"This rule may never be evaluated in CloudFront. Review manually."
                    ),
                    "cf_source_rule": "",
                    "description": f"Shadowed by {a['path_pattern']}",
                })
                warnings.append(
                    f"{b['path_pattern']} potentially shadowed by {a['path_pattern']}"
                )
    return warnings


def _path_covers(a_pat, b_pat):
    """Check if path pattern A covers (is superset of) B."""
    if a_pat in ("*", "/*"):
        return True
    # A is prefix wildcard covering B: /api/* covers /api/v2/*
    if a_pat.endswith("/*"):
        prefix = a_pat[:-1]  # "/api/"
        return b_pat.startswith(prefix)
    return False


def normalize_policy(policy):
    """Normalize a policy object for hashing."""
    def _normalize(obj):
        if isinstance(obj, float) and obj == int(obj):
            return int(obj)
        if isinstance(obj, dict):
            return {k: _normalize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_normalize(v) for v in obj]
        return obj
    return _normalize(policy)


def dedup_policies(all_irs):
    """Deduplicate policies across all domains.

    Returns (dedup_manifest, updated_irs).
    """
    manifest = {}  # policy_id → {hash, type, count, sample_hostname, config}
    hash_to_id = {}  # full_hash → policy_id
    prefix_counts = {}  # 8-char prefix → count (for collision handling)

    policy_keys = [
        ("cache_policy", "cache_policy_id"),
        ("origin_request_policy", "origin_request_policy_id"),
        ("response_headers_policy", "response_headers_policy_id"),
    ]

    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        for beh in ir["cache_behaviors"]:
            for orig_key, ref_key in policy_keys:
                if orig_key not in beh:
                    continue
                policy = normalize_policy(beh[orig_key])

                # Skip empty RHP — no Terraform resource needed
                if orig_key == "response_headers_policy":
                    if (not policy.get("security_headers") and
                        not policy.get("custom_headers") and
                        not policy.get("cors") and
                        not policy.get("remove_headers")):
                        del beh[orig_key]
                        beh[ref_key] = None
                        continue

                policy_json = json.dumps(policy, sort_keys=True, separators=(",", ":"))
                full_hash = hashlib.sha256(policy_json.encode()).hexdigest()

                if full_hash in hash_to_id:
                    pid = hash_to_id[full_hash]
                    manifest[pid]["count"] += 1
                    if hostname not in manifest[pid]["used_by"]:
                        manifest[pid]["used_by"].append(hostname)
                else:
                    prefix = full_hash[:8]
                    if prefix in prefix_counts:
                        prefix_counts[prefix] += 1
                        pid = f"policy-{prefix}-{prefix_counts[prefix]}"
                    else:
                        prefix_counts[prefix] = 1
                        pid = f"policy-{prefix}"
                    hash_to_id[full_hash] = pid
                    manifest[pid] = {
                        "hash": full_hash,
                        "type": orig_key,
                        "count": 1,
                        "sample_hostname": hostname,
                        "used_by": [hostname],
                        "config": policy,
                    }

                # Replace inline policy with reference
                del beh[orig_key]
                beh[ref_key] = pid

    return manifest, all_irs


def generate_report(all_irs, manifest, shadow_warnings, skipped_domains):
    """Generate conversion_report.md content."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_behaviors = sum(len(ir["cache_behaviors"]) for ir in all_irs)
    has_s3 = any(ir["metadata"].get("origin_type") == "s3" for ir in all_irs)

    lines = [
        "# Cloudflare → CloudFront Conversion Report",
        "",
        f"Generated: {now}",
        f"Domains processed: {len(all_irs)}",
        f"Total cache behaviors: {total_behaviors}",
        f"Total unique policies: {len(manifest)}",
        "",
        "---",
        "",
        "## Shadowed Rules",
        "",
    ]

    if shadow_warnings:
        lines.append("| Domain | Path Pattern | Shadowed By | Rule Type |")
        lines.append("|--------|-------------|-------------|-----------|")
        for ir in all_irs:
            for beh in ir["cache_behaviors"]:
                if beh.get("shadowed"):
                    for nc in beh.get("non_convertible", []):
                        if nc.get("type") == "shadowed_rule":
                            lines.append(
                                f"| {ir['metadata']['hostname']} | "
                                f"`{beh['path_pattern']}` | "
                                f"{nc['reason'][:60]}... | shadowed |"
                            )
    else:
        lines.append("No shadowed rules detected.")

    lines += ["", "---", "", "## Domain Summary", ""]
    lines.append("| Domain | Behaviors | Ops | Non-Convertible | Shadowed | Status |")
    lines.append("|--------|-----------|-----|-----------------|----------|--------|")
    for ir in all_irs:
        h = ir["metadata"]["hostname"]
        nb = len(ir["cache_behaviors"])
        nops = sum(len(b.get("viewer_request_ops", [])) + len(b.get("viewer_response_ops", []))
                   for b in ir["cache_behaviors"])
        nnc = sum(len(b.get("non_convertible", [])) for b in ir["cache_behaviors"])
        nsh = sum(1 for b in ir["cache_behaviors"] if b.get("shadowed"))
        lines.append(f"| {h} | {nb} | {nops} | {nnc} | {nsh} | ✅ |")
    for sd in skipped_domains:
        lines.append(f"| {sd.get('hostname', '?')} | — | — | — | — | ⏭ SKIPPED: {sd.get('reason', '?')[:40]} |")

    lines += ["", "---", "", "## Non-Convertible Items", ""]

    nc_rows = []
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        for beh in ir["cache_behaviors"]:
            for nc in beh.get("non_convertible", []):
                if nc.get("type") == "shadowed_rule":
                    continue
                nc_rows.append((hostname, beh["path_pattern"], nc.get("description", ""), nc.get("reason", "")))

    if nc_rows:
        lines.append("| Domain | Cache Behavior | Description | Reason |")
        lines.append("|--------|---------------|-------------|--------|")
        for hostname, pp, desc, reason in nc_rows:
            lines.append(f"| {hostname} | `{pp}` | {desc} | {reason} |")
    else:
        lines.append("No non-convertible items.")

    lines += ["", "---", "", "## Policy Deduplication Summary", ""]
    shared = {pid: v for pid, v in manifest.items() if v["count"] > 1}
    if shared:
        lines.append("| Policy ID | Type | Used By (count) | Sample Domain |")
        lines.append("|-----------|------|-----------------|---------------|")
        for pid in sorted(shared):
            v = shared[pid]
            lines.append(f"| `{pid}` | {v['type']} | {v['count']} | {v['sample_hostname']} |")
    else:
        lines.append("No shared policies (all policies are domain-unique).")

    lines += ["", "---", "", "## Warnings", ""]
    all_warnings = list(shadow_warnings)
    if skipped_domains:
        for sd in skipped_domains:
            all_warnings.append(f"Domain skipped: {sd.get('hostname', '?')} — {sd.get('reason', '?')}")

    # KVS size estimation per domain
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        kvs_data = ir["metadata"].get("kvs_data", [])
        if not kvs_data and not ir["metadata"].get("kvs_requirements", {}).get("needs_continent"):
            continue
        # Estimate: each entry = key bytes + value bytes + ~20 bytes overhead
        total_bytes = sum(len(e.get("key", "")) + len(e.get("value", "")) + 20 for e in kvs_data)
        # Continent/EU mappings add ~3KB
        kvs_req = ir["metadata"].get("kvs_requirements", {})
        if kvs_req.get("needs_continent"):
            total_bytes += 3000
        if kvs_req.get("needs_eu"):
            total_bytes += 300
        if total_bytes > 4_000_000:
            all_warnings.append(
                f"KVS for {hostname}: estimated {total_bytes / 1_000_000:.1f} MB "
                f"(limit 5 MB). Reduce bulk redirects or request KVS quota increase."
            )
        elif total_bytes > 3_000_000:
            all_warnings.append(
                f"KVS for {hostname}: estimated {total_bytes / 1_000_000:.1f} MB "
                f"(limit 5 MB). Approaching limit — monitor after deployment."
            )

    # CloudFront quota checks
    policy_counts = {"cache_policy": 0, "origin_request_policy": 0, "response_headers_policy": 0}
    for entry in manifest.values():
        t = entry["type"]
        if t in policy_counts:
            policy_counts[t] += 1
    for ptype, limit, label in [
        ("cache_policy", 20, "Custom cache policies"),
        ("origin_request_policy", 20, "Custom origin request policies"),
        ("response_headers_policy", 20, "Custom response headers policies"),
    ]:
        count = policy_counts[ptype]
        if count > limit:
            all_warnings.append(f"{label}: {count} (default quota: {limit}). Request quota increase before deploying.")
        elif count > limit * 0.8:
            all_warnings.append(f"{label}: {count} (default quota: {limit}). Approaching limit.")

    # Per-policy item quotas
    for pid, entry in manifest.items():
        cfg = entry["config"]
        used = ", ".join(entry.get("used_by", [entry.get("sample_hostname", "?")]))
        if entry["type"] == "cache_policy":
            qs = cfg.get("query_strings_list", [])
            if isinstance(qs, list) and len(qs) > 10:
                all_warnings.append(f"Cache policy {pid} (used by {used}): {len(qs)} query strings (quota: 10).")
        elif entry["type"] == "response_headers_policy":
            ch = cfg.get("custom_headers", [])
            if isinstance(ch, list) and len(ch) > 10:
                all_warnings.append(f"RHP {pid} (used by {used}): {len(ch)} custom headers (quota: 10).")

    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        beh_count = len(ir["cache_behaviors"])
        if beh_count > 75:
            all_warnings.append(f"{hostname}: {beh_count} cache behaviors (default quota: 75). Request quota increase.")
        elif beh_count > 60:
            all_warnings.append(f"{hostname}: {beh_count} cache behaviors (default quota: 75). Approaching limit.")

    cff_count = len(all_irs) * 2  # viewer_request + viewer_response per domain
    if cff_count > 100:
        all_warnings.append(f"CloudFront Functions: ~{cff_count} (default quota: 100). Request quota increase.")
    elif cff_count > 80:
        all_warnings.append(f"CloudFront Functions: ~{cff_count} (default quota: 100). Approaching limit.")

    # CORS credentials + wildcard check
    for pid, entry in manifest.items():
        if entry["type"] != "response_headers_policy":
            continue
        cors = entry["config"].get("cors")
        if not cors or not isinstance(cors, dict):
            continue
        if cors.get("Access-Control-Allow-Credentials") == "true":
            origins = cors.get("Access-Control-Allow-Origin", "")
            headers = cors.get("Access-Control-Allow-Headers", "")
            if "*" in origins or "*" in headers:
                used = ", ".join(entry.get("used_by", [entry.get("sample_hostname", "?")]))
                all_warnings.append(
                    f"CORS policy {pid} (used by {used}): credentials=true with wildcard "
                    f"origin/headers. CloudFront does not allow this per HTTP spec. "
                    f"Wildcards were replaced with defaults — review and update with "
                    f"your actual allowed origins/headers in policies.tf. "
                    f"If you need wildcard origin with credentials, use CloudFront Functions "
                    f"viewer-response to set CORS headers instead of Response Headers Policy."
                )

    if all_warnings:
        for w in all_warnings:
            lines.append(f"- {w}")
    else:
        lines.append("No warnings.")

    lines += [
        "", "---", "",
        "## Caveats",
        "",
        "- Response Header Transform rules converted to CFF viewer-response will NOT execute "
        "when origin returns HTTP 400+. This differs from Cloudflare where Response Header "
        "Transform runs on all responses. Use Lambda@Edge origin-response if needed.",
        "- Lambda@Edge viewer-response also does NOT execute on 4xx+ origin responses. "
        "Only Lambda@Edge origin-response runs on all origin responses.",
        "- If your rules use more than 10 geo/device headers per cache behavior, "
        "request a CloudFront ORP headers quota increase via AWS Support.",
    ]

    # WAF + Custom Header pattern guidance (if CIDR-related non_convertible items exist)
    has_cidr_nc = any("CIDR" in reason for _, _, _, reason in nc_rows)
    if has_cidr_nc:
        lines += [
            "", "---", "",
            "## WAF + Custom Header Pattern",
            "",
            "Some rules reference IP lists with CIDR ranges, which CloudFront Functions "
            "cannot match (CFF only has access to the viewer's single IP address via "
            "`event.viewer.ip`). Use this pattern to handle CIDR-based IP matching:",
            "",
            "1. Create an AWS WAF IP set containing the CIDR ranges",
            "2. Create a WAF rule with **Count** action that matches the IP set "
            "and adds a custom header (e.g., `x-waf-ip-match: blocklist1`)",
            "3. Associate the WAF Web ACL with the CloudFront distribution",
            "4. In the CloudFront Function, check `request.headers['x-waf-ip-match']` "
            "and execute the corresponding logic (redirect, block, etc.)",
            "",
            "WAF evaluates before CloudFront Functions, so the custom header is "
            "available when the CFF runs. The Count action ensures the request is "
            "not terminated by WAF — it only labels the request for CFF to act on.",
            "",
            "This pattern also supports IPv4/IPv6 mixed lists and CIDR notation, "
            "which are native to AWS WAF IP sets (up to 10,000 entries per set).",
        ]

    # Deployment steps
    domains_with_kvs = [ir["metadata"]["hostname"] for ir in all_irs
                        if any(ir["metadata"].get("kvs_requirements", {}).values())]
    domains_with_le = [ir["metadata"]["hostname"] for ir in all_irs
                       if ir["metadata"].get("lambda_edge", {}).get("origin_response")]
    domain_list = [ir["metadata"] for ir in all_irs]

    lines += [
        "", "---", "",
        "## Deployment Steps",
        "",
        "### 1. Set AWS credentials",
        "```bash",
        "export AWS_PROFILE=<your-profile-name>",
        "```",
        "",
        "### 2. Deploy shared policies",
        "```bash",
        "cd cloudflare-to-aws-cdn/terraform/shared",
        "terraform init && terraform apply",
        "```",
        "",
        "### 3. Deploy each domain",
        "```bash",
    ]
    for m in domain_list:
        san = m["sanitized_name"]
        lines.append(f"cd cloudflare-to-aws-cdn/terraform/domains/{san} && terraform init && terraform apply")
    lines += ["```", ""]

    if domains_with_kvs:
        lines += [
            "### 4. Seed KVS data",
            "",
            "**Requires `boto3`**: `pip install boto3` (not included in stdlib).",
            "",
            "After `terraform apply`, seed each domain's KVS with its data:",
            "",
            "```bash",
        ]
        for m in domain_list:
            if any(m.get("kvs_requirements", {}).values()):
                san = m["sanitized_name"]
                lines.append(f"cd cloudflare-to-aws-cdn/terraform/domains/{san} && python3 seed-kvs.py")
        lines += ["```", ""]

    step_n = 5 if domains_with_kvs else 4
    lines += [
        f"### {step_n}. Validate deployment",
        "",
        "Each domain has a `test-cdn-rules.py` script for post-deployment validation.",
        "Run it against the CloudFront distribution domain name:",
        "",
        "```bash",
    ]
    for m in domain_list:
        san = m["sanitized_name"]
        lines.append(f"cd cloudflare-to-aws-cdn/terraform/domains/{san} && python3 test-cdn-rules.py <distribution-domain>")
    lines += [
        "```",
        "",
        "The script tests redirects, error pages, bulk redirects, and response headers "
        "using curl. Items requiring manual testing (IP-based rules, geo conditions, "
        "origin overrides) are listed as SKIP with instructions.",
        "",
    ]

    step_n += 1
    lines += [
        f"### {step_n}. DNS cutover",
        "",
        "Update DNS records to point to CloudFront distributions:",
        "",
    ]
    for m in domain_list:
        lines.append(f"- `{m['hostname']}` → CNAME to CloudFront distribution domain name")
    lines += [
        "",
        "Get each distribution's domain name:",
        "```bash",
        "cd cloudflare-to-aws-cdn/terraform/domains/<domain> && terraform output distribution_domain_name",
        "```",
        "",
    ]

    if has_s3:
        lines += [
            "", "---", "",
            "## Post-Deployment: S3 Bucket Policy",
            "",
            "After deploying CloudFront distributions, update each S3 bucket policy to "
            "allow access via Origin Access Control (OAC). Replace placeholders with "
            "actual values from `terraform output`.",
            "",
            "```json",
            '{',
            '  "Version": "2012-10-17",',
            '  "Statement": [{',
            '    "Sid": "AllowCloudFrontOAC",',
            '    "Effect": "Allow",',
            '    "Principal": {"Service": "cloudfront.amazonaws.com"},',
            '    "Action": "s3:GetObject",',
            '    "Resource": "<BUCKET_ARN>/*",',
            '    "Condition": {',
            '      "StringEquals": {',
            '        "AWS:SourceArn": "<DISTRIBUTION_ARN>"',
            '      }',
            '    }',
            '  }]',
            '}',
            "```",
        ]

    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) < 2:
        print("Usage: cdn-finalize.py <output_dir> [skipped_domains_json]", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
    skipped_domains = []
    if len(sys.argv) >= 3 and os.path.exists(sys.argv[2]):
        with open(sys.argv[2]) as f:
            skipped_domains = json.load(f)

    acc_dir = os.path.join(output_dir, "ir", "accumulator")
    val_dir = os.path.join(output_dir, "ir", "validation", "chunk")
    final_dir = os.path.join(output_dir, "ir", "final")
    shared_dir = os.path.join(output_dir, "shared")
    os.makedirs(final_dir, exist_ok=True)
    os.makedirs(shared_dir, exist_ok=True)

    # Step 1: Verify all accumulators have V1 PASS
    json_files = sorted(f for f in os.listdir(acc_dir) if f.endswith(".json") and not f.endswith(".error.json"))
    for filename in json_files:
        hostname = filename.replace(".json", "")
        v1_path = os.path.join(val_dir, f"{hostname}-v1.json")
        if not os.path.exists(v1_path):
            print(f"ERROR: V1 validation report not found for {hostname}", file=sys.stderr)
            sys.exit(1)
        with open(v1_path) as f:
            v1 = json.load(f)
        if v1.get("status") != "PASS":
            print(f"ERROR: {hostname} did not pass V1 validation", file=sys.stderr)
            sys.exit(1)

    # Step 2: Load all IRs
    all_irs = []
    for filename in json_files:
        with open(os.path.join(acc_dir, filename)) as f:
            all_irs.append(json.load(f))

    # Step 3: Sort cache behaviors and detect shadows
    all_shadow_warnings = []
    for ir in all_irs:
        ir["cache_behaviors"] = sort_behaviors(ir["cache_behaviors"])
        warnings = detect_shadows(ir["cache_behaviors"])
        all_shadow_warnings.extend(
            f"{ir['metadata']['hostname']}: {w}" for w in warnings
        )

    # Step 4: Policy deduplication
    manifest, all_irs = dedup_policies(all_irs)

    # Step 5: Write finalized IR files
    for ir in all_irs:
        hostname = ir["metadata"]["hostname"]
        ir["metadata"]["finalized_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        out_path = os.path.join(final_dir, f"{hostname}.json")
        with open(out_path, "w") as f:
            json.dump(ir, f, indent=2, ensure_ascii=False)
        print(f"OK: {hostname} → {len(ir['cache_behaviors'])} behaviors")

    # Step 6: Write dedup manifest
    manifest_out = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_policies": len(manifest),
        "policies": dict(sorted(manifest.items())),
    }
    manifest_path = os.path.join(shared_dir, "dedup_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest_out, f, indent=2, ensure_ascii=False)
    print(f"OK: dedup_manifest.json → {len(manifest)} unique policies")

    # Step 7: Write conversion report
    report = generate_report(all_irs, manifest, all_shadow_warnings, skipped_domains)
    report_path = os.path.join(output_dir, "conversion_report.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"OK: conversion_report.md written")

    # Summary
    shared_count = sum(1 for v in manifest.values() if v["count"] > 1)
    print(f"\n{'='*60}")
    print(f"Finalized {len(all_irs)} domains, {len(manifest)} unique policies ({shared_count} shared)")
    if all_shadow_warnings:
        print(f"⚠ {len(all_shadow_warnings)} shadowed rule warnings")
    if skipped_domains:
        print(f"⚠ {len(skipped_domains)} domains skipped")


if __name__ == "__main__":
    main()
