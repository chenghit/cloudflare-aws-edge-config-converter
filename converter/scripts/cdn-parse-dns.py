#!/usr/bin/env python3
"""cdn-parse-dns.py — CDN Stage 1: Parse DNS.txt and produce manifest + domain scope.

Reads DNS.txt, extracts proxied CNAME records, detects SaaS, classifies origins,
writes dns_manifest.yaml and domain_scope.json.

Usage:
    python3 cdn-parse-dns.py <config_path> <output_dir>
"""
import glob as globmod, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdn_common import emit_result

# ── Origin classification ────────────────────────────────────────────────────

S3_PATTERNS = [
    re.compile(r'\.s3\.amazonaws\.com$', re.I),
    re.compile(r'\.s3\.[a-z0-9-]+\.amazonaws\.com$', re.I),
    re.compile(r'^s3\.amazonaws\.com$', re.I),
    re.compile(r'^s3\.[a-z0-9-]+\.amazonaws\.com$', re.I),
]
OBJECT_STORAGE_PATTERNS = [
    re.compile(r's3-website', re.I),
    re.compile(r'\.storage\.googleapis\.com$', re.I),
    re.compile(r'\.blob\.core\.windows\.net$', re.I),
    re.compile(r'\.web\.core\.windows\.net$', re.I),
    re.compile(r'\.oss.*\.aliyuncs\.com$', re.I),
    re.compile(r'\.cos\..*\.myqcloud\.com$', re.I),
    re.compile(r'\.obs\..*\.myhuaweicloud\.com$', re.I),
    re.compile(r'\.oos.*\.ctyunapi\.cn$', re.I),
]


def classify_origin(content):
    for p in S3_PATTERNS:
        if p.search(content):
            return "s3"
    for p in OBJECT_STORAGE_PATTERNS:
        if p.search(content):
            return "object_storage"
    return "server"


# ── Helpers ──────────────────────────────────────────────────────────────────

def find_file(config_path, pattern):
    """Newest timestamp of a per-zone file; fatal if it spans multiple zones."""
    matches = globmod.glob(os.path.join(config_path, "**", pattern), recursive=True)
    if not matches:
        return None
    sources = {os.path.dirname(os.path.dirname(m)) for m in matches}
    if len(sources) > 1:
        zones = sorted(os.path.basename(s) for s in sources)
        print(f"ERROR: {pattern} found under multiple zones: {zones}", file=sys.stderr)
        emit_result("FATAL", exit_code=1, ACTION="FIX",
                    CONTEXT=f"multiple zones detected ({', '.join(zones)}); convert one "
                            f"zone at a time")
    chosen = sorted(matches)[-1]
    if len(matches) > 1:
        print(f"WARNING: {len(matches)} backups of {pattern} found; using newest "
              f"({os.path.basename(os.path.dirname(chosen))})", file=sys.stderr)
    return chosen


def derive_zone_name(dns_path):
    """Zone name = grandparent directory of DNS.txt."""
    parent = os.path.dirname(dns_path)
    grandparent = os.path.dirname(parent)
    return os.path.basename(grandparent)


def derive_timestamp(dns_path):
    """Backup timestamp = parent directory name of DNS.txt."""
    return os.path.basename(os.path.dirname(dns_path))


def yaml_str(val):
    """Quote a YAML string value if it contains special chars."""
    if val is None:
        return "null"
    s = str(val)
    if any(c in s for c in ':.{}[]&*?|>!%@`,"\'') or s != s.strip():
        return f'"{s}"'
    return f'"{s}"'


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: cdn-parse-dns.py <config_path> <output_dir>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])

    # Step 1: Find DNS.txt
    dns_path = find_file(config_path, "DNS.txt")
    if not dns_path:
        print("ERROR: DNS.txt not found", file=sys.stderr)
        emit_result("FATAL", ACTION="FIX", CONTEXT="DNS.txt not found under config path")

    # Step 2: Parse DNS.txt
    try:
        with open(dns_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"ERROR: DNS.txt could not be parsed as JSON: {e}", file=sys.stderr)
        emit_result("FATAL", ACTION="FIX", CONTEXT="DNS.txt is malformed JSON")

    records = data.get("result", [])
    if isinstance(data.get("result"), dict):
        records = data["result"].get("records", records)

    zone_name = derive_zone_name(dns_path)
    backup_timestamp = derive_timestamp(dns_path)

    # Step 3: SaaS detection
    saas_reasons = []

    # Check A: SaaS hostnames
    saas_hostnames = [r["name"] for r in records
                      if r.get("proxied") and r.get("name", "").startswith("saas.")]
    if saas_hostnames:
        saas_reasons.append(f"SaaS subdomain records: {', '.join(saas_hostnames)}")

    # Check B: SaaS-Fallback-Origin.txt
    saas_fallback_path = os.path.join(os.path.dirname(dns_path), "SaaS-Fallback-Origin.txt")
    saas_origin = None
    if os.path.exists(saas_fallback_path):
        try:
            with open(saas_fallback_path) as f:
                saas_data = json.load(f)
            if saas_data.get("success") and isinstance(saas_data.get("result"), dict):
                origin = saas_data["result"].get("origin", "")
                if origin:
                    saas_origin = origin
                    saas_reasons.append(f"SaaS-Fallback-Origin.txt: {origin}")
        except (json.JSONDecodeError, KeyError):
            pass

    if saas_reasons:
        print("ABORT: SaaS configuration detected.", file=sys.stderr)
        for r in saas_reasons:
            print(f"  - {r}", file=sys.stderr)
        emit_result("FATAL", ACTION="FIX",
                    CONTEXT="SaaS configuration detected. Not supported.")

    # Step 4: Extract proxied records, classify
    proxied_domains = []
    non_convertible = []
    cf_loop_excluded = []

    for r in records:
        if not r.get("proxied"):
            continue
        hostname = r.get("name", "")
        rtype = r.get("type", "")
        content = r.get("content", "")

        # A/AAAA records have IP origins — non-convertible
        if rtype in ("A", "AAAA"):
            non_convertible.append({
                "hostname": hostname,
                "record_type": rtype,
                "origin_content": content,
                "reason": "CloudFront requires FQDN origins; IP address not supported",
            })
            continue

        if rtype != "CNAME":
            continue

        # Check C: CloudFront loop
        if "cloudfront.net" in content.lower():
            cf_loop_excluded.append({"hostname": hostname, "origin_content": content})
            continue

        proxied_domains.append({
            "hostname": hostname,
            "apex_domain": zone_name,
            "record_type": rtype,
            "origin_content": content,
            "is_wildcard": hostname.startswith("*."),
            "origin_type": classify_origin(content),
        })

    proxied_domains.sort(key=lambda d: d["hostname"])

    if not proxied_domains:
        msg = "No convertible proxied CNAME records found in DNS.txt."
        if non_convertible:
            msg += f" ({len(non_convertible)} A/AAAA records excluded — IP origins not supported by CloudFront)"
        print(f"ERROR: {msg}", file=sys.stderr)
        emit_result("FATAL", ACTION="FIX", CONTEXT=msg)

    # Step 5: Group by apex domain
    apex_groups = {}
    for d in proxied_domains:
        apex = d["apex_domain"]
        if apex not in apex_groups:
            apex_groups[apex] = {"hostnames": [], "suggested_cert_domain": None}
        apex_groups[apex]["hostnames"].append(d["hostname"])

    for apex, group in apex_groups.items():
        group["hostnames"].sort()
        hn = group["hostnames"]
        if len(hn) == 1 and hn[0] == apex:
            group["suggested_cert_domain"] = apex
        else:
            group["suggested_cert_domain"] = f"*.{apex}"

    # Step 6: Write dns_manifest.yaml
    os.makedirs(output_dir, exist_ok=True)
    manifest_path = os.path.join(output_dir, "dns_manifest.yaml")

    lines = [
        f"zone_name: {yaml_str(zone_name)}",
        f"backup_timestamp: {yaml_str(backup_timestamp)}",
        "saas_detected: false",
        "proxied_domains:",
    ]
    for d in proxied_domains:
        lines.append(f"  - hostname: {yaml_str(d['hostname'])}")
        lines.append(f"    apex_domain: {yaml_str(d['apex_domain'])}")
        lines.append(f"    record_type: {yaml_str(d['record_type'])}")
        lines.append(f"    origin_content: {yaml_str(d['origin_content'])}")
        lines.append(f"    is_wildcard: {'true' if d['is_wildcard'] else 'false'}")
        lines.append(f"    origin_type: {yaml_str(d['origin_type'])}")

    lines.append("apex_groups:")
    for apex in sorted(apex_groups):
        g = apex_groups[apex]
        lines.append(f"  {yaml_str(apex)}:")
        hn_str = ", ".join(yaml_str(h) for h in g["hostnames"])
        lines.append(f"    hostnames: [{hn_str}]")
        lines.append(f"    suggested_cert_domain: {yaml_str(g['suggested_cert_domain'])}")

    if non_convertible:
        lines.append("non_convertible_origins:")
        for nc in non_convertible:
            lines.append(f"  - hostname: {yaml_str(nc['hostname'])}")
            lines.append(f"    record_type: {yaml_str(nc['record_type'])}")
            lines.append(f"    origin_content: {yaml_str(nc['origin_content'])}")
            lines.append(f"    reason: {yaml_str(nc['reason'])}")

    if cf_loop_excluded:
        lines.append("cloudfront_loop_excluded:")
        for ex in cf_loop_excluded:
            lines.append(f"  - hostname: {yaml_str(ex['hostname'])}")
            lines.append(f"    origin_content: {yaml_str(ex['origin_content'])}")

    with open(manifest_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Step 7: Write domain_scope.json
    # All domains: apply_default_cache_behavior=false, cert_arn=null (data_source)
    apex_cert_groups = {}
    for apex in sorted(apex_groups):
        g = apex_groups[apex]
        apex_cert_groups[apex] = {
            "suggested_cert_domain": g["suggested_cert_domain"],
            "hostnames": g["hostnames"],
        }

    scope = {
        "zone_name": zone_name,
        "backup_path": os.path.abspath(config_path),
        "domains": [
            {
                "hostname": d["hostname"],
                "apex_domain": d["apex_domain"],
                "apply_default_cache_behavior": False,
                "cert_arn_mode": "data_source",
                "cert_arn": None,
                "origin_content": d["origin_content"],
                "origin_type": d["origin_type"],
            }
            for d in proxied_domains
        ],
        "apex_cert_groups": apex_cert_groups,
        "global_rules_note": "Rules without http.host condition will be applied to ALL domains during per-domain processing",
    }

    scope_path = os.path.join(output_dir, "domain_scope.json")
    with open(scope_path, "w") as f:
        json.dump(scope, f, indent=2, ensure_ascii=False)

    # Step 8: Print summary
    warnings = []
    if non_convertible:
        print(f"  ⚠️  Non-convertible: {len(non_convertible)} domain(s) with IP address origins:", file=sys.stderr)
        for nc in non_convertible:
            print(f"     - {nc['hostname']} → {nc['origin_content']} ({nc['record_type']} record)", file=sys.stderr)
        warnings.append(f"{len(non_convertible)} IP-origin domains excluded")

    if cf_loop_excluded:
        print(f"  ⚠️  Excluded: {len(cf_loop_excluded)} domain(s) already pointing to CloudFront:", file=sys.stderr)
        for ex in cf_loop_excluded:
            print(f"     - {ex['hostname']} → {ex['origin_content']}", file=sys.stderr)
        warnings.append(f"{len(cf_loop_excluded)} CloudFront-loop domains excluded")

    print(f"OK: {len(proxied_domains)} proxied domains, "
          f"{len(apex_groups)} apex group(s) → {manifest_path}, {scope_path}")

    fields = {"OUTPUT_FILE": scope_path, "DOMAINS": len(proxied_domains)}
    if warnings:
        fields["WARNINGS"] = "; ".join(warnings)
    emit_result("OK", exit_after=False, **fields)


if __name__ == "__main__":
    main()
