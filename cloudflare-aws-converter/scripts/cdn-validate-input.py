#!/usr/bin/env python3
"""cdn-validate-input.py — CDN Stage 2: Validate user_input.csv and produce domain_scope.json.

Replaces cf-cdn-input-validator LLM subagent. Reads user_input.csv + dns_manifest.yaml,
validates completeness and format, writes domain_scope.json.

Usage:
    python3 cdn-validate-input.py <output_dir> <config_path>
"""
import csv, json, os, re, sys

# Use PyYAML if available, otherwise simple parser
try:
    import yaml
    def load_yaml(path):
        with open(path) as f:
            return yaml.safe_load(f)
except ImportError:
    def load_yaml(path):
        """Minimal YAML parser for our known manifest format."""
        return _parse_simple_yaml(path)


ACM_ARN_RE = re.compile(
    r'^arn:aws:acm:[a-z]{2}-[a-z]+-\d+:\d{12}:certificate/'
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
)


def _parse_simple_yaml(path):
    """Parse our specific dns_manifest.yaml format without PyYAML."""
    with open(path) as f:
        text = f.read()

    result = {}
    # Top-level scalars
    for m in re.finditer(r'^(\w+):\s+"?([^"\n]+)"?\s*$', text, re.M):
        key, val = m.group(1), m.group(2)
        if val == "false":
            result[key] = False
        elif val == "true":
            result[key] = True
        else:
            result[key] = val

    # proxied_domains list
    domains = []
    in_proxied = False
    current = None
    for line in text.split("\n"):
        stripped = line.rstrip()
        if stripped == "proxied_domains:":
            in_proxied = True
            continue
        if in_proxied:
            if stripped.startswith("  - hostname:"):
                if current:
                    domains.append(current)
                current = {"hostname": _yval(stripped.split("hostname:")[1])}
            elif stripped.startswith("    ") and current and ":" in stripped:
                key, val = stripped.strip().split(":", 1)
                current[key.strip()] = _yval(val)
            elif not stripped.startswith("  ") and not stripped.startswith("    "):
                if current:
                    domains.append(current)
                    current = None
                in_proxied = False
    if current:
        domains.append(current)
    result["proxied_domains"] = domains

    # apex_groups
    apex_groups = {}
    in_apex = False
    current_apex = None
    for line in text.split("\n"):
        stripped = line.rstrip()
        if stripped == "apex_groups:":
            in_apex = True
            continue
        if in_apex:
            # New apex key (2-space indent, quoted key with colon)
            m = re.match(r'^  "([^"]+)":\s*$', stripped)
            if m:
                current_apex = m.group(1)
                apex_groups[current_apex] = {}
                continue
            if current_apex and stripped.startswith("    hostnames:"):
                hn_str = stripped.split("hostnames:")[1].strip()
                hostnames = re.findall(r'"([^"]+)"', hn_str)
                apex_groups[current_apex]["hostnames"] = hostnames
            elif current_apex and stripped.startswith("    suggested_cert_domain:"):
                apex_groups[current_apex]["suggested_cert_domain"] = _yval(
                    stripped.split("suggested_cert_domain:")[1])
            elif not stripped.startswith("  ") and not stripped.startswith("    ") and stripped:
                in_apex = False
                current_apex = None
    result["apex_groups"] = apex_groups

    return result


def _yval(s):
    """Extract value from YAML scalar."""
    s = s.strip().strip('"')
    if s == "true":
        return True
    if s == "false":
        return False
    if s == "null":
        return None
    return s


def main():
    if len(sys.argv) < 3:
        print("Usage: cdn-validate-input.py <output_dir> <config_path>", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(sys.argv[1])
    config_path = os.path.expanduser(sys.argv[2])

    manifest_path = os.path.join(output_dir, "dns_manifest.yaml")
    csv_path = os.path.join(output_dir, "user_input.csv")

    # Step 1: Verify prerequisites
    if not os.path.exists(manifest_path):
        print("ERROR: dns_manifest.yaml not found. Run cdn-parse-dns.py first.", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              "CONTEXT: dns_manifest.yaml not found")
        sys.exit(2)

    if not os.path.exists(csv_path):
        print("ERROR: user_input.csv not found.", file=sys.stderr)
        print("  Did you rename user_input_template.csv to user_input.csv?", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              "CONTEXT: user_input.csv not found")
        sys.exit(2)

    # Step 2: Read manifest
    manifest = load_yaml(manifest_path)
    if manifest.get("saas_detected"):
        print("ERROR: dns_manifest.yaml has saas_detected=true.", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              "CONTEXT: SaaS configuration detected in manifest")
        sys.exit(2)

    domain_lookup = {}
    for d in manifest.get("proxied_domains", []):
        domain_lookup[d["hostname"]] = d

    expected_hostnames = set(domain_lookup.keys())

    # Step 3: Read CSV
    with open(csv_path, "rb") as f:
        raw = f.read()
    # Strip BOM
    if raw.startswith(b'\xef\xbb\xbf'):
        raw = raw[3:]
    text = raw.decode("utf-8")

    reader = csv.DictReader(text.strip().splitlines())
    if not reader.fieldnames or set(reader.fieldnames) != {"hostname", "apply_default_cache_behavior", "cert_arn"}:
        actual = ",".join(reader.fieldnames) if reader.fieldnames else "(empty)"
        print(f"ERROR: Unexpected CSV headers: {actual}", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"CONTEXT: Expected headers: hostname,apply_default_cache_behavior,cert_arn. Got: {actual}")
        sys.exit(2)

    rows = []
    for row in reader:
        # Skip empty rows
        if all(not v.strip() for v in row.values()):
            continue
        rows.append({k: v.strip() for k, v in row.items()})

    # Step 4-5: Validate
    errors = []
    warnings = []
    seen_hostnames = set()

    for i, row in enumerate(rows, start=2):  # row 1 is header
        hn = row.get("hostname", "")
        dcb = row.get("apply_default_cache_behavior", "")
        cert = row.get("cert_arn", "")

        # 4a: hostname existence
        if hn not in expected_hostnames:
            errors.append(f"Row {i}: hostname \"{hn}\" not in dns_manifest.yaml")

        # Duplicate check
        if hn in seen_hostnames:
            errors.append(f"Row {i}: hostname \"{hn}\" appears multiple times")
        seen_hostnames.add(hn)

        # 4b: apply_default_cache_behavior
        if dcb.upper() not in ("Y", "N"):
            errors.append(f"Row {i}: apply_default_cache_behavior for \"{hn}\" is \"{dcb}\". Must be Y or N.")
        elif dcb != dcb.upper():
            warnings.append(f"Row {i}: apply_default_cache_behavior for \"{hn}\" normalized from \"{dcb}\" to \"{dcb.upper()}\"")

        # 4c: cert_arn format
        if cert:
            if not ACM_ARN_RE.match(cert):
                errors.append(f"Row {i}: cert_arn for \"{hn}\" does not match ACM ARN format: \"{cert}\"")
            else:
                region = cert.split(":")[3]
                if region != "us-east-1":
                    warnings.append(f"Row {i}: cert_arn for \"{hn}\" is in region \"{region}\". CloudFront requires us-east-1.")

    # 5: Missing hostnames
    missing = expected_hostnames - seen_hostnames
    for hn in sorted(missing):
        errors.append(f"Hostname \"{hn}\" from dns_manifest.yaml is missing from user_input.csv")

    # Step 6: Report
    if warnings:
        for w in warnings:
            print(f"  WARNING: {w}", file=sys.stderr)

    if errors:
        print(f"Validation failed. {len(errors)} error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        error_list = "\n  ".join(errors)
        print(f"\n---RESULT---\nSPEC: 1\nSTATUS: ERROR\nACTION: FIX\n"
              f"CONTEXT: {len(errors)} validation error(s):\n  {error_list}")
        sys.exit(1)

    # Step 7: Build domain_scope.json
    domains = []
    for row in rows:
        hn = row["hostname"]
        manifest_entry = domain_lookup.get(hn, {})
        cert = row.get("cert_arn", "").strip()
        domains.append({
            "hostname": hn,
            "apex_domain": manifest_entry.get("apex_domain", ""),
            "apply_default_cache_behavior": row["apply_default_cache_behavior"].upper() == "Y",
            "cert_arn_mode": "explicit" if cert else "data_source",
            "cert_arn": cert if cert else None,
            "origin_content": manifest_entry.get("origin_content", ""),
            "origin_type": manifest_entry.get("origin_type", "server"),
        })
    domains.sort(key=lambda d: d["hostname"])

    # apex_cert_groups from manifest
    apex_cert_groups = {}
    manifest_groups = manifest.get("apex_groups", {})
    valid_hostnames = {d["hostname"] for d in domains}
    for apex, group in manifest_groups.items():
        filtered = [h for h in group.get("hostnames", []) if h in valid_hostnames]
        if filtered:
            apex_cert_groups[apex] = {
                "suggested_cert_domain": group.get("suggested_cert_domain", f"*.{apex}"),
                "hostnames": sorted(filtered),
            }

    scope = {
        "zone_name": manifest.get("zone_name", ""),
        "backup_path": os.path.abspath(config_path),
        "domains": domains,
        "apex_cert_groups": apex_cert_groups,
        "global_rules_note": "Rules without http.host condition will be applied to ALL domains during per-domain processing",
    }

    # Step 8: Write
    scope_path = os.path.join(output_dir, "domain_scope.json")
    with open(scope_path, "w") as f:
        json.dump(scope, f, indent=2, ensure_ascii=False)

    # Summary
    y_count = sum(1 for d in domains if d["apply_default_cache_behavior"])
    explicit_count = sum(1 for d in domains if d["cert_arn_mode"] == "explicit")

    print(f"OK: {len(domains)} domains validated → {scope_path}")
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\n"
          f"OUTPUT_FILE: {scope_path}\nDOMAINS: {len(domains)}")


if __name__ == "__main__":
    main()
