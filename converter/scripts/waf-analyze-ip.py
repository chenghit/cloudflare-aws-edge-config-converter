#!/usr/bin/env python3
"""waf-analyze-ip.py — WAF Stage A1: Analyze IP Lists + IP Access Rules.

Reads IP-Lists.txt,
List-Items-*.txt, and IP-Access-Rules.txt, then generates waf_ir_ip.json.

Usage:
    python3 waf-analyze-ip.py <config_path> <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, glob, ipaddress, re


# ── IP classification ────────────────────────────────────────────────────────

def is_ipv6(addr):
    """Check if an address string (with or without prefix) is IPv6."""
    try:
        ipaddress.IPv6Network(addr, strict=False)
        return True
    except ValueError:
        return False


def ensure_cidr(addr):
    """Ensure an IP address has CIDR notation (/32 for IPv4, /128 for IPv6)."""
    if "/" in addr:
        return addr
    try:
        ipaddress.IPv4Address(addr)
        return addr + "/32"
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(addr)
        return addr + "/128"
    except ValueError:
        pass
    return addr


def split_ipv4_ipv6(addresses):
    """Split a list of IP addresses/CIDRs into IPv4 and IPv6 lists."""
    v4, v6 = [], []
    for addr in addresses:
        addr = addr.strip()
        if not addr:
            continue
        addr = ensure_cidr(addr)
        if is_ipv6(addr):
            v6.append(addr)
        else:
            v4.append(addr)
    return v4, v6


# ── File discovery ───────────────────────────────────────────────────────────

def find_file(config_path, pattern):
    """Find a single per-zone/account file. Returns path or None.

    A file may legitimately appear under multiple timestamp dirs (the user
    backed up the same zone more than once) — take the newest timestamp and
    tell the user which backup was used. But if it appears under more than one
    logical source (zone/account dir), the config path is a multi-zone root —
    that is fatal, and we report the zones so the caller can convert one at a time.
    """
    matches = glob.glob(os.path.join(config_path, "**", pattern), recursive=True)
    if not matches:
        return None
    # Logical source = parent of the timestamp dir (the zone or account dir).
    sources = {os.path.dirname(os.path.dirname(m)) for m in matches}
    if len(sources) > 1:
        zones = sorted(os.path.basename(s) for s in sources)
        print(f"ERROR: {pattern} found under multiple zones: {zones}", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"CONTEXT: multiple zones detected ({', '.join(zones)}); convert one zone at a time")
        sys.exit(1)
    chosen = sorted(matches)[-1]  # same source: timestamp lexical order = chronological
    if len(matches) > 1:
        print(f"WARNING: {len(matches)} backups of {pattern} found; using newest "
              f"({os.path.basename(os.path.dirname(chosen))})", file=sys.stderr)
    return chosen


def find_list_items(config_path, kind, name):
    """Find List-Items file for a given list."""
    pattern = f"List-Items-{kind}-{name}.txt"
    return find_file(config_path, pattern)


def read_json_result(path):
    """Read a JSON file and return the 'result' array."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"  WARN: {path} is empty or invalid JSON, treating as empty", file=sys.stderr)
        return []
    return data.get("result", [])


# ── IP Lists processing ─────────────────────────────────────────────────────

def process_ip_lists(config_path):
    """Process IP-Lists.txt and corresponding List-Items files."""
    lists_path = find_file(config_path, "IP-Lists.txt")
    if not lists_path:
        return []

    lists = read_json_result(lists_path)
    result = []

    for lst in lists:
        name = lst.get("name", "")
        kind = lst.get("kind", "")
        num_items = lst.get("num_items", 0)

        if kind == "redirect":
            result.append({"name": name, "kind": kind, "conversion": "out_of_scope"})
            continue

        if kind == "hostname":
            # Hostname lists ARE convertible: `http.host in $list` → an OR of
            # exact host-header matches (same as an inline `http.host in {...}`).
            if num_items == 0:
                result.append({"name": name, "kind": kind, "conversion": "empty"})
                continue
            items_path = find_list_items(config_path, "hostname", name)
            if not items_path:
                result.append({
                    "name": name, "kind": kind, "conversion": "hostname_set",
                    "items": [], "_warning": f"List-Items-hostname-{name}.txt not found"
                })
                continue
            items = read_json_result(items_path)
            # Cloudflare hostname list items: {"hostname": {"url_hostname": "x"}}
            hostnames = [it["hostname"]["url_hostname"] for it in items
                         if isinstance(it.get("hostname"), dict) and it["hostname"].get("url_hostname")]
            result.append({
                "name": name, "kind": kind, "conversion": "hostname_set",
                "items": hostnames
            })
            continue

        if kind == "ip":
            if num_items == 0:
                result.append({"name": name, "kind": kind, "conversion": "empty"})
                continue

            items_path = find_list_items(config_path, "ip", name)
            if not items_path:
                result.append({
                    "name": name, "kind": kind, "conversion": "ip_set",
                    "items_ipv4": [], "items_ipv6": [],
                    "_warning": f"List-Items-ip-{name}.txt not found"
                })
                continue

            items = read_json_result(items_path)
            addresses = [item.get("ip", "") for item in items if item.get("ip")]
            v4, v6 = split_ipv4_ipv6(addresses)
            result.append({
                "name": name, "kind": kind, "conversion": "ip_set",
                "items_ipv4": v4, "items_ipv6": v6
            })

        elif kind == "asn":
            if num_items == 0:
                result.append({"name": name, "kind": kind, "conversion": "empty"})
                continue

            items_path = find_list_items(config_path, "asn", name)
            if not items_path:
                result.append({
                    "name": name, "kind": kind, "conversion": "asn_inline",
                    "items": [],
                    "_warning": f"List-Items-asn-{name}.txt not found"
                })
                continue

            items = read_json_result(items_path)
            asns = [item.get("asn") for item in items if item.get("asn") is not None]
            result.append({
                "name": name, "kind": kind, "conversion": "asn_inline",
                "items": asns
            })

        else:
            result.append({
                "name": name, "kind": kind, "conversion": "out_of_scope",
                "_warning": f"Unknown list kind: {kind}"
            })

    return result


# ── IP Access Rules processing ───────────────────────────────────────────────

MODE_TO_AWS_ACTION = {
    "block": "block",
    "challenge": "challenge",
    "js_challenge": "challenge",
    "managed_challenge": "challenge",
    "whitelist": "allow",
}


def derive_rule_name(mode, target, value):
    """Derive a descriptive name from mode + target + value."""
    # Normalize mode to kebab-case (js_challenge → js-challenge)
    mode_slug = mode.replace("_", "-")
    value_slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip()).strip("-").lower()
    if len(value_slug) > 30:
        value_slug = value_slug[:30].rstrip("-")
    return f"{mode_slug}-{target}-{value_slug}"


def process_ip_access_rules(config_path):
    """Process IP-Access-Rules.txt."""
    rules_path = find_file(config_path, "IP-Access-Rules.txt")
    if not rules_path:
        return {"count": 0, "rules": []}, []

    raw_rules = read_json_result(rules_path)
    rules = []
    non_convertible = []

    for i, rule in enumerate(raw_rules):
        cfg = rule.get("configuration", {})
        target = cfg.get("target", "")
        value = cfg.get("value", "")
        mode = rule.get("mode", "")

        entry = {
            "position": i + 1,
            "name": derive_rule_name(mode, target, value),
            "mode": mode,
            "target": target,
            "value": value,
            "convertibility": "yes",
        }

        aws_action = MODE_TO_AWS_ACTION.get(mode)
        if not aws_action:
            entry["convertibility"] = "no"
            entry["non_convertible_reason"] = f"Unknown mode: {mode}"
            non_convertible.append({
                "rule": entry["name"],
                "field": f"mode:{mode}",
                "reason": f"Unknown IP Access Rule mode: {mode}",
            })

        if target in ("ip", "ip_range"):
            # Parse addresses — value may be comma-separated
            addresses = [a.strip() for a in value.split(",") if a.strip()]
            addresses = [ensure_cidr(a) for a in addresses]
            v4 = [a for a in addresses if not is_ipv6(a)]
            v6 = [a for a in addresses if is_ipv6(a)]

            entry["conditions"] = {"field": "ip.src", "operator": "in",
                                   "value": "{" + " ".join(addresses) + "}"}
            if v4 or v6:
                # scope_tag "a{position}" makes these names globally unique, matching
                # the c{n}/r{n} scheme the custom/rate analyzers use (see
                # extract_ip_sets). IP-access conditions are built by hand, so the
                # tag is applied here directly.
                tag = f"a{i + 1}"
                entry["ip_sets"] = []
                set_names = []
                if v4:
                    n = f"{tag}_{entry['name']}-ipv4"
                    entry["ip_sets"].append({"name": n, "addresses": v4})
                    set_names.append(n)
                if v6:
                    n = f"{tag}_{entry['name']}-ipv6"
                    entry["ip_sets"].append({"name": n, "addresses": v6})
                    set_names.append(n)
                # Annotate the leaf so the generator can resolve the inline set to
                # its IP-set resource(s) — the expression parser does this for
                # custom/rate rules, but IP-access conditions are built by hand.
                entry["conditions"]["_ip_set_names"] = set_names

        elif target == "country":
            entry["conditions"] = {"field": "ip.src.country", "operator": "eq",
                                   "value": value.upper()}

        elif target == "asn":
            # Value format: "AS13335" → extract number
            asn_num = re.sub(r"[^0-9]", "", value)
            if asn_num:
                entry["value"] = int(asn_num)
            entry["conditions"] = {"field": "ip.geoip.asnum", "operator": "in",
                                   "value": "{" + asn_num + "}" if asn_num else "{0}"}

        else:
            entry["convertibility"] = "no"
            entry["non_convertible_reason"] = f"Unknown target type: {target}"
            non_convertible.append({
                "rule": entry["name"],
                "field": f"target:{target}",
                "reason": f"Unknown IP Access Rule target type: {target}",
            })

        rules.append(entry)

    return {"count": len(rules), "rules": rules}, non_convertible


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: waf-analyze-ip.py <config_path> <output_dir>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])

    if not os.path.isdir(config_path):
        print(f"ERROR: config path not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(output_dir):
        print(f"ERROR: output dir not found: {output_dir}", file=sys.stderr)
        sys.exit(1)

    # Process
    ip_lists = process_ip_lists(config_path)
    access_result, non_convertible = process_ip_access_rules(config_path)

    # Build output
    ir = {
        "ip_lists": ip_lists,
        "ip_access_rules": access_result,
        "non_convertible_notes": non_convertible,
    }

    # Write
    out_path = os.path.join(output_dir, "waf_ir_ip.json")
    with open(out_path, "w") as f:
        json.dump(ir, f, indent=2, ensure_ascii=False)

    # Summary
    ip_count = sum(
        len(l.get("items_ipv4", [])) + len(l.get("items_ipv6", [])) + len(l.get("items", []))
        for l in ip_lists if l.get("conversion") not in ("out_of_scope", "empty")
    )
    print(f"OK: {len(ip_lists)} IP lists ({ip_count} total items), "
          f"{access_result['count']} IP access rules → {out_path}")


if __name__ == "__main__":
    main()
