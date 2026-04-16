#!/usr/bin/env python3
"""waf-check-split.py — Decide split mode and dedup based on IP set counts.

Decision tree:
  Step 1: total IP sets (named + inline) <= 50 → legacy mode
  Step 2: > 50 → split per-domain
  Step 3: inline IP sets > 100 → enable cross-rule dedup

Usage:
    python3 waf-check-split.py <output_dir>

Writes waf_split_decision.json to output_dir.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from waf_common import is_non_convertible


def is_ipv6(addr):
    return ":" in addr.split("/")[0]


def count_ip_sets(ir):
    """Count total IP set resources (named + inline). For Step 1 (50 limit)."""
    count = 0
    for lst in ir.get("ip_lists", []):
        if lst.get("conversion") == "ip_set":
            if lst.get("items_ipv4"):
                count += 1
            if lst.get("items_ipv6"):
                count += 1
    seen = set()
    for section_key in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        section = ir.get(section_key, {})
        for rule in section.get("rules", []):
            for ipset in rule.get("ip_sets", []):
                addrs = tuple(sorted(ipset.get("addresses", [])))
                version = "IPV6" if any(is_ipv6(a) for a in addrs) else "IPV4"
                key = (version, addrs)
                if key not in seen:
                    seen.add(key)
                    count += 1
    return count


def count_inline_ip_sets(ir):
    """Count inline IP sets only (excluding named). For Step 3 (100 limit)."""
    seen = set()
    for section_key in ("ip_access_rules", "custom_rules", "rate_limiting_rules"):
        section = ir.get(section_key, {})
        for rule in section.get("rules", []):
            for ipset in rule.get("ip_sets", []):
                addrs = tuple(sorted(ipset.get("addresses", [])))
                version = "IPV6" if any(is_ipv6(a) for a in addrs) else "IPV4"
                key = (version, addrs)
                seen.add(key)
    return len(seen)


def main():
    force_split = "--force-split" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("Usage: waf-check-split.py <output_dir> [--force-split]", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.expanduser(args[0])
    ir_path = os.path.join(output_dir, "waf_ir.json")

    with open(ir_path) as f:
        ir = json.load(f)

    total = count_ip_sets(ir)
    inline = count_inline_ip_sets(ir)

    if force_split:
        mode = "split"
        dedup = inline > 100
        reason = f"forced split (--force-split); {total} IP sets, {inline} inline"
        if dedup:
            reason += "; dedup enabled"
    elif total <= 50:
        mode = "legacy"
        dedup = False
        reason = f"{total} IP sets <= 50 limit"
    else:
        mode = "split"
        dedup = inline > 100
        reason = f"{total} IP sets > 50 limit → split per-domain"
        if dedup:
            reason += f"; {inline} inline IP sets > 100 → dedup enabled"

    decision = {
        "mode": mode,
        "dedup": dedup,
        "total_ip_sets": total,
        "inline_ip_sets": inline,
        "reason": reason,
    }

    out_path = os.path.join(output_dir, "waf_split_decision.json")
    with open(out_path, "w") as f:
        json.dump(decision, f, indent=2)

    print(f"{total} IP sets {'>' if total > 50 else '<='} 50 limit"
          f" → {mode} mode" + (", dedup enabled" if dedup else ""))
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nMODE: {mode}\nDEDUP: {dedup}\n"
          f"TOTAL_IP_SETS: {total}\nINLINE_IP_SETS: {inline}")


if __name__ == "__main__":
    main()
