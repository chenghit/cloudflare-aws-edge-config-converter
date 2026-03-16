#!/usr/bin/env python3
"""Merge 3 batch IR JSON files into a single waf_ir.json.

Usage:
    python3 waf-merge-ir.py <waf_output_dir>

Reads waf_ir_ip.json, waf_ir_custom.json, waf_ir_rate.json from waf_output_dir.
Writes merged waf_ir.json. Concatenates non_convertible_notes arrays.
Exit 0 on success, exit 1 on error.
"""
import json, sys, os

waf_dir = sys.argv[1]

files = {
    "ip": os.path.join(waf_dir, "waf_ir_ip.json"),
    "custom": os.path.join(waf_dir, "waf_ir_custom.json"),
    "rate": os.path.join(waf_dir, "waf_ir_rate.json"),
}

for name, path in files.items():
    if not os.path.exists(path):
        print(f"ERROR: {path} not found", file=sys.stderr)
        sys.exit(1)

try:
    ip = json.load(open(files["ip"]))
    custom = json.load(open(files["custom"]))
    rate = json.load(open(files["rate"]))
except json.JSONDecodeError as e:
    print(f"ERROR: JSON parse failed: {e}", file=sys.stderr)
    sys.exit(1)

merged = {
    "ip_lists": ip.get("ip_lists", []),
    "ip_access_rules": ip.get("ip_access_rules", {}),
    "custom_rules": custom.get("custom_rules", {}),
    "rate_limiting_rules": rate.get("rate_limiting_rules", {}),
    "non_convertible_notes": custom.get("non_convertible_notes", []) + rate.get("non_convertible_notes", []),
}

out_path = os.path.join(waf_dir, "waf_ir.json")
json.dump(merged, open(out_path, "w"), indent=2)
print(f"OK: merged → {out_path}")
