#!/usr/bin/env python3
"""Extract skip_labels_present from waf_ir_custom.json as single-line text.

Usage:
    python3 waf-extract-skip-labels.py <waf_ir_custom_json_path>

Outputs a single line to stdout:
    http_ratelimit=true all_remaining_custom_rules=false http_request_firewall_managed=true

Exit 0 on success, exit 1 on error.
"""
import json, sys

path = sys.argv[1]

try:
    data = json.load(open(path))
except (json.JSONDecodeError, FileNotFoundError) as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)

custom = data.get("custom_rules")
if not custom or "skip_labels_present" not in custom:
    print("ERROR: skip_labels_present field missing in custom_rules", file=sys.stderr)
    sys.exit(1)

labels = custom["skip_labels_present"]
keys = ["http_ratelimit", "all_remaining_custom_rules", "http_request_firewall_managed"]
for k in keys:
    if k not in labels:
        print(f"ERROR: skip_labels_present.{k} missing", file=sys.stderr)
        sys.exit(1)

parts = [f"{k}={str(labels[k]).lower()}" for k in keys]
print(" ".join(parts))
