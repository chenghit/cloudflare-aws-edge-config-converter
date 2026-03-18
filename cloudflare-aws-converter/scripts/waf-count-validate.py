#!/usr/bin/env python3
"""Validate rule counts between source config files and waf_ir.json.

Usage:
    python3 waf-count-validate.py <config_path> <waf_output_dir>

Exit 0 if all counts match, exit 1 with details if mismatch.
Only uses Python standard library (json, os, sys).
"""
import json, sys, os

config_path = os.path.expanduser(sys.argv[1])
waf_dir = sys.argv[2]

# --- Source counts (ground truth from Cloudflare config files) ---
source = {}

def find_file(base_path, filename):
    """Find a file recursively under base_path. Returns first match or None."""
    for root, dirs, files in os.walk(base_path):
        if filename in files:
            return os.path.join(root, filename)
    return None

# WAF Custom Rules
custom_path = find_file(config_path, "WAF-Custom-Rules.txt")
if custom_path:
    data = json.load(open(custom_path))
    if isinstance(data.get("result"), dict) and "rules" in data["result"]:
        source["custom"] = len(data["result"]["rules"])
    elif isinstance(data.get("result"), list):
        source["custom"] = len(data["result"])
    else:
        source["custom"] = 0
else:
    source["custom"] = 0

# Rate Limiting Rules
rate_path = find_file(config_path, "Rate-limits.txt")
if rate_path:
    data = json.load(open(rate_path))
    if isinstance(data.get("result"), dict) and "rules" in data["result"]:
        source["rate"] = len(data["result"]["rules"])
    elif isinstance(data.get("result"), list):
        source["rate"] = len(data["result"])
    else:
        source["rate"] = 0
else:
    source["rate"] = 0

# IP Access Rules
ip_path = find_file(config_path, "IP-Access-Rules.txt")
if ip_path:
    data = json.load(open(ip_path))
    if isinstance(data.get("result"), list):
        source["ip"] = len(data["result"])
    else:
        source["ip"] = 0
else:
    source["ip"] = 0

# --- IR counts (from waf_ir.json) ---
ir_path = os.path.join(waf_dir, "waf_ir.json")
if not os.path.exists(ir_path):
    print(f"ERROR: {ir_path} not found")
    sys.exit(1)

ir = json.load(open(ir_path))

ir_counts = {
    "custom_count": ir.get("custom_rules", {}).get("count", 0),
    "custom_rules_len": len(ir.get("custom_rules", {}).get("rules", [])),
    "rate_count": ir.get("rate_limiting_rules", {}).get("count", 0),
    "rate_rules_len": len(ir.get("rate_limiting_rules", {}).get("rules", [])),
    "ip_count": ir.get("ip_access_rules", {}).get("count", 0),
    "ip_rules_len": len(ir.get("ip_access_rules", {}).get("rules", [])),
}

# --- Compare ---
errors = []

if source["custom"] != ir_counts["custom_count"]:
    errors.append(f"custom: source={source['custom']} ir_count={ir_counts['custom_count']}")
if source["custom"] != ir_counts["custom_rules_len"]:
    errors.append(f"custom rules array: source={source['custom']} ir_len={ir_counts['custom_rules_len']}")
if ir_counts["custom_count"] != ir_counts["custom_rules_len"]:
    errors.append(f"custom internal: count={ir_counts['custom_count']} rules_len={ir_counts['custom_rules_len']}")

if source["rate"] != ir_counts["rate_count"]:
    errors.append(f"rate: source={source['rate']} ir_count={ir_counts['rate_count']}")
if source["rate"] != ir_counts["rate_rules_len"]:
    errors.append(f"rate rules array: source={source['rate']} ir_len={ir_counts['rate_rules_len']}")
if ir_counts["rate_count"] != ir_counts["rate_rules_len"]:
    errors.append(f"rate internal: count={ir_counts['rate_count']} rules_len={ir_counts['rate_rules_len']}")

if source["ip"] != ir_counts["ip_count"]:
    errors.append(f"ip: source={source['ip']} ir_count={ir_counts['ip_count']}")
if source["ip"] != ir_counts["ip_rules_len"]:
    errors.append(f"ip rules array: source={source['ip']} ir_len={ir_counts['ip_rules_len']}")
if ir_counts["ip_count"] != ir_counts["ip_rules_len"]:
    errors.append(f"ip internal: count={ir_counts['ip_count']} rules_len={ir_counts['ip_rules_len']}")

if errors:
    print("COUNT MISMATCH:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print(f"OK: custom={source['custom']} rate={source['rate']} ip={source['ip']}")
