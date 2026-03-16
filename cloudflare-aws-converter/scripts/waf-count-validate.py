#!/usr/bin/env python3
"""Validate rule counts between source config files and rule_index.json.

Usage:
    python3 waf-count-validate.py <config_path> <waf_output_dir>

Exit 0 if all counts match, exit 1 with details if mismatch.
Only uses Python standard library (json, os, sys).
"""
import json, sys, os

config_path = sys.argv[1]
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

# --- Index counts (from rule_index.json) ---
index_path = os.path.join(waf_dir, "rule_index.json")
if not os.path.exists(index_path):
    print(f"ERROR: {index_path} not found")
    sys.exit(1)

idx = json.load(open(index_path))

index = {
    "custom_count": idx.get("custom_rules", {}).get("count", 0),
    "custom_rules_len": len(idx.get("custom_rules", {}).get("rules", [])),
    "rate_count": idx.get("rate_limiting_rules", {}).get("count", 0),
    "rate_rules_len": len(idx.get("rate_limiting_rules", {}).get("rules", [])),
    "ip_count": idx.get("ip_access_rules", {}).get("count", 0),
    "ip_rules_len": len(idx.get("ip_access_rules", {}).get("rules", [])),
}

# --- Compare ---
errors = []

if source["custom"] != index["custom_count"]:
    errors.append(f"custom: source={source['custom']} index_count={index['custom_count']}")
if source["custom"] != index["custom_rules_len"]:
    errors.append(f"custom rules array: source={source['custom']} index_len={index['custom_rules_len']}")
if index["custom_count"] != index["custom_rules_len"]:
    errors.append(f"custom internal: count={index['custom_count']} rules_len={index['custom_rules_len']}")

if source["rate"] != index["rate_count"]:
    errors.append(f"rate: source={source['rate']} index_count={index['rate_count']}")
if source["rate"] != index["rate_rules_len"]:
    errors.append(f"rate rules array: source={source['rate']} index_len={index['rate_rules_len']}")
if index["rate_count"] != index["rate_rules_len"]:
    errors.append(f"rate internal: count={index['rate_count']} rules_len={index['rate_rules_len']}")

if source["ip"] != index["ip_count"]:
    errors.append(f"ip: source={source['ip']} index_count={index['ip_count']}")
if source["ip"] != index["ip_rules_len"]:
    errors.append(f"ip rules array: source={source['ip']} index_len={index['ip_rules_len']}")
if index["ip_count"] != index["ip_rules_len"]:
    errors.append(f"ip internal: count={index['ip_count']} rules_len={index['ip_rules_len']}")

if errors:
    print("COUNT MISMATCH:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print(f"OK: custom={source['custom']} rate={source['rate']} ip={source['ip']}")
