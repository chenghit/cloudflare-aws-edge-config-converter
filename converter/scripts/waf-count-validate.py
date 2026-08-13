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
# `source` holds ACTIVE (enabled) rule counts — the IR excludes disabled rules,
# so the active count is the one that must reconcile. `disabled` is tracked
# separately for visibility (it never enters the comparison).
source = {}
disabled = {"custom": 0, "rate": 0}

def find_file(base_path, filename):
    """Find a file recursively under base_path. Returns first match or None.

    followlinks=True so a symlinked per-zone view (see SKILL.md multi-zone
    flow) is walked like the glob-based scripts, which follow symlinks.
    """
    for root, dirs, files in os.walk(base_path, followlinks=True):
        if filename in files:
            return os.path.join(root, filename)
    return None

def _fatal(context):
    """Emit the standard ---RESULT--- FATAL block (SCRIPT_STANDARDS) and exit."""
    print(f"ERROR: {context}", file=sys.stderr)
    print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
          f"CONTEXT: {context}")
    sys.exit(1)


def safe_load_json(path):
    """Load a present backup file. Present-but-corrupt is FATAL — counting a
    corrupt export as 0 rules would hide a broken conversion behind a passing
    count check. (Mirrors waf_common.load_backup_json; inlined so this validator
    stays dependency-free, as its docstring promises.)"""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError) as e:
        _fatal(f"{path} is present but not valid JSON: {e} — re-run the backup")
    if not isinstance(data, dict) or data.get("success") is not True:
        _fatal(f"{path} is not a successful Cloudflare API response")
    return data


def count_rules(rules):
    """(active, disabled). Disabled rules are dropped from the IR by the
    analyzers, so the source's ACTIVE count is what must match the IR count."""
    disabled = sum(1 for r in rules if isinstance(r, dict) and r.get("enabled", True) is False)
    return len(rules) - disabled, disabled

def source_rules(data, path):
    """Extract + validate the rules array from a custom/rate backup: a bare list of objects, or an
    object with a list-typed `rules` of objects. FATAL on any other shape (mirror of
    waf_common.backup_rules; inlined to keep this validator dependency-free) — a wrong shape must
    not be silently counted as 0 and pass the check."""
    result = data.get("result")
    if isinstance(result, list):
        rules = result
    elif isinstance(result, dict) and isinstance(result.get("rules"), list):
        rules = result["rules"]
    else:
        _fatal(f"{path}: result is neither a rules list nor a {{rules: [...]}} object")
    if not all(isinstance(r, dict) for r in rules):
        _fatal(f"{path}: a rule entry is not an object")
    return rules

# WAF Custom Rules
custom_path = find_file(config_path, "WAF-Custom-Rules.txt")
if custom_path:
    source["custom"], disabled["custom"] = count_rules(source_rules(safe_load_json(custom_path), custom_path))
else:
    source["custom"] = 0

# Rate Limiting Rules
rate_path = find_file(config_path, "Rate-limits.txt")
if rate_path:
    source["rate"], disabled["rate"] = count_rules(source_rules(safe_load_json(rate_path), rate_path))
else:
    source["rate"] = 0

# IP Access Rules
ip_path = find_file(config_path, "IP-Access-Rules.txt")
if ip_path:
    result = safe_load_json(ip_path).get("result")
    if not isinstance(result, list):
        _fatal(f"{ip_path}: IP access rules result is not a list")
    source["ip"] = len(result)
else:
    source["ip"] = 0

# --- IR counts (from waf_ir.json) ---
ir_path = os.path.join(waf_dir, "waf_ir.json")
if not os.path.exists(ir_path):
    print(f"ERROR: {ir_path} not found")
    sys.exit(1)

with open(ir_path) as f:
    ir = json.load(f)

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

disabled_note = ""
if disabled["custom"] or disabled["rate"]:
    disabled_note = (f" (disabled, excluded from IR: "
                     f"custom={disabled['custom']} rate={disabled['rate']})")
print(f"OK: custom={source['custom']} rate={source['rate']} ip={source['ip']}"
      f"{disabled_note}")
