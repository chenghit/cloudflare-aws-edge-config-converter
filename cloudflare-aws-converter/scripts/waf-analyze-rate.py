#!/usr/bin/env python3
"""waf-analyze-rate.py — WAF Stage A3: Analyze Rate Limiting Rules.

Reads Rate-limits.txt,
parses expressions, calculates rate limits, reads skip labels from
waf_ir_custom.json.

Usage:
    python3 waf-analyze-rate.py <config_path> <output_dir>

Exit codes: 0 = OK, 1 = error.
"""
import json, sys, os, glob, math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from waf_expr_parser import parse, extract_ip_sets, ParseError
from waf_common import classify_convertibility, NON_CONVERTIBLE_AWS_EQUIV, extract_host_scope

# ── Rate limit calculation ───────────────────────────────────────────────────

AWS_WINDOWS = [60, 120, 300, 600]

def calculate_rate_limit(requests_per_period, period):
    """Calculate AWS WAF rate limit parameters.
    Returns (aws_limit, aws_window, mandatory_fallback, calculation_notes)."""
    notes = []
    for window in AWS_WINDOWS:
        limit = requests_per_period * (window / period)
        notes.append(f"{window}s: {requests_per_period}×({window}/{period})={limit:.1f}")
        if limit >= 10:
            return int(math.ceil(limit)), window, False, "; ".join(notes) + f" ≥ 10 ✓"

    return 10, 600, True, "; ".join(notes) + " — all < 10, mandatory fallback: 10/600s"


# ── File discovery ───────────────────────────────────────────────────────────

def find_file(config_path, pattern):
    matches = glob.glob(os.path.join(config_path, "**", pattern), recursive=True)
    return matches[0] if matches else None


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: waf-analyze-rate.py <config_path> <output_dir>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expanduser(sys.argv[1])
    output_dir = os.path.expanduser(sys.argv[2])

    # Read skip labels from waf_ir_custom.json
    custom_ir_path = os.path.join(output_dir, "waf_ir_custom.json")
    skip_http_ratelimit = False
    if os.path.exists(custom_ir_path):
        with open(custom_ir_path) as f:
            custom_ir = json.load(f)
        skip_http_ratelimit = custom_ir.get("custom_rules", {}).get(
            "skip_labels_present", {}).get("http_ratelimit", False)

    rate_path = find_file(config_path, "Rate-limits.txt")
    if not rate_path:
        ir = {"rate_limiting_rules": {"count": 0, "rules": []}, "non_convertible_notes": []}
        out_path = os.path.join(output_dir, "waf_ir_rate.json")
        json.dump(ir, open(out_path, "w"), indent=2)
        print(f"OK: 0 rate-limiting rules → {out_path}")
        return

    try:
        with open(rate_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print(f"  WARN: {rate_path} is empty or invalid JSON, treating as no rate rules", file=sys.stderr)
        data = {"result": {"rules": []}}

    raw_rules = data.get("result", {}).get("rules", [])
    if isinstance(data.get("result"), list):
        raw_rules = data["result"]

    rules = []
    non_convertible_notes = []

    for i, raw in enumerate(raw_rules):
        action = raw.get("action", "block")
        expression = raw.get("expression", "")
        description = raw.get("description", f"rate-rule-{i+1}")
        ratelimit = raw.get("ratelimit", {})

        requests_per_period = ratelimit.get("requests_per_period", 10)
        period = ratelimit.get("period", 60)

        aws_limit, aws_window, fallback, calc_notes = calculate_rate_limit(
            requests_per_period, period)

        entry = {
            "position": i + 1,
            "name": description,
            "action": action,
            "expression": expression,
            "requests_per_period": requests_per_period,
            "period": period,
            "aws_limit": aws_limit,
            "aws_evaluation_window_sec": aws_window,
            "mandatory_fallback": fallback,
            "calculation_notes": calc_notes,
            "scope_down": {"skip_http_ratelimit": skip_http_ratelimit},
            "convertibility": "yes",
        }

        # Parse expression
        try:
            cond = parse(expression)
            entry["conditions"] = cond
        except ParseError as e:
            entry["conditions"] = None
            entry["convertibility"] = "no"
            entry["parse_error"] = str(e)
            rules.append(entry)
            non_convertible_notes.append({
                "rule": description, "field": "expression",
                "reason": f"Parse error: {e}",
            })
            continue

        # Convertibility
        conv, pruned, nc_fields = classify_convertibility(cond)
        # Rate-based rules are always at least partial (rate limiting part is always convertible)
        if conv == "no":
            conv = "partial"
            entry["convertible_conditions"] = None
        elif conv == "partial":
            entry["convertible_conditions"] = pruned
        entry["convertibility"] = conv

        if nc_fields:
            entry["non_convertible_reason"] = ", ".join(nc_fields)
            for f in nc_fields:
                non_convertible_notes.append({
                    "rule": description, "field": f,
                    "reason": f"Non-convertible field in rate-limiting rule: {f}",
                    "aws_equivalent": NON_CONVERTIBLE_AWS_EQUIV.get(f, "No direct equivalent"),
                    "manual_action": f"Configure AWS equivalent for {f}",
                })

        # Extract IP sets
        ip_sets = extract_ip_sets(cond, description, i + 1)
        if ip_sets:
            entry["ip_sets"] = ip_sets

        # Extract host scope
        effective_cond = cond if conv != "partial" else entry.get("convertible_conditions", cond)
        entry["host_scope"] = extract_host_scope(effective_cond)

        if fallback:
            entry["_note"] = (f"Converted using fallback (10 req/600s ≈ "
                              f"{10/600*period:.1f} req/{period}s). Slightly more permissive "
                              f"than original ({requests_per_period} req/{period}s).")

        rules.append(entry)

    ir = {
        "rate_limiting_rules": {"count": len(rules), "rules": rules},
        "non_convertible_notes": non_convertible_notes,
    }

    out_path = os.path.join(output_dir, "waf_ir_rate.json")
    with open(out_path, "w") as f:
        json.dump(ir, f, indent=2, ensure_ascii=False)

    fallback_count = sum(1 for r in rules if r.get("mandatory_fallback"))
    print(f"OK: {len(rules)} rate-limiting rules ({fallback_count} with fallback) → {out_path}")
    print(f"\n---RESULT---\nSPEC: 1\nSTATUS: OK\nOUTPUT_FILE: {out_path}\n"
          f"RULE_COUNT: {len(rules)}\nFALLBACK_COUNT: {fallback_count}")


if __name__ == "__main__":
    main()
