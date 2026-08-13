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
from waf_common import (classify_convertibility, NON_CONVERTIBLE_AWS_EQUIV,
                        extract_host_scope, load_backup_json, backup_rules)

# ── Rate limit calculation ───────────────────────────────────────────────────

AWS_WINDOWS = [60, 120, 300, 600]

# Cloudflare rate-rule actions this pipeline can map (log → AWS Count).
KNOWN_RATE_ACTIONS = {"block", "log", "challenge", "js_challenge", "managed_challenge"}

# Rate aggregation keys that map to an AWS IP-aggregated RateBasedStatement.
# ip.src → per-source-IP (AWS AggregateKeyType=IP). cf.colo.id has no AWS
# equivalent, but the standard Cloudflare combo ["ip.src","cf.colo.id"] means
# "per IP, per Cloudflare data-center"; AWS has one global counter per rule
# instance, so it collapses to a WebACL-wide per-IP counter. That difference is
# documented globally (see docs/limitations) — it's a benign widening, so we
# still convert. The set MUST contain ip.src: the generator always emits
# AggregateKeyType=IP, so a cf.colo.id-only / empty / absent set would silently
# become a per-source-IP counter with different meaning (cf.colo.id alone =
# per-Cloudflare-datacenter). Any OTHER characteristic (header/cookie/path/ASN/
# visitor-id) needs RBR CUSTOM_KEYS, which this tool does not generate. All of
# these → non-convertible.
IP_AGGREGATION_CHARACTERISTICS = {"ip.src", "cf.colo.id"}

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
    """Newest timestamp of a per-zone file; fatal if it spans multiple zones."""
    matches = glob.glob(os.path.join(config_path, "**", pattern), recursive=True)
    if not matches:
        return None
    sources = {os.path.dirname(os.path.dirname(m)) for m in matches}
    if len(sources) > 1:
        zones = sorted(os.path.basename(s) for s in sources)
        print(f"ERROR: {pattern} found under multiple zones: {zones}", file=sys.stderr)
        print("\n---RESULT---\nSPEC: 1\nSTATUS: FATAL\nACTION: FIX\n"
              f"CONTEXT: multiple zones detected ({', '.join(zones)}); convert one zone at a time")
        sys.exit(1)
    chosen = sorted(matches)[-1]
    if len(matches) > 1:
        print(f"WARNING: {len(matches)} backups of {pattern} found; using newest "
              f"({os.path.basename(os.path.dirname(chosen))})", file=sys.stderr)
    return chosen


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

    data = load_backup_json(rate_path, "rate-limit rules")
    raw_rules = backup_rules(data, rate_path, "rate-limit rules")

    rules = []
    non_convertible_notes = []

    for i, raw in enumerate(raw_rules):
        # Disabled rules never run in Cloudflare — drop them (mirror the active
        # config; see waf-analyze-custom.py for the same rationale).
        if raw.get("enabled", True) is False:
            continue

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

        # Rate-limit STRUCTURE gate. Some ratelimit parameters change the COUNTER
        # semantics in ways an AWS RateBasedStatement can't reproduce. Converting
        # anyway would silently mis-limit traffic, so the whole rule is marked
        # non-convertible and reported for manual recreation (the rule stays in
        # the array with convertibility="no" so counts still reconcile).
        struct_nc = []  # list of (field_label, human_reason)
        if action not in KNOWN_RATE_ACTIONS:
            struct_nc.append((f"action:{action}",
                              f"Unsupported Cloudflare rate-rule action: {action}"))
        if ratelimit.get("requests_to_origin") is True:
            struct_nc.append(("ratelimit.requests_to_origin",
                "Cloudflare counts only origin-bound (cache-miss) requests; a CloudFront-scoped "
                "AWS WebACL runs BEFORE the cache and counts every request, so the same threshold "
                "would trip far sooner and throttle cached traffic. Recreate manually with an "
                "AWS-appropriate threshold."))
        if ratelimit.get("counting_expression"):
            struct_nc.append(("ratelimit.counting_expression",
                "Rate rule counts requests matching a separate counting expression; an AWS "
                "RateBasedStatement can only count requests matching its scope-down, with no "
                "distinct counting expression."))
        chars = ratelimit.get("characteristics", [])
        extra_chars = [c for c in chars if c not in IP_AGGREGATION_CHARACTERISTICS]
        if extra_chars:
            struct_nc.append(("ratelimit.characteristics",
                f"Aggregates on {extra_chars}; only ip.src/cf.colo.id map to AWS IP aggregation. "
                f"Other keys require an RBR with CUSTOM_KEYS, which this tool does not generate."))
        elif "ip.src" not in chars:
            # The generator always aggregates on IP (AggregateKeyType=IP). Without ip.src
            # (cf.colo.id-only, empty, or absent) converting would silently produce a
            # per-source-IP counter with different meaning — fail closed. Modern Cloudflare
            # rate rules always include ip.src.
            struct_nc.append(("ratelimit.characteristics",
                f"Rate aggregation {chars or '(none)'} has no ip.src; AWS aggregates per source IP, "
                f"so a cf.colo.id-only / empty / absent characteristic set can't be reproduced "
                f"faithfully. Recreate manually."))
        if struct_nc:
            entry["convertibility"] = "no"
            entry["non_convertible_reason"] = ", ".join(f for f, _ in struct_nc)
            rules.append(entry)
            for field_label, reason in struct_nc:
                non_convertible_notes.append({
                    "rule": description, "field": field_label, "reason": reason,
                    "aws_equivalent": "AWS WAF rate-based rule (manual)",
                    "manual_action": "Recreate this rate limit manually in AWS WAF",
                })
            continue

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

        # Extract IP sets. scope_tag "r{position}" keeps inline-set names unique
        # across rules AND across the custom section (which uses "c{position}").
        ip_sets = extract_ip_sets(cond, description, i + 1, scope_tag=f"r{i + 1}")
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
