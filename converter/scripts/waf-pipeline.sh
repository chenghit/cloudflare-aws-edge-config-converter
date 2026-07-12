#!/bin/bash
# waf-pipeline.sh — Run the entire WAF conversion pipeline.
# Usage: bash waf-pipeline.sh <config_path> [output_dir] [--force-split|--force-no-split]
#
# config_path: CloudflareBackup root directory
# output_dir:  Output directory (default: cloudflare-to-aws-waf under CWD)
#
# Modes:
#   (default)        Legacy mode (1-2 WebACLs), no split. If ref count exceeds 50, warn but continue.
#   --force-split    Skip legacy, go directly to per-domain split.
#
# Exit codes: 0 = OK, 1 = error in a pipeline step.

set -euo pipefail

CONFIG_PATH="${1:?Usage: waf-pipeline.sh <config_path> [output_dir] [--force-split]}"
OUTPUT_DIR="${2:-cloudflare-to-aws-waf}"
SPLIT_FLAG=""
for arg in "$@"; do
    if [ "$arg" = "--force-split" ]; then
        SPLIT_FLAG="--force-split"
    fi
done
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

# Resolve config path
CONFIG_PATH="$(cd "$CONFIG_PATH" 2>/dev/null && pwd)" || {
    echo "ERROR: config path not found: $1" >&2
    echo "---RESULT---"; echo "SPEC: 1"; echo "STATUS: FATAL"
    echo "CONTEXT: Config path '$1' does not exist"
    exit 1
}

# Create output directory
mkdir -p "$OUTPUT_DIR"

run_step() {
    local step_name="$1"; shift
    echo "[WAF] $step_name ..."
    # Capture combined output so we can inspect it before deciding what to emit.
    # `if ! out=$(...)` keeps this safe under `set -e` (a bare assignment from a
    # failing command substitution would abort the script before we can react).
    local out rc=0
    if ! out="$("$@" 2>&1)"; then rc=1; fi
    printf '%s\n' "$out"
    if [ $rc -ne 0 ]; then
        # One RESULT block per run: if the sub-step already emitted its own
        # (e.g. find_file's "multiple zones detected" FATAL), it was passed
        # through above — don't stack a generic block on top of it.
        if ! printf '%s' "$out" | grep -q -- '---RESULT---'; then
            echo ""
            echo "---RESULT---"
            echo "SPEC: 1"
            echo "STATUS: ERROR"
            echo "ACTION: FIX"
            echo "CONTEXT: Pipeline failed at step: $step_name"
        fi
        exit 1
    fi
}

run_step "A1: IP Lists + Access Rules" \
    python3 "$SCRIPTS_DIR/waf-analyze-ip.py" "$CONFIG_PATH" "$OUTPUT_DIR"

run_step "A2: Custom Rules" \
    python3 "$SCRIPTS_DIR/waf-analyze-custom.py" "$CONFIG_PATH" "$OUTPUT_DIR"

run_step "A3: Rate-Limiting Rules" \
    python3 "$SCRIPTS_DIR/waf-analyze-rate.py" "$CONFIG_PATH" "$OUTPUT_DIR"

run_step "Merge IR" \
    python3 "$SCRIPTS_DIR/waf-merge-ir.py" "$OUTPUT_DIR"

run_step "Count Validate" \
    python3 "$SCRIPTS_DIR/waf-count-validate.py" "$CONFIG_PATH" "$OUTPUT_DIR"

run_step "IR Validate" \
    python3 "$SCRIPTS_DIR/waf-validate-ir.py" "$CONFIG_PATH" "$OUTPUT_DIR"

# ── Generate CloudFormation ──────────────────────────────────────────────────

if [ "$SPLIT_FLAG" = "--force-split" ]; then
    # User forced split
    run_step "Split by host" \
        python3 "$SCRIPTS_DIR/waf-split-by-host.py" "$CONFIG_PATH" "$OUTPUT_DIR"
    run_step "Generate CloudFormation (split)" \
        python3 "$SCRIPTS_DIR/waf-generate-cfn.py" "$OUTPUT_DIR" --split

else
    # Default: legacy mode (no split), warn if ref count exceeds 50
    run_step "Generate CloudFormation (legacy)" \
        python3 "$SCRIPTS_DIR/waf-generate-cfn.py" "$OUTPUT_DIR" --force-no-split
fi

run_step "Generate README" \
    python3 "$SCRIPTS_DIR/waf-generate-readme.py" "$OUTPUT_DIR"

# ── Final summary ---RESULT--- ──────────────────────────────────────────────
# This is the last thing the agent sees for the WAF pipeline, so it must carry
# EVERY deploy concern (not just STATUS) — intermediate step RESULTs get diluted
# by later steps (esp. README translation). The generator wrote the facts into
# waf_metadata.json; we summarize them here. `python3 -c` reads the JSON (jq may
# be absent) and prints SUMMARY_* lines the agent must relay to the user.
echo ""
echo "---RESULT---"
echo "SPEC: 1"

python3 - "$OUTPUT_DIR" <<'PYEOF'
import json, os, sys
out = sys.argv[1]
try:
    m = json.load(open(os.path.join(out, "waf_metadata.json")))
except Exception:
    print("STATUS: OK"); print(f"OUTPUT_DIR: {out}"); sys.exit(0)

blocked = m.get("blocked_count", 0)
print("STATUS:", "BLOCKED" if blocked else "OK")
print(f"OUTPUT_DIR: {out}")
print(f"TEMPLATE: {out}/waf-cloudformation.json")
print(f"WEBACLS: {len(m.get('wcu_per_webacl', {}))}")

# --- deploy summary: quota concerns + what the tool auto-resolved ---
lines = []
wcu = m.get("wcu_per_webacl", {})
over_free = m.get("webacls_over_free_tier", {})
if wcu:
    lines.append("WebACL WCU: " + ", ".join(f"{n}={v}" for n, v in wcu.items())
                 + " (hard cap 5000; >1500 = extra charges)")
if over_free:
    lines.append("EXTRA COST — WCU over the 1500 free tier: "
                 + ", ".join(f"{n}={v}" for n, v in over_free.items())
                 + ". Deployable, but bills per 500-WCU tier above 1500.")
groups = m.get("rule_group_count", 0)
rbr = m.get("total_rate_based_rules", 0)
nwebacls = len(wcu) or 1
if groups:
    lines.append(f"AUTO-RESOLVED — {groups} rule group(s) created to fit AWS hard caps "
                 f"(10 rate-based rules + 50 reference statements per WebACL). "
                 + (f"{rbr} rate-based rules total exceed the 10/WebACL cap; "
                    if rbr > 10 * nwebacls else "")
                 + "overflow was packed into referenced rule groups — no action needed, "
                 "this is why the WebACL deploys despite exceeding the raw caps.")
if m.get("compact_size", 0) > 51200:
    kb = m["compact_size"] // 1024
    lines.append(f"PRE-DEPLOY ACTION — template is {kb} KB (> 51 KB direct-upload limit): "
                 "deployment REQUIRES an S3 bucket (see README for the exact command).")
if blocked:
    for b in m.get("blocked_items", []):
        lines.append(f"BLOCKED — {b}")

if lines:
    print("DEPLOY_SUMMARY:")
    for l in lines:
        print(f"  {l}")
PYEOF

# POST_ACTION: force the agent to report the full summary to the user BEFORE it
# moves on (e.g. to the CDN pipeline). A bare "STATUS: OK, running CDN next" is
# NOT acceptable — the deploy concerns above must reach the user first.
BLOCKED=""
if command -v jq &>/dev/null && [ -f "$OUTPUT_DIR/waf_metadata.json" ]; then
    BLOCKED=$(jq -r '.blocked_count // empty' "$OUTPUT_DIR/waf_metadata.json" 2>/dev/null)
fi
if [ -n "$BLOCKED" ] && [ "$BLOCKED" != "0" ]; then
    echo "POST_ACTION: Do ALL of the following, in order:"
    echo "  1. PRINT this to the user and STOP — do NOT deploy and do NOT start another pipeline yet:"
    echo "     ⚠️  WARNING: a generated WebACL exceeds an AWS hard cap and WILL be rejected at deploy."
    echo "     See BLOCKED lines in DEPLOY_SUMMARY for which WebACL/rule. Fix: reduce that WebACL's"
    echo "     rule complexity (or split affected hosts) in the source Cloudflare config, then re-run."
    echo "  2. Report the full DEPLOY_SUMMARY above to the user before any further step."
else
    echo "POST_ACTION: Do ALL of the following, in order:"
    echo "  1. REPORT the full WAF DEPLOY_SUMMARY above to the user — every line — as a completion summary."
    echo "     If another pipeline (e.g. CDN) is queued, present this WAF summary to the user FIRST;"
    echo "     do not collapse it to a bare 'STATUS: OK' before continuing."
    echo "  2. Tell the user the optional pre-deploy WCU check is available:"
    echo "     python3 $SCRIPTS_DIR/waf-verify-wcu.py $OUTPUT_DIR --profile <aws-profile>"
    echo "     (local WCU is calculator-exact; it only corrects the Capacity integer, never rule logic.)"
    echo "  3. If user language is not English, translate README_aws-waf-deployment.md to that language"
    echo "     as README_aws-waf-deployment_{lang}.md."
fi
