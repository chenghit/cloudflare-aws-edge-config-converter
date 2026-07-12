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

# Surface an over-limit BLOCKED state from the generator, if any. The generator
# always writes the template but sets a marker when it won't deploy as-is
# (WCU>5000, or a rule too big to pack). The packer keeps refs/RBR under the
# hard caps, so the old "50-ref → --force-split" fallback is gone.
BLOCKED=""
if command -v jq &>/dev/null && [ -f "$OUTPUT_DIR/waf_metadata.json" ]; then
    BLOCKED=$(jq -r '.blocked_count // empty' "$OUTPUT_DIR/waf_metadata.json" 2>/dev/null)
fi

echo ""
echo "---RESULT---"
echo "SPEC: 1"
if [ -n "$BLOCKED" ] && [ "$BLOCKED" != "0" ]; then
    echo "STATUS: BLOCKED"
else
    echo "STATUS: OK"
fi
echo "OUTPUT_DIR: $OUTPUT_DIR"
echo "TEMPLATE: $OUTPUT_DIR/waf-cloudformation.json"
if [ -n "$BLOCKED" ] && [ "$BLOCKED" != "0" ]; then
    echo "POST_ACTION: PRINT this WARNING to the user exactly as-is, then STOP (do not deploy):"
    echo "  ⚠️  WARNING: the generated WebACL exceeds an AWS hard cap and WILL be rejected at deploy."
    echo "  See BLOCKED_ITEMS in the generate step's ---RESULT--- for which WebACL/rule and why."
    echo "  Fix: reduce that WebACL's rule complexity (or split the affected hosts) in the source"
    echo "  Cloudflare config, then re-run this pipeline. The template was written for inspection only."
else
    echo "POST_ACTION: Before deploying, you MAY reconcile rule-group WCU against AWS with:"
    echo "  python3 $SCRIPTS_DIR/waf-verify-wcu.py $OUTPUT_DIR --profile <aws-profile>"
    echo "  (Optional — local WCU is calculator-exact. It only corrects the Capacity integer, never rule logic.)"
    echo "  If user language is not English, translate README_aws-waf-deployment.md to user language and save as README_aws-waf-deployment_{lang}.md"
fi
