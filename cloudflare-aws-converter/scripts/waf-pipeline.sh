#!/bin/bash
# waf-pipeline.sh — Run the entire WAF conversion pipeline.
# Usage: bash waf-pipeline.sh <config_path> [output_dir]
#
# config_path: CloudflareBackup root directory
# output_dir:  Output directory (default: cloudflare-to-aws-waf under CWD)
#
# Exit codes: 0 = OK, 1 = error in a pipeline step.

set -euo pipefail

CONFIG_PATH="${1:?Usage: waf-pipeline.sh <config_path> [output_dir] [--force-split]}"
OUTPUT_DIR="${2:-cloudflare-to-aws-waf}"
SPLIT_FLAG=""
for arg in "$@"; do
    if [ "$arg" = "--force-split" ]; then
        SPLIT_FLAG="--force-split"
    elif [ "$arg" = "--force-no-split" ]; then
        SPLIT_FLAG="--force-no-split"
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
    if ! "$@"; then
        echo ""
        echo "---RESULT---"
        echo "SPEC: 1"
        echo "STATUS: ERROR"
        echo "ACTION: FIX"
        echo "CONTEXT: Pipeline failed at step: $step_name"
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

# Check split decision
run_step "Check split" \
    python3 "$SCRIPTS_DIR/waf-check-split.py" "$OUTPUT_DIR" $SPLIT_FLAG

# Read split decision
SPLIT_MODE=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f: d = json.load(f)
print(d['mode'])" "$OUTPUT_DIR/waf_split_decision.json")
DEDUP=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f: d = json.load(f)
print(d['dedup'])" "$OUTPUT_DIR/waf_split_decision.json")

if [ "$SPLIT_MODE" = "split" ]; then
    run_step "Split by host" \
        python3 "$SCRIPTS_DIR/waf-split-by-host.py" "$CONFIG_PATH" "$OUTPUT_DIR"
fi

run_step "Generate CloudFormation" \
    python3 "$SCRIPTS_DIR/waf-generate-cfn.py" "$OUTPUT_DIR"

run_step "Generate README" \
    python3 "$SCRIPTS_DIR/waf-generate-readme.py" "$OUTPUT_DIR"

echo ""
echo "---RESULT---"
echo "SPEC: 1"
echo "STATUS: OK"
echo "OUTPUT_DIR: $OUTPUT_DIR"
echo "TEMPLATE: $OUTPUT_DIR/waf-cloudformation.json"
