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

# Check if ref count exceeded (from metadata)
REF_EXCEEDED=""
if command -v jq &>/dev/null && [ -f "$OUTPUT_DIR/waf_metadata.json" ]; then
    REF_EXCEEDED=$(jq -r '.ref_exceeded // empty' "$OUTPUT_DIR/waf_metadata.json" 2>/dev/null)
fi

echo ""
echo "---RESULT---"
echo "SPEC: 1"
echo "STATUS: OK"
echo "OUTPUT_DIR: $OUTPUT_DIR"
echo "TEMPLATE: $OUTPUT_DIR/waf-cloudformation.json"
if [ -n "$REF_EXCEEDED" ]; then
    echo "POST_ACTION: Do BOTH of the following, in order:"
    echo "  1. PRINT this WARNING to the user exactly as-is:"
    echo "     ⚠️  WARNING: AWS WAF IP set reference limit exceeded — deployment WILL FAIL as-is."
    echo "     This WebACL references $REF_EXCEEDED IP sets, but AWS WAF allows at most 50 IP set references per WebACL."
    echo "     Deploying the generated CloudFormation template without changes will fail at create/update time."
    echo "     To fix, choose ONE:"
    echo "       a. Request an AWS WAF quota increase (contact AWS Sales/Support)."
    echo "       b. Re-run the conversion with --force-split to split into per-domain WebACLs (each stays under the 50-reference limit)."
    echo "  2. If user language is not English, translate README_aws-waf-deployment.md to user language and save as README_aws-waf-deployment_{lang}.md"
else
    echo "POST_ACTION: If user language is not English, translate README_aws-waf-deployment.md to user language and save as README_aws-waf-deployment_{lang}.md"
fi
