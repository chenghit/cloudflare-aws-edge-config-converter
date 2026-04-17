#!/bin/bash
# cdn-init.sh — Create output directory structure and copy static Terraform modules
# Called by the orchestrator before running CDN pipeline scripts.
#
# Usage: cdn-init.sh <output_parent_dir> [skills_root]
#   output_parent_dir: cloudflare-to-aws-cdn/ will be created under this directory
#   skills_root:       path to skill installation (default: ~/.kiro/skills/cloudflare-aws-converter)

set -euo pipefail

OUTPUT_PARENT="${1:?Usage: cdn-init.sh <output_parent_dir> [skills_root]}"
SKILLS_ROOT="${2:-$HOME/.kiro/skills/cloudflare-aws-converter}"

OUTPUT_DIR="${OUTPUT_PARENT}/cloudflare-to-aws-cdn"
MODULE_SRC="${SKILLS_ROOT}/references/modules/cloudfront_distribution"
MODULE_DST="${OUTPUT_DIR}/terraform/modules/cloudfront_distribution"

# Create directory structure
mkdir -p \
  "${OUTPUT_DIR}/ir/accumulator" \
  "${OUTPUT_DIR}/ir/final" \
  "${OUTPUT_DIR}/ir/validation/chunk" \
  "${OUTPUT_DIR}/ir/validation/final" \
  "${OUTPUT_DIR}/ir/validation/js" \
  "${OUTPUT_DIR}/shared" \
  "${OUTPUT_DIR}/terraform/shared" \
  "${OUTPUT_DIR}/terraform/domains" \
  "${MODULE_DST}"

# Copy static Terraform module (only if source exists)
if [ -d "${MODULE_SRC}" ]; then
  cp -n "${MODULE_SRC}/main.tf" "${MODULE_DST}/main.tf" 2>/dev/null || true
  cp -n "${MODULE_SRC}/variables.tf" "${MODULE_DST}/variables.tf" 2>/dev/null || true
  cp -n "${MODULE_SRC}/outputs.tf" "${MODULE_DST}/outputs.tf" 2>/dev/null || true
  echo "✅ Terraform module copied to ${MODULE_DST}"
else
  echo "⚠️  Module source not found at ${MODULE_SRC} — tf-domain will copy it later"
fi

echo "✅ CDN output directory initialized at ${OUTPUT_DIR}"
