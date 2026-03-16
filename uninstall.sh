#!/bin/bash
set -e
SKILLS_DIR="$HOME/.kiro/skills/cloudflare-aws-converter"
AGENTS_DIR="$HOME/.kiro/agents"
echo "Uninstalling Cloudflare to AWS Converter Skills..."
# Remove skills
if [ -d "$SKILLS_DIR" ]; then
    echo "Removing skills from $SKILLS_DIR..."
    rm -rf "$SKILLS_DIR"
    echo "  ✓ Skills removed"
else
    echo "  ℹ Skills directory not found (already uninstalled?)"
fi
# Remove subagent configurations
REMOVED_COUNT=0
for agent in \
  cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter \
  cf-waf-summary-scanner cf-functions-converter \
  \
  cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor \
  cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator \
  cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator; do
    if [ -f "$AGENTS_DIR/$agent.json" ]; then
        rm "$AGENTS_DIR/$agent.json"
        ((REMOVED_COUNT++))
    fi
done
if [ $REMOVED_COUNT -gt 0 ]; then
    echo "Removing subagent configurations from $AGENTS_DIR..."
    echo "  ✓ $REMOVED_COUNT subagent(s) removed"
else
    echo "  ℹ Subagent configurations not found (already uninstalled?)"
fi
echo ""
echo "✅ Uninstallation complete!"
