#!/bin/bash
set -e
SKILLS_DIR="$HOME/.kiro/skills/cloudflare-aws-converter"
AGENTS_DIR="$HOME/.kiro/agents"
echo "Uninstalling Cloudflare to AWS Converter..."
# Remove skills
if [ -d "$SKILLS_DIR" ]; then
    echo "Removing skills from $SKILLS_DIR..."
    rm -rf "$SKILLS_DIR"
    echo "  ✓ Skills removed"
else
    echo "  ℹ Skills directory not found (already uninstalled?)"
fi
# Remove old agent configs (from previous versions that used subagents)
if [ -d "$AGENTS_DIR" ]; then
    for agent in \
      cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter \
      cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor \
      cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator \
      cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator cloudflare-aws-converter; do
        rm -f "$AGENTS_DIR/$agent.json"
    done
fi
echo ""
echo "✅ Uninstallation complete!"
