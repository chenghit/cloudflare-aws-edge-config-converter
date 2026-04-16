#!/bin/bash

set -e

SKILLS_DIR="$HOME/.kiro/skills/cloudflare-aws-converter"
AGENTS_DIR="$HOME/.kiro/agents"

echo "Installing Cloudflare to AWS Converter Skills..."

# Create directories
mkdir -p "$SKILLS_DIR"
mkdir -p "$AGENTS_DIR"

# Copy skills
echo "Copying skills to $SKILLS_DIR..."
rm -rf \
  "$SKILLS_DIR/cf-waf-analyzer" \
  "$SKILLS_DIR/cf-waf-analyzer-validator" \
  "$SKILLS_DIR/cf-waf-terraform-generator" \
  "$SKILLS_DIR/cf-waf-converter" \
  "$SKILLS_DIR/cf-functions-converter" \
  "$SKILLS_DIR/cf-cdn-dns-parser" \
  "$SKILLS_DIR/cf-cdn-input-validator" \
  "$SKILLS_DIR/cf-cdn-per-domain-processor" \
  "$SKILLS_DIR/cf-cdn-ir-chunk-validator" \
  "$SKILLS_DIR/cf-cdn-ir-finalizer" \
  "$SKILLS_DIR/cf-cdn-ir-final-validator" \
  "$SKILLS_DIR/cf-cdn-tf-shared-policies" \
  "$SKILLS_DIR/SKILL.md" \
  "$SKILLS_DIR/scripts"

cp -r cf-cdn-dns-parser "$SKILLS_DIR/"
cp -r cf-cdn-input-validator "$SKILLS_DIR/"
cp cloudflare-aws-converter/SKILL.md "$SKILLS_DIR/"
cp -r cloudflare-aws-converter/references "$SKILLS_DIR/"
cp -r cloudflare-aws-converter/scripts "$SKILLS_DIR/"

# Copy subagent configurations (CDN only — WAF pipeline has no LLM subagents)
echo "Copying subagent configurations to $AGENTS_DIR..."
rm -f "$AGENTS_DIR/cf-waf-converter.json"
rm -f "$AGENTS_DIR/cf-functions-converter.json"
rm -f "$AGENTS_DIR/cf-cdn-per-domain-processor.json"
rm -f "$AGENTS_DIR/cf-cdn-ir-chunk-validator.json"
rm -f "$AGENTS_DIR/cf-cdn-ir-finalizer.json"
rm -f "$AGENTS_DIR/cf-cdn-ir-final-validator.json"
rm -f "$AGENTS_DIR/cf-cdn-tf-shared-policies.json"
rm -f "$AGENTS_DIR/cloudflare-aws-converter.json"
# Remove old WAF subagent configs
rm -f "$AGENTS_DIR/cf-waf-analyzer.json"
rm -f "$AGENTS_DIR/cf-waf-analyzer-validator.json"
rm -f "$AGENTS_DIR/cf-waf-terraform-generator.json"
# Remove old CDN JS subagent configs (replaced by Python scripts)
rm -f "$AGENTS_DIR/cf-cdn-tf-domain.json"
rm -f "$AGENTS_DIR/cf-cdn-js-validator.json"
rm -rf "$SKILLS_DIR/cf-cdn-tf-domain"
rm -rf "$SKILLS_DIR/cf-cdn-js-validator"
cp subagents/cf-cdn-dns-parser.json "$AGENTS_DIR/"
cp subagents/cf-cdn-input-validator.json "$AGENTS_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""

# Detect Kiro CLI version and warn about 1.28.0
if command -v kiro-cli &>/dev/null; then
  KIRO_FULL=$(kiro-cli --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ "$KIRO_FULL" = "1.28.0" ]; then
    echo "⚠️  Kiro CLI 1.28.0 detected — this version has known bugs that break"
    echo "   subagent pipelines (#4751, #6163). Please upgrade to 1.28.1+:"
    echo ""
    echo "   curl -fsSL https://cli.kiro.dev/install | bash"
    echo ""
  fi
fi

echo "To start a conversion:"
echo "  kiro-cli chat"
