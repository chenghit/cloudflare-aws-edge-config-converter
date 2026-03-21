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
  "$SKILLS_DIR/cf-cdn-tf-domain" \
  "$SKILLS_DIR/cf-cdn-js-validator" \
  "$SKILLS_DIR/SKILL.md" \
  "$SKILLS_DIR/scripts"

cp -r cf-waf-analyzer "$SKILLS_DIR/"
cp -r cf-waf-analyzer-validator "$SKILLS_DIR/"
cp -r cf-waf-terraform-generator "$SKILLS_DIR/"
cp -r cf-cdn-dns-parser "$SKILLS_DIR/"
cp -r cf-cdn-input-validator "$SKILLS_DIR/"
cp -r cf-cdn-tf-domain "$SKILLS_DIR/"
cp -r cf-cdn-js-validator "$SKILLS_DIR/"
cp cloudflare-aws-converter/SKILL.md "$SKILLS_DIR/"
cp -r cloudflare-aws-converter/scripts "$SKILLS_DIR/"

# Copy subagent configurations
echo "Copying subagent configurations to $AGENTS_DIR..."
rm -f "$AGENTS_DIR/cf-waf-converter.json"
rm -f "$AGENTS_DIR/cf-functions-converter.json"
rm -f "$AGENTS_DIR/cf-cdn-per-domain-processor.json"
rm -f "$AGENTS_DIR/cf-cdn-ir-chunk-validator.json"
rm -f "$AGENTS_DIR/cf-cdn-ir-finalizer.json"
rm -f "$AGENTS_DIR/cf-cdn-ir-final-validator.json"
rm -f "$AGENTS_DIR/cf-cdn-tf-shared-policies.json"
cp subagents/cloudflare-aws-converter.json "$AGENTS_DIR/"
cp subagents/cf-waf-analyzer.json "$AGENTS_DIR/"
cp subagents/cf-waf-analyzer-validator.json "$AGENTS_DIR/"
cp subagents/cf-waf-terraform-generator.json "$AGENTS_DIR/"
cp subagents/cf-cdn-dns-parser.json "$AGENTS_DIR/"
cp subagents/cf-cdn-input-validator.json "$AGENTS_DIR/"
cp subagents/cf-cdn-tf-domain.json "$AGENTS_DIR/"
cp subagents/cf-cdn-js-validator.json "$AGENTS_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""

# Detect Kiro CLI version and show appropriate start command
KIRO_VERSION=""
if command -v kiro-cli &>/dev/null; then
  KIRO_VERSION=$(kiro-cli --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
fi

KIRO_MAJOR=$(echo "$KIRO_VERSION" | cut -d. -f1)
KIRO_MINOR=$(echo "$KIRO_VERSION" | cut -d. -f2)

if [ -n "$KIRO_MAJOR" ] && [ "$KIRO_MAJOR" -ge 1 ] && [ "$KIRO_MINOR" -ge 28 ] 2>/dev/null; then
  echo "⚠️  Kiro CLI $KIRO_MAJOR.$KIRO_MINOR detected."
  echo "   Version 1.28+ has a subagent permission issue (https://github.com/kirodotdev/Kiro/issues/4751)"
  echo "   that requires --trust-all-tools to avoid shell approval prompts blocking the pipeline."
  echo ""
  echo "To start a conversion:"
  echo "  kiro-cli chat --agent cloudflare-aws-converter --trust-all-tools"
elif [ -n "$KIRO_MAJOR" ]; then
  echo "Kiro CLI $KIRO_MAJOR.$KIRO_MINOR detected."
  echo ""
  echo "To start a conversion:"
  echo "  kiro-cli chat"
else
  echo "To start a conversion:"
  echo "  kiro-cli chat --agent cloudflare-aws-converter --trust-all-tools"
  echo ""
  echo "  Kiro CLI 1.24-1.27 users can also use: kiro-cli chat"
fi
