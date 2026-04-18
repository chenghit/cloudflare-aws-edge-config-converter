#!/bin/bash

set -e

SKILLS_DIR="$HOME/.kiro/skills/cloudflare-aws-converter"
AGENTS_DIR="$HOME/.kiro/agents"

echo "Installing Cloudflare to AWS Converter Skills..."

# Create directories
mkdir -p "$SKILLS_DIR"

# Clean up old subagent skills and configs (all replaced by Python scripts)
echo "Cleaning up old subagent installations..."
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

# Remove all old agent configs
if [ -d "$AGENTS_DIR" ]; then
  rm -f "$AGENTS_DIR/cf-waf-converter.json"
  rm -f "$AGENTS_DIR/cf-waf-analyzer.json"
  rm -f "$AGENTS_DIR/cf-waf-analyzer-validator.json"
  rm -f "$AGENTS_DIR/cf-waf-terraform-generator.json"
  rm -f "$AGENTS_DIR/cf-functions-converter.json"
  rm -f "$AGENTS_DIR/cf-cdn-dns-parser.json"
  rm -f "$AGENTS_DIR/cf-cdn-input-validator.json"
  rm -f "$AGENTS_DIR/cf-cdn-per-domain-processor.json"
  rm -f "$AGENTS_DIR/cf-cdn-ir-chunk-validator.json"
  rm -f "$AGENTS_DIR/cf-cdn-ir-finalizer.json"
  rm -f "$AGENTS_DIR/cf-cdn-ir-final-validator.json"
  rm -f "$AGENTS_DIR/cf-cdn-tf-shared-policies.json"
  rm -f "$AGENTS_DIR/cf-cdn-tf-domain.json"
  rm -f "$AGENTS_DIR/cf-cdn-js-validator.json"
  rm -f "$AGENTS_DIR/cloudflare-aws-converter.json"
fi

# Copy skill files (orchestrator + all Python scripts + references)
echo "Copying skills to $SKILLS_DIR..."
cp cloudflare-aws-converter/SKILL.md "$SKILLS_DIR/"
cp -r cloudflare-aws-converter/references "$SKILLS_DIR/"
cp -r cloudflare-aws-converter/scripts "$SKILLS_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""
echo "To start a conversion:"
echo "  kiro-cli chat"
