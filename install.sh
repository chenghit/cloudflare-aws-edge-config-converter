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
  "$SKILLS_DIR/cf-waf-summary-scanner" \
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
cp -r cf-waf-summary-scanner "$SKILLS_DIR/"
cp -r cf-cdn-dns-parser "$SKILLS_DIR/"
cp -r cf-cdn-input-validator "$SKILLS_DIR/"
cp -r cf-cdn-per-domain-processor "$SKILLS_DIR/"
cp -r cf-cdn-ir-chunk-validator "$SKILLS_DIR/"
cp -r cf-cdn-ir-finalizer "$SKILLS_DIR/"
cp -r cf-cdn-ir-final-validator "$SKILLS_DIR/"
cp -r cf-cdn-tf-shared-policies "$SKILLS_DIR/"
cp -r cf-cdn-tf-domain "$SKILLS_DIR/"
cp -r cf-cdn-js-validator "$SKILLS_DIR/"
cp cloudflare-aws-converter/SKILL.md "$SKILLS_DIR/"
cp -r cloudflare-aws-converter/scripts "$SKILLS_DIR/"

# Copy subagent configurations
echo "Copying subagent configurations to $AGENTS_DIR..."
rm -f "$AGENTS_DIR/cf-waf-converter.json"
rm -f "$AGENTS_DIR/cf-functions-converter.json"
cp subagents/cf-waf-analyzer.json "$AGENTS_DIR/"
cp subagents/cf-waf-analyzer-validator.json "$AGENTS_DIR/"
cp subagents/cf-waf-terraform-generator.json "$AGENTS_DIR/"
cp subagents/cf-waf-summary-scanner.json "$AGENTS_DIR/"
cp subagents/cf-cdn-dns-parser.json "$AGENTS_DIR/"
cp subagents/cf-cdn-input-validator.json "$AGENTS_DIR/"
cp subagents/cf-cdn-per-domain-processor.json "$AGENTS_DIR/"
cp subagents/cf-cdn-ir-chunk-validator.json "$AGENTS_DIR/"
cp subagents/cf-cdn-ir-finalizer.json "$AGENTS_DIR/"
cp subagents/cf-cdn-ir-final-validator.json "$AGENTS_DIR/"
cp subagents/cf-cdn-tf-shared-policies.json "$AGENTS_DIR/"
cp subagents/cf-cdn-tf-domain.json "$AGENTS_DIR/"
cp subagents/cf-cdn-js-validator.json "$AGENTS_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""
echo "Installed skills:"
echo "  - Orchestrator: $SKILLS_DIR/SKILL.md"
echo "  - WAF Analyzer: $SKILLS_DIR/cf-waf-analyzer/"
echo "  - WAF Analyzer Validator: $SKILLS_DIR/cf-waf-analyzer-validator/"
echo "  - WAF Terraform Generator: $SKILLS_DIR/cf-waf-terraform-generator/"
echo "  - WAF Summary Scanner: $SKILLS_DIR/cf-waf-summary-scanner/"
echo "  - CDN DNS Parser: $SKILLS_DIR/cf-cdn-dns-parser/"
echo "  - CDN Input Validator: $SKILLS_DIR/cf-cdn-input-validator/"
echo "  - CDN Per-Domain Processor: $SKILLS_DIR/cf-cdn-per-domain-processor/"
echo "  - CDN IR Chunk Validator: $SKILLS_DIR/cf-cdn-ir-chunk-validator/"
echo "  - CDN IR Finalizer: $SKILLS_DIR/cf-cdn-ir-finalizer/"
echo "  - CDN IR Final Validator: $SKILLS_DIR/cf-cdn-ir-final-validator/"
echo "  - CDN TF Shared Policies: $SKILLS_DIR/cf-cdn-tf-shared-policies/"
echo "  - CDN TF Domain: $SKILLS_DIR/cf-cdn-tf-domain/"
echo "  - CDN JS Validator: $SKILLS_DIR/cf-cdn-js-validator/"
echo ""
echo "Installed subagents:"
echo "  - cf-waf-analyzer"
echo "  - cf-waf-analyzer-validator"
echo "  - cf-waf-terraform-generator"
echo "  - cf-waf-summary-scanner"
echo "  - cf-cdn-dns-parser"
echo "  - cf-cdn-input-validator"
echo "  - cf-cdn-per-domain-processor"
echo "  - cf-cdn-ir-chunk-validator"
echo "  - cf-cdn-ir-finalizer"
echo "  - cf-cdn-ir-final-validator"
echo "  - cf-cdn-tf-shared-policies"
echo "  - cf-cdn-tf-domain"
echo "  - cf-cdn-js-validator"
