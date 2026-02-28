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
rm -rf "$SKILLS_DIR/cf-waf-analyzer" "$SKILLS_DIR/cf-waf-analyzer-validator" "$SKILLS_DIR/cf-waf-terraform-generator" "$SKILLS_DIR/cf-waf-converter" "$SKILLS_DIR/cf-functions-converter" "$SKILLS_DIR/cf-cdn-analyzer" "$SKILLS_DIR/cf-cdn-analyzer-validator" "$SKILLS_DIR/SKILL.md"
cp -r cf-waf-analyzer "$SKILLS_DIR/"
cp -r cf-waf-analyzer-validator "$SKILLS_DIR/"
cp -r cf-functions-converter "$SKILLS_DIR/"
cp -r cf-cdn-analyzer "$SKILLS_DIR/"
cp -r cf-cdn-analyzer-validator "$SKILLS_DIR/"
cp cloudflare-aws-converter/SKILL.md "$SKILLS_DIR/"

# Copy subagent configurations
echo "Copying subagent configurations to $AGENTS_DIR..."
# Remove old WAF converter subagent if exists
rm -f "$AGENTS_DIR/cf-waf-converter.json"
cp subagents/cf-waf-analyzer.json "$AGENTS_DIR/"
cp subagents/cf-waf-analyzer-validator.json "$AGENTS_DIR/"
cp subagents/cf-functions-converter.json "$AGENTS_DIR/"
cp subagents/cf-cdn-analyzer.json "$AGENTS_DIR/"
cp subagents/cf-cdn-analyzer-validator.json "$AGENTS_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""
echo "Installed skills:"
echo "  - Orchestrator: $SKILLS_DIR/SKILL.md"
echo "  - WAF Analyzer: $SKILLS_DIR/cf-waf-analyzer/"
echo "  - WAF Analyzer Validator: $SKILLS_DIR/cf-waf-analyzer-validator/"
echo "  - Functions Converter: $SKILLS_DIR/cf-functions-converter/"
echo "  - CDN Analyzer: $SKILLS_DIR/cf-cdn-analyzer/"
echo "  - CDN Analyzer Validator: $SKILLS_DIR/cf-cdn-analyzer-validator/"
echo ""
echo "Installed subagents:"
echo "  - cf-waf-analyzer"
echo "  - cf-waf-analyzer-validator"
echo "  - cf-functions-converter"
echo "  - cf-cdn-analyzer"
echo "  - cf-cdn-analyzer-validator"
