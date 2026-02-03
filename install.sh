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
rm -rf "$SKILLS_DIR/cf-waf-converter" "$SKILLS_DIR/cf-functions-converter"
cp -r cf-waf-converter "$SKILLS_DIR/"
cp -r cf-functions-converter "$SKILLS_DIR/"

# Copy subagent configurations
echo "Copying subagent configurations to $AGENTS_DIR..."
cp subagents/cf-waf-converter.json "$AGENTS_DIR/"
cp subagents/cf-functions-converter.json "$AGENTS_DIR/"

echo ""
echo "✅ Installation complete!"
echo ""
echo "Installed skills:"
echo "  - WAF Converter: $SKILLS_DIR/cf-waf-converter/"
echo "  - Functions Converter: $SKILLS_DIR/cf-functions-converter/"
echo ""
echo "Installed subagents:"
echo "  - cf-waf-converter"
echo "  - cf-functions-converter"
