#!/bin/bash
set -e

# Remove the cloudflare-aws-converter skill from Claude Code (CLI).

SKILLS_DIR="$HOME/.claude/skills/cloudflare-aws-converter"
AGENTS_DIR="$HOME/.claude/agents"

echo "Uninstalling Cloudflare to AWS Converter from Claude Code..."

# Remove skill
if [ -d "$SKILLS_DIR" ]; then
    echo "Removing skill from $SKILLS_DIR..."
    rm -rf "$SKILLS_DIR"
    echo "  ✓ Skill removed"
else
    echo "  ℹ Skill directory not found (already uninstalled?)"
fi

# Remove legacy subagent configs from older designs, if any exist
if [ -d "$AGENTS_DIR" ]; then
    for agent in \
      cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter \
      cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor \
      cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator \
      cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator cloudflare-aws-converter; do
        rm -f "$AGENTS_DIR/$agent.md"
    done
fi

echo ""
echo "✅ Uninstallation complete!"
echo "Restart Claude Code so it stops listing the skill."
