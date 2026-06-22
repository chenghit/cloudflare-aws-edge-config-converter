#!/bin/bash
set -e

# Uninstall the cloudflare-aws-converter skill.
# Usage: uninstall.sh <kiro|claude>
# No default: if no target is given, prompt for one.

TARGET="$1"
if [ -z "$TARGET" ]; then
  if [ -t 0 ]; then
    printf "Uninstall for which tool? [kiro/claude]: " >&2
    read -r TARGET
  else
    echo "ERROR: no target given. Run: uninstall.sh <kiro|claude>" >&2
    exit 1
  fi
fi

case "$TARGET" in
  kiro)   TOOL="Kiro CLI";    BASE="$HOME/.kiro";   AGENT_EXT="json" ;;
  claude) TOOL="Claude Code"; BASE="$HOME/.claude"; AGENT_EXT="md"   ;;
  *) echo "ERROR: unknown target '$TARGET' (use 'kiro' or 'claude')" >&2; exit 1 ;;
esac

SKILLS_DIR="$BASE/skills/cloudflare-aws-converter"
AGENTS_DIR="$BASE/agents"

LEGACY_AGENTS="cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter \
cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor \
cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator \
cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator cloudflare-aws-converter"

echo "Uninstalling Cloudflare to AWS Converter from $TOOL..."

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
    for agent in $LEGACY_AGENTS; do
        rm -f "$AGENTS_DIR/$agent.$AGENT_EXT"
    done
fi

echo ""
echo "✅ Uninstallation complete!"
if [ "$TARGET" = claude ]; then
    echo "Restart Claude Code so it stops listing the skill."
fi
