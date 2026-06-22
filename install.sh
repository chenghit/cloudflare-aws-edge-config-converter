#!/bin/bash

set -e

# Install the cloudflare-aws-converter skill.
# Usage: install.sh <kiro|claude>
#   kiro   → ~/.kiro/skills/   (Kiro CLI, agent configs are *.json)
#   claude → ~/.claude/skills/ (Claude Code, agent configs are *.md; .kiro paths rewritten)
# No default: if no target is given, prompt for one.

TARGET="$1"
if [ -z "$TARGET" ]; then
  if [ -t 0 ]; then
    printf "Install for which tool? [kiro/claude]: " >&2
    read -r TARGET
  else
    echo "ERROR: no target given. Run: install.sh <kiro|claude>" >&2
    exit 1
  fi
fi

case "$TARGET" in
  kiro)   TOOL="Kiro CLI";     BASE="$HOME/.kiro";   AGENT_EXT="json" ;;
  claude) TOOL="Claude Code";  BASE="$HOME/.claude"; AGENT_EXT="md"   ;;
  *) echo "ERROR: unknown target '$TARGET' (use 'kiro' or 'claude')" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/cloudflare-aws-converter"
SKILLS_DIR="$BASE/skills/cloudflare-aws-converter"
AGENTS_DIR="$BASE/agents"

# Legacy subagent names from older designs, cleaned up on every install.
LEGACY_AGENTS="cf-waf-analyzer cf-waf-analyzer-validator cf-waf-terraform-generator cf-waf-converter \
cf-functions-converter cf-cdn-dns-parser cf-cdn-input-validator cf-cdn-per-domain-processor \
cf-cdn-ir-chunk-validator cf-cdn-ir-finalizer cf-cdn-ir-final-validator \
cf-cdn-tf-shared-policies cf-cdn-tf-domain cf-cdn-js-validator cloudflare-aws-converter"

if [ ! -f "$SOURCE_DIR/SKILL.md" ]; then
  echo "ERROR: $SOURCE_DIR/SKILL.md not found. Run this script from the repo." >&2
  exit 1
fi

echo "Installing Cloudflare to AWS Converter skill for $TOOL..."

mkdir -p "$SKILLS_DIR"

# Clean previous install (skill is 100% Python scripts — no subagents)
echo "Cleaning previous installation..."
rm -rf "$SKILLS_DIR/SKILL.md" "$SKILLS_DIR/references" "$SKILLS_DIR/scripts"

# Remove legacy subagent configs from older designs, if any exist
if [ -d "$AGENTS_DIR" ]; then
  for agent in $LEGACY_AGENTS; do
    rm -f "$AGENTS_DIR/$agent.$AGENT_EXT"
  done
fi

# Copy skill files (orchestrator + Python scripts + references)
echo "Copying skill to $SKILLS_DIR..."
cp "$SOURCE_DIR/SKILL.md" "$SKILLS_DIR/"
cp -r "$SOURCE_DIR/references" "$SKILLS_DIR/"
cp -r "$SOURCE_DIR/scripts" "$SKILLS_DIR/"
rm -rf "$SKILLS_DIR/scripts/__pycache__"

# For Claude Code, rewrite the .kiro skill paths to the .claude location in the
# INSTALLED copies. Source files default to ~/.kiro/skills/...; leave them untouched.
# (sed -i.bak works on both macOS/BSD and GNU; remove the backups afterward.)
if [ "$TARGET" = claude ]; then
  echo "Rewriting .kiro skill paths to .claude..."
  find "$SKILLS_DIR" -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) -print0 \
    | xargs -0 sed -i.bak 's|\.kiro/skills|.claude/skills|g'
  find "$SKILLS_DIR" -type f -name "*.bak" -delete
fi

# Keep the pipeline shell scripts executable
chmod +x "$SKILLS_DIR/scripts/"*.sh 2>/dev/null || true

echo ""
echo "✅ Installation complete!"
echo ""
echo "Installed skill: cloudflare-aws-converter -> $SKILLS_DIR"
echo ""
if [ "$TARGET" = claude ]; then
  echo "Restart Claude Code so it picks up the new skill, then verify:"
  echo "  - Type / in a session and look for 'cloudflare-aws-converter'"
  echo "  - Or just describe a conversion: \"Convert Cloudflare WAF rules in <path> to AWS\""
else
  echo "To start a conversion:"
  echo "  kiro-cli chat"
fi
