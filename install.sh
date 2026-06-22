#!/bin/bash

set -e

# Install the cloudflare-aws-converter skill.
# Usage: install.sh <kiro|claude|BASE_DIR> [AGENT_EXT]
#   kiro     → ~/.kiro/skills/   (Kiro CLI, agent configs are *.json)
#   claude   → ~/.claude/skills/ (Claude Code, agent configs are *.md)
#   BASE_DIR → any other skill-based tool: pass its config base dir (the
#              parent of skills/ and agents/), optionally the agent config
#              extension as $2 (default: md).
# For any target whose skills dir differs from the Kiro default, the hardcoded
# ~/.kiro/skills/cloudflare-aws-converter paths in the installed copies are
# rewritten to the actual install dir. No default target: prompt if omitted.

TARGET="$1"
if [ -z "$TARGET" ]; then
  if [ -t 0 ]; then
    printf "Install for which tool? [kiro/claude/<base-dir>]: " >&2
    read -r TARGET
  else
    echo "ERROR: no target given. Run: install.sh <kiro|claude|BASE_DIR>" >&2
    exit 1
  fi
fi

case "$TARGET" in
  kiro)   TOOL="Kiro CLI";    BASE="$HOME/.kiro";   AGENT_EXT="json" ;;
  claude) TOOL="Claude Code"; BASE="$HOME/.claude"; AGENT_EXT="md"   ;;
  *)
    # Custom base dir for another skill-based tool.
    BASE="$TARGET"
    TOOL="custom ($BASE)"
    AGENT_EXT="${2:-md}"
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/cloudflare-aws-converter"
SKILLS_DIR="$BASE/skills/cloudflare-aws-converter"
AGENTS_DIR="$BASE/agents"
KIRO_DEFAULT_DIR="$HOME/.kiro/skills/cloudflare-aws-converter"

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

# Rewrite the hardcoded Kiro skill paths in the INSTALLED copies to the actual
# install dir, whenever it differs from the Kiro default. Source files ship with
# both ~/.kiro/... (SKILL.md, references) and $HOME/.kiro/... (cdn-init.sh)
# literal forms; match both and replace with the resolved absolute install dir.
# Leave the source repo files untouched.
# (sed -i.bak works on both macOS/BSD and GNU; remove the backups afterward.)
if [ "$SKILLS_DIR" != "$KIRO_DEFAULT_DIR" ]; then
  echo "Rewriting skill paths to $SKILLS_DIR..."
  find "$SKILLS_DIR" -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) -print0 \
    | xargs -0 sed -i.bak \
        -e "s|~/.kiro/skills/cloudflare-aws-converter|$SKILLS_DIR|g" \
        -e "s|\$HOME/.kiro/skills/cloudflare-aws-converter|$SKILLS_DIR|g"
  find "$SKILLS_DIR" -type f -name "*.bak" -delete
fi

# Keep the pipeline shell scripts executable
chmod +x "$SKILLS_DIR/scripts/"*.sh 2>/dev/null || true

echo ""
echo "✅ Installation complete!"
echo ""
echo "Installed skill: cloudflare-aws-converter -> $SKILLS_DIR"
echo ""
case "$TARGET" in
  kiro)
    echo "To start a conversion:"
    echo "  kiro-cli chat"
    ;;
  claude)
    echo "Restart Claude Code so it picks up the new skill, then verify:"
    echo "  - Type / in a session and look for 'cloudflare-aws-converter'"
    echo "  - Or just describe a conversion: \"Convert Cloudflare WAF rules in <path> to AWS\""
    ;;
  *)
    echo "Restart your agent tool so it discovers the skill at the path above."
    ;;
esac
