#!/bin/bash

set -e

# Install the cloudflare-aws-converter skill into Claude Code (CLI).
# Claude Code auto-discovers skills under ~/.claude/skills/ — no registration step.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/cloudflare-aws-converter"
SKILLS_DIR="$HOME/.claude/skills/cloudflare-aws-converter"
AGENTS_DIR="$HOME/.claude/agents"

if [ ! -f "$SOURCE_DIR/SKILL.md" ]; then
  echo "ERROR: $SOURCE_DIR/SKILL.md not found. Run this script from the repo." >&2
  exit 1
fi

echo "Installing Cloudflare to AWS Converter skill for Claude Code..."

# Create skill directory
mkdir -p "$SKILLS_DIR"

# Clean previous install (skill is 100% Python scripts — no subagents)
echo "Cleaning previous installation..."
rm -rf \
  "$SKILLS_DIR/SKILL.md" \
  "$SKILLS_DIR/references" \
  "$SKILLS_DIR/scripts"

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

# Copy skill files (orchestrator + Python scripts + references)
echo "Copying skill to $SKILLS_DIR..."
cp "$SOURCE_DIR/SKILL.md" "$SKILLS_DIR/"
cp -r "$SOURCE_DIR/references" "$SKILLS_DIR/"
cp -r "$SOURCE_DIR/scripts" "$SKILLS_DIR/"
rm -rf "$SKILLS_DIR/scripts/__pycache__"

# Rewrite Kiro skill paths to the Claude Code location in the INSTALLED copies.
# Source files default to ~/.kiro/skills/...; Claude Code uses ~/.claude/skills/...
# (sed -i.bak works on both macOS/BSD and GNU; remove the backups afterward.)
echo "Rewriting .kiro skill paths to .claude..."
find "$SKILLS_DIR" -type f \( -name "*.md" -o -name "*.sh" -o -name "*.py" \) -print0 \
  | xargs -0 sed -i.bak 's|\.kiro/skills|.claude/skills|g'
find "$SKILLS_DIR" -type f -name "*.bak" -delete

# Keep the pipeline shell scripts executable
chmod +x "$SKILLS_DIR/scripts/"*.sh 2>/dev/null || true

echo ""
echo "✅ Installation complete!"
echo ""
echo "Installed skill: cloudflare-aws-converter -> $SKILLS_DIR"
echo ""
echo "Restart Claude Code so it picks up the new skill, then verify:"
echo "  - Type / in a session and look for 'cloudflare-aws-converter'"
echo "  - Or just describe a conversion: \"Convert Cloudflare WAF rules in <path> to AWS\""
