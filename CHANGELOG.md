# Changelog

## [Unreleased] — 2026-03-21

### ⚠️ Kiro CLI 1.28+ Users: Subagent Shell Approval Workaround Required

**This only affects Kiro CLI 1.28+ users.** If you're on Kiro CLI 1.24–1.27, everything works as before — no changes needed.

Kiro CLI 1.28 introduced a [subagent permission change](https://github.com/kirodotdev/Kiro/issues/4751) that causes interactive shell approval prompts inside subagents, blocking the automated pipeline. This is a Kiro CLI issue, not a change in this tool. There is currently no configuration-level fix — `trustedAgents`, `allowedTools`, and `--trust-tools` do not apply to subagent internal tool calls ([#5071](https://github.com/kirodotdev/Kiro/issues/5071)).

**Workaround options (pick one):**

1. **`--trust-all-tools` (recommended for automated runs):**
   ```bash
   kiro-cli chat --agent cloudflare-aws-converter --trust-all-tools
   ```
   This trusts all tools for the entire session, including subagent shell calls. Review the orchestrator agent's `allowedTools` in `cloudflare-aws-converter.json` if you want to understand what gets auto-approved.

2. **Manual approval:** Start normally and press `y` at each prompt. Expect ~5-10 prompts for WAF, 50+ for a full CDN conversion.

3. **Wait for Kiro CLI fix:** Track [#4751](https://github.com/kirodotdev/Kiro/issues/4751) and [#5071](https://github.com/kirodotdev/Kiro/issues/5071).

### Added

- `cloudflare-aws-converter.json` orchestrator agent with `trustedAgents: ["cf-*"]`
- `## Available Tools` section in all 7 subagent SKILL.md files, declaring actual subagent runtime tools (`read`, `write`, `shell`, `code`)
- Absolute paths for all `references/` file citations in 5 subagent SKILL.md files (prevents subagents from needing to discover reference file locations)
- Lambda@Edge replica deletion troubleshooting entry in `docs/troubleshooting.md` and `docs/troubleshooting_CN.md`

### Changed

- `install.sh` now installs the orchestrator agent (`cloudflare-aws-converter.json`)
- README "Subagent Permissions and Security" section rewritten to explain the orchestrator agent and subagent runtime tool limitations
- Reordered Lambda@Edge troubleshooting entries: "destroy" issue now appears before "apply" issue

### Fixed

- Subagent `shell` approval blocking that prevented automated pipeline execution
- Subagent SKILL.md files referenced `glob` and `grep` which are not available in subagent runtime
- Relative `references/` paths in SKILL.md files caused subagents to use `ls` to discover file locations
