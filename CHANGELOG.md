# Changelog

## 2026-06-22

### Installer accepts a custom base dir for any skill-based tool

`install.sh` / `uninstall.sh` now accept a third target form: a custom config base directory (the parent of `skills/` and `agents/`), in addition to the `kiro` / `claude` presets. An optional second argument sets the agent-config extension (default `md`). The path-rewrite no longer keys off `target == claude` — it now fires whenever the resolved skill dir differs from the Kiro default, and rewrites the hardcoded `~/.kiro/skills/cloudflare-aws-converter` paths (both `~/` and `$HOME/` literal forms, across SKILL.md, reference docs, and `cdn-init.sh`) to the actual install dir. This makes the README "skill-based tools" workflow real — a third tool is now `./install.sh <base-dir>` with no manual editing.

**What changed**:
- Modified: `install.sh`, `uninstall.sh` — accept `<kiro|claude|BASE_DIR> [AGENT_EXT]`; rewrite gated on "dir differs from Kiro default" and substitutes the resolved install path; closing message handles the custom case
- Modified: `README.md`, `README_CN.md` — skill-based-tool instruction now says to pass the base dir as the target

### Docs: clarify which agent tools the skill model fits

Rewrote the "Using a different agent tool?" note in both READMEs to distinguish two cases: skill-based tools (same `SKILL.md` + `scripts/` layout as Kiro CLI / Claude Code, just a different directory) which need the `BASE`/`SKILLS_DIR` edit plus a path rewrite, versus non-skill tools (e.g. Codex CLI, driven by `AGENTS.md`) where there is nothing to install as a skill — the tool calls the pipeline scripts directly. No script changes.

**What changed**:
- Modified: `README.md`, `README_CN.md` — "Using a different agent tool?" note now covers skill-based vs non-skill tools

### Single install/uninstall script per action

Folded the Claude Code installers into `install.sh` / `uninstall.sh`, which now require an explicit target argument: `kiro` or `claude`. There is no default — running with no argument prompts for the target interactively (or errors with usage if stdin is not a terminal). The separate `install-claude.sh` / `uninstall-claude.sh` scripts are removed — use `./install.sh claude` instead. The target controls the base directory (`~/.kiro` vs `~/.claude`), agent config extension (`json` vs `md`), and the `.kiro`→`.claude` path rewrite (Claude only). The duplicated legacy-subagent cleanup list now lives in one place per script. Also fixed an inconsistency: the Kiro install path now `chmod +x`'s the pipeline shell scripts, matching the Claude path.

**What changed**:
- Modified: `install.sh`, `uninstall.sh` — require explicit `kiro`/`claude` target (prompt if omitted); all logic lives here
- Removed: `install-claude.sh`, `uninstall-claude.sh` — replaced by `./install.sh claude`
- Modified: `README.md`, `README_CN.md` — Installation section documents the required target argument

### Claude Code install support

Added `install-claude.sh` / `uninstall-claude.sh` to install the skill into Claude Code's `~/.claude/skills/` layout, alongside the existing Kiro CLI scripts. The installer rewrites `~/.kiro/skills/` paths to `~/.claude/skills/` in the installed copies (SKILL.md, reference docs, `cdn-init.sh`), automating the manual `sed` step previously documented in the README. Source repo files are left untouched, so the Kiro install path still works.

**What changed**:
- Added: `install-claude.sh`, `uninstall-claude.sh`
- Modified: `README.md`, `README_CN.md` — Installation section now documents both Kiro CLI and Claude Code paths

### WAF: warn AND translate on IP-set ref limit; clearer warning

When IP set references exceed the AWS WAF per-WebACL limit (50), the pipeline now emits a single `POST_ACTION` that does both: prints the warning to the user AND translates the deployment README for non-English users. Previously these were mutually exclusive — the translate reminder only fired when the limit was *not* exceeded. The warning text is also sharper: it states the deployment will fail as-is, shows the actual vs. allowed reference counts, and lists two concrete fixes (quota increase or `--force-split`).

**What changed**:
- Modified: `waf-pipeline.sh` — exceeded branch now emits one multi-step `POST_ACTION` (warn + translate); warning rewritten for clarity
- Modified: `cloudflare-aws-converter/SKILL.md` — removed stale `POST_ACTION_TRANSLATE` field reference; clarified that a single `POST_ACTION` may instruct multiple steps

## 2026-04-21

### CFF and KVS content-hash dedup

**CloudFront Functions dedup**: Identical CFF content across domains is now shared via a single CFF resource in `terraform/shared/`. For 54 domains with mostly identical rules, this reduces CFF count from 108 to 5 (2 shared + 3 independent), eliminating the 100 per-account quota concern.

**KVS dedup**: Same approach for Key Value Stores. Domains with identical KVS data share a single KVS resource. 54 domains → 2 KVS (1 shared + 1 independent).

**Resource Architecture section**: Conversion report now includes an explanation of why all cache behaviors share the same CFF (Cloudflare zone-wide rules), a per-domain resource mapping table, cost optimization guidance, and post-migration customization instructions.

**What changed**:
- Modified: `cdn-generate-js.py` — CFF content-hash dedup, KVS content-hash dedup, shared resource generation, resource architecture report section, CFF name truncation fix (64-char limit)
- Modified: `cdn-generate-tf-scaffold.py` — function_arn references use `local.viewer_request_arn`/`local.viewer_response_arn` for dedup compatibility
- Modified: `cdn-validate-js.py` — reads dedup manifest for shared CFF paths
- Modified: `cdn-finalize.py` — CFF quota check moved to Stage 8 (post-dedup)

## 2026-04-18

### Bug fixes and improvements

**CFF query string bug (P0)**: `request.rawQueryString()` does not exist in CloudFront Functions — replaced with `_qs()` helper that reconstructs raw query string from the parsed `request.querystring` object, handling multi-value parameters.

**WAF IP set reference count bugs**: The pre-check script (`waf-check-split.py`) had three counting bugs — overcounting unreferenced IP lists, undercounting multi-rule references, and including non-convertible rules. Deleted the pre-check entirely. The pipeline now tries legacy mode first and automatically falls back to per-domain split when reference statements exceed the per-WebACL hard limit of 50.

**What changed**:
- Deleted: `waf-check-split.py` (inaccurate pre-check replaced by try-then-fallback)
- Modified: `waf-generate-cfn.py` — CLI args (`--split`, `--force-no-split`), auto-fallback exit code, unreferenced IP set cleanup, dedup fully internal, per-domain PARTIAL support, quota metadata output
- Modified: `waf-pipeline.sh` — three-way branch (default/force-split/force-no-split), `POST_ACTION` translation reminder
- Modified: `waf-generate-readme.py` — Quota Usage section with actual IP set count and per-WebACL reference counts
- Modified: `cdn-generate-js.py` — `_qs()` helper for CFF query string reconstruction
- Fixed: unclosed file handles in `waf-merge-ir.py`, `waf-analyze-custom.py`, `waf-count-validate.py`
- Fixed: shell variable injection in `waf-pipeline.sh`

## 2026-04-16

### CDN Stages 1-2 replaced with Python — entire tool is now zero LLM

CDN Stages 1 (DNS parsing) and 2 (input validation) were the last LLM subagents. Both performed purely structural operations (JSON/CSV/YAML parsing, field validation) that required zero judgment. Now replaced by a single `cdn-parse-dns.py` that outputs both `dns_manifest.yaml` and `domain_scope.json` directly — no user input CSV, no validation stage, no user pause.

**Impact**: The entire tool (WAF + CDN) now runs with zero LLM invocations, zero user interaction. CDN pipeline time drops from ~7 min to <1 second. All domains default to `apply_default_cache_behavior: false` and `cert_arn_mode: "data_source"` (Terraform auto-lookup).

**What changed**:
- New: `cdn-parse-dns.py` — DNS.txt → dns_manifest.yaml + domain_scope.json (SaaS detection, origin classification, CloudFront loop exclusion, A/AAAA non-convertible handling)
- Deleted: `cf-cdn-dns-parser/` subagent
- Deleted: `cf-cdn-input-validator/` subagent
- Deleted: `subagents/` directory (empty after removal)
- Deleted: `cdn-validate-input.py` (no longer needed — no user CSV to validate)
- Updated: `SKILL.md` — Stage 1 outputs domain_scope.json directly, no Stage 2, no user pause
- Updated: `install.sh` — no subagent copying, only cleanup of old configs

### WAF: Per-domain WebACL with host-based rule splitting

When a customer's Cloudflare config has many inline IP lists (>50 total IP sets), the WAF pipeline now automatically switches to per-domain WebACLs — one per proxied domain. This solves the AWS WAF limit of 50 IP set + regex set references per WebACL.

**What changed**:
- New: `waf-check-split.py` — auto-decides legacy (2 WebACLs) vs per-domain split based on IP set count
- New: `waf-split-by-host.py` — splits IR by domain, strips redundant host conditions, re-derives scope-down per domain
- New: `extract_host_scope()` in `waf_common.py` — analyzes condition trees for host field references (eq, in, contains, branched OR)
- Modified: `waf-generate-cfn.py` — per-domain WebACL generation, IP set dedup (when inline >100), injected security rules
- Modified: `waf-generate-readme.py` — per-domain deployment guide with post-deployment checklist
- Modified: `waf-pipeline.sh` — new check-split and split-by-host steps, `--force-split` flag for testing
- Modified: `SKILL.md` — documents new pipeline steps and `--force-split` flag

**Injected security rules** (both legacy and split modes):
- Search engine labeling rule (Count + label for Googlebot/Bingbot/YandexBot by UA + ASN)
- Anti-DDoS AMR with scope-down excluding search engine label
- Always-on challenge rule (Count action — user changes to Challenge after review)
- Legacy mode: Website WebACL gets all three; API/File WebACL gets Anti-DDoS only (challenge disabled)
- Split mode: all domains get all three; users customize per-domain after deployment

**Auto-split decision tree**:
1. Total IP sets (named + inline) ≤ 50 → legacy mode (2 WebACLs)
2. > 50 → per-domain split
3. Inline IP sets > 100 → cross-rule dedup (merge identical inline IP sets)

### CDN JS generation and validation replaced with deterministic Python

CDN Stages 8 (JS generation) and 9 (JS validation) previously used LLM subagents (`cf-cdn-tf-domain`, `cf-cdn-js-validator`) invoked once per domain. These are now deterministic Python scripts (`cdn-generate-js.py`, `cdn-validate-js.py`) that process all domains in a single invocation.

**Performance impact**: CDN pipeline time drops from ~32 min to ~5 min for the example config (7 domains). For 50-domain zones, the improvement is even larger — Stages 8+9 go from ~50 min to <1 second.

**What changed**:
- New: `cdn-generate-js.py` — full JS codegen with condition mapping, dynamic expression translation (concat, regex_replace, wildcard_replace, and 15+ other Cloudflare functions), Lambda@Edge escalation
- New: `cdn-validate-js.py` — forbidden syntax, required structure, IR coverage, KVS consistency, size limit checks
- New: `parse_expression_full()` in `cdn_expr_parser.py` — recursive descent parser eliminating raw_expression fallback
- New: `parse_dynamic_expression()` — parses Cloudflare action expressions
- Deleted: `cf-cdn-tf-domain/` subagent and all reference docs
- Deleted: `cf-cdn-js-validator/` subagent and all reference docs
- CDN pipeline now uses LLM only for Stages 1–2 (DNS parsing, input validation)

## 2026-04-15

### Breaking: WAF pipeline output changed from Terraform to CloudFormation

The Terraform AWS provider hardcodes a 3-level nesting limit for WAFv2 statement blocks ([hashicorp/terraform-provider-aws#14377](https://github.com/hashicorp/terraform-provider-aws/issues/14377)). This caused `WAFInvalidParameterException` errors during `terraform apply` for customers with complex rules — particularly skip rules with many OR/AND branches, and rate-based rules with scope-down statements. The AWS WAF API itself has no nesting limit; the restriction is solely in the Terraform provider's schema.

The WAF pipeline now generates a **CloudFormation JSON template** instead of Terraform HCL, eliminating the nesting limit entirely. The entire WAF pipeline is also now deterministic Python — no LLM subagents are invoked.

### Added

- `waf_expr_parser.py` — recursive descent parser for Cloudflare WAF expressions
- `waf_common.py` — shared convertibility logic (field blacklist)
- `waf-analyze-custom.py` — Python replacement for A2 LLM analyzer batch
- `waf-analyze-rate.py` — Python replacement for A3 LLM analyzer batch
- `waf-validate-ir.py` — Python round-trip validation (replaces LLM validator)
- `waf-generate-cfn.py` — CloudFormation template generator with WCU tracking and quota validation
- `waf-pipeline.sh` — single entry point for the entire WAF pipeline
- `docs/why-cloudformation.md` — explains why CloudFormation instead of Terraform for WAF (nesting limit, `rule_json` drift detection gap, full comparison)

### Changed

- `SKILL.md` (orchestrator) — WAF pipeline section rewritten: single `waf-pipeline.sh` call replaces ~200 lines of LLM subagent dispatch logic
- `waf-analyze-ip.py` — outputs `conditions` field instead of `aws_statement_type` / `split_count`
- `waf-generate-readme.py` — CloudFormation deployment instructions replace Terraform
- `install.sh` — no longer installs WAF LLM subagents; cleans up old subagent configs

### Removed

- `cf-waf-analyzer` LLM subagent (replaced by Python scripts)
- `cf-waf-analyzer-validator` LLM subagent (replaced by Python round-trip validation)
- `cf-waf-terraform-generator` LLM subagent (replaced by Python CloudFormation generator)

### Migration

If you previously deployed WAF resources with the Terraform version:
1. `terraform destroy` in the old `cloudflare-to-aws-waf/` directory
2. Delete `cloudflare-to-aws-waf/` and re-run the pipeline
3. Deploy with `aws cloudformation deploy --template-file waf-cloudformation.json --stack-name cloudflare-waf-migration --region us-east-1`

## 2026-03-21

### Known Issue: Kiro CLI 1.28.0

Kiro CLI 1.28.0 had two bugs that broke subagent pipelines:
1. **Shell approval blocking** ([#4751](https://github.com/kirodotdev/Kiro/issues/4751)) — subagents triggered interactive approval on every `shell` call
2. **Subagent result return failure** ([#6163](https://github.com/kirodotdev/Kiro/issues/6163)) — subagents completed work but the orchestrator never received the result

Both bugs are fixed in **Kiro CLI 1.28.1**. If you're on 1.28.0, upgrade: `curl -fsSL https://cli.kiro.dev/install | bash`. Kiro CLI 1.24–1.27 and 1.28.1+ all work correctly.

### Added

- Absolute paths for all `references/` file citations in 5 subagent SKILL.md files (reduces path ambiguity when subagents read reference documents)
- `glob` pattern hint in `cf-cdn-dns-parser` Step 1 for DNS.txt discovery
- Orchestrator `references/` directory (`waf-pipeline.md`, `cdn-pipeline.md`) added to repo and install script
- Lambda@Edge replica deletion troubleshooting entry in `docs/troubleshooting.md` and `docs/troubleshooting_CN.md`

### Changed

- `install.sh` now copies orchestrator `references/` directory; warns if Kiro CLI 1.28.0 detected
- Reordered Lambda@Edge troubleshooting entries: "destroy" issue now appears before "apply" issue

### Fixed

- Relative `references/` paths in SKILL.md files could cause subagents to spend extra tool calls discovering file locations
