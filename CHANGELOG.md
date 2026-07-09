# Changelog

## 2026-07-09

### CDN: fix 15 convertibility / action-value bugs + subdivision classification

A follow-up audit of the CDN pipeline (commit `ab45880`) surfaced a class of silent bugs where a Cloudflare rule was reported as "converted" but the generated CloudFront Function JS either did nothing, fired on every request, or threw at runtime. All were confirmed by exercising the real processor + generator end-to-end, and every Cloudflare-field / CloudFront-capability assumption was verified against the official docs. The example config exercises none of these paths, which is why they went undetected. All fixes are covered by regression tests in `test_dynamic_values.py` (now 45 checks); the full CDN pipeline still runs green on the example config (54 domains, 108→5 CFF dedup) and every generated JS file passes `node --check`.

**Correctness — was producing silently wrong or crashing JS**:
- `http.request.full_uri` with `contains` / `eq` / `matches` / scheme-less wildcard was dead-coded to `if (false)` — the rule never fired. Now reconstructed as `'https://' + host + uri (+ ?query)` per target and matched for real. Scheme is assumed https (CloudFront edge functions don't expose it); noted in `conversion_report.md`.
- A negated unmappable-field condition emitted `!(false)` = `true` — fail **open** (fired on every request). Now emits `false` regardless of negation, including the `logic:not` wrapper form.
- A viewer-request query rewrite using `sha256()` emitted `crypto.createHash` without `import crypto` → `ReferenceError`. Added `query_expression` to crypto detection.
- A viewer-**response** header value using `sha256()`/HMAC had the same missing-import bug (the response generator never emitted the import at all). Fixed; `_needs_crypto` now scans a single handler's ops so each file pulls its own import.
- `continent` / `is_eu` in a viewer-**response** condition referenced undefined variables — the response generator never emitted the country+KVS preamble and had no `const request`. Now mirrors viewer-request (KVS reads work in viewer-response, AWS-confirmed).
- `add_*_header` dropped a dynamic `value_expression` and shipped `{value: ''}`. Now resolves it like `set_*_header`.
- A redirect target / rewrite path / query expression referencing an unmappable field leaked an inline `'' /* WARNING… */` marker into the JS (tripping the whole-domain validator). Now screened per-rule into a clean `non_convertible`, matching how header values were already handled.
- A single Redirect Rule's `preserve_query_string=True` was stored but never applied. The redirect now appends the incoming query to the `Location`, choosing `?` vs `&` by whether the target already has one.
- A `value_expression` that failed to parse silently shipped an empty value. Now emits the same leak marker the unmappable path uses, so `cdn-validate-js` catches it.

**Correctness — geo field classification** (verified against AWS + Cloudflare docs):
- `ip.src.subdivision_1_iso_code` (first-level region) is convertible via the `CloudFront-Viewer-Country-Region` header — it was wrongly listed as non-convertible while `FIELD_TO_ORP_HEADERS` already mapped it, so the file contradicted itself. Now converts.
- `ip.src.subdivision_2_iso_code` (second-level region) has no CloudFront header — added explicitly as non-convertible with a clear reason.
- `conversion_report.md` now warns that Cloudflare sources geolocation from IPinfo while CloudFront uses MaxMind, so geo field values (country / region / subdivision / derived continent / EU) may differ for the same IP — spot-check geo-sensitive rules after cutover.

**Robustness / cleanup**:
- `cdn-validate-js.py` query-rewrite coverage now checks for the `request.querystring =` assignment, not a bare read that the `bulk_redirect` template's `_qs(request.querystring)` masked.
- Broken-output tripwires (empty Location, empty URI, leaked field) factored into one helper and run over both the viewer-request and viewer-response JS.
- `_dyn_tree_fields` recurses all child nodes instead of white-listing node types, so a field can't slip past the unmappable screen.
- The deferred `raw_expression` parse tree is cached on the op (`_parsed_condition`) so the generator reuses it instead of re-parsing in a second process; the `condition`/`raw_expression` XOR invariant is preserved.
- `_prune_unmappable` walks the OR tree once; the copy-pasted IP-list-resolve + unmappable screen in all 6 rule processors is extracted into `_screen_unmappable`; a dead branch in `_resolve_static_value` was removed.

**What changed**:
- Modified: `converter/scripts/cdn-generate-js.py` — full_uri reconstruction, fail-closed negation guard, subdivision_1 accessor, request/response crypto import, `add_*_header` value_expression, redirect `preserve_query_string`, parse-failure leak marker, `_parsed_condition` reuse
- Modified: `converter/scripts/cdn_expr_parser.py` — subdivision_1/subdivision_2 classification, `_dyn_tree_fields` full recursion
- Modified: `converter/scripts/cdn_rule_processors.py` — action-value expression screening for redirect/rewrite/query, `_screen_unmappable` / `_screen_value_expr` helpers, single-pass OR prune, parsed-tree caching
- Modified: `converter/scripts/cdn-validate-js.py` — assignment-based query coverage check, dual-file broken-output tripwire helper
- Modified: `converter/scripts/cdn-finalize.py` — IPinfo-vs-MaxMind geo caveat, full_uri https assumption note, subdivision_2 note in the report
- Modified: `converter/scripts/test_dynamic_values.py` — a regression case per bug plus a `CF_FIELD_MAP`↔accessor classification invariant to prevent future drift

## 2026-07-03

### Drop the Agent Skill install; make it clone-and-run, and fold in the backup tool

Removed the whole install machinery. Conversion is a rare, often one-shot task and the real work is deterministic Python — the Agent Skill wrapper and its installer added friction for no benefit, and it excluded agents that don't support the skill format (e.g. Codex). The tool is now clone-and-run: any agent that can read a markdown file and run shell commands can drive it.

**What changed**:
- Removed: `install.sh`, `uninstall.sh`, `install.bat`, `uninstall.bat` — no install step anymore
- Renamed: `cloudflare-aws-converter/` → `converter/` (via `git mv`, history preserved)
- Added: `backup/` — the [CloudflareBackup](https://github.com/chenghit/CloudflareBackup) tool (script, `config.example`, README, LICENSE) vendored in, so backup + convert live in one repo. The user still runs the backup locally and configures their own credentials; the agent never sees them.
- Added: `AGENTS.md` at the repo root — a ~15-line navigation stub pointing agents to `converter/SKILL.md`. This is what Codex/Cursor-style tools auto-read. It contains zero pipeline detail, so `SKILL.md` stays the single source of truth.
- Modified: `converter/SKILL.md` — replaced the 13 hardcoded `~/.kiro/skills/...` script paths with a `$REPO`/`$OUT`/`$CONFIG_PATH` convention (all absolute, cwd-independent). Added a Setup section, a backup-guidance section, and hard credential-safety rules (never ask for / read tokens). Wrapped the `terraform` step in a subshell so it can't leave the working directory.
- Modified: `converter/references/*.md`, `converter/scripts/cdn-init.sh` — same path convention; `cdn-init.sh` now self-locates its converter root by default instead of defaulting to `~/.kiro/...`.
- Modified: `README.md`, `README_CN.md` — Quick Start / Prerequisites / Installation rewritten around clone-and-run; new "Getting a backup" and "How to run" sections. Agent docs (`AGENTS.md`, `SKILL.md`) are English-only; human docs stay bilingual.
- Modified: `.gitignore` — ignore `backup/config` and the `cloudflare-to-aws-*/` output dirs.

**Known issue**: the generated deployment README and `conversion_report.md` still contain example commands with relative paths (e.g. `cd cloudflare-to-aws-cdn/terraform/shared`). They assume the user runs from `$OUT`. `SKILL.md` now tells the agent to note this when showing deploy steps; making the generators emit absolute paths is deferred (would require touching `cdn-finalize.py` codegen + tests).

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
