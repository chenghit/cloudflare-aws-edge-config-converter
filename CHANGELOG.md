# Changelog

## 2026-08-09

### CDN converter: native-rule placement follow-ups (review round 5)

Remaining fixes after the root-cause placement change in the previous commit.

- A conditional security/CORS header now falls back to a viewer-response CloudFront Function (which gates on the condition) instead of being dropped as non-convertible. A conditional Cloud Connector origin switch stays non-convertible, now with a reason explaining why a CFF can't carry it (unsigned S3/R2/GCS/Azure origin → 403). Confirmed via dual AWS subagents.
- Site-wide native settings (TTL / compression / security headers) overlay onto ordered behaviors, which are first-match and don't inherit the default; the behavior's own value still wins.
- Ordered behaviors emit most-specific-first so a broad pattern can't shadow a narrower one; a `full_uri` pattern with a query (`?`) is no longer treated as single-path; config-rule ssl/min_tls accepts a pure-host OR/NOT scope; custom-error rules screen unmappable fields like the other processors.

## 2026-08-08

### CDN converter: per-distribution ACM certificate discovery (fixes multi-level subdomains)

Certificate lookup was wrong for any zone with a multi-level subdomain (e.g. `app.eu.example.com`). Every AWS fact below was confirmed with dual subagents that initially DISAGREED, then settled by a live experiment on a real account — request an ACM cert, `terraform apply` a distribution, and `curl` the 4-level host to a real HTTPS 200.

**Root cause**
- The pipeline generated `data "aws_acm_certificate" { domain = "*.<zone-apex>" }` for every distribution. Two independent failures, both verified live:
  1. **CloudFront covers an alias by same-level SAN.** A wildcard covers exactly one DNS label — `*.example.com` covers `www.example.com` but NOT the apex and NOT a two-label-deeper `app.eu.example.com`, which needs `*.eu.example.com`. (Live: a cert with SANs `*.a.letsmakeit.link` + `*.eu.a.letsmakeit.link` served HTTPS 200 for `app.eu.a.letsmakeit.link`, matching only via the `*.eu…` SAN — `tls_verify=0`.)
  2. **The Terraform data source `domain=` matches only a cert's primary DomainName (CN), never its SANs.** (Live: `domain = "*.eu.a.letsmakeit.link"` — a SAN but not the CN — errored `reading ACM Certificates: empty result`; the CN value matched.) So a merged cert or any multi-level subdomain silently failed `terraform plan`. Guessing the domain a level deeper wouldn't help — it would just miss the CN of a merged cert instead.

**Fix — ARN-first certificate discovery** (`cdn_common.py`, `cdn-parse-dns.py`, `cdn-generate-tf-scaffold.py`)
- Two pure functions in `cdn_common.py`, both validated against the real cert's SANs and CloudFront's live behavior: `derive_cert_domain(host)` gives the same-level SAN a host needs (`app.eu.example.com` → `*.eu.example.com`; apex → exact self; `*.x` unchanged), and `cert_covers(cert_names, host)` applies CloudFront's exact-or-same-level-wildcard rule.
- DNS parsing now groups hosts by **required cert coverage**, not by one `*.<apex>` per zone — a zone with subdomains at different depths yields several cert groups (several certificates), surfaced per-coverage in the report.
- Each distribution reads its cert from a `cert_arn_<san>` variable with a validation that fails `terraform plan` when empty, naming the exact SAN coverage that host needs. No `aws_acm_certificate` data source is emitted.
- New generated `resolve-certs.py` (boto3): lists ISSUED us-east-1 certs (with all key types — `list_certificates` defaults to RSA-only), pulls each cert's full SAN list, skips `ManagedBy=CLOUDFRONT` (tenant-managed, not usable here), and fills each domain's **tool-owned** `domains/<san>/certs.auto.tfvars.json` with an ARN whose SAN actually **covers** the host (mirroring `cert_covers`; deterministic latest-expiry pick when several match). Terraform auto-loads that JSON. A cached value is kept only while it stays a VALID pick (still ISSUED and still covering the host) — a stale ARN is dropped and re-resolved, never a false success. To override, pass the higher-precedence `-var cert_arn_<san>=…` (never edit the generated JSON). If any host has no covering cert it writes nothing for it, prints exactly what to provision, and exits non-zero — fail closed.
- Storage is JSON the tool fully owns (no HCL parsing), so `cert_arn`/`cert_arn_mode` no longer live in the IR — that stale `data_source`-era pair was a second, conflicting source of truth. `cert_domain` (the SAN coverage a host needs) threads through the IR and is enforced by `cdn-validate-chunk`.
- Report / SKILL deploy steps rewritten: a per-coverage certificate checklist, the `resolve-certs.py` step before `terraform apply`, and the corrected "`*.apex` does not cover a deeper subdomain" note (was "one `*.apex` covers all subdomains").

**Not touched — rule match/action for multi-level hosts was already correct.** Verified with the real modules: routing (`hostname_matches` is suffix-based), host-condition stripping (eq/in/ne/wildcard stripped, `matches`/`contains`/`len` kept as live predicates), and JS rendering (`host === '…'`, `endsWith('.eu.example.com')`, regex, `full_uri` host∧path, bulk-redirect subdomain walk) all handle 4-level hosts regardless of depth. The bug was confined to certificate discovery.

Verified: full pipeline on a 4-level domain → generated `resolve-certs.py` filled the real ARN by SAN coverage → `terraform apply` created the distribution → `curl https://pipeline.eu.a.letsmakeit.link/` returned **HTTPS 200 with `tls_verify=0`**, served by the SAN-covered cert through CloudFront. New `test/test_cert_coverage.py` (pure-function + mixed 3/4/5-label e2e) plus the existing CDN/WAF regression suites all pass.

## 2026-07-12

### WAF converter: rule-group overflow packer, exact WCU, and a unified over-limit signal

A pass over the WAF pipeline so it fits AWS's hard per-WebACL caps without a per-host WebACL explosion, and reports the truth about deployability. Every AWS fact below was confirmed with dual subagents AND a live CloudFormation deploy on a real account (the deploy caught four bugs the green test suite missed).

**Rule-group overflow packer** (`waf-generate-cfn.py`)
- AWS caps a WebACL at 10 rate-based rules and 50 reference statements (both non-adjustable). Instead of splitting per host (100 domains → 100 WebACLs), overflow rate-based rules and IP-set refs are offloaded into referenced **rule groups** — which escape both caps (a rule group holds ≤4 RBR / ≤50 refs, and the WebACL pays just 1 reference for the whole group). The 22-RBR / 57-ref example now fits in 2 WebACLs. Confirmed live: RBR-in-group and refs-in-group don't count against the WebACL's 10/50.
- Cloudflare phase order (custom → rate → managed, contiguous) and label semantics are preserved: a block's rule-group refs sit right after that block's direct rules, and every `LabelMatchStatement` is rewritten to the correct form — **bare** key when the producer is in the consumer's own container, the producer's fully-qualified `awswaf:${AWS::AccountId}:rulegroup|webacl:<name>:<label>` (via `Fn::Sub`, portable) when cross-container, OR-combined when a label is produced in several containers. A self-container prefix is invalid and is never emitted (that was a live deploy rejection). Wired into both `generate()` and `generate_split()`.

**Exact WCU** (`compute_rules_wcu` / `compute_rule_wcu`)
- The WCU calculator is now a flat recursive statement-sum matching AWS's model, including the modifiers that were missing: ByteMatch 2-or-10 by positional constraint, text-transforms +10 per non-NONE entry per statement, AllQueryArguments +10, JsonBody ×2, IPSet ForwardedIP-ANY +4, RBR +30/custom-key + scope-down. **RuleLabels** cost is pooled per container as `ceil(total_labels/5)` (AWS sums `0.2`/label across the whole batch, one ceiling at the end) — not per-rule; getting this wrong under-declared a rule group's Capacity and failed the deploy. Triple-verified: AWS worked example (15), a mixed ruleset (real CheckCapacity 727), and live WebACL Capacity matching the calculator exactly (2190 / 2149 / 1404).

**Managed rule groups count toward the 50-ref cap**
- Corrected a wrong assumption: AWS managed rule groups are NOT free against the 50-reference limit (live: 45 IP refs + 5 managed = 50 ok, 46 + 5 = 51 rejected). `_count_refs_in_stmt` now counts all four reference types (IP-set, regex-set, own-rule-group, managed-rule-group), and the packer reserves budget for the managed refs.

**Serial throttle mitigation**
- WAFv2's write API is 1 TPS; the previous "batches of 5 in parallel + rely on CFN retries" still throttled and rolled back on 55 IP sets. Switched to a fully serial `DependsOn` chain so CloudFormation creates resources one at a time.

**Unified over-limit signal + optional WCU verify**
- The old "refs > 50 → auto-fallback to `--force-split`" path is gone (the packer makes it unreachable) — removed from the generator, pipeline, README generator, SKILL.md, and README.md. A config is now undeployable only when a WebACL's WCU exceeds 5000 or a single rule is too big to fit one rule group; the generator then **still writes the template** and emits `STATUS: BLOCKED` (exit 0) with the specific WebACL/reason, so the user can inspect it, simplify the source, and re-run — never a silent success, never a hard-fail-without-output. Truly fatal cases (stack over the CloudFormation resource limit) stay `STATUS: FATAL`.
- New `waf-verify-wcu.py <out> --profile <p>`: an OPTIONAL pre-deploy step that reconciles each rule group's declared `Capacity` against AWS `CheckCapacity` (using a throwaway IP set + regex set as ref stand-ins). It rewrites **only** the integer `Capacity` — a hash of the group's `Rules` before/after guarantees zero logic change — and refreshes the managed-rule-group WCU table via `DescribeManagedRuleGroup`. Local WCU is already calculator-exact, so this is a safety net, not a required step; without a profile, deploy as-is (a rule group's Capacity can only ever be slightly high, which still deploys).

Verified: the full example deploys to `CREATE_COMPLETE` (65 resources, 2 WebACLs) and one per-domain split WebACL deploys too, both with AWS-computed Capacity matching the converter exactly; `waf-verify-wcu.py` is a clean no-op on the generated template; regression suites for the WCU calculator and the packer (bare/FQN/OR label keys, phase order, cap fitting) all pass.

## 2026-07-11

### CDN converter: per-host model hardening, origin fidelity, viewer-CFF-only, and conditional cache bypass

A large pass over the CDN converter, following the OR-structuring fixes below. Organized by topic (the net final state; several sub-parts superseded earlier attempts within this pass). AWS facts were verified against the docs / AWS-knowledge subagents, and Host-precedence + cache-bypass mechanics were verified with live experiments on a real CloudFront distribution.

**Host scoping & conditions**
- The host filter evaluates the rule's condition tree against each **concrete proxied hostname** (from DNS) via wildcard-aware matching — no abstract set algebra (an earlier include/exclude, then a satisfiability-set algebra, both had wildcard/negation bugs; concrete-hostname evaluation dissolves the class). `*.example.com` matches every real subdomain; a negated host test scopes to "every distribution except x's"; `full_uri` is atomic (host∧path never split — a negated full_uri imposes no host exclusion). The host filter may over-apply (the full condition still gates per-request) but never under-applies.
- `_strip_host_condition` strips only host leaves the router actually consumed for routing; a **live** host predicate (`len(host) gt 5`, `host contains "x"`) is kept and rendered, not silently dropped (that was a fail-open).
- Conditions render faithfully: `len()` → `.length`, `lower()`/`upper()` → `.toLowerCase()`/`.toUpperCase()`, `full_uri` reconstructed as a real URL match, and un-evaluable conditions fail **closed** (a `_NEVER` value that's contagious through logic/negation — never fires) instead of leaking a `false` string that collided with real output.
- Custom-error rules: the intercepted status comes from the CONDITION (`http.response.code eq N`), the returned status from the action — no longer conflated; a live host predicate on the condition blocks conversion instead of being erased.

**Origin forwarding**
- Cloudflare forwards the full request to origin; CloudFront strips everything not in the cache key unless an ORP forwards it. So every non-S3 behavior gets a forward-all ORP: managed **AllViewer** for plain behaviors, the domain's custom ORP (`allViewerAndWhitelistCloudFront`, with cookies/query = `all`) where CloudFront-* geo/device headers are needed. That custom ORP is attached to **every** behavior (a geo rule on a path behavior read an undefined header before).
- `Host` is read-only in a viewer CFF (writing `request.headers.host` → HTTP 502); the origin Host is set via `cf.updateRequestOrigin({hostHeader})`. Verified live: `updateRequestOrigin`'s `hostHeader` wins over the ORP-forwarded viewer Host (documented fallback chain), so host overrides — conditional or not — just use AllViewer (no `AllViewerExceptHostHeader`; matching requests get the override, non-matching keep the viewer Host). `origin_override` is CFF-only, infers protocol from the rule's port (80/8080 → http, else https), drops no-ops, and never emits the denylisted `Host` custom-origin-header.

**S3 + OAC**
- S3+OAC behaviors get **NO** ORP — CloudFront signs each origin request with SigV4, and forwarding the viewer Host breaks the signature (403). A redundant Cloudflare Origin Rule that rewrites Host to the bucket is dropped (a genuinely different cross-origin override is kept). The mandatory manual step the tool can't do — adding an S3 bucket policy that allows the distribution — is surfaced in `conversion_report.md` and a final-stage `POST_ACTION`. REST endpoint → OAC; website endpoint (`s3-website`) → custom origin, no OAC.

**Viewer events are CloudFront-Functions-only**
- No auto-escalation to Lambda@Edge for viewer events (latency/cost/execution-model). A CFF over the **hard** 10 KB limit (after minify) is reported `SIZE_EXCEEDED` for human intervention; both viewer-request and viewer-response are size-checked. Genuine origin events (default-cache / custom-error origin-response) still use Lambda@Edge, scoped to the behavior. Removed the dead escalation code.
- Complete CloudFront quota evaluation, each labeled **soft** (raisable via Service Quotas) vs **hard** (must redesign), so a user doesn't file a Support request for an unraisable limit.

**Conditional cache bypass** (Cloudflare "Bypass cache")
- CloudFront can't skip the cache at request time, so a viewer-request CFF forces a guaranteed MISS: for matching requests it injects `x-cf-cache-bypass` with a per-request-unique value (FOUR `Math.random()` segments concatenated ≈ 208 bits — concat preserves entropy; add/multiply would collapse it and risk a cross-user cache leak) that is part of the cache key. The `else` branch deletes the header so a client can't self-inject it to poison the shared cache. Verified live (matching → always miss with distinct busters; anonymous → caches; client-injected header → stripped).
- Conditions supported: cookies (`http.cookie` rebuilt from the parsed `request.cookies` map — CFF has **no** raw Cookie header — and named `cookies["x"]`), named request headers (`headers["x"]`, lowercased to match CFF keys), named query args (`uri.args["x"]`), query/user-agent/path substrings. Named cookie/header/arg access is unified (existence → `map['n'] !== undefined`; value → existence-guarded `.value` compare). `any(field["k"][*] == "v")` is non-convertible — and no longer silently disables the whole behavior. Unconditional bypass → the managed CachingDisabled policy. The buster header name is a single shared constant so the CFF and the cache-policy whitelist can't drift.

**Shared CFF attached only where needed**
- Each viewer op carries a **scope** (zone-wide / default-only / a specific behavior), set at placement from whether its condition has a path field and whether that reduces to a CloudFront pattern. The shared CFF is attached per-behavior accordingly: a behavior that exists only for a TTL/cache-key setting, in a domain with no zone-wide rule, no longer carries a no-op CFF — automatically, no hand-editing.

Verified across the pass: full 54-domain example pipeline green at every stage, a synthetic multi-domain e2e asserting the generated Terraform + JS, a brute-force host-filter oracle, `node --check` on all generated JS, and `terraform validate`.

## 2026-07-10

### CDN: fix the OR-structuring fallout — fail-open conditions, dead cache sink, per-host scoping

Making `parse_expression` return a structured `{"logic": "or"/"and"/"not"}` tree (instead of deferring OR to `raw_expression`) was the right direction, but it broke a hidden contract that several downstream consumers relied on, and it took several review rounds to shake out every consequence. This entry covers that whole series (commits `59feefa`, `27910d0`, `8431f50`, `f0ce0c0`, `ca7ea44`, `b6d38d7`, `545d248`). Most of these were silent — a rule reported as "converted" that then did nothing, fired on every request, or dropped config — and none were caught by the existing suite, which only asserted parser structure. All were reproduced against the real modules; the fixes are verified by the full pipeline on the example config (54 domains, 108→5 CFF dedup, all stages green), `node --check` on generated JS, `terraform validate`, an enumerative property test, and synthetic backups driven through the real preprocess.

**CloudFront API**:
- `cf.kvs()` takes **no argument** (the KVS is bound to the function via Terraform `key_value_store_associations`); the generator was emitting `cf.kvs('<id>')` with an ID that was never even populated — i.e. `cf.kvs('')`. Verified against AWS docs.

**Fail-open / fail-closed correctness (conditions)**:
- Reworked how an un-evaluable condition (unmappable field, unresolved list, unknown op) is represented — from a magic `false` string (which collided with real output like `/*x/.test(uri) || m === false`) to a structural `_NEVER` value combined with real three-valued boolean algebra. `_NEVER` is **contagious**: any logic node containing it fails the whole condition closed. This kills a class of fail-opens, most importantly `not (A or <un-evaluable>)`, which previously dropped the un-evaluable branch and negated only `A` (firing when it shouldn't).
- `not ip.src in $list` (an allow-list) rendered `!( /* TODO */ false )` = `true` → fired on every request; now resolved to a negated KVS lookup.
- `in_kvs`/`not_in_kvs` and `continent`/`is_eu` fail closed in the Lambda@Edge target (no `cf.kvs()`/preamble there) instead of emitting an undefined-variable ReferenceError.
- Empty/malformed logic nodes fail closed (an empty OR no longer renders as "fires always").

**Parser correctness**:
- `A and (B or C)` no longer drops the parenthesized OR branch; `(A or B)` (fully-parenthesized) is no longer truncated to `A`. `parse_expression` now routes everything non-trivial through the full recursive-descent parser and only defers to `raw_expression` when the text is genuinely unparseable.
- `not (not X)` normalizes to `X` (was `not_not_eq` → unknown op → `false`, so the rule never fired).
- Every condition-tree walker descends both a logic node's `parts` and a NOT node's `item` (via a shared `iter_condition_children`); NOT-blind walkers previously skipped or `KeyError`-crashed on negated subtrees (ORP-header collection, IP-list resolution, KVS provisioning, cache/compression guards).
- Multi-host OR (`http.host eq "a" or http.host eq "b"`) scopes to the union of hosts only when every branch pins a host, else global — was scoped to only the first branch's host, silently dropping the rule for the rest.

**Cache-rule placement (per-host distributions)**:
- The pipeline builds one distribution per proxied host, so a `http.host eq "<this domain>"` condition inside a domain's IR is redundant and is now **stripped** after host-routing. This makes host-scoped cache rules convertible: `host eq x` → default behavior with caching disabled; `host eq x and uri.path eq /api` → a `/api` cache behavior with the rule's TTL. (Mirrors the WAF pipeline's host-condition stripping.)
- A cache rule whose scope genuinely can't be expressed as a single CloudFront path (e.g. `ip.src.country`, a multi-field AND after stripping) is now recorded **non-convertible in `conversion_report.md`** instead of being routed to `lambda_edge.origin_response.conditional_cache_rules` — a sink that no generator ever consumed, so those rules were silently dropped. `uri.path.extension eq "pdf"` (which yields path `*`, not `*.pdf`) is likewise no longer mis-applied site-wide.

**Custom error / other**:
- A custom-error rule's response code is extracted only from a single positive `http.response.code eq N` leaf (int-coerced). An OR of codes, an AND-scoped code, or a negated code is now non-convertible instead of silently keeping the first / over-matching per-distribution / rejecting a quoted `"404"`.
- Response-header rules using `sha256()`/HMAC or `uri.query` now emit the `import crypto` / `_qs` helper they reference in the viewer-response handler.
- Per-handler KVS: `cf.kvs()` is emitted (and the Terraform association written, and Stage-9 validation checked) per handler, so a response-only KVS need no longer emits an unused handle in the request handler or spuriously fails validation.

**What changed** (all in `converter/scripts/`): `cdn_expr_parser.py`, `cdn_rule_processors.py`, `cdn-preprocess.py`, `cdn-generate-js.py`, `cdn-validate-js.py`, `cdn-validate-chunk.py`, and `test_dynamic_values.py` (now 120 checks, including an enumerative no-fail-open property test over all small condition trees). Removed ~137 lines of an orphaned single-condition parser (`_parse_single_condition` + its regexes) left behind by the full-parser switch, and the dead `conditional_cache_rules` routing.

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
