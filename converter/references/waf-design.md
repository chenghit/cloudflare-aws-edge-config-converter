# WAF Conversion — Design Model

The mental model behind how the WAF pipeline maps Cloudflare WAF / rate-limit /
IP-access rules to an AWS WAFv2 WebACL (CloudFormation). This is **direction, not
implementation** — the details (expression parser, condition walkers, the packer)
live in the code and its comments.

**The pipeline already implements everything below.** Read this to *debug or
extend* the pipeline, or to explain a conversion result to a user — **not** to
hand-edit the generated CloudFormation or to "fix" a rule the pipeline marked
non-convertible. The WAF pipeline is deterministic and 0-LLM by design (see
`SKILL.md` for how to run it); it owns the conversion decisions. If a result looks
wrong, the fix is a code change with a regression test, not a manual override.

This file is the *why* (direction). The **code and its comments are the source of
truth for the *how*** — when a detail here and the code disagree, the code wins
and this file is what's stale. Every AWS behavioral claim below was confirmed by a
live `check-capacity` / `create-web-acl` on a real account (see the memory notes /
commit history); do the same before trusting any AWS assertion here.

## 1. Two WebACLs: `waf-website` and `waf-api-file`

The pipeline emits **two** WebACLs, differing only in their injected anti-DDoS
posture. One CloudFront distribution attaches exactly one WebACL, so this is a
menu, not a split — the customer points each distribution at whichever fits:

- **`waf-website`** — anti-DDoS with the **challenge action ENABLED** (browsers
  can solve a silent/JS challenge), plus a trailing always-on-challenge rule.
  For human-facing hosts.
- **`waf-api-file`** — anti-DDoS in **advanced mode, challenge DISABLED**. API and
  file clients can't solve a browser challenge, so challenging them would break
  them; this variant blocks by rate/score instead.

Both WebACLs get the **same** converted custom + rate + managed rules. The split
is *not* per-host (that would explode to one WebACL per domain) and *not* about
capacity — it's purely "can the clients on this distribution solve a challenge?"
The tool does **not** associate distributions to WebACLs; the customer does that,
guided by the report.

## 2. Cloudflare's fixed phase order is the spine — keep it contiguous

Cloudflare evaluates rules in a fixed phase order, and the WebACL **must** preserve
it as three non-interleaved, contiguous blocks:

1. `http_request_firewall_custom` — custom rules + IP-access rules
2. `http_ratelimit` — rate-limit rules
3. `http_request_firewall_managed` — managed rule groups

Everything the packer does (§4) happens *within* a block; blocks never interleave.
Injected rules bracket them: a search-engine-labeling rule + anti-DDoS run first
(header), an always-on-challenge runs after custom/rate (trailer), managed rule
groups run last. Priority is assigned once, at the end, over the fully assembled
order — the converted rules carry no meaningful priority until then.

## 3. `skip` is an action, and it becomes a label — producers vs consumers

Cloudflare's `skip` action ("skip all remaining custom rules" / "skip the rate
phase" / "skip managed") has no direct AWS equivalent. It's modeled with **labels**:

- A skip rule → **Count action + `RuleLabels`** (it *produces* a label like
  `skip:all_remaining_custom_rules`, `skip:http_ratelimit`,
  `skip:http_request_firewall_managed`). A producer's action must be
  non-terminating (Count) or downstream rules never see the label.
- Every rule the skip should suppress → wraps its statement in **`NOT(LabelMatch)`**
  (custom: `AND(NOT(label), original)`; rate/managed: the `NOT(label)` goes inside
  the scope-down). It *consumes* the label.

This produces a hard rule the rest of the design bends around: **a rule is either
a label PRODUCER (has `RuleLabels`) or a CONSUMER (everything else).** Labels are
visible only to rules evaluated *later* in the same WebACL evaluation — so
producer-before-consumer ordering must be preserved end to end. Rate rules never
consume `skip:all_remaining_custom_rules` (Cloudflare phase separation); it's
`skip:http_ratelimit` for them.

## 4. Rule groups are the escape hatch for the 10-RBR / 50-ref caps

AWS caps a WebACL at **10 rate-based rules** and **50 reference statements**
(IP-set + regex-set + rule-group + managed-rule-group refs — *all four* count),
both non-adjustable. A referenced **custom rule group** escapes both: RBR and
IP-set refs *inside* a group don't count against the WebACL's 10/50 — the WebACL
pays just **1 reference** for the whole group. A group itself holds ≤4 RBR, ≤50
refs, ≤5000 WCU. So a rule group is a general **overflow container**, and the
57-ref / 22-RBR real case fits in the default 2 WebACLs with no per-host split.

Two rules the packer never breaks:

- **Pack MINIMALLY.** Everything stays at WebACL-direct level by default; a rule is
  moved into a group *only* when the block would exceed a cap, and only enough to
  get back under it. A group costs the WebACL 1 ref, so grouping a run of R refs
  saves R−1 — group the heaviest runs first, stop when it fits, and **never group
  a ≤1-ref rule** (zero savings → no pointless single-rule groups). RBR overflow is
  split at rule granularity: 12 RBR → 10 direct + 1 group of 2.
- **A group is ROLE-HOMOGENEOUS** (§3): all producers or all consumers, never
  mixed. A group evaluates as one contiguous block at its reference's priority
  slot; mixing a producer in with consumers means the producer can't suppress
  consumers sitting *before* the group ref, so correctness would hinge on
  accidental ordering. The packer segments a block into maximal same-role runs and
  builds each group from one run, placed at that run's **source slot** — so every
  producer's slot still precedes its consumers'.

## 5. Cross-container labels: bare key vs fully-qualified, OR over producers

Once a producer or consumer moves into a group, label matching gets subtle
(AWS-verified, and a source of silent runtime no-match if wrong):

- A **bare** `LabelMatchStatement.Key` resolves against the matching rule's **own**
  container only. Writing your own container's prefix is *rejected*
  (`awswaf:...:webacl:<self>:...` → "parameter value isn't supported").
- A **cross-container** match needs the producer's fully-qualified key
  (`{"Fn::Sub": "awswaf:${AWS::AccountId}:rulegroup:<name>:<label>"}` — CFN fills
  the account id, template stays portable).
- A label can be produced in **several** containers at once (e.g. one skip at
  WebACL level + more inside an overflow group). So a consumer matches an **OR**
  over every producing container — bare for its own, FQN for each other. Matching a
  not-yet-set label is simply false, so OR-ing all producers is always safe.

Because that OR can nest inside another OR, watch the same-type-nesting rule in §7.

## 6. WCU is computed exactly, and over-limit is delivered, never silently failed

AWS charges by **Web ACL Capacity Unit**; >1500 costs money, >5000 is a hard
rejection. The pipeline computes WCU from the *assembled* template (per-statement
sum + pooled `ceil(labels/5)` + each referenced group's capacity) — matching AWS
`CheckCapacity` exactly, so a rule group's declared `Capacity` (immutable at
create) is right.

When a WebACL genuinely can't deploy — WCU > 5000, or a single rule too complex to
fit one rule group (e.g. >50 refs after any packing) — the pipeline still **writes
the template** and reports `STATUS: BLOCKED` with the offending WebACL/rule. It
never silently succeeds and never hard-fails-without-output: the user inspects it,
simplifies the source, and re-runs. `waf-verify-wcu.py` is an optional pre-deploy
reconcile against a real account (rewrites only the integer `Capacity`, never rule
logic) — a safety net, since the local WCU is already exact.

## 7. Non-convertible fields and same-type nesting — fail closed, stay valid

- **Non-convertible fields** (`cf.bot_management.*`, `cf.waf.score`, `ssl`, …) and
  **Cloudflare managed lists** (`ip.src in $cf.open_proxies` and the four other
  `$cf.*` IP intelligence lists) have no importable AWS equivalent. The offending
  branch is **pruned** and recorded in the report with its closest AWS managed rule
  group; the rest of the rule still converts (→ *partial*). A rate rule whose whole
  condition prunes away becomes an unconditional rate limit (the rate-limiting part
  of an otherwise-normal rule stays convertible); but a rate rule whose COUNTER
  semantics AWS can't reproduce is non-convertible outright (§8). Never silently
  drop, never leave a `MISSING_*` placeholder matching nothing.
- **AWS rejects a same-type statement as a DIRECT child** — `AndStatement` directly
  inside `AndStatement`, `OrStatement` inside `OrStatement` (an intermediate `NOT`
  or different type is fine; min 2 statements per AND/OR; real depth cap is 100, not
  Terraform's 3). Every place that builds an And/Or must flatten same-type direct
  children (`_flatten_statements`) — both the expression translator and the
  label-rewrite OR-expansion (§5), or a multi-producer label inside an OR yields
  OR-in-OR and fails at deploy.

## 8. Rate limits: scale to a legal window; `mitigation_timeout` is lost

Cloudflare rate config (`period`, `requests_per_period`, `mitigation_timeout`) maps
to AWS's closed window enum {60,120,300,600} by scaling the count to the first
window where the limit ≥ 10 (mandatory fallback 10/600). **`mitigation_timeout`
(fixed block duration) has no AWS equivalent and is dropped** — AWS only blocks
while the trailing-window rate stays over the limit. This is a documented
whole-feature limitation, not a per-rule report entry. Rate counters are
per-WebACL-instance: one WebACL on N distributions shares one counter (matches
Cloudflare's zone-wide intent). The tool never auto-merges distinct rate rules (a
shared counter would throttle a client spreading across paths at a fraction of each
rule's threshold). See `workspace/roadmap-waf-rate-limit-features.md` for how to
wire in smaller periods / `mitigation_timeout` if AWS ever ships them.

Some rate rules are **non-convertible outright**: their counter can't be reproduced by
an AWS `RateBasedStatement`, so the whole rule is reported, never converted to a wrong
threshold. Those are `requests_to_origin` (Cloudflare counts only origin-bound /
cache-miss requests, but a CloudFront-scoped WebACL runs before the cache and counts
every request), `counting_expression` (a separate counting expression has no AWS
equivalent), and any `characteristics` set outside `{ip.src, cf.colo.id}` or missing
`ip.src` (other keys need RBR `CUSTOM_KEYS`, which the tool does not generate; the
generator always aggregates on IP). Disabled rate/custom rules are excluded from the IR
entirely (they never run in Cloudflare), and count validation reconciles the ACTIVE
source rule count against the IR.

## Code map — where each decision lives

All paths under `converter/scripts/`. Use this to find the code behind a model
decision instead of guessing; grep within the file for specifics.

| Model decision | File / function |
|---|---|
| Named IP / ASN / hostname list resolution; IP-access rules → conditions | `waf-analyze-ip.py` |
| Custom-rule expression → condition tree; convertibility + pruning | `waf-analyze-custom.py`, `waf_expr_parser.py`, `waf_common.py` (`classify_convertibility`, `is_managed_list_value`) |
| Rate-limit window scaling; `mitigation_timeout` dropped | `waf-analyze-rate.py` (`calculate_rate_limit`) |
| Rate counter-semantics NC gate (requests_to_origin / counting_expression / characteristics); disabled-rule skip; active-count reconcile | `waf-analyze-rate.py`, `waf-analyze-custom.py`, `waf-count-validate.py` |
| Merge the 3 analyzer IRs | `waf-merge-ir.py` |
| Two WebACLs (website/api), injected header/trailer rules | `waf-generate-cfn.py` (`build_one_webacl`, `build_anti_ddos_rule`, `build_always_on_challenge_rule`) |
| skip → Count + labels; consumer `NOT(LabelMatch)` wrap | `waf-generate-cfn.py` (`conditions_to_statement`, rate/custom builders) |
| Rule-group overflow packing; role-homogeneous, minimal, source-order | `waf-generate-cfn.py` (`pack_webacl_rules`, `_pack_block`, `_rule_is_producer`) |
| Cross-container label rewrite (bare / FQN / OR) | `waf-generate-cfn.py` (`_rewrite_label_keys`, `_label_match_node`) |
| Same-type-nesting flatten (AWS INVALID_NESTED_STATEMENT) | `waf-generate-cfn.py` (`_flatten_statements`, `_rewrite_stmt`) |
| Exact WCU; per-container refs count (incl. managed) | `waf-generate-cfn.py` (`compute_rules_wcu`, `_count_refs_in_stmt`) |
| Managed rule groups + their WCU; anti-DDoS scope-down | `waf-generate-cfn.py` (`build_managed_rules`, `MANAGED_RULE_GROUP_WCU`) |
| STATUS: BLOCKED delivery; serial DependsOn (1-TPS throttle) | `waf-generate-cfn.py` (`main`, `_add_throttle_chains`) |
| Optional pre-deploy WCU reconcile vs CheckCapacity | `waf-verify-wcu.py` |
| Deployment README, quota table, POST_ACTION | `waf-generate-readme.py` |
| `--force-split` per-domain WebACLs (available, not default) | `waf-split-by-host.py` + `generate_split()` |
