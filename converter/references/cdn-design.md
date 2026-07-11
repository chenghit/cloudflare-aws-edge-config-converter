# CDN Conversion — Design Model

The mental model behind how the CDN pipeline maps Cloudflare rules to CloudFront.
This is **direction, not implementation** — the details (condition trees, walkers,
codegen) live in the code and its comments.

**The pipeline already implements everything below.** Read this to *debug or
extend* the pipeline, or to explain a conversion result to a user — **not** to
hand-edit generated Terraform/JS or to "fix" a rule the pipeline marked
non-convertible. The CDN pipeline is deterministic and 0-LLM by design (see
`SKILL.md` for how to run it); it owns the conversion decisions. If a result
looks wrong, the fix is a code change with a regression test, not a manual
override.

This file is the *why* (direction). The **code and its comments are the source
of truth for the *how*** — when a detail here and the code disagree, the code
wins and this file is what's stale. See the code map at the end for where each
decision lives.

## 1. One proxied CNAME → one CloudFront distribution

The pipeline reads DNS first and creates **one CloudFront distribution per
proxied Cloudflare CNAME** (each with its own alternate domain name). This is the
foundation everything else builds on: "which distribution?" is always answerable
before any rule is looked at.

## 2. Two orthogonal dimensions

Every Cloudflare rule is placed along **two independent axes**. Keep them
separate — conflating them is where conversions go wrong.

- **Host-match → which distribution(s).** Does the rule match `http.host`?
  - matches a specific host → applies to **only that host's** distribution
  - no host match → zone-wide → applies to **every** distribution
  - `not (http.host eq x)` / `http.host ne x` → **every distribution except x's**
    (an *exclude*, not global — this was a real fail-open when treated as global)
- **Path-convertibility → which behavior.** Does the rule match a `uri` /
  `uri.path` / `full_uri` that reduces to a CloudFront path pattern (only `?`/`*`,
  no regex)?
  - yes → its own **ordered cache behavior** for that path
  - no → the distribution's **default (`*`) behavior**

Once a rule is routed to a host's distribution, the `http.host` test that routed
it is **redundant** and gets stripped — *but only if it was a test the router
actually consumed* (`host eq/in`, `ne/not_in`). A live host *predicate* like
`len(http.host) gt 5` or `http.host contains "x"` does **not** route anything; it
must be kept and rendered, or the predicate is silently dropped.

## 3. Only then, pick the mechanism

After the behavior is chosen (step 2), attach the mechanism that carries the
rule's effect to **that behavior**:

- **Policy** (cache policy / origin-request policy / response-headers policy) —
  for anything expressible as native CloudFront config.
- **CloudFront Function (CFF)** — viewer-request / viewer-response logic.
- **Lambda@Edge** — only when CFF can't (e.g. origin override).

Mechanism is the *last* decision, not the first. "It's a header rule" or "it's a
redirect" does not decide the distribution or the behavior — host-match × path
does.

## 4. A CFF's headers must reach the behavior it runs on (the ORP invariant)

This is the subtle one. Two facts about CloudFront combine into a trap:

- **Behaviors don't inherit function associations.** A CFF must be associated to
  **every** behavior it should run on, explicitly. A zone-wide + all-path rule's
  shared viewer-request CFF is therefore correctly attached to *every* behavior.
- **Native `CloudFront-Viewer-*` headers only appear in the CFF event if the
  behavior's origin-request policy forwards them.** `CloudFront-Viewer-Country`,
  `-City`, `-ASN`, TLS/JA3/JA4, device-type, viewer-address, etc. are not in the
  event by default.

So a CFF that reads a native header needs that header forwarded in the ORP of
**each behavior it runs on** — including path-specific ones. A geo-gated rule
landing on a `/some/path` behavior reads an **undefined** header unless that
behavior's ORP forwards it. (Some headers — Viewer-Address, ASN, TLS/JA3/JA4 —
are ORP-only and can't go in a cache policy.)

Field → header mapping is only half the job; the header has to physically reach
the behavior. The pipeline attaches the custom ORP to every behavior for exactly
this reason.

## 5. When something can't convert, say so — never silently drop or widen

If a rule's scope can't be expressed as a single CloudFront path (e.g. a
multi-field geo condition), or its action has no CloudFront equivalent, it's
recorded **non-convertible in `conversion_report.md`**. The two failure modes to
never accept are **silent drop** (rule vanishes) and **silent widening** (a
path/host-scoped setting applied site-wide, or a gated action firing
unconditionally). Fail *closed* and *visible*.

Cloudflare/AWS caveat worth remembering when reading results: Cloudflare's geo
comes from IPinfo, CloudFront's from MaxMind — same field, occasionally different
answer for edge IPs. Noted in `conversion_report.md`.

## Code map — where each decision lives

All paths are under `converter/scripts/`. Use this to find the code behind a
model decision instead of guessing; grep within the file for the specifics.

| Model decision | File |
|---|---|
| CNAME → distribution; A/AAAA-IP and cloudfront.net-loop origins excluded | `cdn-parse-dns.py` |
| Expression → condition tree; host filter (include/exclude); path-pattern extraction | `cdn_expr_parser.py` |
| Per-rule conversion + non-convertible decisions | `cdn_rule_processors.py` |
| Host routing, host-condition stripping, behavior placement, cache rules | `cdn-preprocess.py` |
| Policy dedup, final IR, `conversion_report.md` | `cdn-finalize.py` |
| Condition/action → CFF & Lambda@Edge JS; CFF↔L@E accessor switch | `cdn-generate-js.py` |
| Distribution `main.tf`; **custom ORP attached to every behavior** | `cdn-generate-tf-scaffold.py` |
| Shared cache/ORP/response-header policies | `cdn-generate-shared-policies.py` |
| IR structural checks (incl. ORP-header consistency) | `cdn-validate-chunk.py` / `cdn-validate-final.py` |
| Generated-JS checks (forbidden syntax, IR coverage, KVS, size) | `cdn-validate-js.py` |
