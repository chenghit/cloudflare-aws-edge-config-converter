# CDN Conversion Policy — Exact / Lossy / Non-Convertible Decision Rules

> Status: draft for review. Updated 2026-08-12 after verifying the reviewer's findings against the code,
> AWS documentation (CloudFront header inventory, Response Headers Policy CORS behavior), and the WHATWG
> Fetch/CORS standard. This is the authoritative conversion boundary for the CDN pipeline. After approval,
> [limitations.md](./limitations.md) will point here for the Exact/Lossy/NC rules, and a Chinese mirror
> (`conversion-policy_CN.md`) will follow.

## Purpose

This tool migrates a Cloudflare edge configuration to AWS CloudFront. It is a **migration tool, not a
Cloudflare runtime emulator.** CloudFront and Cloudflare are not feature-for-feature equivalent, so the
tool converts only what CloudFront can express with clear, verifiable equivalence, and it **reports**
everything else instead of guessing.

This document is the single source of truth. It tells users what to expect before they run the tool, and
it is the boundary the pipeline code (processors, validators, generator) must enforce. When the code and
this document disagree, this document wins and the code is the defect.

## Core principle: fail closed

Every source construct **in the rule files the pipeline reads** (see "What the pipeline reads" below) gets
exactly one outcome, and the default outcome is `NON_CONVERTIBLE`. A construct is converted only if it
appears on an explicit convertible list below **and** the generated CloudFront configuration or function
code is provably equivalent. Anything not proven equivalent is reported, never silently dropped and never
widened in scope.

Cloudflare features the pipeline does **not** read at all (Workers, Snippets, Page Shield, and the rest of
the "Explicitly not converted" list) cannot enter the outcome ledger. They are surfaced by a separate,
lightweight **ignored-feature report**: it lists the known backup files that are present but not processed,
so an unconverted feature is visible to the user rather than invisibly absent.

Two consequences the implementation must honor:

1. **Unconvertibility is decided in the processor**, as a first-class `NON_CONVERTIBLE` outcome that is
   recorded and lets the rest of the configuration continue converting.
2. **A source construct the tool does not support never aborts the migration.** A hard abort is reserved
   for an internal converter bug. A legal-but-unsupported Cloudflare construct is reported, not fatal.

We do not add machinery to *precisely characterize the unsupported space*. The question at every leaf is
only: "is this on the convertible list, and does it render provably-correct output? If not, non-convertible."

## Three outcomes and how they relate to run status

| Outcome | Meaning | Reported as |
|---|---|---|
| `EXACT` | CloudFront reproduces the Cloudflare behavior faithfully. | Converted, no warning |
| `LOSSY` | Converted, with a known behavioral difference the user must review. | Converted, with a warning + reason |
| `NON_CONVERTIBLE` | No faithful CloudFront equivalent. Not converted. | Reported with a reason + suggested alternative |

Process **STATUS reflects whether the run completed and the artifact is deployable, not how much
converted.** A completed run with expected `LOSSY`/`NON_CONVERTIBLE` items is still `STATUS: OK` — NC is the
normal result of a migration, aggregated in `conversion_report.md`, not a failure. The existing status
tokens keep their current meaning and exit codes (`_STATUS_EXIT`):

- `OK` (exit 0): run completed; artifact deployable.
- `BLOCKED` (exit 0): valid but undeployable as-is (a hard quota / WCU cap).
- `PARTIAL` (exit 3): **some domains failed to process** (an execution problem). NC does **not** trigger this.
- `FATAL` (exit 2): an internal ledger-integrity breach (a converter bug).

Conversion **completeness** is a *separate* field in the report, independent of process STATUS:
`COMPLETE_EXACT` (every outcome EXACT) vs `PARTIAL_WITH_NC` (some LOSSY/NC). A normal migration with
expected NC is `STATUS: OK` + `PARTIAL_WITH_NC`. (This supersedes an earlier L2 plan that would have made
NC flip STATUS to PARTIAL — that collides with PARTIAL's existing exit-3 "domains failed" meaning.)

## What the pipeline reads

The CDN pipeline reads exactly these Cloudflare rule exports. **Any other file in a backup is not read and
therefore not converted** (it appears in the ignored-feature report, and the "Explicitly not converted"
list below explains why):

Redirect Rules, URL Rewrite Rules, Configuration Rules, Origin Rules, Cache Rules, Request Header
Transform, Response Header Transform, Custom Error Rules, Compression Rules, Managed Transforms, Cloud
Connector Rules.

## Convertible core, per rule family

| Rule family | Converts (`EXACT`, unless noted) | Non-convertible |
|---|---|---|
| **Redirect Rules** | CFF viewer-request. Target + condition built from the core whitelist below. | Target/condition using a non-core function, field, or operator. |
| **URL Rewrite Rules** | CFF viewer-request. `concat` / `regex_replace` / `wildcard_replace` on `uri.path` / `full_uri` are core. | Non-core function or scope. |
| **Configuration Rules** | Only the two settings the processor maps: viewer protocol policy (from the `ssl` mode) and minimum TLS version (`min_tls_version`). | Everything else: `always_use_https`, HTTP-version toggles, `email_obfuscation`, `browser_check`, `rocket_loader`, `mirage`, `polish`, `hotlink_protection`, `security_level`, `opportunistic_encryption`, `server_side_excludes`, `minify`, etc. |
| **Origin Rules** | CFF `updateRequestOrigin` with `host` / `host_header` / `port` / `sni` (protocol is inferred from the port, not a source override), or an independent cache behavior. An S3+OAC re-point is dropped as unnecessary. | Non-path scope, or an override CloudFront cannot represent. |
| **Cache Rules** | Cache policy on a path-pattern behavior (TTL, cache key). Scope must reduce to a single CloudFront path pattern (`*` `?` only). Conditional "bypass cache" → forced-miss CFF (frozen scope, below). | Regex / multi-field / negated-path scope; `status_code_ttl`; `serve_stale`; `origin_error_page_passthru`; `cache_reserve`; `read_timeout`; respect-origin after a TTL override; `browser_ttl` reset; any `ip.src` condition. |
| **Request Header Transform** | CFF viewer-request + ORP. `set` / `remove` of a writable header with a core-whitelist value. | `add` / append (both phases, see below); disallowed/read-only headers; dynamic value using a non-core function or field. |
| **Response Header Transform** | Static security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, X-XSS-Protection) via Response Headers Policy. CFF viewer-response `set`/`remove` is **`LOSSY`** (a viewer-response function does not run on origin 4xx/5xx, custom-error, or WAF-blocked responses). | `add` / append duplicate; CORS credentials + wildcard (decision #2); a header with no RHP field that is not exactly preservable (e.g. Permissions-Policy). |
| **Custom Error Rules** | Native `custom_error_response` only: supported status codes (400, 403, 404, 405, 414, 416, 500–504) with `response_page_path` / response-code remap. | Inline body (decision #1); response-phase condition; dynamic headers/logic; unsupported status code. |
| **Compression Rules** | Cache policy `enable_gzip` / `enable_brotli`. | Scope CloudFront cannot express; any `ip.src` condition. |
| **Managed Transforms** | Only `True-Client-IP` and explicitly supported security headers. | Every other managed transform (Cloudflare-specific). |
| **Cloud Connector Rules** | An independent behavior selected by path pattern. | Any non-path condition (behaviors select on path only). |

## The core expression whitelist

Conditions and dynamic values convert **only** when built entirely from this whitelist. Anything else is
`NON_CONVERTIBLE`.

- **Condition fields** (string- or boolean-typed only):
  - Request fields: `http.host`, `http.request.uri.path` (and `.extension`), `http.request.uri.query`,
    `http.request.full_uri`, `http.request.uri`, `http.request.method`, `http.user_agent`, `http.referer`,
    named request cookies / headers / query args.
  - Geolocation fields CloudFront provides as **string-valued** native headers: `country`
    (`CloudFront-Viewer-Country`), `city`, region name (`CloudFront-Viewer-Country-Region-Name`),
    `region_code` / `subdivision_1` (`CloudFront-Viewer-Country-Region`), `postal_code`, `timezone`.
  - **Derived geo fields (explicit tool feature):** `continent` (string, e.g. `EU` / `AS`) and
    `is_in_european_union` (`is_eu`, boolean). CloudFront has no native header for either; the tool derives
    them from `CloudFront-Viewer-Country` via a **versioned, tested** country→continent / country→EU KVS
    table, seeded into the store. Outcome is `EXACT` *with a geo-source caveat*: given the CloudFront
    country code the derived mapping is deterministic and exact, but Cloudflare-vs-CloudFront geo-provider
    differences in the country itself remain reported in `conversion_report.md` (the same caveat applies to
    every native geo field, not just the derived ones). **Exception:** `continent == "T1"` (Cloudflare's Tor
    pseudo-continent), or a set containing `"T1"`, is `NON_CONVERTIBLE` — CloudFront has no Tor equivalent,
    so it cannot be derived from country. Kept because EU/continent compliance targeting is a real customer
    need.
  - Device flags (`CloudFront-Is-*-Viewer`, string `"true"`/`"false"`) where used.
- **Operators**: `eq`, `ne`, `contains`, `starts_with`, `ends_with`, `wildcard`, `strict_wildcard`,
  `matches` (regex, rendered into the CFF; it is not a native path pattern), `in` (string set), and their
  negations.
- **Dynamic-value functions**: `concat`, `regex_replace`, `wildcard_replace`, `lower`, `upper`. These are
  the functions the generator renders with a proven runtime equivalent.

**Explicitly NOT on the whitelist → `NON_CONVERTIBLE`:**

- **Numeric-valued geolocation fields**: `asnum`, `latitude`, `longitude`, `metro_code`. CloudFront sends
  these as header text; a numeric comparison needs a parse + fail-closed handling, and they do not occur in
  practice. Off the whitelist.
- **`ip.src` as a scalar comparison**. Only an `in_kvs` IP-list membership is meaningful, and CIDR lists are
  themselves NC (use AWS WAF). A bare `ip.src eq/ne/contains` is NC.
- **Float values, and numeric or otherwise non-string sets.**
- **The function long tail**: `split`, `join`, `sha256`/`sha1`/`md5`/`hmac`, `decode_base64`/`encode_base64`,
  `url_decode`/`url_encode`, `to_string`, `len`, `substring`, `lookup_json_string`/`lookup_json_integer`,
  `remove_query_args`, `remove_bytes`, `uuidv4`, `any`/`all` (multi-value).

**Rationale.** Across the example configurations the pipeline reads, only `concat`, `regex_replace`,
`wildcard_replace`, `starts_with`, `ends_with` and the string/boolean fields above actually occur. The
long-tail functions and the numeric / `ip.src`-scalar comparisons do not appear at all, and each one needs
bespoke, hard-to-prove codegen (this is precisely the surface that produced repeated correctness defects).
They are reported non-convertible until a real configuration demonstrates the need **and** a proven
renderer with a runtime-equivalence test exists.

## Explicitly not converted (Cloudflare features)

These Cloudflare features have no faithful CloudFront configuration equivalent. Most are **not even read**
by the pipeline (they appear in the ignored-feature report); a few are read but reported
`NON_CONVERTIBLE`. Any AWS alternative listed is a manual step.

| Feature | Decision | Why / alternative |
|---|---|---|
| Workers | Abandon | Arbitrary business code + platform bindings. Cannot infer intent from config. → Lambda@Edge / standalone Lambda. |
| Snippets | Abandon (default) | Simple header/URL logic is already covered by declarative rules; complex Snippets need code migration. |
| Page Rules (legacy) | Abandon | Deprecated. Migrate to modern Rules first. |
| Trace | Abandon | Diagnostic feature, not a CloudFront setting. |
| Always Online | Abandon | Cloudflare-proprietary offline cache. |
| Argo Smart Routing | Abandon | Cloudflare network capability; no CloudFront equivalent. |
| Tiered Cache / Smart Tiered Cache | Abandon | Different internal cache topology. |
| Cache Reserve | Abandon | Cloudflare storage/cache product. |
| Early Hints | Abandon or report only | No direct CloudFront migration item. |
| Image Resizing / Polish / Mirage / WebP | Abandon | Cloudflare image optimization; AWS needs a separate design, do not auto-guess. |
| Rocket Loader / Minify | Abandon | Front-end rewrite/optimization, not a CloudFront native. |
| Page Shield | Abandon | Cloudflare security product. Suggest AWS WAF/monitoring, do not convert. |
| Browser Check / Security Level | Abandon | Cloudflare scoring/challenge policy; no equivalent mapping. |
| Hotlink Protection | Abandon auto-conversion | Achievable with Referer logic, but that is a security rewrite; confirm manually. |
| Server Side Excludes | Abandon | Cloudflare-proprietary. |
| DNSSEC | Abandon | Tool does no DNS cutover and must not change zone security settings. |
| Load Balancers / Pools | Abandon | CloudFront origin failover / ALB needs an architecture decision. |
| SaaS Fallback Origin | Abandon | Different architecture. |
| TLS Client Auth / mTLS | Abandon | CloudFront viewer mTLS is not a simple rule mapping. |
| Ciphers / TLS 1.3 / Zero RTT / Opportunistic Encryption | Mostly abandon | Keep only the CloudFront-expressible minimum protocol version; do not guess the rest. |
| WebSockets / IPv6 / HTTP2 / HTTP3 | Convert only where a CloudFront native switch is clearly equivalent | Otherwise report for manual confirmation. |
| URL Normalization | Generate nothing | CloudFront already normalizes per RFC 3986; note in report. |
| Managed Transforms (except True-Client-IP + explicit security headers) | Abandon | Cloudflare-proprietary. |
| Custom Pages | Abandon auto-migration | Not a CloudFront `custom_error_response`; user must host the page on an origin. |
| WAF Managed Rules | Do not port the Cloudflare rules themselves | Use AWS managed rule groups; confirm manually. |
| WAF `$cf.*` managed lists | Abandon direct conversion | Cloudflare intelligence is not exportable. |
| WAF API Abuse / SaaS / mTLS | Abandon | Different product capability and architecture. |
| WAF rate `mitigation_timeout` | Drop + report | AWS WAF has no fixed block duration. |

## Scope-reset decisions (2026-08-12)

Decisions that narrow the current implementation. These are the deltas from what the code does today:

| Item | Decision |
|---|---|
| Custom Error inline body via CFF+KVS | → `NON_CONVERTIBLE`. Keep only native `custom_error_response` (status / `response_page_path` / remap). |
| CORS credentials + wildcard-origin workaround | → `NON_CONVERTIBLE`. The Fetch/CORS standard forbids `Access-Control-Allow-Credentials: true` with `*` (browsers reject the response); CloudFront neither rejects nor fixes the combination, and the ~60-TLD wildcard substitution is not a faithful equivalent of an unconditional `*`+credentials rule. |
| Broad Cloudflare dynamic-expression coverage | → Narrow to the core function whitelist above. Complex, edge, and hard-to-prove functions default to `NON_CONVERTIBLE`. |
| Conditional cache-bypass forced-miss | → Keep the existing capability, but **freeze** its scope. Do not extend it into a general request-time cache simulator. |
| Geo `continent` / `is_in_european_union` | → **KEEP** as an explicit, documented tool feature. `EXACT` (with the geo-source caveat) for the seven real continents / EU membership, derived from `CloudFront-Viewer-Country` via a versioned, tested country→continent / country→EU KVS table. A deliberate exception to "native-only," justified because the derivation is provably exact given the country code. **`continent == "T1"` (Tor) → `NON_CONVERTIBLE`** (no CloudFront equivalent). EU/continent compliance targeting is a real customer requirement. |

## How this is enforced (implementation contract)

- **One authority.** The convertible lists above are represented once in code and consumed by the
  processor, the chunk/JS validators, and the generator. No component keeps its own separate allow-list.
- **Processor decides the outcome.** Each processor classifies every source leaf `EXACT` / `LOSSY` /
  `NON_CONVERTIBLE` against this policy and records it in the outcome ledger.
- **The sink aborts only on an internal bug.** `_append_viewer_op` (and peers) raise a fatal ledger error
  only when an internal producer emits a malformed op, never as the mechanism for rejecting a legal source
  construct (that is a processor NC decision made earlier).
- **Status is orthogonal to completeness.** NC/LOSSY never change process STATUS; they set the report's
  completeness field (`COMPLETE_EXACT` / `PARTIAL_WITH_NC`) and are listed with reasons in
  `conversion_report.md`. Nothing is dropped without a record.
- **Geo forwarding is a hard contract, not best-effort.** A converted geo condition
  (`country`/`city`/region/`postal_code`/`timezone`/`continent`/`is_eu`) requires all of: the needed
  `CloudFront-Viewer-*` / `CloudFront-Is-*-Viewer` header forwarded via the behavior's **origin request
  policy**, the KVS association on the request/response function, and the seed data for any derived table.
  If any of those is missing, that is a converter bug or a deploy blocker, never a runtime best-effort
  fallback. Forwarding is bounded by the ORP header quota (a soft per-policy limit, ~10 CloudFront headers):
  a domain whose rules need more native headers than the budget is a **surfaced quota/deploy concern**
  (raise the quota, or reduce the fields), not a silent drop. The exact ORP strategy — a custom
  whitelist vs a managed CloudFront-headers policy, and the managed policy's Host-forwarding tradeoff — is
  settled in the code phase.

---

*AWS capability boundaries used above (the CloudFront-Viewer-* / CloudFront-Is-*-Viewer header inventory,
the absence of any continent/EU header, and CloudFront Response Headers Policy CORS behavior) were verified
against AWS documentation on 2026-08-12. The credentials+wildcard rule is per the WHATWG Fetch standard.*
