# V3 Validation Checklist — Supplementary Notes

This document supplements the checks defined in SKILL.md. It provides
additional context for specific checks where grep-based detection has
known edge cases. **The authoritative check definitions are in SKILL.md.**

## CFF-02: Optional chaining false positives

`grep -n '\?\.' "<file>"` may match:
- Ternary expressions followed by property access: `x ? obj.prop : default`
- Regex patterns containing `?.`
- String literals containing `?.`

These are false positives. Under adversarial posture, flag them anyway —
false positive is acceptable, false negative is not.

## CFF-05 / CFF-10: Promise and .then/.catch — WARN not FAIL

These are warnings, not failures. Promise methods and chain syntax are
syntactically valid in CloudFront Functions Runtime 2.0. AWS documentation
warns they "can require high function memory usage" and recommends sequential
`await` instead. A WARN does not set `overall_status` to FAIL.

## CFF-09: Return statement patterns

The check looks for `return req`, `return request`, or `return {statusCode`.
For **viewer_response** functions, the return is `return response` — add this
pattern to the grep list for viewer_response files.

## LE-02: Handler export — CommonJS only

Lambda@Edge files must use CommonJS format: `exports.handler`.
ESM syntax (`export const handler`) is not valid for Lambda@Edge deployed
via CloudFront. Only check for `exports.handler`.

## LE-05: default_cache_origin_response.js

The default cache Lambda uses `event.Records[0].cf.response` (not
`event.Records[0].cf.request`). The LE-05 grep for `event.Records[0].cf`
covers both patterns — no special handling needed.

## CROSS-02: KVS usage — what counts

`cf.kvs()` in CFF files indicates KVS usage. The check compares presence
of `cf.kvs()` against IR `kvs_requirements`. Note that continent and EU
lookups also use KVS (not just bulk redirects), so `kvs_requirements` may
be non-empty even without bulk redirects.

## CROSS-03: Lambda@Edge — what counts

The IR `lambda_edge` field has sub-fields: `origin_request`,
`origin_response`, `viewer_request`. Any non-null sub-field means Lambda
files should exist. The `origin_response` sub-field is used for the
default cache behavior Lambda (type: `default_cache`).
