# AGENTS.md

This repo has two parts:

- `backup/` — the bundled backup script. The user runs it to export their Cloudflare config to disk. It is the input for the converter.
- `converter/` — the Cloudflare-to-AWS converter (deterministic Python + a bash entry point). It reads a backup and generates AWS WAF (CloudFormation) and CloudFront (Terraform + JS).

**To do a conversion:** read `converter/SKILL.md` in full, then follow it exactly. It is the single source of truth for how to run the pipeline — script order, path conventions, credential-safety rules, and result handling. Do not infer the workflow from anything else in this repo.

**To modify or debug the CDN pipeline** (not to run a conversion): read `converter/references/cdn-design.md` first — the direction-level model behind how Cloudflare rules map to CloudFront (per-host distributions, host×path routing, the ORP-must-reach-its-behavior invariant). It's for changing the code, not for hand-editing generated output; the pipeline is deterministic and owns the conversion decisions.

**To modify or debug the WAF pipeline** (not to run a conversion): read `converter/references/waf-design.md` first — the direction-level model behind how Cloudflare WAF/rate/IP-access rules map to an AWS WAFv2 WebACL (two WebACLs, Cloudflare phase order, skip→label producers/consumers, rule-group escape of the 10-RBR/50-ref caps, exact WCU + STATUS: BLOCKED). Same rule: change the code with a regression test, don't hand-edit generated CloudFormation.

There is no install step. The scripts self-locate and run from wherever the repo is cloned.
