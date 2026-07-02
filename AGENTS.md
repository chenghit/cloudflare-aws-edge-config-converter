# AGENTS.md

This repo has two parts:

- `backup/` — the CloudflareBackup tool. The user runs it to export their Cloudflare config to disk. It is the input for the converter.
- `converter/` — the Cloudflare-to-AWS converter (deterministic Python + a bash entry point). It reads a backup and generates AWS WAF (CloudFormation) and CloudFront (Terraform + JS).

**To do a conversion:** read `converter/SKILL.md` in full, then follow it exactly. It is the single source of truth for how to run the pipeline — script order, path conventions, credential-safety rules, and result handling. Do not infer the workflow from anything else in this repo.

There is no install step. The scripts self-locate and run from wherever the repo is cloned.
