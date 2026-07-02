# CDN Pipeline

CDN conversion: Cloudflare cache/redirect/origin rules → CloudFront Terraform.

0 LLM stages + 10 Python scripts. All scripts output `---RESULT---` blocks per SCRIPT_STANDARDS.md.

## Stage 1: DNS Parsing + Domain Scope (Python)

```bash
python3 "$REPO/converter/scripts/cdn-parse-dns.py" "$CONFIG_PATH" "$OUT/cloudflare-to-aws-cdn"
```

Outputs: `dns_manifest.yaml` + `domain_scope.json`. No user input needed.
- `STATUS: OK` → proceed to Stage 3
- `STATUS: FATAL` → report error and stop

## Stage 3–9: All Python scripts

See SKILL.md for the full stage-by-stage invocation commands.
All stages are deterministic Python — no LLM, no user interaction.
