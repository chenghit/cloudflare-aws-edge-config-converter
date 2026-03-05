# Why Not cf-terraforming?

[cf-terraforming](https://github.com/cloudflare/cf-terraforming) is Cloudflare's official tool for exporting configurations to Terraform. While it's excellent for Terraform-based infrastructure management, it's fundamentally incompatible with this migration tool.

## The Core Problem: Unpredictable File Structure

This tool's AI skills depend on a **predictable file structure** — fixed directory layout, fixed file names (`WAF-Custom-Rules.txt`, `Rate-limits.txt`, `IP-Lists.txt`, etc.). Skills use these known paths to trigger workflows and locate configuration data.

cf-terraforming requires users to **manually specify output file names and paths** for each resource type:

```bash
cf-terraforming generate --resource-type cloudflare_ruleset --zone $ZONE_ID > my-waf-rules.tf
cf-terraforming generate --resource-type cloudflare_list --account $ACCOUNT_ID > ip-lists.tf
cf-terraforming generate --resource-type cloudflare_rate_limit --zone $ZONE_ID > rate-limits.tf
# ... user chooses any file name and location
```

This means:
- **File names are arbitrary** — one user might name it `waf.tf`, another `my-rules.tf`
- **Directory structure is arbitrary** — files could be in one directory, nested, or scattered
- **No standard layout** — every user's export looks different

AI skills cannot reliably activate or locate configuration data when the file structure is unpredictable. The skill would need to ask "where did you put your files?" and "what did you name them?" — defeating the purpose of automation.

**CloudflareBackup solves this** by producing a fixed, predictable structure every time:

```
example.com/2026-01-12/
├── WAF-Custom-Rules.txt
├── Rate-limits.txt
├── IP-Lists.txt
├── IP-Access-Rules.txt
├── Redirect-Rules.txt
├── ...
```

One command, one structure, every time. Skills know exactly where to find each configuration type.

## Secondary Issue: Still Requires API for Zone IDs

cf-terraforming cannot discover zone IDs from domain names — you must call the Cloudflare API first:

```bash
# cf-terraforming cannot do this:
cf-terraforming generate --resource-type cloudflare_ruleset --domain example.com
# Error: unknown flag: --domain

# You must call the API first:
ZONE_ID=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=example.com" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.result[0].id')

# Then call cf-terraforming:
cf-terraforming generate --resource-type cloudflare_ruleset --zone $ZONE_ID
```

If you're already calling the API to get zone IDs, CloudflareBackup can get zone IDs AND configuration data in one step.

## Comparison

| | cf-terraforming | CloudflareBackup |
|---|---|---|
| File structure | User-defined (unpredictable) | Fixed (predictable) |
| File names | User-defined (arbitrary) | Standardized |
| Zone ID discovery | Manual API call required | Automatic |
| Commands needed | Multiple (one per resource type) | One |
| AI skill compatibility | ❌ Cannot reliably locate files | ✅ Skills know exact paths |

## What cf-terraforming Is Actually For

cf-terraforming is designed for **adopting Terraform to manage Cloudflare** — not for migrating away from Cloudflare:

```
Use case: Manage Cloudflare via Terraform (continue using Cloudflare)
NOT for:  Migrate from Cloudflare to AWS
```

## The Bottom Line

The incompatibility is not about HCL parsing (AI handles that fine) or data quality. It's about **file structure predictability** — the foundation that makes automated skill-based workflows possible.
