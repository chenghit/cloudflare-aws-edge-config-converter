# CloudflareBackup

English | [简体中文](README.zh-CN.md)

Bash script to create comprehensive Cloudflare configuration backups using curl and the Cloudflare API.

> Vendored from [chenghit/CloudflareBackup](https://github.com/chenghit/CloudflareBackup) (MIT-0, see `LICENSE`). This is the input producer for the converter — run it first to export your Cloudflare config, then point the converter at the output. For updates or issues with the backup tool itself, see the upstream repo.

## Requirements

- `bash` (3.2+)
- `curl`
- `jq` — [install instructions](https://jqlang.github.io/jq/download/)
- `python3` (only needed if you use Workers KV with special characters in key names)
- Valid Cloudflare credentials — either an **API Token** with read permissions, or a **Global API Key** + account email

## Setup

1. `cd backup/` (this directory, inside the cloned converter repo)
2. Copy `config.example` to `config`
3. Edit `config` with your API token and domain names

```bash
cd backup
cp config.example config
# Edit config with your editor
```

**Example config (API Token — recommended):**

```
API_TOKEN=your_actual_cloudflare_api_token
DOMAIN1=example.com
DOMAIN2=example.org
DOMAIN3=example.net
```

**Or with a Global API Key (legacy):** leave `API_TOKEN` blank and set both:

```
API_EMAIL=you@example.com
API_KEY=your_global_api_key
DOMAIN1=example.com
```

If `API_TOKEN` is set it takes precedence; otherwise the script falls back to the Global API Key.

> ⚠️ The Global API Key grants full account access and cannot be scoped or limited like an API Token. Prefer the API Token when you can. The key lives on the same [API Tokens page](https://dash.cloudflare.com/profile/api-tokens), under the **API Keys** section → **Global API Key** → **View**.

No limit on the number of domains — add `DOMAIN4`, `DOMAIN5`, etc. as needed.

## Running

### macOS / Linux

```bash
chmod +x cloudflare_backup.sh
./cloudflare_backup.sh
```

### Windows (via WSL)

Windows doesn't run bash natively. Use WSL (Windows Subsystem for Linux):

1. **Install WSL** (one-time, requires admin PowerShell):

   ```powershell
   wsl --install
   ```
   
   Restart your computer when prompted.

2. **Install dependencies** (one-time, inside WSL terminal):

   ```bash
   sudo apt update && sudo apt install -y jq curl
   ```

3. **Run the script**:

   ```bash
   # Navigate to your backup folder (Windows drives are at /mnt/c/, /mnt/d/, etc.)
   cd /mnt/c/Users/YourName/CloudflareBackup

   # Fix line endings if needed (only once after cloning on Windows)
   sed -i 's/\r$//' cloudflare_backup.sh

   # Run
   chmod +x cloudflare_backup.sh
   ./cloudflare_backup.sh
   ```

> **Tip**: You can also run directly from PowerShell without entering WSL first:
> 
> ```powershell
> wsl -e bash -c "cd /mnt/c/Users/YourName/CloudflareBackup && ./cloudflare_backup.sh"
> ```

## Error Handling

The script validates your API token before starting. If any API call fails, the **raw Cloudflare response** is printed to the screen so you can see exactly what went wrong.

Common errors:

- **Token IP restriction**: Your API token has an IP allowlist but your current IP changed
- **Token expired/revoked**: Token no longer valid
- **Permission denied**: Token lacks required read permissions

The script will continue backing up other resources after non-fatal errors and report a count at the end.

## What Gets Backed Up

### Zone-Level Data

| Category | Items |
|----------|-------|
| WAF | Custom Rules, Managed Rules |
| Rules | Rate Limits, Cache, Configuration, Redirect, Origin, Compression, URL Rewrite, Request/Response Header Transform, Custom Error, Cloud Connector |
| DNS | All records (paginated), DNSSEC |
| Infrastructure | Load Balancers, IP Access Rules (paginated), Page Shield, Custom Pages, SaaS Fallback Origin |
| CDN/Performance | Smart Tiered Cache, Cache Reserve, Argo Smart Routing, Tiered Caching, URL Normalization, Managed Transforms |
| TLS/Security | TLS 1.3, Min TLS Version, Ciphers, HTTP/3, HTTP/2, IPv6, 0-RTT, WebSockets, Early Hints, Security Level, Challenge TTL, Browser Check, Opportunistic Encryption, TLS Client Auth |
| Other Settings | Image Resizing, WebP, Development Mode, Always Online, Hotlink Protection, Server Side Excludes |
| Snippets | Snippet list, routing rules, and JavaScript source code |

### Account-Level Data

- IP Lists + all list items
- Bulk Redirect Rules
- Load Balancer Pools
- Workers KV Namespaces (all keys and values, paginated)

## Output Structure

```
Backup Root/
├── example.com/
│   └── 2024-01-15 14-30-00/
│       ├── DNS.txt
│       ├── WAF-Custom-Rules.txt
│       ├── Cache-Rules.txt
│       ├── Snippets.txt
│       ├── Snippet-Rules.txt
│       ├── Snippet-my_snippet.js
│       └── ...
├── example.org/
│   └── 2024-01-15 14-30-00/
│       └── ...
└── account/
    └── 2024-01-15 14-30-00/
        ├── IP-Lists.txt
        ├── List-Items-ip-MyIPList.txt
        ├── Bulk-Redirect-Rules.txt
        ├── Load-Balancer-Pools.txt
        ├── KV-Namespaces.txt
        └── KV-My_Namespace/
            ├── keys-page-1.txt
            ├── value-config_key.txt
            └── ...
```

## API Token Permissions

Create a token at https://dash.cloudflare.com/profile/api-tokens with these read permissions:

- Zone: DNS, Firewall Services, Zone Settings, Cache Rules, Config Rules, Dynamic Redirect, Origin Rules, Zone WAF, Page Shield, Load Balancers
- Account: Account Rulesets, Account Filter Lists, Load Balancing, Workers KV Storage

## Notes

- This backs up **configuration only**, not account settings (billing, team members, etc.)
- All API responses are saved as JSON files
- Zone IDs and Account IDs are auto-discovered from domain names
- Endpoints that return errors for features not on your plan are skipped with an error message
