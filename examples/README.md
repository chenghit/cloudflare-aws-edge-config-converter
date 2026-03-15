# Examples

## Cloudflare Configurations

`cloudflare-configs/` contains sample Cloudflare configurations exported from real zones (with sensitive data removed).

- `account/` — Account-level configurations (IP lists, etc.)
- `c.example.com/` — Zone-level configurations for a sample domain
  > **Note**: `c.example.com` is used as an apex domain here (no real TLD was available for testing). In your own account, this would typically be something like `example.com`.

These can be used to test conversion without your own Cloudflare backup.

## Conversation History

`conversation-history/` contains complete conversation transcripts showing how to use each skill:

- `cloudflare-to-aws-waf.txt` — WAF conversion (3-stage pipeline: analyzer → validator → generator)
- CDN full pipeline example — coming soon

## How to Use

```bash
kiro-cli chat
```

Then reference the example configs:

```
Convert Cloudflare security rules in ./examples/cloudflare-configs/ to AWS WAF
Convert CDN configuration in ./examples/cloudflare-configs/ to CloudFront Terraform
```
