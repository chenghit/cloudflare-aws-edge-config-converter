# CloudFront Origin Request Policy — allExcept and Full Reference

## Valid header_behavior Values

| Value | Description | `headers` block |
|-------|-------------|-----------------|
| `none` | No viewer headers forwarded | Must NOT be specified |
| `whitelist` | Only listed headers forwarded | REQUIRED — headers to include |
| `allViewer` | All viewer headers forwarded | Must NOT be specified |
| `allViewerAndWhitelistCloudFront` | All viewer headers + listed CloudFront-generated headers | REQUIRED — CF headers to add |
| `allExcept` | All viewer headers EXCEPT listed ones | REQUIRED — headers to exclude |

**Note:** `cookie_behavior` and `query_string_behavior` also support `allExcept` and `all`.
`header_behavior` does NOT support `all` — use `allViewer` instead.

---

## allExcept — Exclude Specific Headers

Use when Cloudflare has a "remove header" rule. Forwards everything except the listed headers.

```hcl
resource "aws_cloudfront_origin_request_policy" "exclude_headers" {
  name = "cfcdn-orp-exclude-host"

  headers_config {
    header_behavior = "allExcept"
    headers {
      items = ["Host", "X-Internal-Token"]  # these headers are NOT forwarded to origin
    }
  }

  cookies_config {
    cookie_behavior = "all"
  }

  query_strings_config {
    query_string_behavior = "all"
  }
}
```

---

## allViewerAndWhitelistCloudFront — Add CloudFront-Generated Headers

Use when origin needs geo/device information. Forwards all viewer headers PLUS the listed CloudFront-generated headers.

```hcl
resource "aws_cloudfront_origin_request_policy" "viewer_plus_geo" {
  name = "cfcdn-orp-viewer-plus-geo"

  headers_config {
    header_behavior = "allViewerAndWhitelistCloudFront"
    headers {
      items = [
        "CloudFront-Viewer-Country",
        "CloudFront-Is-Mobile-Viewer",
        "CloudFront-Is-Desktop-Viewer",
        "CloudFront-Viewer-City",
        "CloudFront-Forwarded-Proto",
      ]
    }
  }

  cookies_config { cookie_behavior = "all" }
  query_strings_config { query_string_behavior = "all" }
}
```

### Available CloudFront-Generated Headers

**Device type:**
`CloudFront-Is-Android-Viewer`, `CloudFront-Is-Desktop-Viewer`, `CloudFront-Is-IOS-Viewer`,
`CloudFront-Is-Mobile-Viewer`, `CloudFront-Is-SmartTV-Viewer`, `CloudFront-Is-Tablet-Viewer`

**Viewer location:**
`CloudFront-Viewer-Country`, `CloudFront-Viewer-Country-Name`, `CloudFront-Viewer-City`,
`CloudFront-Viewer-Country-Region`, `CloudFront-Viewer-Country-Region-Name`,
`CloudFront-Viewer-Latitude`, `CloudFront-Viewer-Longitude`, `CloudFront-Viewer-Metro-Code`,
`CloudFront-Viewer-Postal-Code`, `CloudFront-Viewer-Time-Zone`,
`CloudFront-Viewer-Address` (ORP only), `CloudFront-Viewer-ASN` (ORP only)

**TLS (ORP only):**
`CloudFront-Viewer-JA3-Fingerprint`, `CloudFront-Viewer-JA4-Fingerprint`, `CloudFront-Viewer-TLS`

**Other:**
`CloudFront-Forwarded-Proto`, `CloudFront-Viewer-Http-Version`,
`CloudFront-Viewer-Header-Order`, `CloudFront-Viewer-Header-Count`

---

## Cache Policy header_behavior Restriction

Cache Policy `header_behavior` only supports `none` and `whitelist`.
`allExcept`, `allViewer`, `allViewerAndWhitelistCloudFront` are **NOT valid** for cache policies.

```hcl
# Cache policy — headers only: none or whitelist
resource "aws_cloudfront_cache_policy" "example" {
  parameters_in_cache_key_and_forwarded_to_origin {
    headers_config {
      header_behavior = "whitelist"  # only none or whitelist valid here
      headers { items = ["Authorization"] }
    }
    cookies_config  { cookie_behavior = "allExcept"; cookies { items = ["session"] } }
    query_strings_config { query_string_behavior = "allExcept"; query_strings { items = ["utm_source"] } }
  }
}
```
