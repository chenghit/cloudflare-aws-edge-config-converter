# Cloudflare Default Cache Behavior

## Overview

Cloudflare has built-in default cache behavior that automatically caches certain file types and applies default TTLs. These defaults are **implicit** - they don't appear in Cloudflare configuration files but are active for all proxied domains.

**CRITICAL:** When migrating to CloudFront, these implicit behaviors must be explicitly configured, otherwise content that was cached in Cloudflare will not be cached in CloudFront.

## Default Cached File Extensions

Cloudflare automatically caches files with the following extensions (70+ types):

### Images
- `GIF`, `ICO`, `JPG`, `JPEG`, `PNG`, `BMP`, `PICT`, `TIF`, `TIFF`, `SVG`, `SVGZ`, `WEBP`, `AVIF`

### Documents
- `PDF`, `DOC`, `DOCX`, `XLS`, `XLSX`, `PPT`, `PPTX`, `EPS`

### Stylesheets & Scripts
- `CSS`, `JS`, `EJS`

### Fonts
- `EOT`, `OTF`, `TTF`, `WOFF`, `WOFF2`

### Media Files
- `AVI`, `FLAC`, `MID`, `MIDI`, `MKV`, `MP3`, `MP4`, `OGG`, `WEBM`

### Archives & Binaries
- `7Z`, `APK`, `BIN`, `BZ2`, `CLASS`, `DMG`, `EXE`, `GZ`, `ISO`, `JAR`, `RAR`, `TAR`, `ZIP`, `ZST`

### Other
- `CSV`, `PLS`, `PS`, `SWF`

### Special Case: robots.txt
Cloudflare caches `robots.txt` by default.

## What Cloudflare Does NOT Cache by Default

**CRITICAL:** These content types are NOT cached by default:

- **HTML files** (`.html`, `.htm`)
- **JSON files** (`.json`)
- **XML files** (`.xml`)
- **Dynamic content** (no file extension or non-matching extensions)

## Default Edge TTL

When no `Cache-Control` or `Expires` header is present, Cloudflare uses these default TTLs:

| HTTP Status Code | Default TTL |
|------------------|-------------|
| 200, 206, 301 | 120 minutes (2 hours) |
| 302, 303 | 20 minutes |
| 404, 410 | 3 minutes |

All other status codes are not cached by default.

## Cache Behavior Rules

### Cloudflare DOES Cache When:
1. File extension matches the default cached extensions list (above)
2. `Cache-Control: public` with `max-age > 0`
3. `Expires` header is set to a future date

### Cloudflare DOES NOT Cache When:
1. `Cache-Control: private`, `no-store`, `no-cache`, or `max-age=0`
2. `Set-Cookie` header exists in response
3. HTTP method is not `GET`

## Implications for CloudFront Migration

### Problem: Implicit vs Explicit Configuration

**Cloudflare:**
```
User uploads image.jpg → Automatically cached for 2 hours
No configuration needed
```

**CloudFront:**
```
User uploads image.jpg → NOT cached by default
Must explicitly configure Cache Behavior or Cache Policy
```

### What Analyzer Must Note

The Analyzer should include a warning in the Summary section that all proxied hostnames rely on Cloudflare's default cache behavior, and users need to decide which hostnames should replicate this behavior in CloudFront.

## Reference

Source: [Cloudflare Default Cache Behavior Documentation](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/)

Last verified: 2026-02-03
