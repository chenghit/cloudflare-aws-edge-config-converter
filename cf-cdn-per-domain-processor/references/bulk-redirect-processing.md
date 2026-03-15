# Bulk Redirects Processing (Step 3e)

Read this file only when `Bulk-Redirect-Rules.txt` exists in the backup directory.
Also read `references/bulk-redirects-handling.md` and `references/kvs-usage-and-limits.md`
before processing.

---

## Phase 1: Discover Bulk Redirect Lists

Read `Bulk-Redirect-Rules.txt` (check both `<backup_path>/` and
`<backup_path>/account/`). Identify which redirect lists are referenced.

## Phase 2: Read Redirect List Items

For each referenced list name `<name>`, read
`<backup_path>/account/List-Items-redirect-<name>.txt`.
If not found there, also check `<backup_root>/account/<timestamp>/` (CloudflareBackup
stores account-level files separately from zone-level files).

The file is a JSON API response: `{"result": [...]}`. Each item has:
```json
{
  "id": "...",
  "redirect": {
    "source_url": "cdn.c.example.com/old-path",
    "target_url": "https://cdn.c.example.com/new-path",
    "status_code": 301,
    "preserve_query_string": false,
    "include_subdomains": false
  }
}
```

The redirect fields are inside `.result[].redirect`. Note that `include_subdomains`
and `preserve_query_string` may be absent (default to `false`).

## Phase 3: Generate IR Output

- Add `type: bulk_redirect` to `viewer_request_ops`:
  ```yaml
  - type: bulk_redirect
    cf_source_rule: "<rule_id>"
    condition: null
    params:
      kvs_prefix: "redirect:"
  ```
- Set `kvs_requirements.needs_redirects: true`.
- For each redirect item, generate `kvs_data` entries. The KVS key format is
  `redirect:{host}{path}` — the host is included in the key so the CF Function
  can match by both host and path.

  **`include_subdomains: false` (default)** — generate ONE entry:
  ```yaml
  - key: "redirect:example.com/old/path"
    value: "301|0|https://example.com/new/path"
  ```

  **`include_subdomains: true`** — generate TWO entries:
  ```yaml
  - key: "redirect:example.com/old/path"
    value: "301|0|https://example.com/new/path"
  - key: "redirect:.example.com/old/path"
    value: "301|0|https://example.com/new/path"
  ```
  The `.example.com` key (leading dot before the full hostname) enables
  subdomain matching. See `references/bulk-redirects-handling.md` for the
  complete lookup logic and validation checklist.

- **Value format**: `{status_code}|{preserve_qs}|{target_url}`
  - `preserve_qs`: use `1` (true) or `0` (false) — NOT `true`/`false` strings
  - `target_url`: full URL with protocol
  - `status_code`: 301 or 302 (default 301)
