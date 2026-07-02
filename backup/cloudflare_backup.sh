#!/bin/bash

# Cloudflare Backup Script
# Works on macOS, Linux, and Windows (via WSL/Git Bash)

set -euo pipefail

ERRORS=0
CF_SKIP_FILE="/tmp/.cf_skip_reason.$$"
trap 'rm -f "$CF_SKIP_FILE"' EXIT

# --- Config parsing (safe, no source) ---

if [[ ! -f "config" ]]; then
    echo "❌ Error: 'config' file not found!"
    echo "  1. Copy 'config.example' to 'config'"
    echo "  2. Edit 'config' and add your API token and domains"
    exit 1
fi

API_TOKEN=""
API_EMAIL=""
API_KEY=""
declare -a DOMAINS=()

while IFS='=' read -r key value; do
    # Skip comments and empty lines
    [[ -z "$key" || "$key" == \#* ]] && continue
    # Trim whitespace (safe, no xargs)
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    case "$key" in
        API_TOKEN) API_TOKEN="$value" ;;
        API_EMAIL) API_EMAIL="$value" ;;
        API_KEY) API_KEY="$value" ;;
        DOMAIN*)
            if [[ -n "$value" && "$value" != "example.com" && "$value" != example* ]]; then
                DOMAINS+=("$value")
            fi
            ;;
    esac
done < config

# Normalize placeholder token to empty so we can fall back to Global API Key
[[ "$API_TOKEN" == "your_cloudflare_api_token_here" ]] && API_TOKEN=""

# Build curl auth args: prefer API Token, else fall back to Global API Key.
declare -a CF_AUTH_ARGS=()
if [[ -n "$API_TOKEN" ]]; then
    CF_AUTH_ARGS=(-H "Authorization: Bearer $API_TOKEN")
elif [[ -n "$API_EMAIL" && -n "$API_KEY" ]]; then
    CF_AUTH_ARGS=(-H "X-Auth-Email: $API_EMAIL" -H "X-Auth-Key: $API_KEY")
else
    echo "❌ Error: No credentials configured!"
    echo "  Set API_TOKEN, or set both API_EMAIL and API_KEY (Global API Key)."
    exit 1
fi

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    echo "❌ Error: No domains configured!"
    exit 1
fi

BATCH_DATE=$(date +"%Y-%m-%d")
BATCH_TIME=$(date +"%H-%M-%S")

# --- API helper ---
# Calls Cloudflare API. On success: prints response to stdout.
# On failure: prints raw Cloudflare response to stderr, returns 1.
# Non-JSON responses (HTML error pages, etc.) are also caught.
# Usage: cf_api <url> [--fatal]
cf_api() {
    local url="$1"
    local fatal="${2:-}"
    local response

    response=$(curl -s -X GET "$url" \
        "${CF_AUTH_ARGS[@]}" \
        -H "Content-Type: application/json") || true

    if [[ -z "$response" ]]; then
        echo "❌ Empty response: $url (network error or timeout)" >&2
        [[ "$fatal" == "--fatal" ]] && exit 1
        ((ERRORS++)) || true
        return 1
    fi

    # Check if response is valid JSON with success field
    local success
    success=$(echo "$response" | jq -r 'if .success == true then "true" elif .success == false then "false" else "nojson" end' 2>/dev/null) || success="nojson"

    if [[ "$success" == "nojson" ]]; then
        # Not valid JSON or no success field — print raw response
        echo "❌ Non-JSON response: $url" >&2
        echo "$response" | head -c 500 >&2
        echo >&2
        [[ "$fatal" == "--fatal" ]] && exit 1
        ((ERRORS++)) || true
        return 1
    fi

    if [[ "$success" == "false" ]]; then
        local error_code error_msg
        error_code=$(echo "$response" | jq -r '.errors[0].code // 0' 2>/dev/null) || error_code=0
        error_msg=$(echo "$response" | jq -r '.errors[0].message // "unknown"' 2>/dev/null) || error_msg="unknown"
        case "$error_code" in
            9109|6003|6103|10000)
                # Authentication / permission errors — real failures
                echo "❌ API error: $url" >&2
                echo "   $error_msg (code $error_code)" >&2
                [[ "$fatal" == "--fatal" ]] && exit 1
                ((ERRORS++)) || true
                return 1
                ;;
            *)
                # Everything else: not configured / not available / not found
                echo "$error_msg" > "$CF_SKIP_FILE"
                return 1
                ;;
        esac
    fi

    echo "$response"
}

# --- Pre-flight check ---
# /user/tokens/verify is API-Token-only; Global API Key verifies via /user.
if [[ -n "$API_TOKEN" ]]; then
    echo "Verifying API token..."
    cf_api "https://api.cloudflare.com/client/v4/user/tokens/verify" --fatal >/dev/null
    echo "  ✓ API token is valid"
else
    echo "Verifying Global API Key..."
    cf_api "https://api.cloudflare.com/client/v4/user" --fatal >/dev/null
    echo "  ✓ Global API Key is valid"
fi

# --- Paginated API fetch ---
# Fetches all pages of a paginated endpoint, merges .result arrays.
# Usage: cf_api_paginated <url_base> [per_page]
cf_api_paginated() {
    local url_base="$1"
    local per_page="${2:-5000}"
    local page=1
    local separator="?"
    [[ "$url_base" == *"?"* ]] && separator="&"
    local tmp_file
    tmp_file=$(mktemp)

    while true; do
        local url="${url_base}${separator}per_page=${per_page}&page=${page}"
        local response
        response=$(cf_api "$url") || { rm -f "$tmp_file"; return 1; }

        echo "$response" | jq -c '.' >> "$tmp_file"

        local total_pages
        total_pages=$(echo "$response" | jq -r '.result_info.total_pages // 1')
        [[ $page -ge $total_pages ]] && break
        page=$((page + 1))
        [[ $page -gt 100 ]] && echo "⚠️  Pagination limit reached for $url_base" >&2 && break
    done

    # Merge all pages in one pass
    jq -s '{success: true, result: [.[].result[]]}' "$tmp_file"
    rm -f "$tmp_file"
}

# Cursor-based paginated fetch (for list items, etc.)
# Usage: cf_api_cursor <url_base> [per_page]
cf_api_cursor() {
    local url_base="$1"
    local per_page="${2:-300}"
    local separator="?"
    [[ "$url_base" == *"?"* ]] && separator="&"
    local tmp_file
    tmp_file=$(mktemp)
    local cursor=""
    local pages=0

    while true; do
        local url="${url_base}${separator}per_page=${per_page}"
        [[ -n "$cursor" ]] && url="$url&cursor=$cursor"

        local response
        response=$(cf_api "$url") || { rm -f "$tmp_file"; return 1; }

        echo "$response" | jq -c '.' >> "$tmp_file"

        cursor=$(echo "$response" | jq -r '.result_info.cursors.after // empty')
        [[ -z "$cursor" ]] && break
        pages=$((pages + 1))
        [[ $pages -gt 100 ]] && echo "⚠️  Cursor pagination limit reached for $url_base" >&2 && break
    done

    jq -s '{success: true, result: [.[].result[]]}' "$tmp_file"
    rm -f "$tmp_file"
}

# --- Safe filename helper ---
safe_filename() {
    echo "$1" | tr '/:*?"<>|\\' '__________' | tr ' ' '_'
}

# --- Write response to file, skip if .result is empty ---
# Usage: write_response "$json" "$filepath" "$label"
write_response() {
    local json="$1" filepath="$2" label="$3"
    local result_len
    result_len=$(echo "$json" | jq '.result | if type == "array" then length elif . == null then 0 else 1 end' 2>/dev/null) || result_len=1
    if [[ "$result_len" -eq 0 ]]; then
        echo "  ⊘ Skipped $label (empty)"
        return 1
    fi
    echo "$json" > "$filepath"
    echo "  ✓ $label"
}

# --- Zone backup ---
backup_zone() {
    local zone_id=$1
    local domain=$2
    local folder="$domain/$BATCH_DATE $BATCH_TIME"

    echo "Backing up $domain (Zone ID: $zone_id)"
    mkdir -p "$folder"

    local endpoints=(
        "WAF-Custom-Rules.txt:rulesets/phases/http_request_firewall_custom/entrypoint"
        "WAF-Managed-Rules.txt:rulesets/phases/http_request_firewall_managed/entrypoint"
        "Rate-limits.txt:rulesets/phases/http_ratelimit/entrypoint"
        "Cache-Rules.txt:rulesets/phases/http_request_cache_settings/entrypoint"
        "Configuration-Rules.txt:rulesets/phases/http_config_settings/entrypoint"
        "Redirect-Rules.txt:rulesets/phases/http_request_dynamic_redirect/entrypoint"
        "Origin-Rules.txt:rulesets/phases/http_request_origin/entrypoint"
        "Compression-Rules.txt:rulesets/phases/http_request_compress/entrypoint"
        "URL-Rewrite-Rules.txt:rulesets/phases/http_request_transform/entrypoint"
        "Request-Header-Transform.txt:rulesets/phases/http_request_late_transform/entrypoint"
        "Response-Header-Transform.txt:rulesets/phases/http_response_headers_transform/entrypoint"
        "Custom-Error-Rules.txt:rulesets/phases/http_custom_errors/entrypoint"
        "Cloud-Connector-Rules.txt:cloud_connector/rules"
        "DNSSEC.txt:dnssec"
        "Load-Balancers.txt:load_balancers"
        "Smart-Tiered-Cache.txt:cache/smart_tiered_cache"
        "Cache-Reserve.txt:cache/cache_reserve"
        "Argo-Smart-Routing.txt:argo/smart_routing"
        "Tiered-Cache.txt:argo/tiered_caching"
        "URL-Normalization.txt:url_normalization"
        "TLS-1-3.txt:settings/tls_1_3"
        "Min-TLS-Version.txt:settings/min_tls_version"
        "Ciphers.txt:settings/ciphers"
        "HTTP3.txt:settings/http3"
        "HTTP2.txt:settings/http2"
        "IPv6.txt:settings/ipv6"
        "Zero-RTT.txt:settings/0rtt"
        "WebSockets.txt:settings/websockets"
        "Early-Hints.txt:settings/early_hints"
        "Image-Resizing.txt:settings/image_resizing"
        "WebP.txt:settings/webp"
        "Development-Mode.txt:settings/development_mode"
        "Always-Online.txt:settings/always_online"
        "Hotlink-Protection.txt:settings/hotlink_protection"
        "Server-Side-Excludes.txt:settings/server_side_excludes"
        "Security-level.txt:settings/security_level"
        "Challenge-TTL.txt:settings/challenge_ttl"
        "Browser-Check.txt:settings/browser_check"
        "Page_Shield.txt:page_shield"
        "Custom-Pages.txt:custom_pages"
        "Managed-Transforms.txt:managed_headers"
        "Opportunistic-Encryption.txt:settings/opportunistic_encryption"
        "TLS-Client-Auth.txt:settings/tls_client_auth"
    )

    for entry in "${endpoints[@]}"; do
        local file="${entry%%:*}"
        local endpoint="${entry#*:}"
        local response
        rm -f "$CF_SKIP_FILE"
        if response=$(cf_api "https://api.cloudflare.com/client/v4/zones/$zone_id/$endpoint"); then
            write_response "$response" "$folder/$file" "$file" || true
        else
            local reason
            reason=$(cat "$CF_SKIP_FILE" 2>/dev/null)
            if [[ -n "$reason" ]]; then
                echo "  ⊘ Skipped $file ($reason)"
            else
                echo "  ❌ Failed $file"
            fi
        fi
    done

    # SaaS Fallback Origin — always write raw response (downstream tools need it to detect SaaS)
    local saas_response
    saas_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/custom_hostnames/fallback_origin" \
        "${CF_AUTH_ARGS[@]}" \
        -H "Content-Type: application/json") || true
    if [[ -n "$saas_response" ]]; then
        echo "$saas_response" > "$folder/SaaS-Fallback-Origin.txt"
        echo "  ✓ SaaS-Fallback-Origin.txt"
    fi

    # DNS records (paginated — required, skip zone if empty or failed)
    local dns_response
    if ! dns_response=$(cf_api_paginated "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records"); then
        echo "  ⚠️  Skipping $domain: DNS records API failed" >&2
        ((ERRORS++)) || true
        return
    fi
    local dns_count
    dns_count=$(echo "$dns_response" | jq '.result | length' 2>/dev/null) || dns_count=0
    if [[ "$dns_count" -eq 0 ]]; then
        echo "  ⚠️  Skipping $domain: no DNS records (partial setup zone?)" >&2
        ((ERRORS++)) || true
        return
    fi
    echo "$dns_response" > "$folder/DNS.txt"
    echo "  ✓ DNS.txt ($dns_count records)"

    # IP Access Rules (paginated, max per_page=100)
    local ip_rules_response
    rm -f "$CF_SKIP_FILE"
    if ip_rules_response=$(cf_api_paginated "https://api.cloudflare.com/client/v4/zones/$zone_id/firewall/access_rules/rules" 100); then
        write_response "$ip_rules_response" "$folder/IP-Access-Rules.txt" "IP-Access-Rules.txt" || true
    else
        local reason
        reason=$(cat "$CF_SKIP_FILE" 2>/dev/null)
        echo "  ⊘ Skipped IP-Access-Rules.txt (${reason:-API error})"
    fi

    # Snippets
    local snippets
    if snippets=$(cf_api "https://api.cloudflare.com/client/v4/zones/$zone_id/snippets"); then
        write_response "$snippets" "$folder/Snippets.txt" "Snippets.txt" || true

        local snippet_rules
        if snippet_rules=$(cf_api "https://api.cloudflare.com/client/v4/zones/$zone_id/snippets/snippet_rules"); then
            write_response "$snippet_rules" "$folder/Snippet-Rules.txt" "Snippet-Rules.txt" || true
        fi

        while read -r snippet_name; do
            [[ -z "$snippet_name" ]] && continue
            local safe_name
            safe_name=$(safe_filename "$snippet_name")
            local content http_code
            content=$(curl -s -w "\n%{http_code}" -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/snippets/$snippet_name/content" \
                "${CF_AUTH_ARGS[@]}") || true
            http_code="${content##*$'\n'}"
            content="${content%$'\n'*}"
            if [[ "$http_code" != "200" ]]; then
                echo "  ❌ Snippet content failed (HTTP $http_code): $snippet_name" >&2
                echo "$content" >&2
                ((ERRORS++)) || true
            elif [[ -z "$content" ]]; then
                echo "  ❌ Snippet content empty: $snippet_name" >&2
                ((ERRORS++)) || true
            else
                echo "$content" > "$folder/Snippet-$safe_name.js"
                echo "  ✓ Snippet-$safe_name.js"
            fi
        done < <(echo "$snippets" | jq -r '.result[]?.snippet_name // empty')
    fi

    echo "✓ Backup completed for $domain"
}

# --- Account backup ---
backup_account() {
    local account_id=$1
    local folder="account/$BATCH_DATE $BATCH_TIME"

    echo "Backing up account-level resources (Account ID: $account_id)"
    mkdir -p "$folder"

    # IP Lists
    local lists_response
    if lists_response=$(cf_api "https://api.cloudflare.com/client/v4/accounts/$account_id/rules/lists"); then
        write_response "$lists_response" "$folder/IP-Lists.txt" "IP-Lists.txt" || true

        local list_id list_name list_kind
        while IFS='|' read -r list_id list_kind list_name; do
            [[ -z "$list_id" ]] && continue
            local safe_name
            safe_name=$(safe_filename "$list_name")
            local items_response
            if items_response=$(cf_api_cursor "https://api.cloudflare.com/client/v4/accounts/$account_id/rules/lists/$list_id/items"); then
                write_response "$items_response" "$folder/List-Items-$list_kind-$safe_name.txt" "List-Items-$list_kind-$safe_name.txt" || true
            fi
        done < <(echo "$lists_response" | jq -r '.result[]? | .id + "|" + .kind + "|" + .name')
    fi

    # Bulk Redirect Rules
    local redirect_rulesets
    if redirect_rulesets=$(cf_api "https://api.cloudflare.com/client/v4/accounts/$account_id/rulesets?phase=http_request_redirect"); then
        write_response "$redirect_rulesets" "$folder/Bulk-Redirect-Rules.txt" "Bulk-Redirect-Rules.txt" || true
    fi

    # Load Balancer Pools
    local pools_response
    if pools_response=$(cf_api "https://api.cloudflare.com/client/v4/accounts/$account_id/load_balancers/pools"); then
        write_response "$pools_response" "$folder/Load-Balancer-Pools.txt" "Load-Balancer-Pools.txt" || true
    fi

    # Workers KV Namespaces
    local kv_namespaces
    if kv_namespaces=$(cf_api "https://api.cloudflare.com/client/v4/accounts/$account_id/storage/kv/namespaces?per_page=100"); then
        write_response "$kv_namespaces" "$folder/KV-Namespaces.txt" "KV-Namespaces.txt" || true

        local ns_id ns_title
        while IFS='|' read -r ns_id ns_title; do
            [[ -z "$ns_id" ]] && continue
            local safe_title
            safe_title=$(safe_filename "$ns_title")
            mkdir -p "$folder/KV-$safe_title"

            local cursor=""
            local page=1
            while true; do
                local url="https://api.cloudflare.com/client/v4/accounts/$account_id/storage/kv/namespaces/$ns_id/keys?limit=1000"
                [[ -n "$cursor" ]] && url="$url&cursor=$cursor"

                local keys_response
                if ! keys_response=$(cf_api "$url"); then
                    break
                fi
                echo "$keys_response" > "$folder/KV-$safe_title/keys-page-$page.txt"

                local key_name
                while read -r key_name; do
                    [[ -z "$key_name" ]] && continue
                    local encoded_key
                    encoded_key=$(printf '%s' "$key_name" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''))" 2>/dev/null || echo "$key_name")
                    local safe_file
                    safe_file=$(safe_filename "$key_name")
                    local kv_http_code
                    kv_http_code=$(curl -s -o "$folder/KV-$safe_title/value-$safe_file.txt" -w "%{http_code}" \
                        -X GET "https://api.cloudflare.com/client/v4/accounts/$account_id/storage/kv/namespaces/$ns_id/values/$encoded_key" \
                        "${CF_AUTH_ARGS[@]}") || true
                    if [[ "$kv_http_code" != "200" ]]; then
                        echo "  ❌ KV value failed (HTTP $kv_http_code): $ns_title/$key_name" >&2
                        cat "$folder/KV-$safe_title/value-$safe_file.txt" >&2
                        rm -f "$folder/KV-$safe_title/value-$safe_file.txt"
                        ((ERRORS++)) || true
                    fi
                done < <(echo "$keys_response" | jq -r '.result[]?.name // empty')

                cursor=$(echo "$keys_response" | jq -r '.result_info.cursor // empty')
                [[ -z "$cursor" ]] && break
                page=$((page + 1))
                [[ $page -gt 100 ]] && break
            done
            echo "  ✓ KV namespace: $ns_title"
        done < <(echo "$kv_namespaces" | jq -r '.result[]? | .id + "|" + .title')
    fi

    echo "✓ Account backup completed"
}

# --- Main ---
echo "Starting Cloudflare backup..."

# Collect zone IDs and unique account IDs (single API call per domain)
UNIQUE_ACCOUNT_IDS=()
DOMAIN_ZONE_IDS=()  # parallel array with DOMAINS

for domain in "${DOMAINS[@]}"; do
    # Single API call to get both zone ID and account ID
    response=$(cf_api "https://api.cloudflare.com/client/v4/zones?name=$domain") || {
        DOMAIN_ZONE_IDS+=("")
        continue
    }
    zone_id=$(echo "$response" | jq -r '.result[0].id // empty')
    if [[ -z "$zone_id" ]]; then
        echo "❌ Domain not found: $domain"
        ((ERRORS++)) || true
        DOMAIN_ZONE_IDS+=("")
        continue
    fi
    DOMAIN_ZONE_IDS+=("$zone_id")

    account_id=$(echo "$response" | jq -r '.result[0].account.id // empty')
    if [[ -n "$account_id" ]]; then
        found=0
        for existing in "${UNIQUE_ACCOUNT_IDS[@]:-}"; do
            [[ "$existing" == "$account_id" ]] && found=1 && break
        done
        [[ $found -eq 0 ]] && UNIQUE_ACCOUNT_IDS+=("$account_id")
    fi
done

# Backup account-level resources
for account_id in "${UNIQUE_ACCOUNT_IDS[@]:-}"; do
    [[ -z "$account_id" ]] && continue
    backup_account "$account_id"
done

# Backup zones
for i in "${!DOMAINS[@]}"; do
    zone_id="${DOMAIN_ZONE_IDS[$i]}"
    [[ -z "$zone_id" ]] && continue
    backup_zone "$zone_id" "${DOMAINS[$i]}"
done

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo "✅ All backups completed successfully!"
else
    echo "⚠️  Backups completed with $ERRORS error(s). Check messages above."
fi
