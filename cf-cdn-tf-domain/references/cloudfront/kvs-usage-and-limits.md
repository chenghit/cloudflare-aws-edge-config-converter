# CloudFront Key Value Store (KVS) Usage and Limits

## Overview

CloudFront Key Value Store allows you to store key-value pairs that can be accessed from CloudFront Functions. This is useful for:
- Large redirect mappings
- Country/continent lists
- Configuration data
- Dynamic content routing

## File Format

KVS data must be a UTF-8 encoded JSON file:

```json
{
  "data": [
    {
      "key": "key1",
      "value": "value1"
    },
    {
      "key": "key2",
      "value": "value2"
    }
  ]
}
```

## Limits

### File Limits
- **Maximum file size**: 5 MB
- **No duplicate keys**: Each key must be unique
- **Encoding**: UTF-8 only

### Individual Item Limits
- **Maximum key size**: 512 characters (512 bytes)
- **Maximum value size**: 1024 characters (1 KB)

### Store Limits
- **Maximum store size**: 5 MB total
- **Maximum KVS per function**: 1 (only a single Key Value Store can be associated with a function)
- **Maximum functions per KVS**: 10 (a single Key Value Store can be associated with up to 10 functions)

### Important Implications

Since only **one KVS can be associated with a function**, all key-value data must be consolidated into a **single JSON file**. This means:

- Bulk redirects
- Country-to-continent mappings
- EU country lists
- Any other configuration data

**Must all be combined into one KVS file** with unique keys.

## Key Naming Strategy

To avoid key collisions when combining multiple data types, use prefixes:

```json
{
  "data": [
    {"key": "redirect:/old-page", "value": "https://example.com/new-page"},
    {"key": "redirect:/legacy/product", "value": "https://example.com/products/item"},
    {"key": "continent:US", "value": "NA"},
    {"key": "continent:CN", "value": "AS"},
    {"key": "continent:GB", "value": "EU"},
    {"key": "eu:AT", "value": "true"},
    {"key": "eu:BE", "value": "true"}
  ]
}
```

## When to Use KVS

### ✅ Use KVS When:

1. **Large data sets** (>1KB)
   - Bulk redirect lists (hundreds of redirects)
   - Country-to-continent mappings
   - Large configuration tables

2. **Frequently updated data**
   - Data that changes without code deployment
   - A/B testing configurations
   - Feature flags

3. **Exceeding function size limit**
   - Function code approaching 10KB limit
   - Need to offload data to stay under limit

### ❌ Don't Use KVS When:

1. **Small data sets** (<500 bytes)
   - Simple logic
   - Few redirects (<10)
   - Small lists

2. **Performance critical paths**
   - KVS adds latency (~1ms per lookup)
   - Sequential lookups compound latency

3. **Static data that rarely changes**
   - Hardcoding in function may be faster
   - No deployment flexibility needed

## Example: Combined KVS File

### KVS JSON File (`key-value-store.json`)

```json
{
  "data": [
    {"key": "redirect:/old-page", "value": "https://example.com/new-page"},
    {"key": "redirect:/legacy/product", "value": "https://example.com/products/item"},
    {"key": "redirect:/blog/2020/post", "value": "https://blog.example.com/2020/post"},
    
    {"key": "continent:US", "value": "NA"},
    {"key": "continent:CA", "value": "NA"},
    {"key": "continent:MX", "value": "NA"},
    {"key": "continent:GB", "value": "EU"},
    {"key": "continent:DE", "value": "EU"},
    {"key": "continent:FR", "value": "EU"},
    {"key": "continent:CN", "value": "AS"},
    {"key": "continent:JP", "value": "AS"},
    {"key": "continent:IN", "value": "AS"},
    
    {"key": "eu:AT", "value": "true"},
    {"key": "eu:BE", "value": "true"},
    {"key": "eu:BG", "value": "true"},
    {"key": "eu:CY", "value": "true"}
  ]
}
```

### CloudFront Function Using Combined KVS

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    
    // Check for bulk redirect
    try {
        const destination = await kvsHandle.get(`redirect:${uri}`);
        return {
            statusCode: 301,
            statusDescription: 'Moved Permanently',
            headers: {
                'location': { value: destination }
            }
        };
    } catch (err) {
        // No redirect found, continue processing
    }
    
    // Add continent header
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            request.headers['x-continent'] = { value: continent };
        } catch (err) {
            // Country not in continent mapping
        }
        
        // Check if EU country
        try {
            await kvsHandle.get(`eu:${country}`);
            request.headers['x-gdpr-required'] = { value: 'true' };
        } catch (err) {
            // Not EU country
        }
    }
    
    return request;
}
```

## Example: Bulk Redirects Only

### KVS JSON File (`bulk-redirects.json`)

```json
{
  "data": [
    {
      "key": "/old-page",
      "value": "https://example.com/new-page"
    },
    {
      "key": "/legacy/product",
      "value": "https://example.com/products/item"
    },
    {
      "key": "/blog/2020/post",
      "value": "https://blog.example.com/2020/post"
    }
  ]
}
```

### CloudFront Function

```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    
    try {
        const destination = await kvsHandle.get(uri);
        
        return {
            statusCode: 301,
            statusDescription: 'Moved Permanently',
            headers: {
                'location': { value: destination }
            }
        };
    } catch (err) {
        // No redirect found, continue with original request
        return request;
    }
}
```

## Example: Country to Continent Mapping

**Strategy: Always use KVS**

Store country-to-continent mapping in KVS to reduce function size.

**KVS JSON File** (combined with other data):
```json
{
  "data": [
    {"key": "continent:US", "value": "NA"},
    {"key": "continent:CA", "value": "NA"},
    {"key": "continent:CN", "value": "AS"},
    {"key": "continent:GB", "value": "EU"}
  ]
}
```

**CloudFront Function**:
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            // Example: Redirect Asia users to Asia-specific page
            if (continent === 'AS' && uri === '/welcome') {
                return {
                    statusCode: 302,
                    headers: {
                        'location': { value: '/asia/welcome' }
                    }
                };
            }
        } catch (err) {
            // Country not in mapping, continue with default behavior
        }
    }
    
    return request;
}
```

**KVS JSON File** (combined with other data):
```json
{
  "data": [
    {"key": "continent:US", "value": "NA"},
    {"key": "continent:CA", "value": "NA"},
    {"key": "continent:GB", "value": "EU"}
  ]
}
```

**CloudFront Function**:
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    if (country) {
        try {
            const continent = await kvsHandle.get(`continent:${country}`);
            // Example: Redirect Asia users to Asia-specific page
            if (continent === 'AS' && uri === '/welcome') {
                return {
                    statusCode: 302,
                    headers: {
                        'location': { value: '/asia/welcome' }
                    }
                };
            }
        } catch (err) {
            // Country not in mapping, continue with default behavior
        }
    }
    
    return request;
}
```

## Example: EU Country Check

**Strategy: Always use KVS**

Store EU country flags in KVS with prefix `eu:`. This keeps function size small.

**KVS JSON File** (combined with other data):
```json
{
  "data": [
    {"key": "eu:AT", "value": "1"},
    {"key": "eu:BE", "value": "1"},
    {"key": "eu:BG", "value": "1"}
  ]
}
```

**CloudFront Function**:
```javascript
import cf from 'cloudfront';

const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    const uri = request.uri;
    const country = request.headers['cloudfront-viewer-country'] ? request.headers['cloudfront-viewer-country'].value : undefined;
    
    let isEU = false;
    if (country) {
        try {
            await kvsHandle.get(`eu:${country}`);
            isEU = true;
        } catch (err) {
            // Not EU country, isEU remains false
        }
    }
    
    // Example: Redirect EU users to EU-specific page
    if (isEU && uri === '/welcome') {
        return {
            statusCode: 302,
            headers: {
                'location': { value: '/eu/welcome' }
            }
        };
    }
    
    return request;
}
```

## Initial Deployment

**CRITICAL**: The `import-source` parameter (importing from S3) can **ONLY** be used when creating a new KVS. It **CANNOT** be used to update existing KVS data.

### Step 1: Prepare KVS JSON File

Save your data in the required format:

```json
{
  "data": [
    {"key": "key1", "value": "value1"},
    {"key": "key2", "value": "value2"}
  ]
}
```

### Step 2: Upload JSON to S3

The S3 bucket must be in the same AWS account as CloudFront.

```bash
aws s3 cp key-value-store.json s3://your-bucket/key-value-store.json
```

### Step 3: Create KVS with S3 Import

**Using AWS CLI**:
```bash
aws cloudfront create-key-value-store \
    --name my-kvs \
    --comment "Description" \
    --import-source SourceType=S3,SourceARN=arn:aws:s3:::your-bucket/key-value-store.json
```

**Using AWS Console**:
1. Navigate to **CloudFront** → **Key Value Stores**
2. Click **Create key value store**
3. Enter name and description
4. Under **Import source**, select **S3**
5. Enter S3 URI: `s3://your-bucket/key-value-store.json`
6. Click **Create** and wait for status: **Ready**

### Step 4: Associate KVS with Function

This is done when creating or updating the CloudFront Function configuration (see function deployment).

---

## Updating KVS Data

**KVS does NOT support bulk re-import or full replacement after creation.**

To update KVS data, you must add/edit/delete keys individually using:
- AWS Console (manual key management)
- AWS CLI (`update-keys` command)
- CloudFront API

For detailed update procedures, refer to AWS documentation:
- [Working with Key Value Stores](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/kvs-with-functions.html)
- [UpdateKeys API Reference](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_UpdateKeys.html)

## Best Practices

### 1. Sequential Lookups

```javascript
// ❌ BAD - Uses Promise.all()
const [val1, val2] = await Promise.all([
    kvsHandle.get('key1'),
    kvsHandle.get('key2')
]);

// ✅ GOOD - Sequential await
let val1, val2;
try {
    val1 = await kvsHandle.get('key1');
} catch (err) {
    // Key not found
}
try {
    val2 = await kvsHandle.get('key2');
} catch (err) {
    // Key not found
}
```

### 2. Error Handling

Always wrap KVS operations in `try...catch`:

```javascript
try {
    const value = await kvsHandle.get(key);
    // Use value
} catch (err) {
    // Handle missing key
}
```

### 3. Key Design with Prefixes

Use meaningful prefixes to organize different data types:

```javascript
// ✅ GOOD - Clear prefixes for different data types
"redirect:/old-page"
"continent:US"
"eu:AT"
"config:feature-flag"

// ❌ BAD - No organization, potential collisions
"/old-page"  // Could conflict with continent code
"US"         // Ambiguous - redirect or continent?
"AT"         // EU country or something else?
```

### 4. Value Size Optimization

Keep values under 1KB. For larger data, use references:

```javascript
// ❌ BAD - Large value
{
  "key": "product-123",
  "value": "{\"name\":\"Product\",\"description\":\"Long description...\",\"specs\":{...}}"
}

// ✅ GOOD - Concise value
{
  "key": "redirect:/product-123",
  "value": "https://example.com/products/123"
}
```

## When to Use KVS

**Always use KVS for:**
- Bulk redirects (any number)
- Continent mappings (any number of countries)
- EU country checks (all 27 countries)

**Reason**: Reduces function size, easier to update, consistent approach.

## Common Use Cases

| Use Case | Approach | Reason |
|----------|----------|--------|
| Bulk redirects (any number) | KVS | Efficient lookup, easy updates, scalable |
| Continent mapping | KVS | Reduces function size, complete coverage |
| EU country check | KVS | Reduces function size, consistent approach |

## Output Strategy for This Skill

This skill will generate:
1. **One CloudFront Function JS file** (`viewer-request-function.js`)
2. **One KVS JSON file** (if needed) (`key-value-store.json`)

All KVS data (redirects, continent mappings, EU countries, etc.) will be **consolidated into a single JSON file** using prefix-based key naming to avoid collisions.
