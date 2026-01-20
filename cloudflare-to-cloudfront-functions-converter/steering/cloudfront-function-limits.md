# CloudFront Function Limits and Constraints

## Size Limits

- **Maximum function size**: 10KB (not adjustable)
- **Recommended target**: <8KB to leave room for future customization
- **Calculation**: Total character count of JavaScript code

## Memory Limits

- **Maximum memory**: 2MB
- **Implication**: Avoid loading large data structures in memory
- **Best practice**: Use CloudFront Key Value Store for large datasets

## Execution Time

- **Approximate limit**: ~1ms
- **Implication**: Cannot process complex regex or extensive computations
- **Best practice**: Optimize for CPU efficiency

## Async Operations

**DO NOT use:**
- `Promise.all()`
- `Promise.any()`
- Promise chain methods (`then`, `catch`)

**DO use:**
- Sequential `await` statements
- `try...catch` blocks for error handling

Example:
```javascript
// ❌ BAD - Uses Promise.all()
const [value1, value2] = await Promise.all([
    kvsHandle.get('key1'),
    kvsHandle.get('key2')
]);

// ✅ GOOD - Sequential await
let value1, value2;
try {
    value1 = await kvsHandle.get('key1');
} catch (err) {
    console.log('key1 not found');
}
try {
    value2 = await kvsHandle.get('key2');
} catch (err) {
    console.log('key2 not found');
}
```

## CPU Optimization

### Pattern Optimization Strategy

**CRITICAL**: Only optimize simple patterns. Preserve user's regex from `matches` operator.

**Decision tree for each Cloudflare expression:**

```
Cloudflare operator?
├─ `eq "value"` → Convert to: `===`
├─ `ne "value"` → Convert to: `!==`
├─ `contains "substring"` → Convert to: `includes()`
├─ `wildcard r"*.domain"` → Convert to: `endsWith('.domain')`
├─ `wildcard r"/prefix/*"` → Convert to: `startsWith('/prefix/')`
├─ `strict wildcard` → Same as wildcard but case-sensitive
├─ `matches r"regex"` → Keep original regex (user explicitly chose regex)
├─ `starts_with(field, "prefix")` → Convert to: `startsWith()`
├─ `ends_with(field, "suffix")` → Convert to: `endsWith()`
└─ `in { ... }` → Convert to: `[...].includes()`
```

### Safe Conversions

**1. Exact match (`eq`/`ne`)**
```javascript
// Cloudflare: http.host eq "example.com"
if (host === 'example.com') { }

// Cloudflare: http.host ne "example.com"
if (host !== 'example.com') { }
```

**2. Contains (`contains`)**
```javascript
// Cloudflare: http.user_agent contains "Mobi"
const ua = request.headers['user-agent'];
if (ua && ua.value.includes('Mobi')) { }
```

**3. Simple wildcard suffix (`wildcard r"*.domain"`)**
```javascript
// Cloudflare: http.host wildcard r"*.example.com"
if (host.endsWith('.example.com')) { }
```

**4. Simple wildcard prefix (`wildcard r"/path/*"`)**
```javascript
// Cloudflare: http.request.uri.path wildcard r"/api/*"
if (uri.startsWith('/api/')) { }
```

**5. Functions (`starts_with`, `ends_with`)**
```javascript
// Cloudflare: starts_with(http.request.uri.path, "/api/")
if (uri.startsWith('/api/')) { }

// Cloudflare: ends_with(http.request.uri.path, ".html")
if (uri.endsWith('.html')) { }
```

**6. In set (`in { ... }`)**
```javascript
// Cloudflare: http.host in {"a.com" "b.com" "c.com"}
if (['a.com', 'b.com', 'c.com'].includes(host)) { }
```

### Preserve Original Regex

**Do NOT optimize - keep as regex:**

```javascript
// Cloudflare: http.request.uri.path matches r"^/products/([0-9]+)/([a-z\-]+)$"
// Keep as:
if (/^\/products\/([0-9]+)\/([a-z\-]+)$/.test(uri)) { }

// Cloudflare: http.request.uri.path matches "^/blog/([0-9]{4})/([0-9]{2})/([a-z0-9\\-]+)$"
// Keep as:
if (/^\/blog\/([0-9]{4})\/([0-9]{2})\/([a-z0-9\-]+)$/.test(uri)) { }
```

**Why preserve `matches` operator?**
- User explicitly chose regex for complex pattern matching
- Changing to string methods would alter matching logic
- CloudFront Functions support regex - use it when needed
- The `matches` operator requires Business/Enterprise plan, indicating intentional use

## Runtime Requirements

- **Must use**: JavaScript Runtime 2.0
- **Required import**: `import cf from 'cloudfront';`
- **Event types**: viewer-request or viewer-response

## Unsupported ES6+ Features

**CRITICAL**: CloudFront Functions Runtime 2.0 does NOT support these modern JavaScript features:

### ❌ Optional Chaining (`?.`)

```javascript
// ❌ BAD - Will cause FunctionExecutionError
const country = request.headers['cloudfront-viewer-country']?.value;
const ua = request.headers['user-agent']?.value || '';

// ✅ GOOD - Use conditional checks
const country = request.headers['cloudfront-viewer-country'] 
    ? request.headers['cloudfront-viewer-country'].value 
    : undefined;
const ua = request.headers['user-agent'] 
    ? request.headers['user-agent'].value 
    : '';
```

### ❌ Array Destructuring

```javascript
// ❌ BAD - Will cause FunctionExecutionError
const [status, preserveQs, target] = redirectData.split('|');

// ✅ GOOD - Use array indexing
const parts = redirectData.split('|');
const status = parts[0];
const preserveQs = parts[1];
const target = parts[2];
```

### ❌ Object Destructuring

```javascript
// ❌ BAD - Will cause FunctionExecutionError
const { value } = request.headers.host;

// ✅ GOOD - Direct property access
const value = request.headers.host.value;
```

### ✅ Supported ES6+ Features

These features ARE supported and can be used:
- `const` and `let` declarations
- Template literals (backticks)
- Arrow functions
- `async/await`
- `for...of` loops
- Spread operator in function calls (limited)

## Code Structure

```javascript
import cf from 'cloudfront';

// Initialize KVS if needed (can be at top level)
const kvsHandle = cf.kvs();

async function handler(event) {
    const request = event.request;
    
    // Your logic here
    
    return request; // or response for viewer-response
}
```

## Size Optimization Techniques

1. **Remove comments** in production version
2. **Shorten variable names** (but keep readable)
3. **Move large data to KVS** (country lists, redirect mappings)
4. **Avoid redundant code** (extract common logic)
5. **Use ternary operators** instead of if-else where appropriate

## Minification Example

Before (with comments):
```javascript
// Check if request is from EU country
const euCountries = ['AT', 'BE', 'BG', ...];
const countryHeader = request.headers['cloudfront-viewer-country'];
const country = countryHeader ? countryHeader.value : undefined;
if (euCountries.includes(country)) {
    // Add GDPR header
    request.headers['x-gdpr-required'] = { value: 'true' };
}
```

After (minified):
```javascript
const eu=['AT','BE','BG',...];
const ch=request.headers['cloudfront-viewer-country'];
const c=ch?ch.value:undefined;
if(eu.includes(c))request.headers['x-gdpr-required']={value:'true'};
```

## When to Use Key Value Store

Use KVS when:
- Data size >1KB
- Frequently updated data
- Large lists (countries, redirects, etc.)

Don't use KVS when:
- Data <500 bytes
- Simple logic
- Performance critical (KVS adds latency)
