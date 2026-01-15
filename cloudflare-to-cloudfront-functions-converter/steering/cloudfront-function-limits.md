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

### Avoid Complex Regex

For matching patterns like `*.example.com`:

```javascript
// ❌ BAD - Complex regex
if (/^.*\.example\.com$/.test(host)) { }

// ✅ GOOD - String method
if (host.endsWith('.example.com')) { }
```

### Optimize Wildcard Matching

For URL patterns like `https://*.example.com/path/*`:

Break into components:
1. Host: Use `endsWith('.example.com')`
2. URI path: Use `startsWith('/path/')`
3. Query string: Use `rawQueryString()` if needed

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
const country = request.headers['cloudfront-viewer-country']?.value;
if (euCountries.includes(country)) {
    // Add GDPR header
    request.headers['x-gdpr-required'] = { value: 'true' };
}
```

After (minified):
```javascript
const eu=['AT','BE','BG',...];
const c=request.headers['cloudfront-viewer-country']?.value;
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
