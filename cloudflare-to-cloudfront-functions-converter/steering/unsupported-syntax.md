# CloudFront Functions Runtime 2.0 - Unsupported ES6+ Features

## Discovery Date
2026-01-01

## Background

AWS documentation states that CloudFront Functions Runtime 2.0 "supports some features of ES versions 6 through 12" but does **NOT** provide a comprehensive list of unsupported features. Through testing, we discovered critical ES6+ features that cause runtime errors.

## Confirmed Unsupported Features

### 1. Optional Chaining (`?.`)

**Status**: ❌ NOT SUPPORTED - Causes `FunctionExecutionError` at runtime

**AWS Documentation**: Not mentioned (neither supported nor unsupported)

**Test Evidence**: Confirmed through live testing on 2026-01-01

```javascript
// ❌ WRONG - Causes FunctionExecutionError
const country = request.headers['cloudfront-viewer-country']?.value;
const ua = request.headers['user-agent']?.value || '';

// ✅ CORRECT - Use conditional checks
const country = request.headers['cloudfront-viewer-country'] 
    ? request.headers['cloudfront-viewer-country'].value 
    : undefined;
const ua = request.headers['user-agent'] 
    ? request.headers['user-agent'].value 
    : '';
```

### 2. Array Destructuring

**Status**: ❌ NOT SUPPORTED - Causes `FunctionExecutionError` at runtime

**AWS Documentation**: Not mentioned (neither supported nor unsupported)

**Test Evidence**: Confirmed through live testing on 2026-01-01

```javascript
// ❌ WRONG - Causes FunctionExecutionError
const [status, preserveQs, target] = redirectData.split('|');

// ✅ CORRECT - Use array indexing
const parts = redirectData.split('|');
const status = parts[0];
const preserveQs = parts[1];
const target = parts[2];
```

### 3. Object Destructuring

**Status**: ❌ LIKELY NOT SUPPORTED (not tested, but assumed based on array destructuring)

**AWS Documentation**: Not mentioned (neither supported nor unsupported)

```javascript
// ❌ WRONG - Likely causes FunctionExecutionError
const { value } = request.headers.host;
const { host, uri } = request;

// ✅ CORRECT - Use direct property access
const value = request.headers.host.value;
const host = request.headers.host.value;
const uri = request.uri;
```

## Confirmed Supported ES6+ Features

Based on AWS documentation and testing:

### Core Features (Documented)
- ✅ `const` and `let` declarations (ES6)
- ✅ Template literals with interpolation (ES6): `` `redirect:${host}${uri}` ``
- ✅ Arrow functions (ES6): `(x) => x * 2`
- ✅ `async` and `await` (ES8)
- ✅ Rest parameter syntax (ES6): `function(...args)`

### String Methods (Documented)
- ✅ `String.prototype.startsWith()` (ES6)
- ✅ `String.prototype.endsWith()` (ES6)
- ✅ `String.prototype.includes()` (ES6)
- ✅ `String.prototype.repeat()` (ES6)
- ✅ `String.prototype.padStart()` (ES8)
- ✅ `String.prototype.padEnd()` (ES8)
- ✅ `String.prototype.replaceAll()` (ES12)

### Array Methods (Documented)
- ✅ `Array.prototype.find()` (ES6)
- ✅ `Array.prototype.findIndex()` (ES6)
- ✅ `Array.prototype.includes()` (ES7)

### Object Methods (Documented)
- ✅ `Object.assign()` (ES6)
- ✅ `Object.entries()` (ES8)
- ✅ `Object.values()` (ES8)

### Other Features (Documented)
- ✅ `for...of` loops (ES6)
- ✅ Exponentiation operator `**` (ES7)
- ✅ Numeric separators (ES12): `1_000_000`
- ✅ Named capture groups in regex (ES9)

## Why This Matters

**Critical Issue**: AWS documentation does not explicitly list unsupported ES6+ features. The statement "supports some features of ES versions 6 through 12" is vague and can lead to runtime errors.

**Impact**: 
- Code that passes validation during deployment can fail at runtime
- No syntax errors during function creation
- Errors only appear when function executes with real traffic
- Results in `FunctionExecutionError` and 503 responses to users

## Testing Methodology

1. **Optional Chaining Test**: Deployed function with `?.` syntax → FunctionExecutionError
2. **Array Destructuring Test**: Deployed function with `const [a,b,c] = array` → FunctionExecutionError
3. **Working Code Test**: Replaced with ES5-compatible syntax → Function executed successfully

## Recommendations for Code Generation

### DO NOT USE
- Optional chaining (`?.`)
- Nullish coalescing (`??`)
- Array destructuring (`const [a, b] = array`)
- Object destructuring (`const { prop } = obj`)
- Spread in object literals (`{ ...obj }`) - not tested but likely unsupported
- Default parameters with destructuring

### SAFE TO USE
- `const` and `let`
- Template literals
- Arrow functions
- `async/await`
- Traditional array indexing
- Ternary operators
- Logical operators (`&&`, `||`)
- String methods (startsWith, endsWith, includes)
- Array methods (find, findIndex, includes)

## Code Generation Rules

When generating CloudFront Functions:

1. **Always use conditional checks instead of optional chaining**
   ```javascript
   // Use: obj ? obj.prop : default
   // Not: obj?.prop ?? default
   ```

2. **Always use array indexing instead of destructuring**
   ```javascript
   // Use: const a = arr[0]; const b = arr[1];
   // Not: const [a, b] = arr;
   ```

3. **Always use direct property access**
   ```javascript
   // Use: const val = obj.prop;
   // Not: const { prop: val } = obj;
   ```

4. **Test with real traffic before full deployment**
   - Validation passes don't guarantee runtime success
   - Use test distributions or canary deployments

## AWS Documentation Reference

**Source**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html

**Quote**: "The CloudFront Functions JavaScript runtime environment is compliant with ECMAScript (ES) version 5.1 and also supports some features of ES versions 6 through 12."

**Gap**: Documentation lists supported features but does not list unsupported features, leading to trial-and-error discovery.

## Updated Skill Files

1. `/references/cloudfront-function-limits.md` - Added "Unsupported ES6+ Features" section
2. `SKILL.md` - Added "Code Generation Rules" section
3. `SKILL.md` - Updated "Code quality" guidelines
4. `SKILL.md` - Updated "Key constraints" list

## Conclusion

While AWS documentation claims ES6-12 support, critical modern JavaScript features like optional chaining and destructuring are **not supported**. Always use ES5-compatible syntax for critical operations to avoid runtime errors.
