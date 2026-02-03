# Power 3-11 Architecture Design: Cloudflare to CloudFront Migration

**Version:** 2.0  
**Last Updated:** 2026-01-31

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Overview](#architecture-overview)
3. [Power 3: cloudflare-cdn-config-analyzer](#power-3-cloudflare-cdn-config-analyzer)
4. [Power 4: cloudfront-implementation-planner](#power-4-cloudfront-implementation-planner)
5. [Power 5: implementation-plan-validator](#power-5-implementation-plan-validator)
6. [Power 7: cloudfront-migration-orchestrator](#power-6-cloudfront-migration-orchestrator)
7. [Converter Powers (7-11)](#converter-powers-7-11)
8. [Complete Workflow](#complete-workflow)
9. [Key Design Decisions](#key-design-decisions)
10. [Implementation Notes](#implementation-notes)
11. [Appendix](#appendix)

---

## Overview

This document describes the architecture design for migrating Cloudflare CDN configurations to AWS CloudFront using a multi-skill approach.

### Key Design Principles

- ✅ **Separation of concerns** - Analyzer (parse), Planner (decide), Orchestrator (assign)
- ✅ **Implementation-based task assignment** - Assign tasks based on CloudFront implementation method (not Cloudflare rule type)
- ✅ **Functions first, then configuration** - Convert CloudFront Functions and Lambda@Edge first, then generate Terraform configuration
- ✅ **Separate sessions** - Execute each skill in separate Kiro CLI sessions to avoid context pollution
- ✅ **Stateless design** - Use Markdown files for state transfer between skills
- ✅ **Cost awareness** - Mark high-cost solutions (Viewer Lambda@Edge) as non-convertible

### Why This Architecture?

**Problem:** Cloudflare and CloudFront have fundamentally different architectures:
- **Cloudflare:** Zone-level rules with flexible Match-Action patterns
- **CloudFront:** Distribution-level configuration with Cache Behaviors as the core concept

**Solution:** Multi-stage conversion with human-in-the-loop decision making:
1. **Analyze** - Parse Cloudflare config, group by hostname, identify decision points
2. **Decide** - User provides business context and cost acceptance
3. **Plan** - Determine CloudFront implementation methods based on config + decisions
4. **Validate** - Verify implementation plan correctness (critical: wrong plan = wrong converters)
5. **Orchestrate** - Generate task assignments for converter powers
6. **Convert** - Execute specialized converters in separate sessions
7. **Deploy** - Apply Terraform configuration

### Why Group Rules by Proxied DNS Record?

**Critical Design Decision:** Power 3 organizes all rules by proxied DNS record (domain name). This is essential for three reasons:

#### 1. CloudFront Architecture Alignment
- **One proxied DNS record = One CloudFront Distribution**
- Each Distribution is an independent configuration unit with its own:
  - Origin configuration
  - Cache Behaviors
  - Policies (Cache, Origin Request, Response Headers)
  - Function/Lambda associations
  - TLS certificate

#### 2. Clear Task Assignment
- Power 4 generates separate task files for each domain
- Power 9 generates separate Terraform resources for each Distribution
- Users can review and deploy configurations domain by domain

#### 3. CloudFront Function Size Limit (10KB)
**This is a critical technical constraint:**

- CloudFront Functions have a **hard 10KB size limit**
- If all domains share one function, it may exceed 10KB even when minified
- By grouping rules by domain, we can split into multiple functions:

**Without splitting (all domains in one function):**
```javascript
// One giant viewer-request function for all domains
function handler(event) {
  // example.com: 20 rules
  // api.example.com: 15 rules  
  // cdn.example.com: 18 rules
  // Total: May exceed 10KB! ❌
}
```

**With splitting (one function per domain):**
```javascript
// functions/viewer-request-example-com.js (3KB)
function handler(event) {
  // Only example.com's 20 rules
}

// functions/viewer-request-api-example-com.js (2.5KB)
function handler(event) {
  // Only api.example.com's 15 rules
}

// Each stays within 10KB limit! ✅
```

**Benefits of domain-based splitting:**

| Aspect | Single Function (All Domains) | Split by Domain |
|--------|------------------------------|-----------------|
| Function Size | May exceed 10KB ❌ | Each < 10KB ✅ |
| Deployment Risk | One function affects all domains | Independent deployment |
| Debugging | Hard to isolate issues | Clear domain-specific logic |
| Performance | Executes unnecessary checks | Only relevant logic runs |

**Note:** Lambda@Edge doesn't have strict size limits (50MB uncompressed, 1MB compressed), but domain-based splitting still provides benefits for clarity, independent deployment, and debugging.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│              Power 3: Analyzer (Parse & Group)              │
│  Input: Cloudflare configs → Output: Hostname-based summary│
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│         Power 4: Planner (Implementation Decision)          │
│  Input: Config summary → Output: Implementation plan       │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    User fills decisions
                              ↓
┌─────────────────────────────────────────────────────────────┐
│            Power 7: Orchestrator (Task Assignment)          │
│  Input: Plan + Decisions → Output: Task assignments        │
└─────────────────────────────────────────────────────────────┘
                              ↓
              ┌───────────────┴───────────────┐
              ↓                               ↓
┌─────────────────────────┐   ┌─────────────────────────┐
│ Power 8: Viewer Request │   │ Power 9: Viewer Response│
│   CloudFront Function   │   │   CloudFront Function   │
└─────────────────────────┘   └─────────────────────────┘
              ↓                               ↓
┌─────────────────────────┐   ┌─────────────────────────┐
│ Power 10: Origin Request │   │ Power 11: Origin Response│
│      Lambda@Edge        │   │      Lambda@Edge        │
└─────────────────────────┘   └─────────────────────────┘
              ↓                               ↓
              └───────────────┬───────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│         Power 11: CloudFront Config Generator               │
│  Input: Task + Functions + Lambda → Output: Terraform      │
└─────────────────────────────────────────────────────────────┘
```

**Note:** Viewer Request/Response Lambda@Edge are marked as **non-convertible** due to high cost (10-100x more expensive than Origin Lambda).

---

## Power 3: cloudflare-cdn-config-analyzer

### Responsibility
Parse Cloudflare CDN configurations and group rules by proxied DNS records (hostnames).

**Key Point:** This power does NOT make implementation decisions. It only parses and organizes Cloudflare configurations.

### Trigger Keywords
- `analyze cloudflare cdn config`
- `analyze cloudflare cdn configuration`

### Input Files
Cloudflare configuration files (all CDN-related):
- `DNS.txt`
- `Cache-Rules.txt`
- `Origin-Rules.txt`
- `Configuration-Rules.txt`
- `Redirect-Rules.txt`
- `URL-Rewrite-Rules.txt`
- `Request-Header-Transform.txt`
- `Response-Header-Transform.txt`
- `Compression-Rules.txt`
- `Custom-Error-Rules.txt`
- `SaaS-Fallback-Origin.txt`

### Output Files

#### `hostname-based-config-summary.md`
Configuration summary grouped by proxied DNS records.

**Structure:**
```markdown
# Cloudflare CDN Configuration Summary

## Summary
- Total Proxied DNS Records: 3
- Total Rules: 45

## DNS Record: example.com
- Type: CNAME
- Value: origin.example.com
- Proxied: Yes
- Total Rules: 15

### Cache Rules (5 rules)
| Rule ID | Priority | Match Expression | Action | Settings |
|---------|----------|------------------|--------|----------|
| cache-1 | 1 | `http.request.uri.path matches "^/api/.*"` | Set cache TTL | TTL: 0s |
| cache-2 | 2 | `http.request.uri.path matches ".*\\.jpg$"` | Set cache TTL | TTL: 86400s |

### Origin Rules (3 rules)
| Rule ID | Priority | Match Expression | Action | Settings |
|---------|----------|------------------|--------|----------|
| origin-1 | 1 | `http.request.uri.path matches "^/api/.*"` | Override origin | Host: api-backend.example.com |

### Redirect Rules (2 rules)
| Rule ID | Priority | Match Expression | Target URL | Status Code |
|---------|----------|------------------|------------|-------------|
| redirect-1 | 1 | `http.request.uri.path eq "/old"` | `/new` | 301 |

### URL Rewrite Rules (2 rules)
| Rule ID | Priority | Match Expression | Rewrite Action |
|---------|----------|------------------|----------------|
| rewrite-1 | 1 | `http.request.uri.path matches "^/api/v1/(.*)"` | `/v2/$1` |

### Request Header Transform Rules (2 rules)
| Rule ID | Priority | Match Expression | Header Action |
|---------|----------|------------------|---------------|
| header-1 | 1 | `http.request.uri.path matches "^/api/.*"` | Set `X-API-Version: 2.0` |

### Response Header Transform Rules (1 rule)
| Rule ID | Priority | Match Expression | Header Action |
|---------|----------|------------------|---------------|
| resp-header-1 | 1 | `true` | Set `X-Frame-Options: DENY` |

---

## DNS Record: api.example.com
- Type: A
- Value: 203.0.113.10
- Proxied: Yes
- Total Rules: 10

[Similar structure...]

---

## Global Rules (no http.host match)
These rules may apply to multiple DNS records. User decision required for assignment.

### Cache Rules (2 rules)
[Similar structure...]
```

**Key Characteristics:**
- Pure data extraction, no implementation decisions
- Organized by hostname for CloudFront Distribution alignment
- Preserves all Cloudflare rule details
- Identifies global rules that need user assignment

---

## Power 4: cloudfront-implementation-planner

### Responsibility
Determine CloudFront implementation methods for each Cloudflare rule based on technical requirements and constraints.

**Key Point:** This power makes technical decisions about HOW to implement each rule in CloudFront, but does NOT make business/cost decisions (that's for users).

### Trigger Keywords
- `plan cloudfront implementation`
- `determine cloudfront implementation methods`

### Input Files
- `hostname-based-config-summary.md` (from Power 3)

### Output Files

#### 1. `implementation-plan.md`
**Core output**: Maps each rule to CloudFront implementation method.

**Structure:**
```markdown
# CloudFront Implementation Plan

## DNS Record: example.com

### Rules Requiring Viewer Request CloudFront Function
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| redirect-1 | Redirect Rule | Redirect `/old` to `/new` | Simple redirect logic, no external data needed |
| header-1 | Request Header Transform | Add `X-API-Version: 2.0` | Simple header manipulation |

**Estimated Function Size:** ~2KB  
**Complexity:** Low  
**Note:** This domain's rules will be in a separate function file (`viewer-request-example-com.js`) to stay within the 10KB limit.

---

### Rules Requiring Viewer Response CloudFront Function
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| resp-header-1 | Response Header Transform | Add `X-Frame-Options: DENY` | Simple response header manipulation |

**Estimated Function Size:** ~1KB  
**Complexity:** Low  
**Note:** This domain's rules will be in a separate function file (`viewer-response-example-com.js`).

---

### Rules Requiring Origin Request Lambda@Edge
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| origin-1 | Origin Rule | Dynamic origin selection based on path | Need to modify origin before cache lookup |
| rewrite-1 | URL Rewrite Rule | Complex regex pattern `/api/v1/(.*)` → `/v2/$1` | Regex complexity exceeds CloudFront Function limits |

**Estimated Lambda Size:** ~5KB  
**Complexity:** Medium  
**Cost Impact:** Moderate (runs on cache miss only, ~10-30% of requests)  
**Note:** Lambda@Edge doesn't have strict size limits, but domain-based splitting provides clarity and independent deployment.

---

### Rules Requiring Origin Response Lambda@Edge
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| error-1 | Custom Error Rule | Custom error page with dynamic content | Need to generate response body |

**Estimated Lambda Size:** ~3KB  
**Complexity:** Low  
**Cost Impact:** Moderate (runs on cache miss only, ~10-30% of requests)

---

### Rules Requiring CloudFront Configuration/Policy
| Rule ID | Original Type | Rule Summary | Implementation |
|---------|---------------|--------------|----------------|
| cache-1 | Cache Rule | Cache `/api/*` with TTL 0s | Cache Behavior (path: `/api/*`) + Cache Policy (TTL: 0s) |
| cache-2 | Cache Rule | Cache `*.jpg` for 1 day | Cache Behavior (path: `*.jpg`) + Cache Policy (TTL: 86400s) |

**Configuration Complexity:** Low

---

### Rules Requiring Viewer Lambda@Edge (High Cost - Non-Convertible)
| Rule ID | Original Type | Rule Summary | Why Viewer Lambda Needed | Estimated Cost Impact |
|---------|---------------|--------------|--------------------------|----------------------|
| auth-1 | Custom Rule | Real-time JWT validation on every request | Must run on every request including cache hits | **CRITICAL: $50-500 per million requests** |

⚠️ **WARNING:** These rules require Viewer Request/Response Lambda@Edge, which runs on EVERY request including cache hits. This is **10-100x more expensive** than Origin Request/Response Lambda.

**Cost Comparison:**
| Lambda Type | Execution Frequency | Relative Cost | Typical Use Case |
|-------------|-------------------|---------------|------------------|
| Viewer Request Lambda | Every request | 100x | Rarely recommended |
| Origin Request Lambda | Cache miss only | 10x | Common |
| Origin Response Lambda | Cache miss only | 10x | Common |

---

## DNS Record: api.example.com
[Similar structure...]
```

#### 2. `user-decisions-template.md`
Template for users to make business/cost decisions.

**Structure:**
```markdown
# User Decisions Required

## High-Cost Rules Requiring Approval

### DNS Record: example.com

#### Rule: auth-1 (Viewer Request Lambda@Edge)
- **Description:** Real-time JWT validation on every request
- **Cost Impact:** $50-500 per million requests (100x more expensive than Origin Lambda)
- **Alternative:** Move authentication to origin or use CloudFront signed URLs
- **Your Decision:** [ ] Proceed with Viewer Lambda (accept high cost) / [ ] Use alternative approach / [ ] Skip this rule

---

## Global Rules Assignment

### Rule: cache-global-1
- **Description:** Cache all static assets for 1 day
- **Applies To:** (Select one or more)
  - [ ] example.com
  - [ ] api.example.com
  - [ ] cdn.example.com

---

[Additional decisions...]
```

### Decision Logic

**Implementation Method Selection Criteria:**

1. **CloudFront Function (Viewer Request/Response)**
   - Simple logic (< 10KB code size)
   - No external dependencies
   - Fast execution (< 1ms)
   - Examples: Simple redirects, header manipulation, URL rewrites

2. **Lambda@Edge (Origin Request/Response)**
   - Complex logic or external dependencies
   - Regex patterns too complex for CloudFront Function
   - Need to access/modify origin
   - Examples: Dynamic origin selection, complex transformations

3. **CloudFront Configuration/Policy**
   - Static configuration (no dynamic logic)
   - Examples: Cache TTL, compression, CORS headers

4. **Viewer Lambda@Edge (Non-Convertible)**
   - Must run on EVERY request (including cache hits)
   - Examples: Real-time authentication, A/B testing on every request
   - **Marked as non-convertible due to extreme cost**

---

## Power 7: cloudfront-migration-orchestrator

### Responsibility
Generate task assignment files for converter powers based on implementation plan and user decisions.
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| header-5 | Response Header Transform | Add security headers to response | Simple response header manipulation |

**Estimated Function Size:** ~1KB  
**Complexity:** Low  
**Note:** This domain's rules will be in a separate function file (`viewer-response-example-com.js`).

---

### Rules Requiring Origin Request Lambda@Edge
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| origin-3 | Origin Rule | Dynamic origin selection based on cookie | Complex logic, need cookie access |
| cache-8 | Cache Rule | Complex regex pattern matching | Regex too complex for CloudFront Function |

**Estimated Lambda Size:** ~5KB  
**Complexity:** Medium  
**Cost Impact:** Moderate (runs on cache miss only, ~10-30% of requests)  
**Note:** Lambda@Edge doesn't have strict size limits, but domain-based splitting provides clarity and independent deployment.

---

### Rules Requiring Origin Response Lambda@Edge
| Rule ID | Original Type | Rule Summary | Reason |
|---------|---------------|--------------|--------|
| header-7 | Response Header Transform | Add CORS headers based on origin | Need to modify response headers dynamically |
| error-2 | Custom Error Rule | Custom error page with dynamic content | Need to generate response body |

**Estimated Lambda Size:** ~3KB  
**Complexity:** Low  
**Cost Impact:** Moderate (runs on cache miss only, ~10-30% of requests)

---

### Rules Requiring CloudFront Configuration/Policy
| Rule ID | Original Type | Rule Summary | Implementation |
|---------|---------------|--------------|----------------|
| cache-1 | Cache Rule | Cache all `*.jpg` for 1 day | Cache Behavior (path: `*.jpg`) + Cache Policy (TTL: 86400s) |
| cache-2 | Cache Rule | Include query string `version` in cache key | Cache Policy (query string: `version`) |
| header-2 | Response Header Transform | Add `X-Frame-Options: DENY` | Response Headers Policy |
| compress-1 | Compression Rule | Enable Gzip for text/* | Cache Policy (compression: Gzip) |

**Configuration Complexity:** Low

---

### Rules Requiring Viewer Lambda@Edge (High Cost - Non-Convertible)
| Rule ID | Original Type | Rule Summary | Why Viewer Lambda Needed | Estimated Cost Impact |
|---------|---------------|--------------|--------------------------|----------------------|
| auth-1 | Custom Rule | Real-time JWT validation on every request | Must run on every request including cache hits | **CRITICAL: $50-500 per million requests** |

⚠️ **WARNING:** These rules require Viewer Request/Response Lambda@Edge, which runs on EVERY request including cache hits. This is **10-100x more expensive** than Origin Request/Response Lambda.

**Cost Comparison:**
| Lambda Type | Execution Frequency | Relative Cost | Typical Use Case |
|-------------|-------------------|---------------|------------------|
| Viewer Request Lambda | Every request | 100x | Rarely recommended |
| Origin Request Lambda | Cache miss only | 10x | Common |
| Origin Response Lambda | Cache miss only | 10x | Common |
| Viewer Response Lambda | Every request | 100x | Rarely recommended |

**Recommendation:** 
1. Review if the requirement is truly necessary
2. Consider alternative implementations:
   - Can it be handled by CloudFront Function? (much cheaper)
   - Can it be deferred to Origin Request Lambda? (10x cheaper)
   - Can it be handled by AWS WAF? (for security rules)
3. If confirmed necessary, implement manually with cost monitoring
4. Set up CloudWatch billing alarms

**These rules are marked as NON-CONVERTIBLE and require manual implementation with explicit cost awareness.**

---

### Rules Not Convertible (Other Reasons)
| Rule ID | Original Type | Rule Summary | Reason | Manual Action Required |
|---------|---------------|--------------|--------|------------------------|
| origin-1 | Origin Rule | Origin is IP address 192.168.1.1 | CloudFront doesn't support IP origins | Use ALB/NLB as origin, or use domain name |
| cache-9 | Cache Rule | Uses Cloudflare-specific field `cf.bot_management.score` | Field not available in CloudFront | Implement using AWS WAF Bot Control |

---

## DNS Record: api.example.com
[Similar structure for each DNS record...]

---

## Global Rules Assignment
These rules don't have `http.host` match field. User must specify which DNS records need these rules.

| Rule ID | Original Type | Rule Summary | Apply to DNS Records (User fills) |
|---------|---------------|--------------|-----------------------------------|
| cache-global-1 | Cache Rule | Cache all static assets | [FILL IN: All / example.com, api.example.com] |
| header-global-2 | Response Header Transform | Add security headers | [FILL IN: All / example.com] |
```

#### 3. `user-decisions-template.md`
Template for user to fill in decisions.

**Structure:**
```markdown
# User Decisions for CloudFront Migration

## Instructions
Please fill in the following decisions. This file will be used by Power 4 (Orchestrator) to generate task assignments.

---

## DNS Record: example.com

### Content Type
**Question:** Is this DNS record serving static content, dynamic content, or both?

**Options:**
- `Static` - Mostly static files (images, CSS, JS). High cache hit ratio. Lambda@Edge cost is acceptable.
- `Dynamic` - Mostly dynamic API responses. Low cache hit ratio. Avoid Lambda@Edge if possible.
- `Both` - Mixed content. Requires multiple cache behaviors.

**Your Decision:** [FILL IN: Static / Dynamic / Both]

**If "Both":** This requires multiple cache behaviors with different policies. This is complex and may require manual configuration. Are you comfortable with this complexity?
- [FILL IN: Yes / No]

---

### Lambda@Edge Acceptance
**Question:** Are you willing to use Origin Request/Response Lambda@Edge for complex rules?

**Cost Impact:**
- Origin Request Lambda: Runs on cache miss (~10-30% of requests for static sites)
- Origin Response Lambda: Runs on cache miss (~10-30% of requests for static sites)
- Estimated cost: $0.20 per 1 million requests (plus compute time)

**Your Decision:** [FILL IN: Yes / No]

**If No:** Complex rules will be marked as "manual implementation required"

---

### High-Cost Features (Viewer Lambda@Edge)
The following rules require Viewer Request/Response Lambda@Edge, which runs on EVERY request (including cache hits) and is **10-100x more expensive** than Origin Lambda.

| Rule ID | Estimated Cost | Alternative Solutions |
|---------|----------------|----------------------|
| auth-1 | $50-500 per million requests | Consider AWS WAF, CloudFront Function, or Origin Request Lambda |

**Question:** Do you want to implement these rules manually, or explore alternative solutions?

**Options:**
- `Manual` - I will implement these manually with full cost awareness
- `Alternative` - Help me find alternative solutions
- `Skip` - Skip these rules for now

**Your Decision:** [FILL IN: Manual / Alternative / Skip]

---

### Custom Notes (Optional)
[Any additional context or requirements]

---

## DNS Record: api.example.com
[Similar structure for each DNS record...]

---

## Global Rules Assignment

| Rule ID | Apply to DNS Records |
|---------|---------------------|
| cache-global-1 | [FILL IN: All / example.com, api.example.com] |
| header-global-2 | [FILL IN: All / example.com] |

---

## Certificate Configuration

**Question:** Do you already have ACM certificates for these domains?

**Your Decision:** [FILL IN: Yes / No]

**If Yes, provide ARNs:**
- example.com: [FILL IN: <ACM_CERTIFICATE_ARN>]
- api.example.com: [FILL IN: <ACM_CERTIFICATE_ARN>]

**If No:** Power 9 will generate instructions for requesting certificates.

---

## Deployment Preferences

**Question:** Do you want to deploy all distributions at once, or one by one?

**Your Decision:** [FILL IN: All at once / One by one]

**Question:** Do you need a rollback plan?

**Your Decision:** [FILL IN: Yes / No]
```

### Core Logic: Implementation Method Determination

Power 3 must determine the implementation method for each rule using the following decision tree:

```
For each rule:
  ├─ Does it modify the request?
  │   ├─ Can CloudFront Function handle it?
  │   │   - Simple logic (URI rewrite, redirect, header manipulation)
  │   │   - No external API calls
  │   │   - No request body access
  │   │   - Total function size < 10KB
  │   │   → Viewer Request CloudFront Function ✅
  │   │
  │   ├─ Can Origin Request Lambda handle it?
  │   │   - Complex logic or external API calls
  │   │   - Need request body access
  │   │   - Acceptable to run only on cache miss
  │   │   → Origin Request Lambda@Edge ✅
  │   │
  │   └─ Requires Viewer Request Lambda?
  │       - Must run on EVERY request (including cache hit)
  │       - Cannot be deferred to origin request
  │       → ⚠️ Mark as Non-convertible (High Cost)
  │       → Require manual review and implementation
  │
  ├─ Does it modify the response?
  │   ├─ Can Response Headers Policy handle it?
  │   │   - Static headers only
  │   │   → Response Headers Policy ✅
  │   │
  │   ├─ Can Viewer Response CloudFront Function handle it?
  │   │   - Simple response header manipulation
  │   │   - No response body modification
  │   │   - Total function size < 10KB
  │   │   → Viewer Response CloudFront Function ✅
  │   │
  │   ├─ Can Origin Response Lambda handle it?
  │   │   - Complex header logic
  │   │   - Response body modification
  │   │   - Acceptable to run only on cache miss
  │   │   → Origin Response Lambda@Edge ✅
  │   │
  │   └─ Requires Viewer Response Lambda?
  │       - Must modify response on EVERY request (including cache hit)
  │       - Cannot be handled at origin response
  │       → ⚠️ Mark as Non-convertible (High Cost)
  │       → Require manual review and implementation
  │
  ├─ Is it configuration only?
  │   ├─ Cache TTL, Query String handling, Compression
  │   │   → Cache Policy ✅
  │   │
  │   ├─ Origin selection, Host header (static)
  │   │   → Origin + Origin Request Policy ✅
  │   │
  │   └─ Static response headers
  │       → Response Headers Policy ✅
  │
  └─ Is it unsupported?
      → Mark as non-convertible
```

### Implementation Method Reference Table

| Cloudflare Rule | Implementation | Reason |
|----------------|----------------|--------|
| Cache Rule: Match `/api/*`, TTL=0 | Cache Behavior + Cache Policy | Simple path pattern + cache setting |
| Cache Rule: Match complex regex on URI | Viewer Request Function | Need dynamic inspection |
| Cache Rule: Match based on cookie value | Origin Request Lambda | Need cookie access, runs on cache miss |
| Origin Rule: Change host header (static) | Origin Request Policy | Simple configuration |
| Origin Rule: Dynamic origin based on cookie | Origin Request Lambda | Need cookie-based decision |
| Redirect Rule: `/old` → `/new` | Viewer Request Function | Simple redirect |
| Redirect Rule: Complex regex with capture groups | Viewer Request Function | CloudFront Function supports regex |
| Request Header Transform: Add static header | Viewer Request Function | Simple header manipulation |
| Request Header Transform: JWT validation (every request) | ⚠️ Non-convertible (Viewer Request Lambda) | High cost, manual implementation |
| Response Header Transform: Add `X-Frame-Options` | Response Headers Policy | Static header |
| Response Header Transform: Add security headers | Viewer Response Function | Simple response header manipulation |
| Response Header Transform: Add CORS based on origin | Origin Response Lambda | Dynamic header based on request |
| Response Header Transform: Encrypt response body (every request) | ⚠️ Non-convertible (Viewer Response Lambda) | High cost, manual implementation |
| Compression Rule: Enable Gzip | Cache Policy | Native CloudFront feature |
| Custom Error Rule: Return custom error page | CloudFront Distribution config | Native feature |
| Custom Error Rule: Dynamic error page content | Origin Response Lambda | Need to generate response body |

### Special Cases

#### 1. SaaS Detection
**CRITICAL:** Read `SaaS-Fallback-Origin.txt` first.

If the API returns HTTP 200 with `origin` field and `status: "active"`:
- **STOP the conversion immediately**
- Output message: "SaaS configuration detected. Cloudflare Custom Hostnames and CloudFront SaaS have different implementation models. This requires a separate skill or manual migration. Conversion terminated."

If the API returns other results, continue conversion.

#### 2. IP Address Origins
If DNS record value is an IP address (A or AAAA record):
- Mark as non-convertible
- Reason: CloudFront doesn't support IP-based origins
- Manual action: Use ALB/NLB as origin, or use domain name

#### 3. Complex Content Type (Both Static and Dynamic)
If user selects "Both" for content type:
- Requires multiple cache behaviors with different policies
- High complexity for automated conversion
- Recommend: Manual configuration or split into separate distributions

#### 4. Viewer Lambda@Edge Requirements
If a rule truly requires Viewer Request/Response Lambda@Edge:
- Mark as non-convertible with high cost warning
- Provide cost estimation ($50-500 per million requests)
- Suggest alternatives (CloudFront Function, Origin Lambda, AWS WAF)
- Require explicit user acknowledgment for manual implementation

---

## Power 4: cloudfront-migration-orchestrator

### Responsibility
Task assignment and execution order management (does NOT perform conversion)

### Trigger Keywords
- `orchestrate cloudfront migration`
- `generate cloudfront migration tasks`

### Input
- `implementation-plan.md` (from Power 3)
- `user-decisions.md` (user-filled version of template)

### Output Files

See continuation in next section...

#### 1. Task Assignment Files

##### `task-assignments/task-viewer-request-function.md`
```markdown
# Task: Convert Viewer Request CloudFront Functions

## DNS Record: example.com

### Rules to Convert
| Rule ID | Original Type | Rule Summary | Implementation Notes |
|---------|---------------|--------------|---------------------|
| redirect-2 | Redirect Rule | Redirect `/old` to `/new` | Return 301 redirect response |
| header-3 | Request Header Transform | Add `X-Custom-Header: value` | Add to `request.headers` |

### Original Cloudflare Configuration
[Paste relevant sections from original config files]

### Requirements
- Output file: `functions/viewer-request-example-com.js`
- CloudFront Function Runtime: JavaScript 2.0
- Size limit: 10KB
- Follow CloudFront Function best practices (no optional chaining, sequential await)
- Include error handling

---

## DNS Record: api.example.com
[Similar structure...]
```

##### `task-assignments/task-viewer-response-function.md`
```markdown
# Task: Convert Viewer Response CloudFront Functions

## DNS Record: example.com

### Rules to Convert
| Rule ID | Original Type | Rule Summary | Implementation Notes |
|---------|---------------|--------------|---------------------|
| header-5 | Response Header Transform | Add security headers | Add `X-Frame-Options`, `X-Content-Type-Options` to response headers |

### Original Cloudflare Configuration
[Paste relevant sections]

### Requirements
- Output file: `functions/viewer-response-example-com.js`
- CloudFront Function Runtime: JavaScript 2.0
- Size limit: 10KB
- Follow CloudFront Function best practices
- Only modify response headers (cannot modify body)

---

## DNS Record: api.example.com
[Similar structure...]
```

##### `task-assignments/task-origin-request-lambda.md`
```markdown
# Task: Convert Origin Request Lambda@Edge

## DNS Record: example.com

### Rules to Convert
| Rule ID | Original Type | Rule Summary | Implementation Notes |
|---------|---------------|--------------|---------------------|
| origin-3 | Origin Rule | Dynamic origin selection based on cookie | Read cookie `region`, select origin based on value |
| cache-8 | Cache Rule | Complex regex pattern matching | Implement regex matching, add custom header for cache behavior |

### Original Cloudflare Configuration
[Paste relevant sections]

### Requirements
- Output directory: `lambda/origin-request-example-com/`
- Files: `index.js`, `package.json`
- Runtime: Node.js 20.x
- Event type: origin-request
- Include error handling and logging
- Add CloudWatch Logs integration

---

## DNS Record: api.example.com
[Similar structure...]
```

##### `task-assignments/task-origin-response-lambda.md`
```markdown
# Task: Convert Origin Response Lambda@Edge

## DNS Record: example.com

### Rules to Convert
| Rule ID | Original Type | Rule Summary | Implementation Notes |
|---------|---------------|--------------|---------------------|
| header-7 | Response Header Transform | Add CORS headers based on origin | Check request origin, add appropriate CORS headers |
| error-2 | Custom Error Rule | Custom error page with dynamic content | Generate custom error response body |

### Original Cloudflare Configuration
[Paste relevant sections]

### Requirements
- Output directory: `lambda/origin-response-example-com/`
- Files: `index.js`, `package.json`
- Runtime: Node.js 20.x
- Event type: origin-response
- Include error handling and logging
- Can modify response headers and body

---

## DNS Record: api.example.com
[Similar structure...]
```

##### `task-assignments/task-cloudfront-config.md`
```markdown
# Task: Generate CloudFront Terraform Configuration

## DNS Record: example.com

### Distribution Configuration
- Alternate domain name: example.com
- ACM certificate ARN: <ACM_CERTIFICATE_ARN>
- Origin: origin.example.com
- Content type: Static

### Cache Behaviors

#### Default Behavior (*)
- Origin: origin.example.com
- Cache Policy: example-com-default (to be created)
- Origin Request Policy: example-com-default (to be created)
- Response Headers Policy: example-com-security (to be created)
- Viewer Request Function: viewer-request-example-com (reference: `../functions/viewer-request-example-com.js`)
- Viewer Response Function: viewer-response-example-com (reference: `../functions/viewer-response-example-com.js`)
- Origin Request Lambda: origin-request-example-com (reference: `../lambda/origin-request-example-com/`)
- Origin Response Lambda: origin-response-example-com (reference: `../lambda/origin-response-example-com/`)

#### Behavior: *.jpg
- Path pattern: `*.jpg`
- Origin: origin.example.com
- Cache Policy: example-com-static (to be created) - TTL: 86400s
- No functions or Lambda

#### Behavior: *.css
- Path pattern: `*.css`
- Origin: origin.example.com
- Cache Policy: example-com-static (to be created) - TTL: 86400s
- Compression: Gzip, Brotli

### Cache Policy Configuration
| Policy Name | TTL (Default/Min/Max) | Query Strings | Headers | Cookies | Compression |
|-------------|----------------------|---------------|---------|---------|-------------|
| example-com-default | 0/0/0 | version | Host, User-Agent | None | Gzip |
| example-com-static | 86400/3600/31536000 | None | None | None | Gzip, Brotli |

### Origin Request Policy Configuration
| Policy Name | Query Strings | Headers | Cookies |
|-------------|---------------|---------|---------|
| example-com-default | All | Host, User-Agent, CloudFront-Viewer-Country | None |

### Response Headers Policy Configuration
| Policy Name | Headers |
|-------------|---------|
| example-com-security | X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security: max-age=31536000 |

### Rules Requiring Manual Configuration
| Rule ID | Reason | Manual Action |
|---------|--------|---------------|
| origin-1 | IP-based origin | Use ALB/NLB or domain name |
| auth-1 | Requires Viewer Request Lambda (high cost) | Implement manually with cost monitoring |

---

## DNS Record: api.example.com
[Similar structure...]

---

## Requirements
- Output directory: `terraform/`
- Files: 
  - `main.tf` - CloudFront distributions
  - `origins.tf` - Origin configurations
  - `policies.tf` - Cache/Origin/Response policies
  - `functions.tf` - CloudFront Function associations
  - `lambda.tf` - Lambda@Edge associations
  - `variables.tf` - Variable definitions
  - `terraform.tfvars` - Variable values
  - `versions.tf` - Terraform and provider versions
- Terraform version: >= 1.8.0
- AWS Provider version: >= 6.4.0
- Reference generated functions and Lambda from previous tasks
- Generate `README_deployment.md` with deployment instructions
```

#### 2. `execution-guide.md`
Step-by-step execution guide for the user.

```markdown
# CloudFront Migration Execution Guide

## Overview
This migration requires executing **5 separate skills** in **5 separate Kiro CLI sessions**.

**Why separate sessions?**
- Avoid context pollution and AI hallucinations
- Each skill focuses on a specific task
- Allows re-running individual steps if needed

**Estimated total time:** 2-4 hours

---

## Execution Order

### Step 1: Convert Viewer Request CloudFront Functions
**Estimated time:** 20-30 minutes

**Start a new Kiro CLI session:**
```bash
kiro-cli chat
```

**In the chat, say:**
```
Convert viewer request CloudFront Function using task file: 
./task-assignments/task-viewer-request-function.md
```

**Expected output:**
- `functions/viewer-request-example-com.js`
- `functions/viewer-request-api-example-com.js`
- `functions/README.md`

**Verification:**
- Check function file size < 10KB
- Review function logic matches original Cloudflare rules
- Test function syntax (optional): Use CloudFront Function test feature

---

### Step 2: Convert Viewer Response CloudFront Functions
**Estimated time:** 15-20 minutes

**Start a NEW Kiro CLI session:**
```bash
kiro-cli chat
```

**In the chat, say:**
```
Convert viewer response CloudFront Function using task file:
./task-assignments/task-viewer-response-function.md
```

**Expected output:**
- `functions/viewer-response-example-com.js`
- `functions/viewer-response-api-example-com.js`

**Verification:**
- Check function file size < 10KB
- Ensure only response headers are modified (no body modification)

---

### Step 3: Convert Origin Request Lambda@Edge
**Estimated time:** 30-40 minutes

**Start a NEW Kiro CLI session:**
```bash
kiro-cli chat
```

**In the chat, say:**
```
Convert origin request Lambda@Edge using task file:
./task-assignments/task-origin-request-lambda.md
```

**Expected output:**
- `lambda/origin-request-example-com/index.js`
- `lambda/origin-request-example-com/package.json`
- `lambda/README.md`

**Verification:**
- Check Lambda code includes error handling
- Review package.json dependencies
- Ensure CloudWatch Logs integration

---

### Step 4: Convert Origin Response Lambda@Edge
**Estimated time:** 30-40 minutes

**Start a NEW Kiro CLI session:**
```bash
kiro-cli chat
```

**In the chat, say:**
```
Convert origin response Lambda@Edge using task file:
./task-assignments/task-origin-response-lambda.md
```

**Expected output:**
- `lambda/origin-response-example-com/index.js`
- `lambda/origin-response-example-com/package.json`

**Verification:**
- Check Lambda code handles response modification correctly
- Ensure proper error handling

---

### Step 5: Generate CloudFront Terraform Configuration
**Estimated time:** 40-60 minutes

**Start a NEW Kiro CLI session:**
```bash
kiro-cli chat
```

**In the chat, say:**
```
Generate CloudFront Terraform configuration using task file:
./task-assignments/task-cloudfront-config.md

Reference the following generated resources:
- Viewer Request Functions: ./functions/viewer-request-*.js
- Viewer Response Functions: ./functions/viewer-response-*.js
- Origin Request Lambda: ./lambda/origin-request-*/
- Origin Response Lambda: ./lambda/origin-response-*/
```

**Expected output:**
- `terraform/main.tf` - CloudFront distributions
- `terraform/origins.tf` - Origin configurations
- `terraform/policies.tf` - Cache/Origin/Response policies
- `terraform/functions.tf` - CloudFront Function associations
- `terraform/lambda.tf` - Lambda@Edge associations
- `terraform/variables.tf` - Variable definitions
- `terraform/terraform.tfvars` - Variable values
- `terraform/versions.tf` - Version constraints
- `README_deployment.md` - Deployment instructions

**Verification:**
- Check Terraform syntax: `cd terraform && terraform validate`
- Review function and Lambda references are correct
- Check ACM certificate ARNs match user decisions
- Ensure all cache behaviors are defined

---

## Summary

| Step | Skill | Output | Session Required |
|------|-------|--------|------------------|
| 1 | Viewer Request Function Converter | `functions/viewer-request-*.js` | New session |
| 2 | Viewer Response Function Converter | `functions/viewer-response-*.js` | New session |
| 3 | Origin Request Lambda Converter | `lambda/origin-request-*/` | New session |
| 4 | Origin Response Lambda Converter | `lambda/origin-response-*/` | New session |
| 5 | CloudFront Config Generator | `terraform/` | New session |

**Total sessions:** 5  
**Total estimated time:** 2-4 hours

---

## Troubleshooting

### If a step fails:
1. Review the error message
2. Check the task file for correctness
3. Re-run that specific step in a new session
4. Other completed steps are not affected

### If you need to modify a task:
1. Edit the corresponding task file in `task-assignments/`
2. Re-run that specific skill in a new session

### If function size exceeds 10KB:
1. Review the function code for optimization opportunities
2. Consider moving complex logic to Origin Request Lambda
3. Split into multiple functions if possible

### If Lambda deployment fails:
1. Check IAM permissions for Lambda@Edge
2. Ensure Lambda is deployed in us-east-1 region
3. Review CloudWatch Logs for errors

---

## Next Steps

After all conversions are complete:
1. Review all generated files
2. Follow `README_deployment.md` for deployment instructions
3. Deploy Lambda@Edge functions first (they need to replicate)
4. Deploy CloudFront Functions
5. Deploy CloudFront distributions
6. Test in a staging environment before production
7. Set up monitoring and alarms
8. Plan DNS cutover from Cloudflare to CloudFront
```

---

## Converter Powers (7-11)

### Power 7: viewer-request-function-converter

**Responsibility:** Convert rules to Viewer Request CloudFront Functions

**Trigger Keywords:** `convert viewer request cloudfront function`

**Input:** `task-assignments/task-viewer-request-function.md`

**Output:**
- `functions/viewer-request-[dns-record].js` (one file per DNS record)
- `functions/README.md` (function documentation)

**Key Requirements:**
- CloudFront Function Runtime: JavaScript 2.0
- Size limit: 10KB per function
- No optional chaining (`?.`)
- Sequential `await` (not `Promise.all()`)
- No external dependencies
- Include error handling

---

### Power 8: viewer-response-function-converter

**Responsibility:** Convert rules to Viewer Response CloudFront Functions

**Trigger Keywords:** `convert viewer response cloudfront function`

**Input:** `task-assignments/task-viewer-response-function.md`

**Output:**
- `functions/viewer-response-[dns-record].js` (one file per DNS record)
- `functions/README.md` (function documentation)

**Key Requirements:**
- CloudFront Function Runtime: JavaScript 2.0
- Size limit: 10KB per function
- Can only modify response headers (not body)
- No optional chaining (`?.`)
- Sequential `await`
- Include error handling

---

### Power 9: origin-request-lambda-converter

**Responsibility:** Convert rules to Origin Request Lambda@Edge

**Trigger Keywords:** `convert origin request lambda`

**Input:** `task-assignments/task-origin-request-lambda.md`

**Output:**
- `lambda/origin-request-[dns-record]/index.js`
- `lambda/origin-request-[dns-record]/package.json`
- `lambda/README.md` (Lambda documentation)

**Key Requirements:**
- Runtime: Node.js 20.x
- Event type: origin-request
- Include error handling and logging
- CloudWatch Logs integration
- Can access and modify request
- Can access request body
- Runs only on cache miss

---

### Power 10: origin-response-lambda-converter

**Responsibility:** Convert rules to Origin Response Lambda@Edge

**Trigger Keywords:** `convert origin response lambda`

**Input:** `task-assignments/task-origin-response-lambda.md`

**Output:**
- `lambda/origin-response-[dns-record]/index.js`
- `lambda/origin-response-[dns-record]/package.json`
- `lambda/README.md` (Lambda documentation)

**Key Requirements:**
- Runtime: Node.js 20.x
- Event type: origin-response
- Include error handling and logging
- CloudWatch Logs integration
- Can modify response headers and body
- Runs only on cache miss

---

### Power 11: cloudfront-config-generator

**Responsibility:** Generate CloudFront Terraform configuration

**Trigger Keywords:** `generate cloudfront terraform configuration`

**Input:**
- `task-assignments/task-cloudfront-config.md`
- Generated Functions (from Powers 5-6)
- Generated Lambda (from Powers 7-8)

**Output:**
- `terraform/main.tf` - CloudFront distributions
- `terraform/origins.tf` - Origin configurations
- `terraform/policies.tf` - Cache/Origin/Response policies
- `terraform/functions.tf` - CloudFront Function associations
- `terraform/lambda.tf` - Lambda@Edge associations
- `terraform/variables.tf` - Variable definitions
- `terraform/terraform.tfvars` - Variable values
- `terraform/versions.tf` - Version constraints
- `README_deployment.md` - Deployment instructions

**Key Requirements:**
- Terraform version: >= 1.8.0
- AWS Provider version: >= 6.4.0
- Reference generated functions and Lambda correctly
- Include all cache behaviors
- Include all policies
- Generate deployment guide

---

## Complete Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ Session 1: Analysis (Power 3)                              │
├─────────────────────────────────────────────────────────────┤
│ User: "Analyze Cloudflare CDN config in ./cloudflare_config/" │
│   ↓                                                         │
│ Power 3 executes:                                           │
│   1. Read all Cloudflare config files                       │
│   2. Check SaaS configuration (terminate if detected)       │
│   3. Parse and group rules by DNS record                    │
│   4. Determine implementation method for each rule          │
│   5. Mark Viewer Lambda@Edge as non-convertible (high cost)│
│   6. Generate analysis report and implementation plan       │
│   ↓                                                         │
│ Output:                                                     │
│   - cdn-config-analysis.md                                  │
│   - implementation-plan.md                                  │
│   - user-decisions-template.md                              │
│   ↓                                                         │
│ User action: Fill in user-decisions.md                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Session 2: Orchestration (Power 4)                         │
├─────────────────────────────────────────────────────────────┤
│ User: "Orchestrate CloudFront migration using ./user-decisions.md" │
│   ↓                                                         │
│ Power 4 executes:                                           │
│   1. Read implementation-plan.md and user-decisions.md      │
│   2. Generate task files for each converter skill           │
│   3. Generate execution guide with step-by-step instructions│
│   ↓                                                         │
│ Output:                                                     │
│   - task-assignments/task-viewer-request-function.md        │
│   - task-assignments/task-viewer-response-function.md       │
│   - task-assignments/task-origin-request-lambda.md          │
│   - task-assignments/task-origin-response-lambda.md         │
│   - task-assignments/task-cloudfront-config.md              │
│   - execution-guide.md                                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Session 3: Viewer Request Function (Power 7)               │
├─────────────────────────────────────────────────────────────┤
│ User: "Convert viewer request CloudFront Function using     │
│        ./task-assignments/task-viewer-request-function.md"  │
│   ↓                                                         │
│ Power 5 executes                                            │
│   ↓                                                         │
│ Output: functions/viewer-request-*.js                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Session 4: Viewer Response Function (Power 8)              │
├─────────────────────────────────────────────────────────────┤
│ User: "Convert viewer response CloudFront Function using    │
│        ./task-assignments/task-viewer-response-function.md" │
│   ↓                                                         │
│ Power 6 executes                                            │
│   ↓                                                         │
│ Output: functions/viewer-response-*.js                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Session 5: Origin Request Lambda (Power 9)                 │
├─────────────────────────────────────────────────────────────┤
│ User: "Convert origin request Lambda@Edge using             │
│        ./task-assignments/task-origin-request-lambda.md"    │
│   ↓                                                         │
│ Power 7 executes                                            │
│   ↓                                                         │
│ Output: lambda/origin-request-*/                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Session 6: Origin Response Lambda (Power 10)                │
├─────────────────────────────────────────────────────────────┤
│ User: "Convert origin response Lambda@Edge using            │
│        ./task-assignments/task-origin-response-lambda.md"   │
│   ↓                                                         │
│ Power 8 executes                                            │
│   ↓                                                         │
│ Output: lambda/origin-response-*/                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Session 7: CloudFront Configuration (Power 11)              │
├─────────────────────────────────────────────────────────────┤
│ User: "Generate CloudFront Terraform configuration using    │
│        ./task-assignments/task-cloudfront-config.md         │
│        Functions: ./functions/                              │
│        Lambda: ./lambda/"                                   │
│   ↓                                                         │
│ Power 9 executes                                            │
│   ↓                                                         │
│ Output: terraform/ + README_deployment.md                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

### 1. Why group rules by proxied DNS record?
- **CloudFront architecture alignment:** One proxied DNS record = One CloudFront Distribution
- **Clear task assignment:** Each domain gets separate task files and Terraform resources
- **10KB function size limit:** Critical constraint that requires splitting functions by domain
  - CloudFront Functions have a hard 10KB limit
  - Grouping by domain allows splitting one large function into multiple smaller functions
  - Each domain's function stays within the 10KB limit
- **Independent deployment:** Deploy and test one domain at a time, reducing risk
- **Better debugging:** Domain-specific functions are easier to troubleshoot

### 2. Why separate sessions?
- **Avoid context pollution:** Each skill has a clean context
- **Prevent AI hallucinations:** No mixing of different conversion tasks
- **Enable re-execution:** Failed steps can be re-run independently
- **Reduce context window pressure:** Each session only loads necessary information

### 3. Why task files?
- **State transfer:** Pass information between sessions without maintaining state
- **Human review:** Users can review and modify task files before execution
- **Debugging:** Clear record of what each skill should do
- **Flexibility:** Users can edit task files to customize conversion

### 4. Why convert Functions first?
- **Dependency order:** CloudFront configuration references Functions and Lambda
- **Validation:** Ensure Functions are valid before generating configuration
- **Size constraints:** CloudFront Functions have 10KB limit, need to verify early and potentially split by domain

### 5. Why implementation-based task assignment?
- **CloudFront architecture:** CloudFront uses different mechanisms (Functions, Lambda, Policies, Config)
- **Not 1:1 mapping:** One Cloudflare rule may need multiple CloudFront components
- **Optimization:** Choose the most appropriate implementation method for each rule

### 6. Why mark Viewer Lambda@Edge as non-convertible?
- **Cost risk:** 10-100x more expensive than Origin Lambda
- **Requires business judgment:** AI cannot determine if the cost is justified
- **Usually has alternatives:** CloudFront Function or Origin Lambda can handle most cases
- **AWS best practice:** Avoid Viewer Lambda unless absolutely necessary
- **Explicit user consent:** High-cost features require manual implementation with full awareness

---

## Implementation Notes

### Power 3 Challenges
- **Accurate implementation determination:** Requires deep understanding of both Cloudflare and CloudFront
- **Cost awareness:** Must identify high-cost solutions (Viewer Lambda) and warn users
- **Function size estimation:** Must estimate function size per domain to warn if approaching 10KB limit
- **Edge cases:** Complex rules may have multiple valid implementations
- **Recommendation:** Create detailed reference documents in `references/` directory

### Power 4 Challenges
- **Task file generation:** Must include all necessary information for converter powers
- **Dependency management:** Ensure correct execution order
- **User guidance:** Provide clear instructions in execution guide
- **Domain-based splitting:** Ensure each domain's tasks are clearly separated

### Converter Powers (7-11) Challenges
- **Code generation quality:** Must generate production-ready code
- **Error handling:** Include proper error handling and logging
- **Optimization:** CloudFront Functions have strict size limits (10KB per function)
  - Must generate one function file per domain to avoid exceeding limit
  - Optimize code for size (minification, efficient patterns)
  - Warn if a single domain's function approaches 10KB
- **Testing:** Provide test cases or validation scripts

### Function Size Management
- **Per-domain splitting:** Each domain gets its own function file
- **Size estimation:** Power 3 estimates function size per domain
- **Size warning:** If a single domain's function may exceed 10KB:
  - Recommend moving complex rules to Origin Request Lambda
  - Suggest simplifying regex patterns
  - Consider using Key Value Store for bulk data
  - May require splitting into multiple cache behaviors
- **Lambda@Edge alternative:** No strict size limits (50MB uncompressed, 1MB compressed)

### Cost Management
- **Viewer Lambda warning:** Always warn about high cost before suggesting Viewer Lambda
- **Alternative suggestions:** Provide cheaper alternatives when possible
- **Cost estimation:** Include estimated costs in implementation plan
- **Monitoring recommendations:** Suggest CloudWatch billing alarms

---

## Appendix

### File Structure

```
project-root/
├── cloudflare_config/          # Input: Cloudflare configuration files
│   ├── DNS.txt
│   ├── Cache-Rules.txt
│   ├── Origin-Rules.txt
│   ├── SaaS-Fallback-Origin.txt
│   └── ...
│
├── cdn-config-analysis.md      # Output from Power 3
├── implementation-plan.md      # Output from Power 3
├── user-decisions-template.md  # Output from Power 3
├── user-decisions.md           # User-filled version
│
├── task-assignments/           # Output from Power 4
│   ├── task-viewer-request-function.md
│   ├── task-viewer-response-function.md
│   ├── task-origin-request-lambda.md
│   ├── task-origin-response-lambda.md
│   └── task-cloudfront-config.md
│
├── execution-guide.md          # Output from Power 4
│
├── functions/                  # Output from Powers 5-6
│   ├── viewer-request-example-com.js
│   ├── viewer-response-example-com.js
│   ├── viewer-request-api-example-com.js
│   ├── viewer-response-api-example-com.js
│   └── README.md
│
├── lambda/                     # Output from Powers 7-8
│   ├── origin-request-example-com/
│   │   ├── index.js
│   │   └── package.json
│   ├── origin-response-example-com/
│   │   ├── index.js
│   │   └── package.json
│   └── README.md
│
└── terraform/                  # Output from Power 9
    ├── main.tf
    ├── origins.tf
    ├── policies.tf
    ├── functions.tf
    ├── lambda.tf
    ├── variables.tf
    ├── terraform.tfvars
    ├── versions.tf
    └── README_deployment.md
```

### Cost Comparison Table

| Solution | Execution Frequency | Cost per 1M Requests | Use Case |
|----------|-------------------|---------------------|----------|
| CloudFront Function (Viewer Request) | Every request | $0.10 | Simple request manipulation |
| CloudFront Function (Viewer Response) | Every request | $0.10 | Simple response header manipulation |
| Lambda@Edge (Origin Request) | Cache miss only (~10-30%) | $0.20 + compute | Complex request logic |
| Lambda@Edge (Origin Response) | Cache miss only (~10-30%) | $0.20 + compute | Complex response logic |
| Lambda@Edge (Viewer Request) | Every request | $2.00 + compute | ⚠️ Rarely recommended |
| Lambda@Edge (Viewer Response) | Every request | $2.00 + compute | ⚠️ Rarely recommended |
| Response Headers Policy | Every request | $0 (included) | Static response headers |
| Cache Policy | Every request | $0 (included) | Cache configuration |

**Note:** Costs are approximate and may vary by region. Compute costs for Lambda@Edge depend on execution time and memory allocation.

---

## Conclusion

This architecture provides a structured, modular approach to migrating Cloudflare CDN configurations to AWS CloudFront. By separating concerns into distinct skills and using file-based state transfer, we achieve:

- ✅ Clean separation of responsibilities
- ✅ Avoidance of context pollution
- ✅ Flexibility for users to review and modify at each stage
- ✅ Ability to re-run individual steps
- ✅ Scalability to handle large configurations
- ✅ Cost awareness and risk mitigation
- ✅ Support for both CloudFront Functions and Lambda@Edge

The key innovations are:
1. **Implementation-based task assignment** - Aligns with CloudFront's architecture
2. **Multi-stage conversion** - Allows human-in-the-loop decision making
3. **Cost-aware design** - Marks high-cost solutions as non-convertible
4. **Stateless workflow** - Enables batch processing and re-execution

**Next Steps:**
1. Implement Power 3 (Analyzer) first
2. Test with real Cloudflare configurations
3. Implement Power 4 (Planner) and Power 5 (Validator)
4. Implement Powers 6-11 iteratively
5. Create comprehensive reference documents
