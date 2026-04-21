[English](./limitations.md)

# 限制与注意事项

## CDN Pipeline——能转换的内容

CDN pipeline 把以下 Cloudflare 规则类型转换为 CloudFront 等价物：

| 规则类型 | CloudFront 等价物 |
|-----------|----------------------|
| Redirect Rules | CloudFront Functions (viewer-request) |
| URL Rewrite Rules | CloudFront Functions (viewer-request) |
| Configuration Rules | Distribution 设置（TLS、HTTP 版本、协议策略） |
| Origin Rules | CloudFront Functions (`updateRequestOrigin`) 或独立 cache behaviors |
| Bulk Redirects | KVS + CloudFront Functions |
| Request Header Transform | CloudFront Functions + Origin Request Policy |
| Cache Rules | Cache behaviors 上的 cache policies |
| Cloud Connector Rules | 独立 cache behaviors + 独立 origins |
| Custom Error Rules | CloudFront custom error responses |
| Response Header Transform | Response Headers Policy + CloudFront Functions (viewer-response) |
| Compression Rules | Cache policy `enable_gzip` / `enable_brotli` |

## CDN Pipeline——不能转换的内容

### 不处理的规则类型

| 项目 | 原因 | 替代方案 |
|------|--------|-------------|
| Page Rules (legacy) | Cloudflare 已弃用。先迁移到现代规则类型，再用本工具。 | Cloudflare 迁移指南 |
| Snippets | 跑在 Cloudflare V8 runtime 上的 JavaScript 代码。虽然 Snippets 不能用存储绑定（KV、D1、R2、DO），但可以用 `fetch()`（子请求）、`HTMLRewriter` 和 `request.body`——这些在 CloudFront Functions 中都不可用。只操作 headers、URL 和 cookies 的 Snippets 理论上可以转换，但这些用例已经被 Cloudflare 的声明式规则类型（Redirect Rules、Transform Rules 等）覆盖，本工具已经在转换这些规则。用了 `fetch()`、`HTMLRewriter` 或 body 访问的 Snippets 需要 Lambda@Edge。 | 逐个评估每个 Snippet。简单的 header/URL 逻辑 → CloudFront Functions。`fetch()` 或 `HTMLRewriter` → Lambda@Edge。`request.cf.botManagement` → AWS WAF Bot Control。 |
| Workers | 带完整 Cloudflare 平台绑定（KV、Durable Objects、R2、D1、Queues 等）的 TypeScript/JavaScript。任意业务逻辑，需要理解意图才能重写。 | Lambda@Edge 处理请求/响应。复杂的 Workers 可能需要 CloudFront 后面挂独立 Lambda，或完全重写应用。 |
| URL Normalization | CloudFront 默认按 RFC 3986 标准化 URI，不需要转换。 | N/A |
| Managed Transforms（True-Client-IP 除外） | Cloudflare 专有功能。 | CloudFront 原生等价物（如果有的话） |
| Trace | Cloudflare 专有测试功能。 | CloudWatch Logs、CloudFront real-time logs |

### 可转换规则类型中无法映射的设置

| 设置 | 规则类型 | 原因 | 替代方案 |
|---------|-----------|--------|-------------|
| `ip.src` / `ip.src in` 条件 | Cache Rules、Compression Rules | CloudFront Functions 无法控制缓存或压缩决策 | AWS WAF IP 规则 |
| `ip.src in $list_name`（含 CIDR） | 所有规则类型 | CFF `event.viewer.ip` 是单个 IP，无法做 CIDR 匹配 | AWS WAF IP set + Count action + 自定义 header（见 conversion_report.md 中的 WAF + Custom Header Pattern） |
| `serve_stale` (SWR/SIE) | Cache Rules | CloudFront cache policy 没有对应项 | Origin `Cache-Control: stale-while-revalidate`（有限支持） |
| `origin_error_page_passthru` | Cache Rules | 需要 Lambda@Edge 拦截 origin 错误 | Lambda@Edge origin-response |
| 自定义错误 + inline content > 1 KB | Custom Error Rules | 超过 CloudFront KVS 1024 字符 value 限制 | 将错误页面部署为 origin 上的静态文件 + `response_page_path` |
| 自定义错误 + inline content + response-phase 条件 | Custom Error Rules | CFF viewer-response 在 4xx+ 时不执行 | 将错误页面部署为 origin 上的静态文件 |
| 自定义错误 + 不支持的状态码 | Custom Error Rules | CloudFront 只支持：400、403、404、405、414、416、500–504 | Lambda@Edge origin-response |
| 自定义错误 + 动态 headers/逻辑 | Custom Error Rules | CFF 和 L@E viewer-response 在 4xx+ 时不执行 | Lambda@Edge origin-response |
| 仅 query string 的 rewrite | URL Rewrite | CloudFront Functions 无法单独修改 query strings | Lambda@Edge |
| `browser_check` | Configuration | CloudFront 没有对应项 | AWS WAF Bot Control |
| `minify` (HTML/CSS/JS) | Configuration | CloudFront 原生不支持 | Origin 端压缩 |
| `rocket_loader` | Configuration | Cloudflare 专有 JS 优化 | N/A |
| `hotlink_protection` | Configuration | 需要自定义 referer 检查逻辑 | Lambda@Edge |
| Device detection headers (UA regex) | Request Header Transform | CloudFront 提供原生设备检测 | Origin Request Policy + `CloudFront-Is-*-Viewer` headers |
| 含不可映射 CF 变量的动态值 | Request/Response Header Transform | CloudFront Functions 无法计算所有 Cloudflare 表达式 | 手动检查 |
| 非 path 表达式的 Cloud Connector | Cloud Connector | CloudFront cache behaviors 只能按 path pattern 匹配 | 手动配置 origin |
| 不允许/只读的 response headers | Response Header Transform | CloudFront 限制修改某些 headers（`Via`、`X-Amz-Cf-*` 等） | N/A |

### CORS `credentials: true` + 通配符 origin

Cloudflare 允许 `Access-Control-Allow-Credentials: true` 与 `Access-Control-Allow-Origin: *` 同时使用。CloudFront 的 Response Headers Policy 按照 CORS 规范拒绝此组合。

工具通过 TLD 通配符模式（`*.com`、`*.net`、`*.io` 等约 60 个常见 TLD）替代 `*` 来解决此问题。CloudFront 将请求的 `Origin` header 与这些模式匹配，并回显实际的 origin 值，符合 CORS 规范。

限制：
- 不在默认列表中的 TLD 的 origin 不会匹配。按需在 `policies.tf` 中添加模式。
- 不带 scheme 的通配符模式（`*.com`）不匹配带非标准端口的 origin（如 `http://example.com:8080`）。CloudFront 仅在 80/443 端口提供服务，因此这只影响来自非标准端口 origin 的跨域请求。
- 当 Cloudflare 规则使用 `add` 操作（而非 `set`）时，`origin_override` 设为 `false`。此模式下，CloudFront 仅在请求包含 `Origin` header 时返回 CORS headers。Cloudflare 无论请求是否包含 `Origin` header 都会添加 CORS headers。此差异仅影响非浏览器客户端（curl、SDK 等）— 浏览器在跨域请求时始终发送 `Origin`。

### CloudFront Function 大小限制

CloudFront Functions 压缩后有 10 KB 大小限制。当域名的 `viewer_request.js` 超过此限制时：

1. 如果函数包含 `origin_override` 操作，这些操作会被拆分到 Lambda@Edge origin-request handler，减小 CFF 大小。
2. 如果拆分后 CFF 仍超过 10 KB，最低优先级的操作会被移除并标记为 `non_convertible`。这些操作**不会**升级到 Lambda@Edge viewer-request——viewer 事件只使用 CloudFront Functions。

### CloudFront 配额限制

| 资源 | 限制 | 超出时的处理 |
|----------|-------|---------------------------|
| 每账号 CloudFront Functions 数量 | 100 | Content-hash 去重自动共享相同 CFF（如 54 域名 → 5 CFF）。去重后仍超限则在转换报告中警告。此配额未在 Service Quotas 中列为可调整——可联系 AWS Support 咨询，但不保证批准 |
| 每个 distribution 的 cache behaviors | 75 | Pipeline 报错——需减少 Cloudflare 规则 |
| Cache policy headers (whitelist) | 10 | 标记为 non_convertible |
| Cache policy cookies (whitelist) | 10 | 标记为 non_convertible |
| Cache policy query strings (whitelist) | 10 | 标记为 non_convertible |
| Origin request policy headers | 10 | 标记为 non_convertible |

### 没有 CloudFront 对应项的 Cloudflare 匹配字段

| 字段 | 原因 |
|-------|--------|
| `cf.edge.server_port`, `cf.zone.name`, `cf.metal.id`, `cf.ray_id` | Cloudflare 专有内部字段 |
| `cf.tls_client_auth.*` | mTLS 证书字段在 CloudFront Functions 中不可用 |
| `ip.src.subdivision_2_iso_code` | CloudFront 只提供一级行政区划 |
| `http.request.timestamp.sec/msec` | 在 CloudFront Functions 中用 `Date.now()` 代替 |

### Regex 限制

CloudFront path patterns 只支持 `*` 和 `?` 通配符——不支持 regex。当 Cloudflare 规则用了无法映射为通配符的 regex path 表达式时：

- **Cache Rules**：路由到 Lambda@Edge origin-response，在运行时计算 regex 并设置 `Cache-Control` header。
- **其他规则类型**（redirect、rewrite、header transform）：分配到默认 `"*"` behavior，原始表达式保留为 `raw_expression` 供 CloudFront Function JS 生成使用。

### 不可转换项的处理方式

不可转换的项目**不会被静默丢弃**。Pipeline 会：
1. 在 IR 中记录每一项，附带 `reason` 字符串
2. 汇总到 `conversion_report.md`（由 finalizer 生成）
3. 报告按域名和规则类型分组，方便人工审查

## WAF Pipeline——不能转换的内容

| 项目 | 原因 | 替代方案 |
|------|--------|-------------|
| Cloudflare Managed Rules (OWASP 等) | 用 AWS WAF 自己的 managed rule groups | AWS Managed Rules for WAF |
| API Abuse Detection | Cloudflare 专有 ML 功能 | AWS WAF Bot Control + 自定义规则 |
| SaaS / mTLS 配置 | 架构根本不同 | 需要手动设计 |

## 通用限制

### 需要人工审查

AI 生成的配置在上生产前必须人工审查。重点关注：
- 复杂条件逻辑和正则表达式
- Origin 路由规则（确认后端映射正确）
- Cache TTL 值（确认符合业务需求）
- 安全相关的 headers

### 大规模配置

- **API 速率限制**可能拖慢并行处理。调整 batch size 的方法见 README。

### 本工具不配置的功能

- **CloudFront access logging**——涉及 S3 bucket、日志格式、共享还是按域名分等决策，超出迁移范围。
- **Lambda@Edge origin-request 部署**——当 CFF 超过 10 KB 且 origin_override 操作被拆分到 Lambda@Edge 时，生成的 `origin_request_handler.js` 文件头部包含需要手动添加到 `main.tf` 的条目。这只适用于 CFF 大小溢出触发拆分的域名——大多数域名不需要。Lambda@Edge origin-response 是全自动的（IAM role、archive、Lambda 函数和 `main.tf` 中的 `qualified_arn` 引用都由 scaffold 生成）。
- **DNS 切换**——工具会生成 CloudFront distributions，但不会动 DNS 记录。确认配置没问题后，你自己更新 DNS 指向 CloudFront。
