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
| Snippets / Workers | 跑在 Cloudflare V8 runtime 上的任意 JavaScript/TypeScript 代码，不是声明式配置。可能用了 Cloudflare 专有 API（KV、Durable Objects、R2、D1），CloudFront 没有对应的。需要理解业务逻辑才能重写。 | 手动改写为 CloudFront Functions 或 Lambda@Edge。复杂的 Workers 可能需要 Lambda@Edge 或 CloudFront 后面挂独立 Lambda。 |
| URL Normalization | CloudFront 默认按 RFC 3986 标准化 URI，不需要转换。 | N/A |
| Managed Transforms（True-Client-IP 除外） | Cloudflare 专有功能。 | CloudFront 原生等价物（如果有的话） |
| Trace | Cloudflare 专有测试功能。 | CloudWatch Logs、CloudFront real-time logs |

### 可转换规则类型中无法映射的设置

| 设置 | 规则类型 | 原因 | 替代方案 |
|---------|-----------|--------|-------------|
| `serve_stale` (SWR/SIE) | Cache Rules | CloudFront cache policy 没有对应项 | Origin `Cache-Control: stale-while-revalidate`（有限支持） |
| `origin_error_page_passthru` | Cache Rules | 需要 Lambda@Edge 拦截 origin 错误 | Lambda@Edge origin-response |
| 仅 query string 的 rewrite | URL Rewrite | CloudFront Functions 无法单独修改 query strings | Lambda@Edge |
| `browser_check` | Configuration | CloudFront 没有对应项 | AWS WAF Bot Control |
| `minify` (HTML/CSS/JS) | Configuration | CloudFront 原生不支持 | Origin 端压缩 |
| `rocket_loader` | Configuration | Cloudflare 专有 JS 优化 | N/A |
| `hotlink_protection` | Configuration | 需要自定义 referer 检查逻辑 | Lambda@Edge |
| Device detection headers (UA regex) | Request Header Transform | CloudFront 提供原生设备检测 | Origin Request Policy + `CloudFront-Is-*-Viewer` headers |
| 含不可映射 CF 变量的动态值 | Request/Response Header Transform | CloudFront Functions 无法计算所有 Cloudflare 表达式 | 手动检查 |
| 非 path 表达式的 Cloud Connector | Cloud Connector | CloudFront cache behaviors 只能按 path pattern 匹配 | 手动配置 origin |
| 不允许/只读的 response headers | Response Header Transform | CloudFront 限制修改某些 headers（`Via`、`X-Amz-Cf-*` 等） | N/A |

### 没有 CloudFront 对应项的 Cloudflare 匹配字段

| 字段 | 原因 |
|-------|--------|
| `cf.edge.server_port`, `cf.zone.name`, `cf.metal.id`, `cf.ray_id` | Cloudflare 专有内部字段 |
| `cf.tls_client_auth.*` | mTLS 证书字段在 CloudFront Functions 中不可用 |
| `ip.src.subdivision_2_iso_code` | CloudFront 只提供一级行政区划 |
| `http.request.timestamp.sec/msec` | 在 CloudFront Functions 中用 `Date.now()` 代替 |

### Regex 限制

CloudFront path patterns 只支持 `*` 和 `?` 通配符——不支持 regex。当 Cloudflare 规则用了无法映射为通配符的 regex path 表达式时，pipeline 会把它分配到默认的 `"*"` behavior，并加一条 `non_convertible` 备注。

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

- **Token 消耗**随规则数量增加。域名多或规则集大的 zone 建议用 `claude-sonnet-4.6-1m`。
- **API 速率限制**可能拖慢并行处理。调整 batch size 的方法见 README。

### 本工具不配置的功能

- **CloudFront access logging**——涉及 S3 bucket、日志格式、共享还是按域名分等决策，超出迁移范围。
- **Lambda@Edge 部署**——工具会生成 Lambda 代码，但用的是 `REPLACE_WITH_DEPLOYED_LAMBDA_ARN` 占位符。你得先部署 Lambda 函数，填好 ARN，再 `terraform apply`。
- **DNS 切换**——工具会生成 CloudFront distributions，但不会动 DNS 记录。确认配置没问题后，你自己更新 DNS 指向 CloudFront。
