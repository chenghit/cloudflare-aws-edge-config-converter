[English](./limitations.md)

# 限制与注意事项

> **转换边界以此为准**：[docs/conversion-policy.md](./conversion-policy.md) 是权威规范，定义了哪些能转换（EXACT / LOSSY）、哪些报告为 `NON_CONVERTIBLE`、以及哪些 Cloudflare 功能根本不读取。本文说明面向用户的注意事项，以规范文档为准。

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
| Cache Rules（TTL / cache key） | Cache behaviors 上的 cache policies |
| Cache Rules（条件式 "Bypass cache"） | viewer-request CloudFront Function，对匹配的请求强制 cache miss（见下）；无条件 bypass → 一个具有 CachingDisabled 语义的自定义 cache policy（所有 TTL 为 0、无 cache-key 输入） |
| Cloud Connector Rules | 独立 cache behaviors + 独立 origins |
| Custom Error Rules | CloudFront custom error responses |
| Response Header Transform | Response Headers Policy + CloudFront Functions (viewer-response) |
| Compression Rules | Cache policy `enable_gzip` / `enable_brotli` |

### 条件式缓存绕过（cache bypass）

CloudFront 没有请求时"跳过缓存"的开关——缓存决策由 behavior 上的 cache policy 固定，而 behavior 只按路径选择（不按 cookie/header/query）。要转换一条条件式 bypass 缓存的 Cloudflare Cache Rule（例如带 `wordpress_logged_in` cookie 时 bypass，或 `?test=true`），工具会生成一个 viewer-request CloudFront Function：对匹配的请求，注入一个值每请求唯一的 header（`x-cf-cache-bypass`），并把它纳入 cache key。这样每个匹配请求都得到唯一的 cache key → 必然 miss → 必然回源。这是强制 **miss**，不是真正的跳过（响应仍会被存储，但存在一个永不复用的一次性 key 下），但对访客的效果完全一致。

支持的 bypass 条件：任何能在边缘计算的字段——cookie（`http.cookie`、`http.request.cookies["name"]`）、具名 request header（`http.request.headers["name"]`）、具名 query 参数（`http.request.uri.args["name"]`）、query / user-agent / path 子串、method、referer，以及 geo/device 的 `CloudFront-Viewer-*` 字段——存在性检查或标量值比较。（bypass 条件走的是和其他所有规则类型相同的 CFF 条件渲染器，所以别处能转的这里都能转。）

注意：
- 多值形式 `any(http.request.cookies["x"][*] == "v")`（以及 header/arg 的等价写法）**不**转换——会被标记为 non-convertible，而不是猜测其意图。
- 由于 bypass 写入 cache key，它会在运行的 behavior 上产生一次 CFF 调用开销，并为匹配请求产生一次性缓存条目（无害——永不复用，会自然过期淘汰）。

### 源站转发与 Host 覆盖

Cloudflare 把完整请求转发给源站；CloudFront 则会剥掉一切不在 cache key 里的内容，除非 **origin request policy (ORP)** 转发它。每个 behavior 的 ORP 按以下优先级选择（domain 级 all-or-nothing，因此某 behavior 绝不会相对它的 CFF 出现转发不足）：

1. **S3 + OAC 源站 → 不用 ORP。** OAC 对请求签名（SigV4）；转发 viewer Host 或任意 header 会破坏签名（403）。CloudFront 会把 Host 设为 bucket 域名本身。
2. **domain 里任一 behavior 需要 CloudFront native headers**（`CloudFront-Viewer-Country`、device 标志等，因为某条规则要读它们）→ 给该 domain 的**每个**非 S3 behavior 挂一个**自定义 ORP**（`allViewerAndWhitelistCloudFront`）。它转发所有 viewer headers（含 Host）**外加** CloudFront-* native headers，因此读 native header 的 CFF 无论落在哪个 behavior 都能看到。
3. **否则 → 托管 AllViewer**——转发所有 viewer headers（含 Host），与 Cloudflare 默认一致。

**Host 覆盖**（Cloudflare Origin Rule）**不**改变这个选择——它是正交的。源站 Host 由 CFF 里的 `cf.updateRequestOrigin({hostHeader})` 设置，其显式值优先于 ORP 转发的任何 Host（已实测），所以一个 behavior 可以既需要 native headers（→ 自定义 ORP，它也转发 Host）**又**覆盖 Host，两者不冲突。不存在"Host 覆盖 → 丢弃 viewer Host"的 ORP（旧的 `AllViewerExceptHostHeader` 选择已删除——它会让不匹配的请求无 Host 可用，而且毫无收益,因为 `hostHeader` 本来就赢）。

## CDN Pipeline——不能转换的内容

### 不处理的规则类型

| 项目 | 原因 | 替代方案 |
|------|--------|-------------|
| Page Rules (legacy) | Cloudflare 已弃用。先迁移到现代规则类型，再用本工具。 | Cloudflare 迁移指南 |
| Snippets | 跑在 Cloudflare V8 runtime 上的 JavaScript 代码。虽然 Snippets 不能用存储绑定（KV、D1、R2、DO），但可以用 `fetch()`（子请求）、`HTMLRewriter` 和 `request.body`——这些在 CloudFront Functions 中都不可用。只操作 headers、URL 和 cookies 的 Snippets 理论上可以转换，但这些用例已经被 Cloudflare 的声明式规则类型（Redirect Rules、Transform Rules 等）覆盖，本工具已经在转换这些规则。用了 `fetch()`、`HTMLRewriter` 或 body 访问的 Snippets 需要 Lambda@Edge。 | 逐个评估每个 Snippet。简单的 header/URL 逻辑 → CloudFront Functions。`fetch()` 或 `HTMLRewriter` → Lambda@Edge。`request.cf.botManagement` → AWS WAF Bot Control。 |
| Workers | 带完整 Cloudflare 平台绑定（KV、Durable Objects、R2、D1、Queues 等）的 TypeScript/JavaScript。任意业务逻辑，需要理解意图才能重写。 | Lambda@Edge 处理请求/响应。复杂的 Workers 可能需要 CloudFront 后面挂独立 Lambda，或完全重写应用。 |
| URL Normalization | CloudFront 默认按 RFC 3986 标准化 URI，不需要转换。 | N/A |
| Managed Transforms（True-Client-IP 和 security headers 除外） | Cloudflare 专有功能。 | CloudFront 原生等价物（如果有的话） |
| Trace | Cloudflare 专有测试功能。 | CloudWatch Logs、CloudFront real-time logs |

### 可转换规则类型中无法映射的设置

| 设置 | 规则类型 | 原因 | 替代方案 |
|---------|-----------|--------|-------------|
| `ip.src` / `ip.src in` 条件 | Cache Rules、Compression Rules | CloudFront Functions 无法控制缓存或压缩决策 | AWS WAF IP 规则 |
| `ip.src in $list_name`（含 CIDR） | 所有规则类型 | CFF `event.viewer.ip` 是单个 IP，无法做 CIDR 匹配 | AWS WAF IP set + Count action + 自定义 header（见 conversion_report.md 中的 WAF + Custom Header Pattern） |
| `serve_stale` (SWR/SIE) | Cache Rules | CloudFront cache policy 没有对应项 | Origin `Cache-Control: stale-while-revalidate`（有限支持） |
| `origin_error_page_passthru` | Cache Rules | 需要 Lambda@Edge 拦截 origin 错误 | Lambda@Edge origin-response |
| 自定义错误带**任何** inline content（`content`） | Custom Error Rules | CloudFront 原生 `custom_error_response` 没有 inline body，工具不再生成 CFF+KVS 内联错误页（该路径已退役） | 将错误页面部署为 origin 上的静态文件 + `response_page_path` |
| 自定义错误 + 不支持的状态码 | Custom Error Rules | CloudFront 只支持：400、403、404、405、414、416、500–504 | Lambda@Edge origin-response |
| 自定义错误 + 动态 headers/逻辑 | Custom Error Rules | CFF 和 L@E viewer-response 在 4xx+ 时不执行 | Lambda@Edge origin-response |
| `browser_check` | Configuration | CloudFront 没有对应项 | AWS WAF Bot Control |
| `minify` (HTML/CSS/JS) | Configuration | CloudFront 原生不支持 | Origin 端压缩 |
| `rocket_loader` | Configuration | Cloudflare 专有 JS 优化 | N/A |
| `hotlink_protection` | Configuration | 需要自定义 referer 检查逻辑 | Lambda@Edge |
| Device detection headers (UA regex) | Request Header Transform | CloudFront 提供原生设备检测 | Origin Request Policy + `CloudFront-Is-*-Viewer` headers |
| 含不可映射 CF 变量的动态值 | Request/Response Header Transform | CloudFront Functions 无法计算所有 Cloudflare 表达式 | 手动检查 |
| 非 path 表达式的 Cloud Connector | Cloud Connector | CloudFront cache behaviors 只能按 path pattern 匹配 | 手动配置 origin |
| 不允许/只读的 response headers | Response Header Transform | CloudFront 限制修改某些 headers（`Via`、`X-Amz-Cf-*` 等） | N/A |

### CORS `credentials: true` + 通配符 origin（不转换，报告 NON_CONVERTIBLE）

Cloudflare 规则如果同时设置 `Access-Control-Allow-Origin: *` 和 `Access-Control-Allow-Credentials: true`，本工具不转换，整条规则报告为 `NON_CONVERTIBLE`。

这个组合被 WHATWG Fetch（CORS）标准禁止。带凭证的响应如果 `Access-Control-Allow-Origin` 是 `*`，浏览器会拒绝。注意，拒绝的是浏览器，不是 CloudFront 的 Response Headers Policy。但就算把它生成出来，带凭证的请求也拿不到浏览器能接受的响应。CloudFront 没有忠实的等价配置，所以工具把它列进转换报告，而不是去猜。请在源头修正：改成具体的允许 origin，不要用 `*`；或者由源站返回正确的、按 origin 区分的 CORS 响应。

早期版本试过用 TLD 通配符绕过，把 `*` 换成 `*.com`、`*.net` 等约 60 个 TLD。这个绕过已经删除，因为它会悄悄改变 CORS 语义，不是忠实转换。

### CloudFront Function 大小限制

CloudFront Functions 有 **硬** 10 KB 大小限制（无法通过 Service Quotas 或 AWS Support 提高）。viewer 事件只使用 CloudFront Functions——本工具从不为 viewer-request/response 回退到 Lambda@Edge，因为 L@E 会增加延迟和每请求成本，并改变执行模型。

当某域名的 `viewer_request.js` 或 `viewer_response.js` 超过 10 KB 时，工具会先压缩；若仍超限，则**整个域名**报告为 `SIZE_EXCEEDED` 交由人工处理（CFF 无法部分部署，request/response 是一个逻辑单元）。工具不会静默丢弃操作，也不会迁移到 Lambda@Edge。可选做法是：简化/拆分该 host 的 Cloudflare 规则，或删除放不下的规则。（`origin_override` 始终留在 CFF 里，用 `cf.updateRequestOrigin`。Lambda@Edge 只用于 default-cache-behavior 的 TTL origin-response——不用于 viewer 事件，也不用于 custom error。）

### CloudFront 配额限制

配额标注为**软**（可提高）或**硬**（必须重新设计）。大多数软配额通过 Service Quotas 自助提高；少数（如 Functions per account）不在 Service Quotas 里，需要开 AWS Support case。转换报告会为每条警告标明是哪种，避免为不可提高的限制去提交请求。

| 资源 | 限制 | 软/硬 | 超出时的处理 |
|----------|-------|-------|---------------------------|
| 每账号 CloudFront Functions 数量 | 100 | 软（Support case） | Content-hash 去重自动共享相同 CFF（如 54 域名 → 5 CFF）。去重后检查；仍超限则在转换报告中警告。此配额**不**在 Service Quotas 里——需开 AWS Support case 提高，而非自助控制台 |
| 每账号 distributions 数量 | 500 | 软 | 警告（每个代理 host 一个 distribution） |
| 每账号 KeyValueStores 数量 | 50 | 软 | 警告（每个需要 KVS 的 host 一个） |
| 每个 distribution 的 cache behaviors | 75 | 软 | 校验报错 + 警告——提高配额或减少 Cloudflare 规则 |
| 每账号自定义 cache/ORP/RHP policy 数量 | 各 20 | 软 | 警告 |
| Cache policy headers / cookies / query strings (whitelist) | 各 10 | 软 | 校验报错 + 警告——配额提高（Service Quotas）之前配置无法部署 |
| Origin request policy headers | 10 | 软 | 警告 |
| 每个 policy 的 query/header/cookie **名称合计长度** | 1024 | 硬 | 警告（无法提高） |
| CloudFront Function 大小 | 10 KB | 硬 | 域名报告 `SIZE_EXCEEDED`（见上） |

### 没有 CloudFront 对应项的 Cloudflare 匹配字段

| 字段 | 原因 |
|-------|--------|
| `cf.edge.server_port`, `cf.zone.name`, `cf.metal.id`, `cf.ray_id` | Cloudflare 专有内部字段 |
| `cf.tls_client_auth.*` | mTLS 证书字段在 CloudFront Functions 中不可用 |
| `ip.src.subdivision_2_iso_code` | CloudFront 只提供一级行政区划 |
| `http.request.timestamp.sec/msec` | 在 CloudFront Functions 中用 `Date.now()` 代替 |

### Regex 限制

CloudFront path patterns 只支持 `*` 和 `?` 通配符——不支持 regex。当 Cloudflare 规则用了无法映射为单个通配符的 regex/复杂 path 表达式时：

- **Cache Rules**（TTL / cache-key 设置）：cache 设置作用于某个具体 behavior 的 cache policy，因此其 scope 必须能用该 behavior 的 path pattern 表达。表达不了的（regex、多字段 AND、取反 path）会被记录为 **non-convertible** 并上报——不会路由到 Lambda@Edge 条件式缓存 handler（那个 sink 曾经存在、无人消费、会静默丢规则，已删除）。
- **其他规则类型**（redirect、rewrite、header transform、cache **bypass**）：这些在 CloudFront Function 里运行，函数会逐请求计算完整条件。它们落在默认 `"*"` behavior，条件被渲染进 CFF JS（基于 `request.uri` 匹配），因此 regex/复杂 path 仍然有效——只是不作为独立的 cache behavior。

### 不可转换项的处理方式

不可转换的项目**不会被静默丢弃**。Pipeline 会：
1. 在 IR 中记录每一项，附带 `reason` 字符串
2. 汇总到 `conversion_report.md`（由 finalizer 生成）
3. 报告按域名和规则类型分组，方便人工审查

## WAF Pipeline——不能转换的内容

| 项目 | 原因 | 替代方案 |
|------|--------|-------------|
| Cloudflare Managed Rules (OWASP 等) | 用 AWS WAF 自己的 managed rule groups | AWS Managed Rules for WAF |
| Cloudflare 托管 **List**（`$cf.*`） | Cloudflare 自己维护的 IP 情报，不可导出 | AWS managed rule groups（见下文） |
| API Abuse Detection | Cloudflare 专有 ML 功能 | AWS WAF Bot Control + 自定义规则 |
| SaaS / mTLS 配置 | 架构根本不同 | 需要手动设计 |

### Cloudflare 托管 List（`$cf.*`）

Cloudflare 提供 5 个**托管 IP List**——它自己维护的 IP 威胁情报源，在表达式里用 `ip.src in $cf.open_proxies` 这样引用。它们仅限 Enterprise、由 Cloudflare 维护、**无法导出**，所以没法在 AWS 侧重建成 IP set。引用了托管 List 的规则条件因此不可转换：

| Cloudflare 托管 List | 最接近的 AWS 等价物 |
|----------------------|---------------------|
| `$cf.open_proxies` | Amazon IP reputation list / Anonymous IP list managed rule group |
| `$cf.anonymizer` | Anonymous IP list managed rule group |
| `$cf.vpn` | Anonymous IP list managed rule group |
| `$cf.malware` | Amazon IP reputation list managed rule group |
| `$cf.botnetcc` | Amazon IP reputation list managed rule group |

工具对引用了托管 List 的规则的处理方式：

- 该托管 List 条件会从规则里**丢弃**，并在转换报告里记录（带上面的 AWS 等价物）——不会被静默保留成空匹配或字面匹配。
- 如果托管 List 只是规则的**一个分支**（如 `... and ip.src in $cf.vpn`），规则其余部分照常转换（该分支被剪掉，规则变成 *partial*）。
- 如果它是某条**限速**规则的**全部**条件，限速会保留但变成无条件（限速永远可转换，只丢失托管 List 的 scope-down）。如果它是某条 **block/challenge** 自定义规则的全部条件，该规则会被丢弃——相应防护改由生成的 WebACL 已包含的 **Amazon IP reputation** 和 **Anti-DDoS** managed rule group 覆盖。请查看报告，如需更严格的覆盖，部署后再加上 **Anonymous IP list** managed rule group。

### AWS WAF 硬上限与工具的处理方式

AWS 对每个 WebACL 强制若干**不可提高**的上限（Service Quotas、Support 都不行）：

| 上限 | 限制 | 工具如何处理 |
|------|------|-------------|
| 每 WebACL 速率规则数 | 10 | 超出的速率规则被打包进被引用的 **rule group**（每组 ≤4 条），不计入这 10 条。 |
| 每 WebACL 引用语句数 | 50（IP set + regex set + rule group + **托管规则组**引用都计入） | 超出的 IP set 引用被打包进 rule group；WebACL 每个 group 只算 1 条引用。 |
| 每 WebACL 的 WCU | 5000（超过 1500 产生额外费用） | 从组装好的模板精确计算。若某 WebACL 超过 5000，工具报告 `STATUS: BLOCKED`——打包无法降低，必须简化规则。 |
| 每个 rule group | ≤4 速率规则、≤50 引用、≤5000 WCU | packer 每组填到 ≤4 速率规则 / ≤50 引用、以及 **4500 WCU 预算**（5000 上限减去安全余量），超过就开新组。 |

packer 保留 Cloudflare 固定的阶段顺序（custom → rate → managed），并在规则移入 rule group 时把 label key 改写成正确形式。因此即使配置引用远超 50 个 IP set，默认输出仍是 **2 个 WebACL**——50 引用上限不再强制 per-host 拆分。只有当某 WebACL 的 WCU 超过 5000、或单条规则复杂到无法装入一个 rule group 时才无法部署（`STATUS: BLOCKED`，模板仍会写出供检查）。

### 会改变的速率限制语义

- **`mitigation_timeout`（封禁时长）会丢失。** Cloudflare 可在触发后固定封禁一段时间；AWS WAF 只在滑动窗口速率持续超限时封禁（速率下降后约 ≤30s 解封）。AWS 没有对应能力，因此这个字段不会被带过来——速率规则本身仍会转换（阈值 + 窗口），只是丢掉固定封禁时长。这是整体功能层面的限制，在此文档说明；生成的部署报告不会逐条标注。
- **过低的阈值会被放大，不会被丢弃。** AWS 每个评估窗口（{60,120,300,600} 秒）最低速率是 10；低于此的 Cloudflare 速率会被放大到第一个合法窗口，兜底为 10/600s。略微宽松，报告中注明。
- **计数器是 per-WebACL-实例的。** 一个 WebACL 挂到 N 个 CloudFront distribution 会跨它们共享一个计数器（符合 Cloudflare 的 zone-wide 语义）。工具不合并不同的速率规则（共享计数器会让一个跨路径分散请求的客户端以远低于各规则阈值的量被限流）。

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
- **Lambda@Edge origin-response**——当某规则需要它时（default-cache-behavior 的 TTL handler），这是**全自动**的：IAM role、archive、Lambda 函数和 `main.tf` 中的 `qualified_arn` 引用都由 scaffold 生成。工具**不**为 custom-error 规则生成 Lambda@Edge origin-response，也不再生成 CFF+KVS 内联错误页（该路径已退役）。Custom error 规则只有在 CloudFront 原生 `custom_error_response` 能表达 status/path/remap 时才转换，否则报告为 non-convertible（见上面的 Custom Error 行）。viewer 事件也没有 Lambda@Edge——超过 10 KB 的 CFF 会报告 `SIZE_EXCEEDED` 交由人工处理，绝不拆分到 L@E。
- **DNS 切换**——工具会生成 CloudFront distributions，但不会动 DNS 记录。确认配置没问题后，你自己更新 DNS 指向 CloudFront。
