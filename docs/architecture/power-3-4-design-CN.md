# Power 3-4 架构设计：Cloudflare到CloudFront迁移

**版本：** 1.0  
**最后更新：** 2026-01-13

---

## 目录

1. [概述](#概述)
2. [架构总览](#架构总览)
3. [Power 3: cloudflare-cdn-config-analyzer](#power-3-cloudflare-cdn-config-analyzer)
4. [Power 4: cloudfront-migration-orchestrator](#power-4-cloudfront-migration-orchestrator)
5. [转换器Powers (5-9)](#转换器powers-5-9)
6. [完整工作流](#完整工作流)
7. [关键设计决策](#关键设计决策)
8. [实施注意事项](#实施注意事项)
9. [附录](#附录)

---

## 概述

本文档描述了使用多skill方法将Cloudflare CDN配置迁移到AWS CloudFront的架构设计。

### 核心设计原则

- ✅ **基于实现方式的任务分配** - 根据CloudFront实现方式分配任务（而非Cloudflare规则类型）
- ✅ **先转换Functions，再转换配置** - 先转换CloudFront Functions和Lambda@Edge，然后生成Terraform配置
- ✅ **独立会话** - 在独立的Kiro CLI会话中执行每个skill，避免context污染
- ✅ **无状态设计** - 使用Markdown文件在skills之间传递状态
- ✅ **成本意识** - 将高成本方案（Viewer Lambda@Edge）标记为不可转换

### 为什么需要这个架构？

**问题：** Cloudflare和CloudFront的架构根本不同：
- **Cloudflare：** Zone级别的规则，灵活的Match-Action模式
- **CloudFront：** Distribution级别的配置，以Cache Behavior为核心概念

**解决方案：** 多阶段转换，人工参与决策：
1. **分析** - 解析Cloudflare配置并确定实现方式
2. **决策** - 用户提供业务上下文和成本接受度
3. **编排** - 为转换器skills生成任务分配
4. **转换** - 在独立会话中执行专门的转换器
5. **部署** - 应用Terraform配置

### 为什么按Proxied DNS记录分组规则？

**关键设计决策：** Power 3按proxied DNS记录（域名）组织所有规则。这对于三个原因至关重要：

#### 1. CloudFront架构对齐
- **一个proxied DNS记录 = 一个CloudFront Distribution**
- 每个Distribution是独立的配置单元，有自己的：
  - Origin配置
  - Cache Behaviors
  - Policies（Cache、Origin Request、Response Headers）
  - Function/Lambda关联
  - TLS证书

#### 2. 清晰的任务分配
- Power 4为每个域名生成独立的任务文件
- Power 9为每个Distribution生成独立的Terraform资源
- 用户可以逐个域名审查和部署配置

#### 3. CloudFront Function大小限制（10KB）
**这是一个关键的技术约束：**

- CloudFront Functions有**硬性10KB大小限制**
- 如果所有域名共用一个function，即使minified也可能超过10KB
- 通过按域名分组规则，我们可以拆分成多个function：

**不拆分（所有域名在一个function中）：**
```javascript
// 一个巨大的viewer-request function，包含所有域名
function handler(event) {
  // example.com: 20条规则
  // api.example.com: 15条规则  
  // cdn.example.com: 18条规则
  // 总计：可能超过10KB！❌
}
```

**拆分后（每个域名一个function）：**
```javascript
// functions/viewer-request-example-com.js (3KB)
function handler(event) {
  // 仅example.com的20条规则
}

// functions/viewer-request-api-example-com.js (2.5KB)
function handler(event) {
  // 仅api.example.com的15条规则
}

// 每个都在10KB限制内！✅
```

**基于域名拆分的好处：**

| 方面 | 单个Function（所有域名） | 按域名拆分 |
|-----|------------------------|-----------|
| Function大小 | 可能超过10KB ❌ | 每个<10KB ✅ |
| 部署风险 | 一个function影响所有域名 | 独立部署 |
| 调试难度 | 难以定位问题 | 清晰的域名特定逻辑 |
| 性能 | 执行不必要的检查 | 只运行相关逻辑 |

**注意：** Lambda@Edge没有严格的大小限制（未压缩50MB，压缩后1MB），但基于域名的拆分仍然提供了清晰性、独立部署和调试的好处。

---

## 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│                    Power 3: 分析器                          │
│  输入: Cloudflare配置 → 输出: 分析报告 + 实施计划          │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    用户填写决策
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                 Power 4: 编排器                             │
│  输入: 计划 + 决策 → 输出: 任务分配                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
              ┌───────────────┴───────────────┐
              ↓                               ↓
┌─────────────────────────┐   ┌─────────────────────────┐
│ Power 5: Viewer Request │   │ Power 6: Viewer Response│
│   CloudFront Function   │   │   CloudFront Function   │
└─────────────────────────┘   └─────────────────────────┘
              ↓                               ↓
┌─────────────────────────┐   ┌─────────────────────────┐
│ Power 7: Origin Request │   │ Power 8: Origin Response│
│      Lambda@Edge        │   │      Lambda@Edge        │
└─────────────────────────┘   └─────────────────────────┘
              ↓                               ↓
              └───────────────┬───────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│          Power 9: CloudFront配置生成器                      │
│  输入: 任务 + Functions + Lambda → 输出: Terraform         │
└─────────────────────────────────────────────────────────────┘
```

**注意：** Viewer Request/Response Lambda@Edge被标记为**不可转换**，因为成本太高（比Origin Lambda贵10-100倍）。

---

## Power 3: cloudflare-cdn-config-analyzer

### 职责
配置分析 + 实现方式判断 + 用户决策收集

### 触发关键词
- `analyze cloudflare cdn config`
- `analyze cloudflare cdn configuration`
- `分析cloudflare cdn配置`

### 输入文件
Cloudflare配置文件（所有CDN相关）：
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

### 输出文件

#### 1. `cdn-config-analysis.md`
按proxied DNS record分组的配置分析报告。

**结构：**
```markdown
# Cloudflare CDN配置分析

## 摘要
- Proxied DNS记录总数: 3
- 规则总数: 45
- 可转换规则: 38
- 不可转换规则: 7

## DNS记录: example.com
- 类型: CNAME
- 值: origin.example.com
- 规则总数: 15

### Cache规则 (5条)
| 规则ID | 优先级 | 匹配表达式 | 动作 | 设置 |
|--------|--------|-----------|------|------|
| cache-1 | 1 | `http.request.uri.path matches "^/api/.*"` | 设置cache TTL | TTL: 0s |
| cache-2 | 2 | `http.request.uri.path matches ".*\\.jpg$"` | 设置cache TTL | TTL: 86400s |

### Origin规则 (3条)
[类似结构...]

### Transform规则 (7条)
[类似结构...]

---

## DNS记录: api.example.com
[类似结构...]

---

## 全局规则（无http.host匹配）
这些规则可能应用于多个DNS记录。需要用户决策。

### Cache规则 (2条)
[类似结构...]
```

#### 2. `implementation-plan.md`
**核心输出**：为每条规则确定实现方式。

**结构：**
```markdown
# CloudFront实施计划

## DNS记录: example.com

### 需要Viewer Request CloudFront Function的规则
| 规则ID | 原始类型 | 规则摘要 | 原因 |
|--------|---------|---------|------|
| redirect-2 | Redirect Rule | 重定向 `/old` 到 `/new` | 简单重定向逻辑 |
| header-3 | Request Header Transform | 添加 `X-Custom-Header` | 简单header操作 |

**预估Function大小：** ~2KB  
**复杂度：** 低

---

### 需要Viewer Response CloudFront Function的规则
| 规则ID | 原始类型 | 规则摘要 | 原因 |
|--------|---------|---------|------|
| header-5 | Response Header Transform | 添加安全headers到响应 | 简单响应header操作 |

**预估Function大小：** ~1KB  
**复杂度：** 低

---

### 需要Origin Request Lambda@Edge的规则
| 规则ID | 原始类型 | 规则摘要 | 原因 |
|--------|---------|---------|------|
| origin-3 | Origin Rule | 基于cookie动态选择origin | 复杂逻辑，需要访问cookie |
| cache-8 | Cache Rule | 复杂正则表达式匹配 | 正则表达式对CloudFront Function太复杂 |

**预估Lambda大小：** ~5KB  
**复杂度：** 中等  
**成本影响：** 中等（仅在cache miss时运行，约10-30%的请求）

---

### 需要Origin Response Lambda@Edge的规则
| 规则ID | 原始类型 | 规则摘要 | 原因 |
|--------|---------|---------|------|
| header-7 | Response Header Transform | 基于origin添加CORS headers | 需要动态修改响应headers |
| error-2 | Custom Error Rule | 带动态内容的自定义错误页面 | 需要生成响应body |

**预估Lambda大小：** ~3KB  
**复杂度：** 低  
**成本影响：** 中等（仅在cache miss时运行，约10-30%的请求）

---

### 需要CloudFront配置/Policy的规则
| 规则ID | 原始类型 | 规则摘要 | 实现方式 |
|--------|---------|---------|---------|
| cache-1 | Cache Rule | 缓存所有 `*.jpg` 1天 | Cache Behavior (path: `*.jpg`) + Cache Policy (TTL: 86400s) |
| cache-2 | Cache Rule | 将query string `version` 加入cache key | Cache Policy (query string: `version`) |
| header-2 | Response Header Transform | 添加 `X-Frame-Options: DENY` | Response Headers Policy |
| compress-1 | Compression Rule | 为text/*启用Gzip | Cache Policy (compression: Gzip) |

**配置复杂度：** 低

---

### 需要Viewer Lambda@Edge的规则（高成本 - 不可转换）
| 规则ID | 原始类型 | 规则摘要 | 为何需要Viewer Lambda | 预估成本影响 |
|--------|---------|---------|---------------------|-------------|
| auth-1 | Custom Rule | 每个请求实时JWT验证 | 必须在每个请求上运行，包括cache hit | **严重：每百万请求$50-500** |

⚠️ **警告：** 这些规则需要Viewer Request/Response Lambda@Edge，它在每个请求上运行，包括cache hit。这比Origin Request/Response Lambda**贵10-100倍**。

**成本对比：**
| Lambda类型 | 执行频率 | 相对成本 | 典型使用场景 |
|-----------|---------|---------|-------------|
| Viewer Request Lambda | 每个请求 | 100x | 极少推荐 |
| Origin Request Lambda | 仅cache miss | 10x | 常用 |
| Origin Response Lambda | 仅cache miss | 10x | 常用 |
| Viewer Response Lambda | 每个请求 | 100x | 极少推荐 |

**建议：** 
1. 审查需求是否真的必要
2. 考虑替代实现方案：
   - 能否用CloudFront Function处理？（便宜得多）
   - 能否推迟到Origin Request Lambda？（便宜10倍）
   - 能否用AWS WAF处理？（针对安全规则）
3. 如果确认必要，手动实现并配置成本监控
4. 设置CloudWatch账单告警

**这些规则被标记为不可转换，需要在明确了解成本的情况下手动实现。**

---

### 不可转换的规则（其他原因）
| 规则ID | 原始类型 | 规则摘要 | 原因 | 需要的手动操作 |
|--------|---------|---------|------|---------------|
| origin-1 | Origin Rule | Origin是IP地址 192.168.1.1 | CloudFront不支持IP origin | 使用ALB/NLB作为origin，或使用域名 |
| cache-9 | Cache Rule | 使用Cloudflare专有字段 `cf.bot_management.score` | CloudFront中不可用 | 使用AWS WAF Bot Control实现 |

---

## DNS记录: api.example.com
[每个DNS记录的类似结构...]

---

## 全局规则分配
这些规则没有 `http.host` 匹配字段。用户必须指定哪些DNS记录需要这些规则。

| 规则ID | 原始类型 | 规则摘要 | 应用到哪些DNS记录（用户填写） |
|--------|---------|---------|------------------------------|
| cache-global-1 | Cache Rule | 缓存所有静态资源 | [填写: All / example.com, api.example.com] |
| header-global-2 | Response Header Transform | 添加安全headers | [填写: All / example.com] |
```

#### 3. `user-decisions-template.md`
用户填写决策的模板。

**结构：**
```markdown
# CloudFront迁移用户决策

## 说明
请填写以下决策。此文件将被Power 4（编排器）用于生成任务分配。

---

## DNS记录: example.com

### 内容类型
**问题：** 此DNS记录提供静态内容、动态内容，还是两者都有？

**选项：**
- `Static` - 主要是静态文件（图片、CSS、JS）。高cache命中率。Lambda@Edge成本可接受。
- `Dynamic` - 主要是动态API响应。低cache命中率。尽量避免Lambda@Edge。
- `Both` - 混合内容。需要多个cache behavior。

**您的决策：** [填写: Static / Dynamic / Both]

**如果是"Both"：** 这需要多个cache behavior和不同的policy。这很复杂，可能需要手动配置。您能接受这种复杂度吗？
- [填写: Yes / No]

---

### Lambda@Edge接受度
**问题：** 您愿意为复杂规则使用Origin Request/Response Lambda@Edge吗？

**成本影响：**
- Origin Request Lambda: 在cache miss时运行（静态站点约10-30%的请求）
- Origin Response Lambda: 在cache miss时运行（静态站点约10-30%的请求）
- 预估成本: 每百万请求$0.20（加上计算时间）

**您的决策：** [填写: Yes / No]

**如果No：** 复杂规则将被标记为"需要手动实现"

---

### 高成本功能（Viewer Lambda@Edge）
以下规则需要Viewer Request/Response Lambda@Edge，它在每个请求上运行（包括cache hit），比Origin Lambda**贵10-100倍**。

| 规则ID | 预估成本 | 替代方案 |
|--------|---------|---------|
| auth-1 | 每百万请求$50-500 | 考虑AWS WAF、CloudFront Function或Origin Request Lambda |

**问题：** 您想手动实现这些规则，还是探索替代方案？

**选项：**
- `Manual` - 我将在完全了解成本的情况下手动实现
- `Alternative` - 帮我找替代方案
- `Skip` - 暂时跳过这些规则

**您的决策：** [填写: Manual / Alternative / Skip]

---

### 自定义备注（可选）
[任何额外的上下文或需求]

---

## DNS记录: api.example.com
[每个DNS记录的类似结构...]

---

## 全局规则分配

| 规则ID | 应用到哪些DNS记录 |
|--------|------------------|
| cache-global-1 | [填写: All / example.com, api.example.com] |
| header-global-2 | [填写: All / example.com] |

---

## 证书配置

**问题：** 您已经为这些域名申请了ACM证书吗？

**您的决策：** [填写: Yes / No]

**如果Yes，提供ARN：**
- example.com: [填写: <ACM_CERTIFICATE_ARN>]
- api.example.com: [填写: <ACM_CERTIFICATE_ARN>]

**如果No：** Power 9将生成申请证书的说明。

---

## 部署偏好

**问题：** 您想一次部署所有distribution，还是逐个部署？

**您的决策：** [填写: All at once / One by one]

**问题：** 您需要回滚计划吗？

**您的决策：** [填写: Yes / No]
```

### 核心逻辑：实现方式判断

Power 3必须使用以下决策树为每条规则确定实现方式：

```
对于每条规则:
  ├─ 是否修改请求？
  │   ├─ CloudFront Function能处理吗？
  │   │   - 简单逻辑（URI重写、重定向、header操作）
  │   │   - 无外部API调用
  │   │   - 无请求body访问
  │   │   - 总function大小 < 10KB
  │   │   → Viewer Request CloudFront Function ✅
  │   │
  │   ├─ Origin Request Lambda能处理吗？
  │   │   - 复杂逻辑或外部API调用
  │   │   - 需要请求body访问
  │   │   - 可接受仅在cache miss时运行
  │   │   → Origin Request Lambda@Edge ✅
  │   │
  │   └─ 需要Viewer Request Lambda？
  │       - 必须在每个请求上运行（包括cache hit）
  │       - 无法推迟到origin request
  │       → ⚠️ 标记为不可转换（高成本）
  │       → 需要手动审查和实现
  │
  ├─ 是否修改响应？
  │   ├─ Response Headers Policy能处理吗？
  │   │   - 仅静态headers
  │   │   → Response Headers Policy ✅
  │   │
  │   ├─ Viewer Response CloudFront Function能处理吗？
  │   │   - 简单响应header操作
  │   │   - 无响应body修改
  │   │   - 总function大小 < 10KB
  │   │   → Viewer Response CloudFront Function ✅
  │   │
  │   ├─ Origin Response Lambda能处理吗？
  │   │   - 复杂header逻辑
  │   │   - 响应body修改
  │   │   - 可接受仅在cache miss时运行
  │   │   → Origin Response Lambda@Edge ✅
  │   │
  │   └─ 需要Viewer Response Lambda？
  │       - 必须在每个请求上修改响应（包括cache hit）
  │       - 无法在origin response处理
  │       → ⚠️ 标记为不可转换（高成本）
  │       → 需要手动审查和实现
  │
  ├─ 仅是配置？
  │   ├─ Cache TTL、Query String处理、压缩
  │   │   → Cache Policy ✅
  │   │
  │   ├─ Origin选择、Host header（静态）
  │   │   → Origin + Origin Request Policy ✅
  │   │
  │   └─ 静态响应headers
  │       → Response Headers Policy ✅
  │
  └─ 不支持？
      → 标记为不可转换
```

### 实现方式参考表

| Cloudflare规则 | 实现方式 | 原因 |
|---------------|---------|------|
| Cache Rule: 匹配 `/api/*`, TTL=0 | Cache Behavior + Cache Policy | 简单path pattern + cache设置 |
| Cache Rule: URI上的复杂正则 | Viewer Request Function | 需要动态检查 |
| Cache Rule: 基于cookie值匹配 | Origin Request Lambda | 需要cookie访问，在cache miss时运行 |
| Origin Rule: 更改host header（静态） | Origin Request Policy | 简单配置 |
| Origin Rule: 基于cookie动态选择origin | Origin Request Lambda | 需要基于cookie的决策 |
| Redirect Rule: `/old` → `/new` | Viewer Request Function | 简单重定向 |
| Redirect Rule: 带捕获组的复杂正则 | Viewer Request Function | CloudFront Function支持正则 |
| Request Header Transform: 添加静态header | Viewer Request Function | 简单header操作 |
| Request Header Transform: JWT验证（每个请求） | ⚠️ 不可转换（Viewer Request Lambda） | 高成本，手动实现 |
| Response Header Transform: 添加 `X-Frame-Options` | Response Headers Policy | 静态header |
| Response Header Transform: 添加安全headers | Viewer Response Function | 简单响应header操作 |
| Response Header Transform: 基于origin添加CORS | Origin Response Lambda | 基于请求的动态header |
| Response Header Transform: 加密响应body（每个请求） | ⚠️ 不可转换（Viewer Response Lambda） | 高成本，手动实现 |
| Compression Rule: 启用Gzip | Cache Policy | CloudFront原生功能 |
| Custom Error Rule: 返回自定义错误页面 | CloudFront Distribution配置 | 原生功能 |
| Custom Error Rule: 动态错误页面内容 | Origin Response Lambda | 需要生成响应body |

### 特殊情况

#### 1. SaaS检测
**关键：** 首先读取 `SaaS-Fallback-Origin.txt`。

如果API返回HTTP 200，包含 `origin` 字段和 `status: "active"`：
- **立即停止转换**
- 输出消息："检测到SaaS配置。Cloudflare Custom Hostnames和CloudFront SaaS有不同的实现模型。这需要单独的skill或手动迁移。转换终止。"

如果API返回其他结果，继续转换。

#### 2. IP地址Origin
如果DNS记录值是IP地址（A或AAAA记录）：
- 标记为不可转换
- 原因：CloudFront不支持基于IP的origin
- 手动操作：使用ALB/NLB作为origin，或使用域名

#### 3. 复杂内容类型（静态和动态都有）
如果用户为内容类型选择"Both"：
- 需要多个cache behavior和不同的policy
- 自动转换复杂度高
- 建议：手动配置或拆分成独立的distribution

#### 4. Viewer Lambda@Edge需求
如果规则真的需要Viewer Request/Response Lambda@Edge：
- 标记为不可转换，带高成本警告
- 提供成本估算（每百万请求$50-500）
- 建议替代方案（CloudFront Function、Origin Lambda、AWS WAF）
- 需要用户明确确认手动实现

---

## Power 4: cloudfront-migration-orchestrator

### 职责
任务分配和执行顺序管理（不执行转换）

### 触发关键词
- `orchestrate cloudfront migration`
- `generate cloudfront migration tasks`
- `编排cloudfront迁移`
- `生成cloudfront迁移任务`

### 输入
- `implementation-plan.md`（来自Power 3）
- `user-decisions.md`（用户填写的版本）

### 输出文件

继续下一部分...

详细的任务分配文件、执行指南、转换器Powers说明、完整工作流、关键设计决策等内容，请参考英文版文档 `skill-3-4-architecture-design-EN.md`。

中文版的核心内容已在上文呈现，包括：
- Power 3的职责、输入输出、实现方式判断逻辑
- Power 4的职责和触发关键词
- 特殊情况处理（SaaS检测、IP地址Origin、Viewer Lambda@Edge高成本警告）

完整的任务文件模板、执行指南、Powers 5-9的详细说明、文件结构等，与英文版完全对应，建议直接参考英文版文档。

---

## 关键要点总结

### 架构创新

1. **基于域名分组规则**
   - 一个proxied DNS记录 = 一个CloudFront Distribution
   - 满足CloudFront Function 10KB大小限制的关键策略
   - 每个域名的规则生成独立的function文件
   - 支持独立部署和调试

2. **基于实现方式的任务分配**
   - 不按Cloudflare规则类型分配任务
   - 按CloudFront实现方式（Function、Lambda、Policy、Config）分配任务
   - 符合CloudFront的架构特点

3. **多阶段转换流程**
   - 分析阶段：解析配置，判断实现方式，按域名分组
   - 决策阶段：用户提供业务上下文
   - 编排阶段：生成任务分配
   - 转换阶段：执行专门的转换器
   - 部署阶段：应用Terraform配置

4. **成本意识设计**
   - 识别高成本方案（Viewer Lambda@Edge）
   - 标记为不可转换，需要手动实现
   - 提供成本估算和替代方案
   - 符合AWS最佳实践

5. **无状态工作流**
   - 通过Markdown文件传递状态
   - 支持分批处理
   - 允许重新执行单个步骤
   - 避免context window限制

### Function大小管理策略

| 策略 | 说明 | 好处 |
|-----|------|------|
| 按域名拆分 | 每个域名生成独立的function文件 | 避免超过10KB限制 |
| 大小估算 | Power 3估算每个域名的function大小 | 提前发现潜在问题 |
| 超限警告 | 如果单个域名可能超过10KB，提供建议 | 引导用户优化或使用Lambda |
| Lambda替代 | 复杂规则可以使用Origin Request Lambda | 无严格大小限制 |

### Skills清单

| Skill | 职责 | 输出 |
|-------|-----|------|
| Power 3 | 配置分析和实现方式判断（按域名分组） | 分析报告、实施计划、用户决策模板 |
| Power 4 | 任务编排和执行顺序管理 | 任务分配文件、执行指南 |
| Power 5 | 转换Viewer Request CloudFront Function（每域名一个文件） | Function代码 |
| Power 6 | 转换Viewer Response CloudFront Function（每域名一个文件） | Function代码 |
| Power 7 | 转换Origin Request Lambda@Edge | Lambda代码 |
| Power 8 | 转换Origin Response Lambda@Edge | Lambda代码 |
| Power 9 | 生成CloudFront Terraform配置 | Terraform文件、部署指南 |

### 成本对比

| 方案 | 执行频率 | 每百万请求成本 | 使用场景 |
|-----|---------|---------------|---------|
| CloudFront Function (Viewer Request) | 每个请求 | $0.10 | 简单请求操作 |
| CloudFront Function (Viewer Response) | 每个请求 | $0.10 | 简单响应header操作 |
| Lambda@Edge (Origin Request) | 仅cache miss (~10-30%) | $0.20 + 计算 | 复杂请求逻辑 |
| Lambda@Edge (Origin Response) | 仅cache miss (~10-30%) | $0.20 + 计算 | 复杂响应逻辑 |
| Lambda@Edge (Viewer Request) | 每个请求 | $2.00 + 计算 | ⚠️ 极少推荐 |
| Lambda@Edge (Viewer Response) | 每个请求 | $2.00 + 计算 | ⚠️ 极少推荐 |
| Response Headers Policy | 每个请求 | $0（包含） | 静态响应headers |
| Cache Policy | 每个请求 | $0（包含） | Cache配置 |

### 文件结构

```
project-root/
├── cloudflare_config/          # 输入: Cloudflare配置文件
│   ├── DNS.txt
│   ├── Cache-Rules.txt
│   └── ...
│
├── cdn-config-analysis.md      # Power 3输出（按域名分组）
├── implementation-plan.md      # Power 3输出（按域名分组）
├── user-decisions-template.md  # Power 3输出
├── user-decisions.md           # 用户填写版本
│
├── task-assignments/           # Power 4输出
│   ├── task-viewer-request-function.md
│   ├── task-viewer-response-function.md
│   ├── task-origin-request-lambda.md
│   ├── task-origin-response-lambda.md
│   └── task-cloudfront-config.md
│
├── execution-guide.md          # Power 4输出
│
├── functions/                  # Powers 5-6输出
│   ├── viewer-request-*.js
│   ├── viewer-response-*.js
│   └── README.md
│
├── lambda/                     # Powers 7-8输出
│   ├── origin-request-*/
│   └── origin-response-*/
│
└── terraform/                  # Power 9输出
    ├── main.tf
    ├── policies.tf
    ├── functions.tf
    ├── lambda.tf
    └── README_deployment.md
```

### 执行流程

1. **会话1：分析**（Power 3）
   - 读取Cloudflare配置
   - 判断实现方式
   - 生成分析报告和决策模板

2. **用户填写决策**
   - 内容类型（Static/Dynamic/Both）
   - Lambda@Edge接受度
   - 高成本功能处理方式

3. **会话2：编排**（Power 4）
   - 读取计划和决策
   - 生成任务分配文件
   - 生成执行指南

4. **会话3-6：转换**（Powers 5-8）
   - 每个skill在独立会话中执行
   - 生成Functions和Lambda代码

5. **会话7：配置生成**（Power 9）
   - 生成Terraform配置
   - 引用已生成的Functions和Lambda
   - 生成部署指南

### 为什么这样设计？

1. **按域名分组规则**
   - 一个域名对应一个Distribution
   - 满足10KB function大小限制
   - 支持独立部署和调试
   - 逻辑清晰，便于维护

2. **独立会话避免context污染**
   - 每个skill有干净的context
   - 防止AI幻觉
   - 允许重新执行失败的步骤

3. **任务文件传递状态**
   - 无需维护状态
   - 用户可以审查和修改
   - 清晰的调试记录

4. **先转换Functions**
   - CloudFront配置引用Functions
   - 验证Function大小限制（10KB）
   - 提前发现需要拆分或优化的情况
   - 确保依赖顺序正确

5. **标记高成本方案为不可转换**
   - AI无法判断成本是否可接受
   - 需要用户明确知情同意
   - 符合AWS最佳实践

---

## 下一步

1. 实现Power 3（分析器）
   - 实现按域名分组逻辑
   - 实现function大小估算
   - 实现超限警告机制
2. 用真实Cloudflare配置测试
3. 完善实现方式判断逻辑
4. 迭代实现Powers 4-9
5. 创建详细的参考文档

---

**完整的英文版文档：** `power-3-4-design-EN.md`
