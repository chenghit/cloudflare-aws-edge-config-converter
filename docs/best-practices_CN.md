[English](./best-practices.md)

# 最佳实践

## ✅ 推荐

1. **一次只转换一个项目**
   - 完成一个域名的转换后，开启新的聊天会话
   - 避免在同一会话中混合多个项目的配置

2. **提供 CloudflareBackup 目录路径**
   - 示例：`Convert security rules in /path/to/cloudflare-backup to AWS WAF`
   - Kiro 会自动在备份目录中定位配置文件

3. **使用明确的关键词**
   - WAF：提到 "security rules" 或 "AWS WAF"
   - CloudFront Functions：提到 "transformation rules" 或 "CloudFront Functions"
   - CDN 分析：提到 "CDN configuration" 或 "CDN config"

## ❌ 避免

1. **不要在一个会话中混合多个项目**
   - 会导致上下文混乱和幻觉

2. **不要在一个会话中混合不同规则类型**
   - 每种规则类型使用不同的 subagent，有独立的上下文。混合使用可能导致 agent 丢失之前的工作进度。

3. **不要使用模糊描述**
   - ❌ "帮我转换 Cloudflare 配置"
   - ✅ "将 Cloudflare 安全规则转换为 AWS WAF 配置"
