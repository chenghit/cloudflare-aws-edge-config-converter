[English](./troubleshooting.md)

# 故障排除

## Subagent 未正确激活

**问题**：编排器自动调用 subagent 时，subagent 没有按 skill 的工作流执行

**症状**：
- Agent 生成临时分析而不是按定义的步骤执行
- 输出文件未创建或文件名错误
- Agent 没有读取参考文档

**解决方案**：
1. 先尝试手动调用：`/agent swap cf-waf-analyzer`，然后给出指令。如果手动调用正常，问题出在编排器路由，不是 skill 本身。
2. 检查安装：确认 `~/.kiro/agents/cf-waf-analyzer.json` 是否存在
3. 重启 Kiro CLI：退出并重新启动 `kiro-cli chat`
4. 列出可用 agent：使用 `/agent list` 查看已安装的 subagent

## 关键词未触发正确的 Skill

**问题**：编排器没有路由到正确的 subagent

**解决方案**：在请求中使用明确的关键词：
- WAF：说 "convert **security rules**" 或 "convert to **AWS WAF**"
- CloudFront Functions：说 "convert **transformation rules**" 或 "convert to **CloudFront Functions**"
- CDN：说 "analyze **CDN configuration**" 或 "analyze **CDN config**"

**示例**：
- ❌ 模糊："analyze my cloudflare config files"
- ✅ 明确："convert **security rules** in /path/to/config to **AWS WAF**"

## 转换结果不符合预期

**问题**：生成的配置不符合预期

**解决方案**：
1. 检查 Cloudflare 配置文件是否完整
2. 在新会话中重新尝试转换
3. 考虑分批转换复杂配置

## 上下文混乱

**问题**：AI 混淆了不同项目或不同规则类型

**解决方案**：
1. 立即停止当前会话
2. 开启新会话
3. 每次只为一个项目转换一种规则类型

## CDN Python 脚本报错

**问题**：CDN Stage 3–6（Python 脚本）执行失败

**症状**：
- `cdn-preprocess.py` 退出码 1（部分失败）或 2（全部失败）
- `cdn-validate-chunk.py` 报告某些域名 FAIL
- `cdn-finalize.py` 或 `cdn-validate-final.py` 报错退出

**解决方案**：
1. 查看错误输出——Python 脚本会在 stderr 打印具体错误信息
2. 预处理失败：查看 `cloudflare-to-aws-cdn/ir/accumulator/<domain>.error.json`
3. 校验失败：查看 `cloudflare-to-aws-cdn/ir/validation/chunk/<domain>-v1.json` 或 `final/<domain>-v2.json`
4. 常见原因：
   - `domain_scope.json` 未找到 → 先运行 Stage 2（Input Validator）
   - Cloudflare 配置 JSON 解析错误 → 检查 CloudflareBackup 导出是否完整
   - Zone 目录未找到 → 确认配置路径指向 CloudflareBackup 根目录（包含 `account/` 和 zone 子目录）
5. 重试单个域名：`python3 cdn-preprocess.py <config_path> cloudflare-to-aws-cdn --domain <hostname>`
