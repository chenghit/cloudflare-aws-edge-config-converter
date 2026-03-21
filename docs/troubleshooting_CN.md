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

## CloudFront Console 无法编辑 Cache Behavior

**问题**：在 CloudFront console 点击某个 cache behavior 时显示 "Your CloudFront distribution behavior configuration page failed to load"

**原因**：Distribution 状态还是 `InProgress`（正在部署到边缘节点）。部署完成前 console 无法加载 behavior 编辑页面。

**解决方案**：
1. 检查 distribution 状态：`aws cloudfront get-distribution --id <DIST_ID> --query 'Distribution.Status'`
2. 等状态变成 `Deployed`。通常需要 5–15 分钟，cache behavior 多或有 Lambda@Edge 关联的会更久。
3. 或者用命令等待：`aws cloudfront wait distribution-deployed --id <DIST_ID>`

## Lambda@Edge 函数在 Destroy 时无法删除

**问题**：`terraform destroy` 报错 `InvalidParameterValueException: Lambda was unable to delete ... because it is a replicated function`

**原因**：CloudFront distribution 删除后，边缘节点上的 Lambda@Edge 副本由 AWS 异步清理。在所有副本清理完之前，Lambda 函数本身无法删除。通常需要 30–60 分钟，偶尔可能需要几个小时。

**解决方案**：

1. **等待后重试**（推荐）：等 30–60 分钟后重新执行 `terraform destroy`，副本会自动清理。

2. **从 state 中移除，稍后自动清理**：如果不想等：
   ```bash
   cd cloudflare-to-aws-cdn/terraform/domains/<sanitized_domain>

   # 查看剩余资源
   terraform state list

   # 从 state 中移除 Lambda 函数（AWS 会在副本清理后自动删除）
   terraform state rm 'aws_lambda_function.<resource_name>'

   # 销毁剩余资源
   terraform destroy -auto-approve
   ```
   副本清理完成后 Lambda 函数会被 AWS 自动删除，无需手动操作。

3. **检查副本状态**：可以查看副本是否还存在：
   ```bash
   aws lambda list-versions-by-function --function-name cfcdn-<sanitized_domain>-origin-response --query 'Versions[?Version!=`$LATEST`].[Version,State]'
   ```

**注意**：这是 AWS 侧的限制，不是 Terraform 或工具的 bug。通过 AWS Console 或 CLI 手动删除也会遇到同样的问题。

## Lambda@Edge IAM Role 未被 Destroy

**问题**：`terraform apply` 报错 `EntityAlreadyExists: Role with name cfcdn-<domain>-lambda-edge already exists`，之前已经跑过 `terraform destroy`

**原因**：Lambda@Edge 函数会被复制到 CloudFront 边缘节点。销毁 distribution 后，AWS 异步清理这些副本——可能需要几个小时。副本存在期间 IAM role 无法删除，所以 `terraform destroy` 可能删除 role 失败（静默失败或超时报错）。

**解决方案**：
1. 把已有 role import 到 Terraform state：
   ```bash
   cd cloudflare-to-aws-cdn/terraform/domains/<sanitized_domain>
   terraform import aws_iam_role.<sanitized_domain>_lambda_edge cfcdn-<sanitized_domain>-lambda-edge
   ```
   其中 `<sanitized_domain>` 是 `domains/` 下的目录名（点和横线替换为下划线，例如 `ext.c.letsmakeit.link` 对应 `ext_c_letsmakeit_link`）。
   然后重新 `terraform apply`。
2. 或者等几个小时让副本清理完，然后手动删除：
   ```bash
   aws iam detach-role-policy --role-name cfcdn-<sanitized_domain>-lambda-edge --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
   aws iam delete-role --role-name cfcdn-<sanitized_domain>-lambda-edge
   ```
   然后重新 `terraform apply`。
