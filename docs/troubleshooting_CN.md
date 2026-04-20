[English](./troubleshooting.md)

# 故障排除

## 脚本执行错误

**问题**：Pipeline 脚本执行失败

**解决方案**：
1. 检查输出中的 `---RESULT---` 块——包含 `STATUS`、`ACTION` 和 `CONTEXT` 字段
2. `STATUS: FATAL` 表示不可恢复——查看 `CONTEXT` 了解根本原因
3. `STATUS: ERROR` + `ACTION: FIX` 表示需要用户操作（如缺少输入文件）
4. 重启 Kiro CLI：退出并启动新的 `kiro-cli chat` 会话

## 关键词未触发正确的 Skill

**问题**：编排器未识别转换请求

**解决方案**：在请求中使用明确的关键词：
- WAF：说"转换**安全规则**"或"转换到 **AWS WAF**"
- CDN：说"转换 **CDN 配置**"或"转换到 **CloudFront**"
- 两者都转：说"转换**所有配置**"或"**全量迁移**"

**示例**：
- ❌ 模糊："分析我的 cloudflare 配置文件"
- ✅ 明确："将 /path/to/config 中的**安全规则**转换为 **AWS WAF**"

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
   - `domain_scope.json` 未找到 → 先运行 Stage 1（cdn-parse-dns.py）
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


## WAF CloudFormation "重复资源"错误

**问题**：`aws cloudformation deploy` 失败，报错 `some resource in your request is a duplicate of an existing one`

**原因**：之前的 CloudFormation stack 部署失败并回滚，但部分资源（IP sets、WebACLs）没有完全清理。CloudFormation 无法创建同名 + 同 Scope 的资源。

**解决方法**：

1. 删除失败的 stack：
   ```bash
   aws cloudformation delete-stack --stack-name cloudflare-waf-migration --region us-east-1
   aws cloudformation wait stack-delete-complete --stack-name cloudflare-waf-migration --region us-east-1
   ```

2. 如果 stack 删除后仍有残留资源，手动删除：
   ```bash
   # 列出残留资源
   aws wafv2 list-ip-sets --scope CLOUDFRONT --region us-east-1
   aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1

   # 逐个删除（从 list 输出中获取 Id 和 LockToken）
   aws wafv2 delete-ip-set --scope CLOUDFRONT --region us-east-1 \
     --name <name> --id <id> --lock-token <lock-token>
   aws wafv2 delete-web-acl --scope CLOUDFRONT --region us-east-1 \
     --name <name> --id <id> --lock-token <lock-token>
   ```

3. 重新部署：
   ```bash
   aws cloudformation deploy \
     --template-file waf-cloudformation.json \
     --stack-name cloudflare-waf-migration \
     --region us-east-1
   ```

## WAF CloudFormation Stack 删除失败（ThrottlingException）

**问题**：`aws cloudformation delete-stack` 失败，stack 状态变为 `DELETE_FAILED`。一个或多个 WebACL 或 IP set 资源删除失败，报 `ThrottlingException`。

**原因**：WAFv2 API 写操作（包括 `DeleteWebACL`、`DeleteIPSet`）限速为每账号每区域 **1 次/秒**，这是固定限制，不可提升。CloudFormation 并行删除资源时会超过此限制。

**解决方案**：重试删除。第二次只需要删除剩余的 1-2 个资源，不会再触发限流：

```bash
aws cloudformation delete-stack \
  --stack-name cloudflare-waf-migration \
  --region us-east-1
```

如果 stack 卡在 `ROLLBACK_FAILED`（创建失败导致），用 `--retain-resources` 跳过卡住的资源，然后手动删除：

```bash
# 先删除 stack，保留卡住的资源
aws cloudformation delete-stack \
  --stack-name cloudflare-waf-migration \
  --retain-resources StuckResource1 StuckResource2 \
  --region us-east-1

# 然后通过 AWS Console 或 CLI 手动删除保留的 IP set
```

## 单域名在 Per-Domain 拆分后仍超过 50 引用语句限制

**问题**：Pipeline 自动拆分为 per-domain WebACL 后，某个域名仍然超过每个 WebACL 50 个 IP set + regex set 引用的限制。Pipeline 会在 `FAILED_ITEMS` 中报告该域名。

**为什么这种情况极少发生**：单域名超过 50 个引用意味着该域名有 50+ 条规则各自引用不同的 IP set。Cloudflare Enterprise 计划每个 zone 最多 100 条自定义规则，其中引用 IP set 的通常不超过 20-30 条。

**解决方案**（按优先级排序）：

1. **合并 IP set**：将用途相同的多个 IP set 合并为一个（例如，将多个 block list 合并）。IP set 越少，引用越少。

2. **申请 entity-level 限制提升**：联系 AWS Support 将特定 WebACL 的引用限制从 50 提升到 100。步骤：
   - 用 CloudFormation 部署一个最小 WebACL（仅默认动作）
   - 将 WebACL ARN 提供给 AWS Support，申请引用限制提升
   - 批准后，重新部署完整的 CloudFormation 模板更新该 WebACL
   - 注意：这是 per-WebACL 的，不是账号级别。新建的 WebACL 仍然默认 50。

3. **Rule Group 方案**：将 IP set 引用放入 Rule Group。WebACL 引用 Rule Group（算 1 个引用），Rule Group 内部的 IP set 引用不计入 WebACL 的限制。注意事项：
   - Rule Group 内部也有 50 引用限制，可能需要多个 Rule Group
   - Rule Group 创建时需要声明固定的 WCU 容量
   - WebACL 层规则产生的 label 在 Rule Group 内部不可见，会破坏 skip/scope-down 逻辑
   - 优先级管理更加复杂

Per-domain 拆分方案能处理绝大多数真实场景。以上方案是极端配置的应急手段。
