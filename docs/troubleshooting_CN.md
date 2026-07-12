[English](./troubleshooting.md)

# 故障排除

## 脚本执行错误

**问题**：Pipeline 脚本执行失败

**解决方案**：
1. 检查输出中的 `---RESULT---` 块——包含 `STATUS`、`ACTION` 和 `CONTEXT` 字段
2. `STATUS: FATAL` 表示不可恢复——查看 `CONTEXT` 了解根本原因
3. `STATUS: ERROR` + `ACTION: FIX` 表示需要用户操作（如缺少输入文件）
4. 重启你的 agent：如果编排器混乱，启动一个新会话

## Agent 未识别请求

**问题**：agent 未识别转换请求（或基于 skill 的 agent 未自动触发）

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

> **手动运行脚本？** 脚本不在你的 `PATH` 里——用克隆路径调用（例如 `python3 /path/to/clone/converter/scripts/cdn-preprocess.py`），并在输出所在的工作目录下运行，这样 `cloudflare-to-aws-cdn` 这类相对输出路径才能正确解析。下面的命令为简洁起见用了裸文件名。

**解决方案**：
1. 查看错误输出——Python 脚本会在 stderr 打印具体错误信息
2. 预处理失败：查看 `cloudflare-to-aws-cdn/ir/accumulator/<domain>.error.json`
3. 校验失败：查看 `cloudflare-to-aws-cdn/ir/validation/chunk/<domain>-v1.json` 或 `final/<domain>-v2.json`
4. 常见原因：
   - `domain_scope.json` 未找到 → 先运行 Stage 1（cdn-parse-dns.py）
   - Cloudflare 配置 JSON 解析错误 → 检查 CloudflareBackup 导出是否完整
   - Zone 目录未找到 → 确认配置路径指向 CloudflareBackup 根目录（包含 `account/` 和 zone 子目录）
5. 重试单个域名：`python3 /path/to/clone/converter/scripts/cdn-preprocess.py <config_path> cloudflare-to-aws-cdn --domain <hostname>`

## "found under multiple zones" 错误

**问题**：脚本中止并报 `ERROR: <file> found under multiple zones: [...]`

**原因**：config 路径指向的备份包含多个 zone（多个域名）。脚本每次只处理一个 zone，所以拒绝猜测你想转哪个。

**解决**：多域名备份出现这个是正常的——不需要重新备份。逐个 zone 转换：让 pipeline 指向一个只暴露目标 zone + 共享 `account/` 目录的路径。如果你通过 agent 操作，它会自动处理（构建单 zone 视图，把每个 zone 转换到各自的输出目录）。如果手动跑脚本，创建一个临时目录，用符号链接指向那一个 zone 文件夹和 `account/`，把它作为 config 路径传入。

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

## STATUS: BLOCKED — 某个 WebACL 超过 AWS 硬上限

**问题**：生成步骤报告 `STATUS: BLOCKED` 并带有 `BLOCKED_ITEMS`。模板仍会写出（供检查），但它会在**部署时被拒绝**，不能照原样部署。

**关于 50 引用 / 10 速率规则上限**：这两项很少会导致 BLOCKED。rule-group overflow packer 会自动把超出的 IP set 引用和速率规则移入被引用的 rule group，而 rule group 内的引用不计入 WebACL 的 10 速率规则 / 50 引用上限（整个 rule group 只算 WebACL 的 1 条引用）。它还会把 label key 改写成正确的跨容器形式，并重新计算每个 rule group 的 WCU。所以过去需要 per-host 拆分的配置，现在能装进默认的 2 个 WebACL。旧文档里那个「引用超 50 → `--force-split` 回退」已不存在。

**真正会 BLOCK 的两种情况**：

1. **某 WebACL 的 WCU 超过 5000 硬上限。** WCU 是每条规则的成本（模型见 [限制](./limitations_CN.md)）加上每个被引用 rule group 的容量之和。这无法靠打包降低——规则本身就是太贵了。
   - **解决**：简化该 WebACL 的源 Cloudflare 规则——减少 `contains`/正则字节匹配、减少 text transformation、减少 regex-pattern-set 引用——然后重跑。或用 `--force-split` 把部分域名拆到单独部署。

2. **单条规则复杂到无法装入一个 rule group**（某条规则自身的引用/WCU 超过一个 rule group 的上限，无法被移入）。
   - **解决**：在 Cloudflare 里拆分那一条规则（例如把一个巨大的 IP 列表 OR 拆成几条规则），然后重跑。

`BLOCKED_ITEMS` 会指明具体的 WebACL/规则和原因。修复源配置后重跑 pipeline——不要手改模板。

**部署前可选的 WCU 核对**：`python3 converter/scripts/waf-verify-wcu.py <output_dir> --profile <aws-profile>` 会对每个 rule group 调用 AWS `CheckCapacity`，若 AWS 算出的数不同则修正声明的 `Capacity`（只改这个整数，绝不改规则逻辑）。本地 WCU 已经精确，所以这是安全网——没有 profile 就跳过。
