# 支持的模型 | [English](./supported-models.md)

本工具对模型的核心要求是足够的**输出 token 上限**——WAF Terraform 生成器可能产生较大的 HCL 文件，CDN JS 生成器也需要足够的空间处理复杂的 CloudFront Function 逻辑。

**最低要求：64K 输出 token。**

---

## Kiro CLI 用户

Kiro CLI 仅支持 Amazon Bedrock 上的 Claude 模型。在 Kiro 中通过 `/model` 切换。

| 模型 | 输入 Token | 输出 Token | 适用场景 |
|------|-----------|-----------|---------|
| Claude Sonnet 4.6 (1M) | 1M | 64K | ✅ 默认推荐——WAF ≤ 100 条规则，所有 CDN 场景 |
| Claude Opus 4.6 (1M) | 1M | 128K | ✅ WAF > 100 条规则，复杂 CDN JS 生成 |
| Claude Opus 4.5 | 200K | 64K | ✅ WAF ≤ 100 条规则，所有 CDN 场景 |
| Claude Sonnet 4.5 | 200K | 64K | ✅ WAF ≤ 100 条规则，所有 CDN 场景 |
| Claude Opus 4.1 | 200K | 64K | ✅ WAF ≤ 100 条规则，所有 CDN 场景 |

**选型参考：**
- WAF pipeline：每条 AWS WAF 规则约产生 150 output tokens 的 HCL。CF 规则的典型拆分比例约 2x（简单 zone 约 1.5x，复杂 zone 最高 3x）。
  - 64K 输出 → 约 200 条 AWS WAF 规则（约 100 条 CF 规则）→ 用 Sonnet
  - 128K 输出 → 约 400 条 AWS WAF 规则（约 200 条 CF 规则）→ 用 Opus
- CDN pipeline：每个 LLM 阶段独立处理一个域名，单次约生成 200 行输出。Sonnet 的 64K 对所有 CDN 阶段均足够。

---

## 其他 Agent 工具用户

如果你已将本工具适配到其他 agent 框架（参见 README 中关于批量替换 `~/.kiro/skills/` 路径的说明），任何满足 64K 输出要求的模型理论上都可以使用。以下模型经过调研，确认满足最低要求：

### 国内厂商

| 模型 | 提供商 | 输入 Token | 输出 Token | 备注 |
|------|--------|-----------|-----------|------|
| MiMo-V2-Pro | 小米 | 1M | 128K | 1T 参数 MoE（42B 激活）；强 Agent/工具调用 |
| Kimi K2.5 | Moonshot AI | 256K | 64K | 1T 参数 MoE（32B 激活）；多模态 |
| GLM5 Turbo | Z.AI（智谱） | ~203K | 131K | 专为 OpenClaw Agent 场景优化 |
| MiniMax M2.5 | MiniMax | 196K | 64K | 230B MoE（10B 激活） |
| Step 3.5 Flash | 阶跃星辰 | 256K | 256K | 196B MoE（11B 激活）；350 TPS |

### 国际厂商

| 模型 | 提供商 | 输入 Token | 输出 Token | 备注 |
|------|--------|-----------|-----------|------|
| Amazon Nova 2 Lite | Amazon | 1M | 64K | 可通过 OpenRouter 接入；Kiro CLI 不原生支持 |
| GPT-5.3 Codex | OpenAI | 400K | 128K | 专注代码/工程任务 |
| GPT-5.4 | OpenAI | 922K | 128K | 首个集成 Codex 能力的主线推理模型 |
| Grok 4 | xAI | 256K | 256K | 推理常开；超过 128K 输入后价格翻倍 |
| Gemini 2.5 Pro | Google | 1M | 64K | Adaptive thinking |
| Gemini 2.5 Flash | Google | 1M | 64K | 可控思考预算 |
| Gemini 3 Flash Preview | Google | 1M | 64K | 多模态 |
| Gemini 3 Pro Preview | Google | 1M | 64K | 2026-03-26 下线，被 3.1 Pro 取代 |
| Gemini 3.1 Pro Preview | Google | 1M | 64K | 多模态旗舰 |

> 以上模型均未经过本工具实测。实际兼容性取决于你所使用的 agent 框架对 skill 编排逻辑的支持程度。

---

## 不满足最低要求的模型（输出 Token < 64K）

| 模型 | 提供商 | 输入 Token | 输出 Token | 备注 |
|------|--------|-----------|-----------|------|
| Amazon Nova Premier | Amazon | 1M | 25K | 低于最低要求 |
| Magistral Small 2509 | Mistral AI | 128K | 40K | 低于最低要求 |
| Kimi K2 Thinking（Bedrock 版） | Moonshot AI | 128K | 16K | 低于最低要求 |
| Kimi K2.5（Bedrock 版） | Moonshot AI | 128K | 16K | 低于最低要求 |
| Qwen3 Coder 480B A35B | Qwen | 128K | 16K | 低于最低要求 |
| DeepSeek V3.2 | DeepSeek | 128K | 8K | 低于最低要求 |
| MiniMax M2.1 | MiniMax | 1M | 8K | 低于最低要求 |
| GLM 4.7 | Z.AI | 128K | 4K | 低于最低要求 |
| GPT-5.3 Chat | OpenAI | 128K | 16K | 低于最低要求 |
| Grok 3 | xAI | 131K 总计 | — | 输入输出共享 131K，有效输出不足 |
| Grok 4 Fast | xAI | 2M | 30K | 低于最低要求 |

---

## 参考数据来源

- [Amazon Bedrock 推理模型文档](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-reasoning.html)
- [OpenRouter 模型列表](https://openrouter.ai/models)
- [xAI 模型与定价](https://docs.x.ai/developers/models)
- [Gemini 3 开发者指南](https://ai.google.dev/gemini-api/docs/gemini-3)
