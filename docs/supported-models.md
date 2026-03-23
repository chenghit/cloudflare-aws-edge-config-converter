# Supported Models | [中文](./supported-models_CN.md)

This tool requires a model with sufficient **output token capacity** — the WAF Terraform generator can produce large HCL files, and the CDN JS generator needs enough headroom for complex CloudFront Function logic.

**Minimum requirement: 64K output tokens.**

---

## Kiro CLI Users

Kiro CLI only supports Claude models on Amazon Bedrock. Switch models with `/model` in Kiro.

| Model | Input Tokens | Output Tokens | Use Case |
|-------|-------------|--------------|----------|
| Claude Sonnet 4.6 (1M) | 1M | 64K | ✅ Default — WAF ≤ 100 rules, all CDN |
| Claude Opus 4.6 (1M) | 1M | 128K | ✅ WAF > 100 rules, complex CDN JS |
| Claude Opus 4.5 | 200K | 64K | ✅ WAF ≤ 100 rules, all CDN |
| Claude Sonnet 4.5 | 200K | 64K | ✅ WAF ≤ 100 rules, all CDN |
| Claude Opus 4.1 | 200K | 64K | ✅ WAF ≤ 100 rules, all CDN |

**Rule of thumb:**
- WAF pipeline: each AWS WAF rule ≈ 150 output tokens of HCL. Typical split ratio from CF rules is ~2x (simple zones ~1.5x, complex zones up to 3x).
  - 64K output → safe for ~200 AWS WAF rules (~100 CF rules) → use Sonnet
  - 128K output → safe for ~400 AWS WAF rules (~200 CF rules) → use Opus
- CDN pipeline: each LLM stage processes one domain independently, generating ~200 lines of output. Sonnet's 64K is sufficient for all CDN stages.

---

## Other Agent Tool Users

If you've adapted this tool for another agent framework (see the installation note in the README about replacing `~/.kiro/skills/` paths), any model meeting the 64K output requirement should work. The following models have been researched and confirmed to meet the minimum:

### Chinese Providers

| Model | Provider | Input Tokens | Output Tokens | Notes |
|-------|----------|-------------|--------------|-------|
| MiMo-V2-Pro | Xiaomi | 1M | 128K | 1T-param MoE (42B active); strong agent/tool-call |
| Kimi K2.5 | Moonshot AI | 256K | 64K | 1T-param MoE (32B active); multimodal |
| GLM5 Turbo | Z.AI (Zhipu) | ~203K | 131K | Optimized for OpenClaw agent workflows |
| MiniMax M2.5 | MiniMax | 196K | 64K | 230B MoE (10B active) |
| Step 3.5 Flash | StepFun | 256K | 256K | 196B MoE (11B active); 350 TPS |

### International Providers

| Model | Provider | Input Tokens | Output Tokens | Notes |
|-------|----------|-------------|--------------|-------|
| Amazon Nova 2 Lite | Amazon | 1M | 64K | Available via OpenRouter; not supported natively in Kiro CLI |
| GPT-5.3 Codex | OpenAI | 400K | 128K | Code/engineering focused |
| GPT-5.4 | OpenAI | 922K | 128K | First mainline reasoning model with Codex capabilities |
| Grok 4 | xAI | 256K | 256K | Reasoning always-on; pricing doubles above 128K input |
| Gemini 2.5 Pro | Google | 1M | 64K | Adaptive thinking |
| Gemini 2.5 Flash | Google | 1M | 64K | Controllable thinking budget |
| Gemini 3 Flash Preview | Google | 1M | 64K | Multimodal |
| Gemini 3 Pro Preview | Google | 1M | 64K | Retiring 2026-03-26, replaced by 3.1 Pro |
| Gemini 3.1 Pro Preview | Google | 1M | 64K | Multimodal flagship |

> These models are not tested with this tool. Compatibility depends on how well your agent framework maps the skill orchestration logic to the model's API.

---

## Models That Don't Meet the Minimum (Output Tokens < 64K)

| Model | Provider | Input Tokens | Output Tokens | Notes |
|-------|----------|-------------|--------------|-------|
| Amazon Nova Premier | Amazon | 1M | 25K | Below minimum |
| Magistral Small 2509 | Mistral AI | 128K | 40K | Below minimum |
| Kimi K2 Thinking (Bedrock) | Moonshot AI | 128K | 16K | Below minimum |
| Kimi K2.5 (Bedrock) | Moonshot AI | 128K | 16K | Below minimum |
| Qwen3 Coder 480B A35B | Qwen | 128K | 16K | Below minimum |
| DeepSeek V3.2 | DeepSeek | 128K | 8K | Below minimum |
| MiniMax M2.1 | MiniMax | 1M | 8K | Below minimum |
| GLM 4.7 | Z.AI | 128K | 4K | Below minimum |
| GPT-5.3 Chat | OpenAI | 128K | 16K | Below minimum |
| Grok 3 | xAI | 131K total | — | Total context 131K shared between input and output |
| Grok 4 Fast | xAI | 2M | 30K | Below minimum |

---

## Reference: Data Sources

- [Amazon Bedrock inference and reasoning models](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-reasoning.html)
- [OpenRouter model listings](https://openrouter.ai/models)
- [xAI Models and Pricing](https://docs.x.ai/developers/models)
- [Gemini 3 Developer Guide](https://ai.google.dev/gemini-api/docs/gemini-3)
