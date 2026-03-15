[中文](./roadmap_CN.md)

# Roadmap

## 🚧 Skills 3-11: Complete CDN Configuration Migration Solution

A comprehensive CDN configuration migration solution with multiple specialized skills.

Each skill is bound to its own subagent with isolated context. The default agent (`kiro_default`) loads the `cloudflare-aws-converter` orchestrator skill and automatically dispatches to the appropriate subagents based on user intent.

**Architecture Design Documents:**
- [Skill 3-11 Architecture Design (English)](./architecture/skill-3-11-design-EN.md)
- [Skill 3-11 架构设计 (中文)](./architecture/skill-3-11-design-CN.md)
- [Architecture Changelog](./architecture/CHANGELOG.md)

**Planned Skills:**

| Skill | Responsibility | Status |
|-------|---------------|--------|
| **Skill 3** | Config Analyzer — Parse CDN config, group by hostname (`cf-cdn-analyzer`) | ✅ Implemented |
| **Skill 4** | Implementation Planner — Determine CloudFront methods | 🎨 Architecture Design |
| **Skill 5** | Plan Validator — Verify plan correctness (`cf-cdn-analyzer-validator`) | ✅ Implemented |
| **Skill 6** | Task Orchestrator (`cloudflare-aws-converter`) | ✅ Implemented |
| **Skill 7** | Viewer Request Function Converter | 📝 To Be Designed |
| **Skill 8** | Viewer Response Function Converter | 📝 To Be Designed |
| **Skill 9** | Origin Request Lambda Converter | 📝 To Be Designed |
| **Skill 10** | Origin Response Lambda Converter | 📝 To Be Designed |
| **Skill 11** | CloudFront Config Generator (Terraform) | 📝 To Be Designed |

⚠️ When Skills 3-11 are fully implemented, `cf-functions-converter` will be deprecated — Skills 3-11 provide more complete CDN conversion with domain-based grouping, Lambda@Edge support, and validation.

**Timeline:**
- 2026 Q1: Architecture design, implement Skills 3, 5, 6 as subagent prototypes ✅
- 2026 Q2: Implement Skills 4, 7-11, deprecate `cf-functions-converter`
- 2026 Q3: Optimize workflow and user experience
