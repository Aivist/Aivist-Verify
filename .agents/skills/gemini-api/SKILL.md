---
name: gemini-api
description: 规范 Agent 使用最新的 google-genai 官方 SDK 接入 Gemini 2.5 模型进行漏洞日志分析与自愈代码生成。
---

# Gemini 接口开发规范

## 1. 依赖库要求
- 必须使用最新官方 SDK：`google-genai`，不要使用已废弃的旧版本。

## 2. 身份验证
- 严禁将 API 密钥写在代码中。
- 必须使用 `settings.GEMINI_API_KEY` 或通过系统的环境变量 `GEMINI_API_KEY` 读取。

## 3. 模型分配策略
- 模型标识统一从 `settings.GEMINI_PRO_MODEL` 读取，不要硬编码模型名。
- 代码默认值为 `gemini-2.5-flash`（兼顾速度与成本）；如需更强推理，可在 `.env` 中将
  `GEMINI_PRO_MODEL` 覆盖为 `gemini-2.5-pro`。
- 当前 Nuclei 日志分类与“代码漏洞修复对比栏”推理共用同一个 `GEMINI_PRO_MODEL`。
  若未来要拆分快/慢双模型，请新增配置项（不要复活已废弃的 `GEMINI_FLASH_MODEL`），并同步更新本规范。

## 4. 异常处理
- 必须对 API 请求进行 `try-except` 封装。如果 API 请求超限或密钥无效，应回退至安全的本地提示，并在数据库中记录任务失败状态，不能导致后台程序崩溃。
