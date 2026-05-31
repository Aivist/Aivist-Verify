---
name: tailwind-light-ux
description: 规范 Agent 编写企业级、白色清新风格（Light Theme）的 SaaS 安全仪表盘，并支持完整的双语、攻击路径可视化及防御审计报告。
---

# 企业级浅色安全面板设计规范 (SaaS Light UX)

## 1. 配色体系 (Light Color Palette)
- **背景背景**：使用极简、开阔的 Slate-50 (或 Gray-50) 浅色柔和背景，拒绝任何刺眼的暗色、霓虹发光。
- **容器与卡片**：使用纯白卡片背景 (`bg-white`)，辅以非常淡的灰色描边 (`border border-slate-100`) 和温和的小阴影 (`shadow-sm`)。
- **主色调与高亮**：交互按钮和核心聚焦采用 Indigo-600（靛蓝色）或 Blue-600（科技蓝），体现商务与专业感。
- **文本颜色**：主标题使用极深灰 `Slate-900`，次要描述使用 `Slate-500`，确保符合无障碍可读性标准。
- **危险与警告**：高危漏洞使用纯净的 Red-600 和浅粉底色 (`bg-red-50`)，中危使用 Amber-500（琥珀黄）。

## 2. 攻击路径可视化 (Attack Path Visualization)
- 必须在主界面显眼位置，设计一个可视化进度节点链（横向或纵向步骤条 Step Chain），标明当前执行到哪个具体阶段：
  1. 目标可达性探测 / Target Handshake (建立连接，验证是否在线)
  2. 端口与指纹识别 / Fingerprinting & Port Mapping (探测对方使用的是什么技术栈，如 ThinkPHP、React)
  3. 漏洞特征匹配审计 / Vulnerability Signature Matching (正在尝试安全的 PoC 发送)
  4. AI 深度自愈防护分析 / AI Defense Remediation (大模型正在分析并生成代码补丁)

## 3. 防御审计报告 (Defense Audit & Meaning)
- 对于发现的漏洞，界面上必须有极其明确的三个核心模块，且全部采用中英双语展示：
  1. **【漏洞意味着什么 / Vulnerability Impact】**：用非技术人员也能懂的商业大白话，解释这个漏洞被黑客利用后，会给公司带来什么损失（如：数据被盗、服务器被控）。
  2. **【攻击还原 / Attack Path Verification】**：展示 Nuclei 发送的 PoC 交互请求报文和响应报文。
  3. **【防御自愈审计 / AI Remediated Patch】**：用清晰的红绿代码 Diff 对比，展示漏洞源码与修复后代码，并带有 Gemini 的自愈防护总结。

## 4. 中英双语 (Bilingual Support)
- 界面上的所有标签（Label）、按钮（Button）、系统提示信息，必须以 `中/英双语并列` 的形式展示。
- 示例：`Target URL / 目标地址`, `Launch Scan / 启动安全审计`。
