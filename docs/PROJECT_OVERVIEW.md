# Anti-Gravity · AI 渗透测试平台 — 项目总览（验收版）

> 本文面向**项目验收 / 合伙评估**。目标：不了解代码的人读完即可判断「这是什么、有什么、到什么程度、能不能落地」。
> 原则：**如实陈述,不夸大、不隐瞒**。带 ✅/🟡/⚪ 的成熟度标记和「已知限制」一节都是真实现状。
> 基准：本文与当前代码一致(最近一次提交)。代码为准——如发现不符,以代码为准并请更新本文。
>
> **阅读顺序**:[`STATUS.md`](./STATUS.md)(现在进展到哪了:当前状态快照)→ [`ROADMAP.md`](./ROADMAP.md)(为什么 / 去哪:战略与非目标)→ **本文**(现状快照 + 端到端链路 + 运行/验收清单)→ [`ARCHITECTURE.md`](./ARCHITECTURE.md)(怎么实现)→ 组件文档([`VERIFY_ENGINE.md`](./VERIFY_ENGINE.md) / [`DEEP_VERIFY.md`](./DEEP_VERIFY.md) 等)→ [`TECH_DEBT.md`](./TECH_DEBT.md)(已知缺口)。

---

## 1. 一句话定位

**一个本地运行、AI 辅助的 Web 应用渗透测试平台**:既能跑传统的"已知漏洞"扫描,又能用大模型挖"业务逻辑漏洞"并**自动主动验证漏洞是否真实可利用**。

后者(逻辑挖掘 + 差分验证)是本项目的技术纵深与差异化所在;前者(Nuclei 扫描)是相对常规的扫描器封装。

---

## 2. 当前阶段(诚实定位)

| 维度 | 现状 |
|---|---|
| 形态 | **单租户、本地运行的原型(prototype)**,功能链路完整,尚未上线/未做多用户化 |
| 核心链路 | Hunter→验证 全链路 **已端到端跑通**(真实服务 + 真实本地靶机 + 真实数据库,详见 §7) |
| 鉴权 | **暂无任何鉴权**(刻意延后,仅限本地/可信网络使用,见 §8 / D2) |
| 测试 | **后端 285 个自动化测试全绿**(pytest)+ 靶机 31 个(独立套件),覆盖核心服务 + API 层 + 被动代理雷达 + 验证判定层(含 B-1 影子路径回归测试 + M1.1/M1.2 判定与豁免测试) |
| 前端 | 主用单文件仪表盘已联通后端(含 Step 9 代理雷达页,该页 UI 接线**尚未提交**——属后续前端阶段);另有一个遗留的 Vite 前端(mock 数据,非产品基线) |
| 版本管理 | 已纳入 git,提交历史清晰;密钥/数据库已隔离出版本库。B-1 已提交(`37769b3`);当前**唯一**未提交改动是代理雷达前端页,见 [`STATUS.md`](./STATUS.md) |

一句话:**"地基稳、核心通、可演示;尚未商用化(无鉴权、无多租户、本地 SQLite)"**。

---

## 3. 系统架构

两个相对独立的分析子系统,共享同一套数据库与前端:

```
   浏览器 ─(HTTP/S 代理)→ ③ 被动代理雷达 (mitmdump 子进程)
                                │  Tier-1 内联过滤(域锁+静态veto)
                                │  环回 HTTP POST → /proxy/internal-ingest
                                ▼
                ┌──────────────────────────────────────────────┐
   操作员/前端 → │  FastAPI (ASGI, uvicorn) · /api/v1/*          │
                └───────────────┬──────────────────────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                      ▼
  ① Nuclei 扫描引擎      ② AI 逻辑狩猎 Logic Hunter   ③ 代理雷达管线
  - 调用本地 nuclei      - 解析原始 HTTP / 导入 HAR    - 有界摄取队列(背压)
    子进程               - pruner 剪枝(暴露评分)       - Tier-2 异步评分(复用 pruner)
  - 流式解析 JSONL 发现   - Gemini 分析越权类逻辑漏洞    - SSE 实时推流(/proxy/stream)
  - 对高危发现调 Gemini   - 产出结构化攻击 payload      - 落库 captured_flows
    生成修复补丁         - 【差分 Fuzzing 引擎】主动验证 ★
          └─────────────────────┼─────────────────────┘
                                ▼
   SQLAlchemy 2.0 async + SQLite(WAL) · 统一单写者服务(WriterService)串行落库
   —— fuzzing 记录与代理流量共用同一个写协程,全局至多一个 SQLite 写者
```

### 端到端链路(从一条流量到一个判定)

上图是**组件视角**;下面是**数据视角**——一条流量如何一路走到「判定 + 证据」。
这条链路是本项目的主线,④ 是差异化护城河。

```
输入(三选一)
  ├─ 原始 HTTP 报文   ──────────────────────────────┐
  ├─ HAR 导入 → /hunter/ingest-har[-file] → pruner 剪枝 → 选一条 ─┤
  └─ 代理雷达被动抓包 → captured_flows → 一键 Send to Hunter ──────┘
                                                     │
                                                     ▼
① 逻辑狩猎   POST /hunter/analyze
   traffic_parser 结构化 → Gemini 分析越权类逻辑漏洞(无 Key 优雅降级)
   产出:report_markdown + 机器可执行的 automation_payloads[]
                                                     │
                                                     ▼
② 落库(Step D 桥接)   POST /hunter/findings
   存成可 fuzz 的 VulnerabilityFinding(source="hunter"),返回 finding_id
                                                     │
                                                     ▼
③ 差分验证(规则预言机,产品核心)   POST /hunter/verify/{id} | /verify/batch
   fuzzer:发基线 → 按 payload 变异重放 → _differential_verdict 差分比对
   (自愈式 auth 托管 + 单主机 scope 锁 + 统一单写者落库)
   → 三值判定 verified / suspicious / failed   →   FuzzingRecord 落库
                                                     │
                                        (仅 suspicious 记录,且两个开关都开启;默认关闭)
                                                     ▼
④ 影子深度验证(Phase 7,只读观测)   deep_verifier
   两轮式 AI「写后读」:发攻击请求 → 回读**同一资源**或**写记录** → 判定
   → 四值判定 verified / failed / inconclusive / suspicious
   (+ 确定性结构化跨资源守卫;保留模型原始判定 ai_verdict_raw)
   ★ 仅写日志,不改写 verification_status、不影响用户所见
                                                     │
                                                     ▼
   前端轮询   GET /hunter/verify/{id}/results   → 展示判定 + 差分/证据链
```

> 一句话:①②③ 是「已提交、已跑通」的规则链路(用户所见判定来自 ③ 的三值预言机);
> ④ 是**默认关闭、只读观测**的 AI 深度验证层——把 ③ 停在 `suspicious` 的「沉默型」越权
> (写接口恒返回 `200 {"status":"ok"}`)通过「写后读」区分真伪。④ 的「跨路径自信判定」
> (B-1)已跑通并**已提交**(`37769b3`;X-CROSS→verified、X-SAFE→安全,并有自动化回归测试锁定),详见 [`STATUS.md`](./STATUS.md)。
> **当前权威度量为高 N 复测**(gemini-2.5-pro、单靶、每次全新播种、0 降级):**140 次 SAFE/控制组 → 0 误报;70 次 VULN → 全部 `verified`**(`scripts/audit/shadow_highN_zerofp_run.out.txt` + `…_highN_xequiv_run.out.txt`);其中 40 次 SAFE 上模型原始判定想放行、闸门每次都拒绝。下文各形态的 `5/5` 是最初的 N=5 单形态记录,已被此高 N 复测取代。

### 技术栈

| 层 | 技术 |
|---|---|
| Web 框架 | FastAPI(ASGI),uvicorn 运行 |
| 数据校验 | Pydantic v2 + pydantic-settings(启动即校验,fail-fast) |
| ORM | SQLAlchemy 2.0 **异步** |
| 数据库 | SQLite（`aiosqlite`,WAL 模式） |
| HTTP 客户端 | `httpx.AsyncClient`(对自签名靶机刻意关闭 TLS 校验) |
| 外部扫描器 | Nuclei(子进程调用,需本地安装) |
| 被动代理 | mitmproxy 的 `mitmdump`(子进程,由 `ProxyManager` 托管 + 监督;跨平台进程树清杀) |
| AI | Google Gemini,官方 `google-genai` SDK(Gemini 2.5) |
| 前端(主用) | `preview_dashboard.html` — 单文件 React(CDN+Babel)+ Tailwind,白色清新风,已联通后端 |
| 前端(遗留) | `frontend/` — Vite + TS,深色 + mock 数据,**非产品基线** |
| 运行环境 | Python 3.11 |

### 并发模型(为什么稳)

单进程、单事件循环。长任务走 FastAPI `BackgroundTasks`;**网络 I/O 并行,但数据库写入由一个应用级统一写者服务(WriterService)串行化**——fuzzing 记录与被动代理捕获的流量都提交到同一个写协程,全局至多一个 SQLite 写者,从根上规避 "database is locked"。代理子进程(mitmdump)运行在独立解释器,通过环回 HTTP POST 做进程间通信(IPC)。auth 失效有自愈状态机兜底。

### 目录结构

```
anti gravity/
├─ README.md                      # 根目录精简指路（指向 docs/）
├─ preview_dashboard.html         # 主用前端（单文件，连 :8000）
├─ backend/
│  ├─ run.py                      # uvicorn 入口
│  ├─ requirements.txt            # 运行依赖（已锁版本）
│  ├─ requirements-dev.txt        # 开发依赖（pytest）
│  ├─ .env.example                # 配置样例（真实 .env 不入库）
│  ├─ app/
│  │  ├─ main.py                  # 应用装配、生命周期(建表+schema自检)、CORS、路由
│  │  ├─ core/                    # config.py(配置校验) / database.py(异步引擎、会话)
│  │  ├─ models/scan.py           # ORM：ScanTask / VulnerabilityFinding / FuzzingRecord / CapturedFlow
│  │  ├─ schemas/                 # Pydantic 契约（scan.py / hunter.py / proxy.py）
│  │  ├─ api/v1/                  # 路由：scan.py(Nuclei) / hunter.py(Hunter/验证/HAR/批量/proxy)
│  │  ├─ proxy/radar_addon.py     # mitmdump 插件(独立解释器,Tier-1 过滤 + 环回上报)
│  │  └─ services/                # nuclei.py / traffic_parser.py / pruner.py / fuzzer.py(核心)
│  │                              # + proxy_manager.py(进程状态机) / proxy_pipeline.py(队列+SSE+统一写者)
│  │                              # + deep_verifier.py(AI 深度验证,影子 Phase 7) / endpoint_catalog.py(D18 端点目录)
│  └─ tests/                      # pytest（285 个）
├─ vulnerable_target/             # 独立的地面真值靶机（:8001，14 个 pytest 用例）
├─ scripts/audit/                 # 判定准确率的测量脚本/记录（非产品代码）
├─ docs/                          # 全部项目文档（本文 + ROADMAP/STATUS/架构/各管线/API/技术债）
└─ frontend/                      # 遗留 Vite 前端（mock，非基线）
```

---

## 4. 功能清单（按成熟度标注）

> 图例：✅ 已实现且经测试/E2E 验证　🟡 已实现、可用(自动化覆盖有限)　⚪ 占位/受限

### A. Nuclei 扫描引擎（查"已知"漏洞）
- 🟡 **异步扫描**:`POST /scan/start` 提交目标 → 后台跑 nuclei 子进程,立即返回 `scan_id`;轮询状态与结果。
- 🟡 **三阶段管线**:启动 → 流式解析 JSONL 发现 → 完成后对 **critical/high** 发现批量调 Gemini 生成**修复补丁 + 根因分析**。
- 🟡 **自适应扫描参数**:按目标特征拼装 nuclei 参数。
- 说明:依赖本地安装的 `nuclei` 二进制;自动化测试中对子进程做了 mock(未在 CI 里跑真实外网扫描)。

### B. AI 逻辑狩猎 Logic Hunter（挖"未知"业务逻辑漏洞）
- ✅ **原始流量解析**:粘贴原始 HTTP 报文 → 结构化(method/path/query/headers/body)。
- ✅ **HAR 摄取与剪枝**:导入浏览器/抓包导出的 HAR → `pruner` 按"暴露评分"过滤噪声、识别疑似登录端点;支持 JSON body 与大文件流式上传两种入口。
- 🟡 **Gemini 逻辑分析**:针对越权类漏洞(BOLA/IDOR、垂直越权、Mass-Assignment、参数污染、竞态)给出**专家级 Markdown 报告** + 机器可执行的 `automation_payloads`。无 API Key 时优雅降级(不报 500)。
- ✅ **分析落库为可验证发现**(Step D 桥接):`POST /hunter/findings` 把分析结果存成可 fuzz 的 finding,返回 `finding_id`。

### C. 差分 Fuzzing 验证引擎 ★（产品核心壁垒）
- ✅ **差分验证**:发基线请求 → 按 payload 变异重放 → **差分预言机**比对(状态码、响应长度偏移、相似度等),配合降噪/否决/升级规则,判定 `verified / suspicious / failed`。
- ✅ **自愈式 auth 托管**:会话(session/token)在扫描途中失效时,自动重放"身份提供方锚点"(登录请求)刷新凭证后继续,避免误判;期间对前端透出 `running` 诊断态。
- ✅ **真并行批量**:`POST /hunter/verify/batch` 在**单一共享 auth 托管**下并发验证多个端点(并发上限可配 1–20)。
- ⚪ **单主机限制**:批量仅允许同一主机;混合主机/越界目标会被拒绝(刻意的安全约束,见 §8 / D11)。
- ✅ **身份锚点试运行**:`POST /hunter/auth/dry-run` 上线批量前先验证登录锚点是否能拿到新凭证(不落库)。
- ⚪ **AI 深度验证（影子模式 / Phase 7，只读观测）**:新增独立组件 `services/deep_verifier.py`——两轮式 AI-in-the-loop「写后读」(Gemini),用于解决规则预言机在"沉默型"越权(写接口恒返回 `200 {"status":"ok"}`)上只能停在 `suspicious` 的盲区。其判定为**四值**(`verified`/`failed`/`inconclusive`/`suspicious`),比规则预言机 `_differential_verdict` 的**三值**(`verified`/`suspicious`/`failed`,保持不变)多出 `inconclusive`——证据不足(如跨资源回读未反映被攻击对象)时如实给出。另有确定性**结构化跨资源守卫**(B-2.2,`_apply_cross_resource_guard`):当 `verified`/`failed` 依赖的回读路径与攻击路径不同,降级为 `inconclusive`;结果同时保留模型原始判定与改写痕迹(`ai_verdict_raw` + `guard_override`,`ai_verdict` 为守卫后的最终值)。已作为**纯增量、只读**的 Phase 7 接入 `execute_parallel_fuzzing`:批次结束后对 `suspicious` 记录复核,**仅写日志**(`AI_shadow_verdict=…`),**不改写** `verification_status`/`diff_details`、不影响用户所见、失败即吞。受两个默认关闭的开关门控:`AI_DEEP_VERIFY_ENABLED` 与 `AI_DEEP_VERIFY_SHADOW`(两者都为 True 才会真正调用 Gemini)。端点目录由 `services/endpoint_catalog.py`(`catalog_from_openapi`)提供:每条以 `"METHOD /path"` 打头,并**携带该操作在 spec 里真实声明的 `tags` 与 `operationId`**(有则附,无则退回裸 `"METHOD /path"`——不臆造),让模型能判断某端点「是什么」(例如识别一个审计/日志端点是写记录)。spec 来源走 `settings.AI_DEEP_VERIFY_OPENAPI_SPEC`(`getattr` 读取,并非已声明配置项,见 [`TECH_DEBT.md`](./TECH_DEBT.md) D21),未配置时回退到同资源占位目录。相关接缝(auth 上下文、端点目录/spec 接线)见 [`TECH_DEBT.md`](./TECH_DEBT.md) D18;尚未作为权威判定见 D19。准确率基准见 [`../vulnerable_target/benchmark/RESULTS.md`](../vulnerable_target/benchmark/RESULTS.md)(共 11 个用例:AI 同路径置信判定 **8/8** 正确,2 个跨路径达"完整性下限"判 `inconclusive`,**0 误报 / 0 漏报**)。
  - 🟢 **B-1「跨路径自信判定」(✅ 已完成并提交 `37769b3`)**:让 ④ 不止停在 `inconclusive`,而是**自信地**判定跨路径写越权。机制:目录携带语义(上)+ **确定性写记录回读采集**(代码而非模型选定审计/日志端点)+ **写记录豁免守卫**(结构化核对回读确系「本次攻击」的记录才放行 `verified`)。**离线单测 + 线上影子复测均已通过**(N=5:X-CROSS→`verified` 5/5、X-SAFE→`inconclusive`/安全 5/5 零误报、同路径反向 guard 不回归),并有**自动化回归测试**锁定(`test_d18_b1_shadow_integration.py`,D22 已闭合)。守卫加固(D23 绑定 owner/subject 键 + D23b 绑定非主键内容字段)**均已完成**。**后续(非 B-1 阻塞)**:D21(声明 spec 配置项)、更多漏洞形态、更新 RESULTS.md、D19。详见 [`STATUS.md`](./STATUS.md) 与 [`DEEP_VERIFY.md`](./DEEP_VERIFY.md)。
  - 🟢 **M1.1「读型语义等价」(✅ 已完成 `002b33c`)**:两条读路径暴露同一对象,响应刻意做成**等长**,规则预言机无法凭大小判定而停在 `suspicious`,**必须由 AI 依语义判断**。判定同时携带 `evidence_path` 与代码计算的 `anchoring_result`(AI 做语义判断、代码做锚定核对;仅观测,不作预言机)。线上影子 N=5:X-EQUIV-VULN→`verified` 5/5、X-EQUIV-SAFE→`failed` 5/5,**零误报**。
  - 🟢 **M1.2「沉默写 · 对象自身状态回读」(✅ 已完成)**:第三种被确认的漏洞形态。攻击是沉默写,**既无同路径 GET、也无相关写记录**,唯一决定性证据是**被攻击对象自身的状态(位于另一条路径)**。三部分:**(A)** 第二条守卫豁免通道 `STATE_READBACK_EXEMPTION_REASON`(与 B-1 写记录通道**互斥**,仅对 `verified`),仅当代码同时确认三个锚点才放行——owner==被攻击 ∧ caller≠owner **且 payload-causality**(本次攻击注入的**唯一值**确实出现);**causality 是防误报的关键闸门**,因为前两者对「被安全丢弃的写」同样成立。**(B)** **确定性对象状态采集** `select_object_state_endpoint`(目标无关:资源名词 + 对象作用域模板绑定被攻击 id;排除日志类端点;找不到就不臆造)——模型自己**0/5**找不到该路径,代码采集后 **5/5**。**(C)** **提示词豁免**(rule 5 / turn-2 / options-block):把「**系统自行采集**的被攻击对象状态读」也列为决定性证据,解决了代码与提示词互相打架的问题(模型手握决定性证据却因 rule 5 判 `inconclusive`),使 VULN 从 **3/5 → 5/5**。线上影子 N=5:X-SILENT-VULN→`verified` **5/5**、**X-SILENT-SAFE→`verified` 0/5**(causality `absent` → 不豁免 → `inconclusive`)、B-1 X-CROSS **未回归**(仍 `verified` 5/5)。**已知边界**:payload-causality 假设写入值是**高熵**的,布尔/小整数/枚举字段或并发运行下可能碰撞(该边界已由 M1.4 收口,见下)。
  - 🟢 **M1.3「删除型 · 否定式断言」(✅ 已完成)**:第四种被确认的形态,也是第一个**以「不存在」而非「存在」为证据**的形态。跨用户 DELETE 返回不透明的 `200 {"status":"ok"}`,唯一决定性证据是受害者对象**从存在变为消失**。两个新机制:**(1) 前置读(pre-flight,巧合闸门)**——代码在发出 DELETE **之前**先读受害者对象自身状态(作用域锁定,复用 `select_object_state_endpoint`)并缓存;「它消失了」只有在「它此前确实存在且有效」被锚定后才能证明删除,**没有前置存在证明就绝不 `verified`**。**(2) 双轨否定式断言** `_anchor_negative_assertion`——**物理**移除(404/403/410)**或**逻辑/软删除(仍 200,但生命周期字段翻转,靠通用词表识别),**404 绝不硬编码**为唯一证据(真实 API 多数是软删除)。第三条互斥豁免通道 `DELETE_READBACK_EXEMPTION_REASON`(caller-identity 取自**前置读**的 body,因为物理删除后的 AFTER 读是 404 无 owner 可锚)。线上 N=5:X-DELETE-VULN-HARD→`verified` **5/5**(`confirmed_physical`)、X-DELETE-VULN-SOFT→`verified` **5/5**(`confirmed_logical`)、**X-DELETE-SAFE→`verified` 0/5**(`still_present`)、**X-DELETE-CONTROL(对象从未存在)→`verified` 0/5**(`preflight_absent`——AFTER 读同样是 404,但巧合闸门守住了)。
  - 🟢 **M1.4「批量赋值 · 低熵状态跳变」(✅ 已完成 —— M1 收官)**:第五种也是最后一种 M1 形态。攻击者把特权字段(`role`/`is_admin`/`tier`)夹带进对**受害者对象**的写入。**这里 payload-causality 本身失效**:它假设写入值是唯一的,而 `"admin"` 是**低熵**值——「读到 role 是 admin」无法区分「是我写的」和「本来就是」。因果改由 **STATE JUMP(状态跳变)** 证明:攻击发出的**每一个字段**都必须从**已知的前置状态**跳变到注入值。**MISSING(在一次成功 2xx 读里字段不存在)是合法的原始状态**(特权字段常被隐藏),所以 `missing→injected` 成立(隐藏字段提权);但**请求失败/非 2xx/JSON 畸形是 UNKNOWN**,永远不能确认跳变、永远不会 `verified`、也绝不崩。第四条互斥通道 `STATE_JUMP_EXEMPTION_REASON`。**顺带修掉了一个真实误报**:在「特权字段被白名单剥离、但合法字段确实落地」的安全用例上,旧的 causality 闸门会放行一个**安全**端点;现在**只要存在前置状态基线,就一律由 state-jump 闸门接管**(按证据而非按声明的攻击类型路由)——这是**收窄**而非削弱,只会产生更少的豁免,其余四种形态判定不变(离线 285 个测试全绿证明)。线上 N=5:X-MASS-VULN(有值 / MISSING→注入)→`verified` **5/5 各**、**X-MASS-SAFE(有值 + 缺失)→`verified` 0/5**、**CONTROL(注入值==原值,无跳变)→`verified` 0/5**。安全用例上模型**原始判定说 `verified`**,而闸门**每一次都拒绝了**——守住底线的是代码,不是模型的听话程度。**修复后线上回归复测:四种既有形态全部确认无回归**(N=5 各,**30/30 次全部干净、零降级**,`scripts/audit/shadow_m14_regress_run.out.txt`):B-1 X-CROSS→`verified` **5/5**(仍走 `write_record` 通道)、X-SILENT-VULN→`verified` **5/5**、X-DELETE-VULN-HARD/SOFT→`verified` **5/5 各**(`confirmed_physical`/`confirmed_logical`)、**X-SILENT-SAFE 与 X-DELETE-SAFE 均 0 次 `verified`**。其中 X-SILENT-VULN 的豁免通道从 `state_readback` 变为 `state_jump`——这**正是路由修复按设计生效**(存在前置状态基线时由更严的闸门接管),判定本身未变。(首轮复测曾因 Gemini 月度支出上限中断:55 次里 27 次 `429 RESOURCE_EXHAUSTED` → `status=degraded` 不出判定;预算恢复后**完整重跑**,而非当作「仅离线覆盖」的缺口交付。)
  - ✅ **M1 完成**:五种形态、零误报。下一条线是 D21(声明 spec 配置项)→ D19(把 AI 判定提升为权威)→ 发布前清单 → 真实靶标前清单。

### D. 被动流量摄取 · 代理雷达(Step 9)
- 🟡 **托管式拦截代理**:`POST /hunter/proxy/start` 启动并监督一个 `mitmdump` 子进程;浏览器把 HTTP 代理指向 `127.0.0.1`,即可被动捕获流量。`/proxy/stop` 跨平台强制清杀整个进程树(Windows `taskkill /F /T`、Unix 进程组信号),不漏端口。
- 🟡 **两级低延迟过滤**:Tier-1 在 mitmdump 钩子内联做域锁 + 静态资源否决(不阻塞浏览器);Tier-2 在 FastAPI 侧异步复用 `pruner.calculate_exposure_score` 评分,并标记疑似登录端点。
- 🟡 **实时雷达推流**:`GET /hunter/proxy/stream` 以 SSE(`text/event-stream`)实时推送捕获流;每客户端有界队列 + 断开即清理,杜绝内存泄漏。
- 🟡 **CA 证书门户**:`GET /hunter/proxy/cert` 下载 mitmproxy CA 证书以拦截 HTTPS(首次启动后生成)。
- 🟡 **送入 Hunter**:雷达列表可一键把某条流量带入逻辑狩猎工作流(登录候选自动预填身份锚点)。
- ⚪ **隔离与防滥用**:内部摄取端点 `/proxy/internal-ingest` 仅环回可达 + 每会话令牌 + 不进 OpenAPI 文档;失败一律返回 404。

---

## 5. 数据模型（4 张表）

| 表 | 作用 |
|---|---|
| `scan_tasks` | 一次扫描任务(目标、状态、cookie、时间戳) |
| `vulnerability_findings` | 漏洞发现。用 `source` 字段区分来源:`"nuclei"`(有 `scan_id`)或 `"hunter"`(`scan_id=NULL`)。Step D 新增 `parsed_request` / `automation_payloads` 等 JSON 列承载可 fuzz 数据 |
| `fuzzing_records` | 每条 payload 的验证记录(发出的请求、收到的响应、判定状态、差分细节) |
| `captured_flows` | **(Step 9)** 被动代理雷达捕获的一次 HTTP 交换:方法/主机/路径、请求与响应(截断)、Tier-2 暴露评分、是否登录候选、是否在域内。独立表(不与发现表强耦合),`promoted_finding_id` 单向回链已送入 Hunter 的流量 |

> 注:Hunter 发现的 `severity` 存真实等级 `INFO`,其"漏洞类型"记在 `template_id`(如 `logic-hunter:BOLA`)与 payload JSON 里——避免类型字符串污染按严重度的过滤/排序。
> 迁移:启动时 `create_all` 建表,并新增 **schema 漂移自检**——若旧库缺列会**清晰报错拒绝启动**(而非运行中深处崩);尚未引入 Alembic 正式迁移(见 §8 / D1)。

---

## 6. API 端点总览

> Base：`http://127.0.0.1:8000`,全部挂在 `/api/v1`。交互式文档:`GET /api/docs`(Swagger)、`GET /api/redoc`。

| 方法 & 路径 | 作用 | 状态码 |
|---|---|---|
| `GET /` | 健康检查 / 诊断信息 | 200 |
| `POST /api/v1/scan/start` | 启动 Nuclei 异步扫描 | 202 |
| `GET /api/v1/scan/{id}` | 查询扫描状态 | 200/404 |
| `GET /api/v1/scan/{id}/findings` | 列出该扫描的发现(仅 Nuclei) | 200/404 |
| `POST /api/v1/hunter/analyze` | 原始 HTTP + Gemini 逻辑分析 | 200(永不 500) |
| `POST /api/v1/hunter/findings` | 把分析存为可验证发现 | 201/422 |
| `POST /api/v1/hunter/verify/{id}` | 触发单目标差分验证 | 202/404 |
| `GET /api/v1/hunter/verify/{id}/results` | 取某发现的验证记录 | 200/404 |
| `POST /api/v1/hunter/verify/batch` | 单托管下并发验证多端点 | 202/400/404 |
| `POST /api/v1/hunter/auth/dry-run` | 身份锚点试运行(不落库) | 200 |
| `POST /api/v1/hunter/ingest-har` | HAR(JSON body)剪枝 | 200(永不 500) |
| `POST /api/v1/hunter/ingest-har-file` | HAR(文件上传,流式防 OOM) | 200(永不 500) |
| `POST /api/v1/hunter/proxy/start` | 启动被动拦截代理雷达 | 200 |
| `POST /api/v1/hunter/proxy/stop` | 停止代理并清杀进程树 | 200 |
| `GET /api/v1/hunter/proxy/status` | 雷达进程状态 + 摄取/推流遥测 | 200 |
| `GET /api/v1/hunter/proxy/stream` | 捕获流量的 SSE 实时推流 | 200 |
| `GET /api/v1/hunter/proxy/flows` | 列出最近捕获的流量 | 200 |
| `GET /api/v1/hunter/proxy/cert` | 下载 mitmproxy CA 证书 | 200/404 |
| `POST /api/v1/hunter/proxy/internal-ingest` | 内部摄取(仅环回 + 令牌,不入文档) | 202/404/413/503 |

详尽请求/响应体见 `docs/API_REFERENCE.md`。

---

## 7. 质量与工程化（可验收的证据）

- **自动化测试:后端 285 个,全部通过**(本会话亲测;`python -m pytest backend/tests -q`)。另有靶机独立套件 31 个。覆盖:
  - `test_pruner.py` — 剪枝评分 + 去除非确定性(随机种子下稳定);
  - `test_step8_custody.py` — auth 自愈托管 / 并行引擎;
  - `test_step_d_hunter_link.py` — Hunter→验证 数据桥接(列优先 + 旧格式回退);
  - `test_api_endpoints.py` — **API 层集成测试**(FastAPI TestClient,隔离临时库,Gemini/nuclei/后台任务均 mock):analyze、findings 落库、verify/batch 的 404、scan 启动/状态等;
  - `test_step9_proxy.py` —(**Step 9**)统一写者串行化、SSE 扇出 + 溢出丢弃、摄取背压、Tier-2 富化、ProxyManager 状态机、内部摄取端点环回/令牌/超限守卫;
  - `test_verdict_oracle.py` — 规则预言机判定正确性(离线,含误报杀手 / 弱信号守卫);
  - `test_endpoint_catalog.py` — 端点目录 OpenAPI→目录适配(Phase-7 影子输入);
  - `test_d18_phase2_crosspath.py` / `test_d18_b22_guard.py` / `test_d18_b1_write_record.py` — 跨路径判定 + B-2.2 跨资源守卫 + B-1 写记录机制(离线)。
  > 注:含 B-1 的写记录离线单测与影子路径回归测试(`test_d18_b1_write_record.py`、`test_d18_b1_shadow_integration.py`)。见 [`STATUS.md`](./STATUS.md)。
- **端到端验证(文档记录的真实跑通,TECH_DEBT R1/R4)**:
  - Hunter→验证:真实服务 + 真实本地靶机 + 真实数据库,走通 `analyze → 保存 → verify`,产出带判定的 `FuzzingRecord`。
  - 代理雷达三路(Step 9):①浏览器(代理客户端)→ mitmdump → 摄取 → 队列 → 统一写者 → DB(`captured_flows`);②摄取 → SSE → 实时事件;③代理流量 → analyze → findings → verify → `FuzzingRecord` → results。三路均以真实运行证据(DB 读 + 后端日志)确认。另:真机验证了 mitmdump 启动/绑定端口/`stop` 进程树清杀后端口释放无残留。
- **版本管理**:已纳入 git,提交历史清晰(基线 → 卫生清理 → 加固 → Step 9 → 验证判定层 → B-1 `37769b3`);`.env`、本地数据库、缓存均已 `.gitignore` 排除,**不会泄露密钥**。当前**唯一**未提交改动是代理雷达前端页(属后续前端阶段),见 [`STATUS.md`](./STATUS.md)。
- **配置即密钥分离**:所有外部依赖(nuclei 路径、Gemini Key、超时、host/port)走 `.env` + Pydantic 校验,启动即校验。
- **文档体系**:`docs/` 下有 8 份工程文档（架构、数据模型、各管线、API、开发指南、技术债 + 索引 README）；验收入口见根目录 `PROJECT_OVERVIEW.md`。文档以当前代码为准，发现冲突时请更新文档。

---

## 8. 已知限制与未完成（如实清单）

> 这些是**有意为之或已登记**的现状,不是隐藏缺陷。详见 `docs/TECH_DEBT.md`。

| 编号 | 事项 | 现状 / 影响 |
|---|---|---|
| **D2** | **无鉴权** | 任何能访问端口者都能发起扫描/验证。**刻意延后**,仅限本地/可信网络。鉴权依赖(jose/passlib)已就位,商用前必须补。 |
| **D5** | **两套前端** | 单文件仪表盘是主用且联通;`frontend/` Vite 是 mock 遗留,需收敛(规划中,单独专项)。 |
| **D1** | **无正式数据库迁移** | 仅 `create_all` + 启动期 schema 自检(缺列会清晰报错)。模型若频繁变更,建议上 Alembic。 |
| **D11** | **批量仅单主机** | v1 刻意约束,拒绝跨主机/第三方探测。多主机需按主机各自托管控制器。 |
| **D13** | **出站关闭 TLS 校验** | 为适配自签名渗透靶机,刻意全局关闭;非 bug,但需知悉。 |
| **D14** | **代理 Tier-1 丢弃越界/静态流量** | 雷达只捕获域内动态流量,静态资源与越界主机在 mitmdump 钩子内即被否决(不落库)。刻意设计,避免噪声与第三方探测。 |
| **D15** | **HTTPS 拦截需信任 CA** | 需在浏览器/系统导入 mitmproxy CA 证书才能解密 HTTPS;证书在代理**首次启动后**才生成,故 `/proxy/cert` 在那之前返回 404。 |
| **D16** | **mitmproxy 引入的版本耦合** | 安装 mitmproxy 强制锁定 `httpcore==1.0.7`、`bcrypt==4.0.1`(详见 `docs/DEVELOPMENT.md`)。升级 mitmproxy/httpx/passlib 前需复核此约束。 |
| — | **数据库为单机 SQLite** | 适合本地/单租户;高并发或多实例场景需迁移到 Postgres 等。 |
| — | **强依赖外部服务** | Gemini 需联网 + API Key(已加 60s 超时兜底);Nuclei 需本地安装二进制。 |

---

## 9. 如何运行 & 验收清单（合伙人可亲手过一遍）

### 前置
- Python 3.11;本地安装 **Nuclei** 二进制(用于 ① 扫描引擎);一个 **Gemini API Key**(用于 AI 分析,可选——无 Key 会优雅降级)。
- **mitmproxy**(用于 ③ 代理雷达)随 `backend/requirements.txt` 一并安装(`mitmdump`);默认从 PATH 解析,也可用 `.env` 的 `MITMDUMP_PATH` 指定绝对路径。

### 启动
```powershell
# 1. 安装依赖
pip install -r backend/requirements.txt
pip install -r backend/requirements-dev.txt   # 跑测试用

# 2. 配置（复制样例后填入真实值）
copy backend\.env.example backend\.env
#   关键项：NUCLEI_BINARY_PATH(绝对路径)、GEMINI_API_KEY、API_HOST(默认 0.0.0.0)

# 3. 启动后端
python backend/run.py
#   打开 http://127.0.0.1:8000/api/docs 看交互式 API 文档

# 4. 打开前端
#   直接双击 preview_dashboard.html（或静态托管），它会连 :8000
```

### 验收清单（建议逐项打勾）
- [ ] **测试全绿**:仓库根目录运行 `python -m pytest backend/tests -q` → 应见 `285 passed`。
- [ ] **服务健康**:`GET http://127.0.0.1:8000/` 返回 `status: online` 与诊断信息。
- [ ] **API 文档**:`/api/docs` 能看到全部端点与请求/响应模型。
- [ ] **逻辑狩猎链路**:在前端粘贴一段原始 HTTP 报文 → analyze 出报告与 payloads → 保存为 finding → 触发 verify → 在结果里看到带判定(verified/suspicious/failed)的验证记录。
- [ ] **(可选)Nuclei 扫描**:对一个你拥有/授权的靶机 `POST /scan/start` → 轮询状态 → 查看发现与 AI 修复建议。
- [ ] **(可选)代理雷达**:在前端「Proxy Radar」页填入授权域并 `start` → 浏览器把 HTTP 代理指向 `127.0.0.1:<PROXY_LISTEN_PORT>`(HTTPS 需先在 `/proxy/cert` 下载并信任 CA)→ 访问目标 → 雷达里实时看到捕获流 → 一键「Send to Hunter」进入分析。
- [ ] **诚信项核对**:确认 §8 的限制(尤其"无鉴权""仅本地")你能接受作为当前阶段定位。

---

## 10. 路线图与方向

> **战略、非目标(non-goals)、主线方向(B-1 / D19 / scope-lock)与授权边界统一收敛到根目录 [`ROADMAP.md`](./ROADMAP.md)(唯一事实源),本文不再重复。**
>
> 一句话定位:当前重心是把**差分验证引擎**的差异化能力打磨到可量化、可展示(公开靶场对比 + 2 分钟全链路 demo);鉴权(D2)、多租户、Postgres 迁移 / Alembic(D1)、企业部署等"产品 / 规模化"项一律暂缓。完整论证与解锁条件见 [`ROADMAP.md`](./ROADMAP.md),已知缺口见 [`TECH_DEBT.md`](./TECH_DEBT.md)。

---

*本文为验收用途的真实快照;深入细节请进 `docs/`。代码与文档冲突时以代码为准。*
