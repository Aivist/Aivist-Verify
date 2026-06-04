# Anti-Gravity · AI 渗透测试平台 — 项目总览（验收版）

> 本文面向**项目验收 / 合伙评估**。目标：不了解代码的人读完即可判断「这是什么、有什么、到什么程度、能不能落地」。
> 原则：**如实陈述,不夸大、不隐瞒**。带 ✅/🟡/⚪ 的成熟度标记和「已知限制」一节都是真实现状。
> 基准：本文与当前代码一致(最近一次提交)。代码为准——如发现不符,以代码为准并请更新本文。

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
| 测试 | **73 个自动化测试全绿**(pytest),覆盖核心服务 + API 层 + 被动代理雷达 |
| 前端 | 主用单文件仪表盘已联通后端;另有一个遗留的 Vite 前端(mock 数据,非产品基线) |
| 版本管理 | 已纳入 git,有 3 个清晰快照;密钥/数据库已隔离出版本库 |

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
├─ PROJECT_OVERVIEW.md            # ← 本文（验收入口）
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
│  └─ tests/                      # pytest（73 个）
├─ docs/                          # 工程内部文档（架构/数据模型/各管线/API/技术债）
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
- ⚪ **AI 深度验证（影子模式 / Phase 7，只读观测）**:新增独立组件 `services/deep_verifier.py`——两轮式 AI-in-the-loop「写后读」(Gemini),用于解决规则预言机在"沉默型"越权(写接口恒返回 `200 {"status":"ok"}`)上只能停在 `suspicious` 的盲区。已作为**纯增量、只读**的 Phase 7 接入 `execute_parallel_fuzzing`:批次结束后对 `suspicious` 记录复核,**仅写日志**(`AI_shadow_verdict=…`),**不改写** `verification_status`/`diff_details`、不影响用户所见、失败即吞。受两个默认关闭的开关门控:`AI_DEEP_VERIFY_ENABLED` 与 `AI_DEEP_VERIFY_SHADOW`(两者都为 True 才会真正调用 Gemini)。两处已知接缝(auth 上下文、最小端点目录)见 `docs/TECH_DEBT.md` D18;尚未作为权威判定见 D19。准确率基准见 `vulnerable_target/benchmark/RESULTS.md`(n=9,AI 8/8 正确,0 误报/漏报)。

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

- **自动化测试:73 个,全部通过**(本会话亲测)。覆盖:
  - `test_pruner.py` — 剪枝评分 + 去除非确定性(随机种子下稳定);
  - `test_step8_custody.py` — auth 自愈托管 / 并行引擎;
  - `test_step_d_hunter_link.py` — Hunter→验证 数据桥接(列优先 + 旧格式回退);
  - `test_api_endpoints.py` — **API 层集成测试**(FastAPI TestClient,隔离临时库,Gemini/nuclei/后台任务均 mock):analyze、findings 落库、verify/batch 的 404、scan 启动/状态等;
  - `test_step9_proxy.py` —(**Step 9**)统一写者串行化、SSE 扇出 + 溢出丢弃、摄取背压、Tier-2 富化、ProxyManager 状态机、内部摄取端点环回/令牌/超限守卫。
- **端到端验证(文档记录的真实跑通,TECH_DEBT R1/R4)**:
  - Hunter→验证:真实服务 + 真实本地靶机 + 真实数据库,走通 `analyze → 保存 → verify`,产出带判定的 `FuzzingRecord`。
  - 代理雷达三路(Step 9):①浏览器(代理客户端)→ mitmdump → 摄取 → 队列 → 统一写者 → DB(`captured_flows`);②摄取 → SSE → 实时事件;③代理流量 → analyze → findings → verify → `FuzzingRecord` → results。三路均以真实运行证据(DB 读 + 后端日志)确认。另:真机验证了 mitmdump 启动/绑定端口/`stop` 进程树清杀后端口释放无残留。
- **版本管理**:git 3 个快照(基线 → 卫生清理 → 加固);`.env`、本地数据库、缓存均已 `.gitignore` 排除,**不会泄露密钥**。
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
- [ ] **测试全绿**:仓库根目录运行 `python -m pytest backend/tests -q` → 应见 `73 passed`。
- [ ] **服务健康**:`GET http://127.0.0.1:8000/` 返回 `status: online` 与诊断信息。
- [ ] **API 文档**:`/api/docs` 能看到全部端点与请求/响应模型。
- [ ] **逻辑狩猎链路**:在前端粘贴一段原始 HTTP 报文 → analyze 出报告与 payloads → 保存为 finding → 触发 verify → 在结果里看到带判定(verified/suspicious/failed)的验证记录。
- [ ] **(可选)Nuclei 扫描**:对一个你拥有/授权的靶机 `POST /scan/start` → 轮询状态 → 查看发现与 AI 修复建议。
- [ ] **(可选)代理雷达**:在前端「Proxy Radar」页填入授权域并 `start` → 浏览器把 HTTP 代理指向 `127.0.0.1:<PROXY_LISTEN_PORT>`(HTTPS 需先在 `/proxy/cert` 下载并信任 CA)→ 访问目标 → 雷达里实时看到捕获流 → 一键「Send to Hunter」进入分析。
- [ ] **诚信项核对**:确认 §8 的限制(尤其"无鉴权""仅本地")你能接受作为当前阶段定位。

---

## 10. 路线图（按名片 / 验证优先）

> 当前唯一目标：把差异化能力打磨到可展示、可量化。
> 商业化相关项一律暂缓，仅在对比数据证明值得后才解锁。

### 主线（现在投精力）
1. **差分验证引擎深化**：差分预言机精度、覆盖更多越权类型（BOLA/IDOR、垂直越权、Mass-Assignment、参数污染、竞态）。这是本项目的智力核心与唯一壁垒。
2. **公开靶场对比实验**：在故意有漏洞的靶机上，量化「本引擎的确定性差分验证」vs「agent 式自由 PoC 验证」的误报率 / 复现率。这是回答“能否商业化”的唯一证据。
3. **2 分钟全链路 demo**：抓流量 → AI 分析出 IDOR/BOLA 候选 → 差分引擎判定 verified，录屏。
4. **前端收敛（D5）**：退役 mock 版 `frontend/`，只保留 `preview_dashboard.html` 一个。

### 暂缓 —— 不在当前主线（解锁条件：上面第 2 项的对比数据证明值得商业化后才启动）
- **鉴权（D2）**、**多租户**、**Postgres 迁移 / Alembic（D1）**、**企业部署**
  这些是“产品 / 规模化”范畴，与“名片 / 验证”无关。在拿到对比数据前，投入到这些上的精力都是浪费。

---

*本文为验收用途的真实快照;深入细节请进 `docs/`。代码与文档冲突时以代码为准。*
