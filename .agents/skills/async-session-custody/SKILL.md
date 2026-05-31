---
name: async-session-custody
description: 规范 Anti-Gravity 后端 (FastAPI + SQLAlchemy 2.0 async + aiosqlite) 的异步并发与数据库 session 托管 (custody) 设计。涉及 fuzzer.py 并发改造、Step 7 session custody state machine、asyncio 并发写 DB、SQLite 锁、AsyncSession 共享等问题时必读。
---

# 异步 Session Custody 开发规范

适用于 `backend/app/services/fuzzer.py` 及所有后台异步任务。

## 1. 硬约束（违反必出 bug）

- **`AsyncSession` 不是并发安全的**：一个 session 持有单条 DB 连接，同一时刻只能执行一个操作。**严禁**把同一个 session 传给多个并发的 `asyncio` task 同时 `await`，否则触发 `InvalidRequestError` / greenlet 错误（"this session is already... "）。
- **SQLite 是单写者**：`sqlite+aiosqlite` 下并行写不存在。提速只能来自**网络侧并发**（httpx 并发请求），**DB 写必须串行化**。
- **当前未启用 WAL**：`database.py` 只设了 `check_same_thread=False`。多写场景前应启用 `PRAGMA journal_mode=WAL;` 缓解 "database is locked"。
- **后台任务永不崩溃**：所有 orchestrator 顶层包 `try/except`，失败写入 DB 状态，不抛到事件循环。

## 2. 现存技术债（改造前先知道）

`execute_differential_fuzzing()` 里 `semaphore = asyncio.Semaphore(3)` **从未生效**——payload 是 `for` 循环里顺序 `await _execute_single_fuzz(...)`，没有 `gather`/`create_task`/`TaskGroup`，所以实际是串行。它"没出事"只是因为串行恰好规避了 AsyncSession 并发问题。**一旦上真并发，必须同步解决 session 归属。**

## 3. 目标 Custody 模式（两选一）

**模式 A — 单写者 + 队列（推荐用于 SQLite）**
- N 个 worker task 并发跑网络请求（`httpx` + `Semaphore(N)` + `gather`/`TaskGroup`）。
- worker 不碰 DB，只把结果 `put` 进 `asyncio.Queue`。
- **唯一一个 writer task 独占那个 AsyncSession**，从队列 `get` 并串行持久化。
- 用哨兵（sentinel）或 `queue.join()` 做有序关闭，避免悬挂 → deadlock-free。

**模式 B — session-per-task**
- 每个并发 task 用 `async with async_session_factory() as db:` 开**自己的** session。
- 适合非 SQLite（Postgres）；SQLite 下仍受单写者限制，写多时仍需限流。

## 4. 复用现有设施

- 写入用 `_commit_with_retry(db)`（已实现指数退避处理 "database is locked"）。
- 导入路径统一 `from backend.app...`（项目从仓库根运行）。

## 5. 检查清单

```
- [ ] 没有把单个 AsyncSession 跨并发 task 共享
- [ ] 网络并发与 DB 写已分离（写串行化）
- [ ] 关闭路径无悬挂（sentinel/join 覆盖异常分支）
- [ ] 顶层 try/except 保证后台任务不崩
- [ ] 写入走 _commit_with_retry
- [ ] 如启用并发写，已加 PRAGMA journal_mode=WAL
```
