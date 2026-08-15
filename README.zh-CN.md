[English](./README.md) · [简体中文](./README.zh-CN.md)

<!-- Logo lives at docs/assets/logo.png -->
<p align="center">
  <img src="docs/assets/logo.png" alt="Aivist Verify" width="140"/>
</p>

<h1 align="center">Aivist Verify</h1>

<p align="center">
  <strong>一个模型无法把它说服成 false positive 的 BOLA/IDOR 访问控制确认引擎。</strong>
</p>

<p align="center">
  AI 负责提出。<strong>代码</strong>负责裁决 —— 而代码只可能说<em>不</em>。
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"/>
  <img src="https://img.shields.io/badge/false%20positives-0%2F300-brightgreen" alt="0 false positives on the benchmark"/>
</p>

<p align="center">
  <a href="https://aivist.dev"><strong>aivist.dev</strong></a>
</p>

---

大多数访问控制工具交给你的是一堆*可能*——一批疑似 IDOR，你还得在凌晨 2 点一个一个手工去验。**Aivist Verify 交给你的是证据，或者一个诚实的"没有"。** 你给它一个候选项——一个端点、两个身份——它告诉你攻击者是否真的跨越了用户边界、拿到了受害者的资源，并附上一条可复现的 evidence chain。

真正关键的地方在于：**判定由代码做出，而不是模型。** AI 读取流量并*提出*；一道确定性的、downgrade-only 的闸门*裁决*。在一次 430 次运行的基准测试中，模型的原始输出有 **79 次**要求把一个**安全的**端点标记为 `verified`——而代码闸门**每一次都拒绝了**。零 false positive。不是"更少"。是零——这由结构决定，而且这个基准测试你可以用一条命令自己重跑。之后我们把它带到两个并非我们编写的公开脆弱目标上——crAPI 和 VAmPI——它在那里确认了两个真实的跨用户 BOLA，没有产生任何一个 false positive。

## 为什么会有这个项目

围绕这个问题已经存在两类工具，而它们留下了同一个缺口：

- **开源扫描器**擅长把*可能*翻出来。它们标记出疑似 IDOR，然后——往往就写在它们自己的 README 里——把真正的确认工作交回给你。
- **闭源 SaaS 验证服务**确实会跑可利用性检查，但逻辑是个黑盒，产出的是一份你无法独立复现的报告，而"更少的 false positive"是一种统计上的期望，不是结构性的保证。

Aivist Verify 是夹在两者之间的那一层：**开源、本地运行，并且在结构上就不可能给出一个错误的 `verified`**——同时附带一条任何审阅者都能重放的 evidence chain。它并非一开始就长这样。它起初是一个完整的 AI 渗透测试*平台*——有服务器、有 API、有仪表盘。在构建过程中的某一刻，一件事变得很明显：这个世界不需要又一个把*可能*翻出来的东西；它需要的是能够*确认*的东西。于是整个服务器层被删掉了，一切收敛到唯一真正有价值的那一部分：确认引擎。剩下的东西小，是刻意为之。

## 它如何工作 —— AI 提出，代码裁决

```
 candidate (endpoint + attacker/owner identities)
        │
        ▼
 [ AI proposes ]   the model reads the real baseline/attack traffic and proposes a candidate
        │          verdict; it may request ONE extra evidence fetch, executed for real.
        ▼
 [ CODE disposes ] deterministic gates re-check the proposal against the attack's own runtime
        │          bytes. They can only DOWNGRADE. A `verified` survives only if a structural
        │          exemption, computed in code, actually holds. The model's opinion is not an input.
        ▼
 verdict + evidence chain   (the model's RAW verdict AND the gate's decision, recorded separately)
```

这不是"AI 没用，真正干活的是代码"。恰恰相反：**两者你都需要，而大多数工具把分工搞反了。** 只有模型能读懂杂乱的、与具体业务强相关的流量，并从上千个端点里挑出哪一个*值得一查*——代码猜不出来。而也只有代码才能随后裁定这次访问*是否真的*跨越了用户边界——因为模型一旦被交予裁决权，就会带着十足的把握说出一个 false positive。模型是那个能嗅出金子可能在哪里的探矿者；代码是那台从不会把黄铁矿当成金子的化验设备。Aivist Verify 把两者各自放在合适的位置：**AI 负责广度，代码握有最终决定权，而这个最终决定只可能是拿走一个结论**——绝不可能凭空造出一个。这就是为什么模型无法把它说服成一个 false positive。

每一条结果都会把模型的**原始**判定（`ai_verdict_raw`）*和*闸门的决定（`guard_override`）记录为**两个独立字段**，因此 evidence chain 读起来就是"模型提出了 X；代码裁定为 Y"。引擎和 CLI 都无法制造出一个 `verified`。

## 亲眼看看 —— 一次真实的确认，未经编辑

`aivist demo` 会启动一个内置的脆弱实验环境，端到端地确认一次真实的跨用户写入——不需要 Docker，不需要目标，不需要 token。下面是实际的、未经修改的输出：

```text
[CONFIRMED]  cross-user write (BOLA) - POST /api/users/1/display-name
  Verdict: verified  (confirming channel: write-record read-back)  (guard_override=write_record_readback_decisive)
  Basis: a deterministic code gate authorized this (write-then-independent-read proof), not the model's opinion alone.
  What the engine proved:
    Wrote as the attacker, then read the object back through a different
    endpoint as another identity. A record carrying the victim's object id and
    the exact value this attack wrote was found on that read-back, so the
    unauthorized write provably persisted. That persisted read-back is the
    proof.
  Here's what happened - the Evidence chain (physical bytes the engine actually exchanged):
    1. Sent as the attacker:
       POST http://127.0.0.1:8001/api/users/2/display-name
       Content-Type: application/json
       Authorization: ***REDACTED***
       Body: {"display_name": "vm-1-eae9d9d20e"}
    2. Attack response received:
       -> HTTP 200 | Content-Length: 15
       {"status":"ok"}
    3. What decided it (byte-level):
       - the write was attributed to the attacker's own identity  (caller_identity=same_as_caller)
       - this attack's unique value was present in the read-back body - the write landed  (payload_causality=confirmed_in_body)
       - the anchoring read-back path was not found (observe-only)  (anchoring_result=failed_path_not_found)
    4. Not taken as proof:
       - the model's raw opinion alone did NOT decide this - the deterministic code channel did  (ai_verdict_raw=verified)
  Re-runnable evidence package (fill <REDACTED> from YOUR config; never a live token):
    # 1) The attack request - reproduces the cross-user access AS THE ATTACKER:
    curl -X POST 'http://127.0.0.1:8001/api/users/2/display-name' \
    -H 'Content-Type: application/json' \
    -H 'Authorization: <REDACTED>' \
    --data '{"display_name": "vm-1-eae9d9d20e"}'
  So what / Next step:
    A real cross-user access bug: the attacker could write to the victim's
    object. It is reproducible (the request above).
    Next: report it, or fix by enforcing an ownership check on this endpoint.
  [lab oracle] lab label=REAL (expects verified); engine said 'verified' - AGREES. (informational only; NEVER an input to the verdict)
```

而当攻击者什么也没得到时，工具会如实说明：一次没有产生跨用户效果的运行会返回 **`[REFUTED]`**（"代码闸门守住了防线——未确认存在跨用户效果"）；一次被限流或遇上过期 token 的运行会返回 **`[NOT DATA]`**，并且**根本不给出任何判定**——既不说安全，也不说有漏洞。它拒绝猜测。这种拒绝正是整件事的意义所在。

## 证据 —— 430 次运行，零 false positive

五种确认形态——跨用户写入、读取型语义等价、静默写入 / 对象状态、删除 / 反向断言，以及批量赋值 / 低熵状态跳变——在**两个结构上完全不同、各自独立的脆弱实验环境**（整数 id 与 UUID id）上运行，由一个**真实的** `gemini-2.5-pro` 循环驱动，每次运行都重新播种：

| | 结果 |
|---|---|
| SECURE / 对照组运行 → 最终 `verified` | **300 → 0** —— 零 false positive |
| 真实漏洞运行 → 最终 `verified` | **130 → 130** —— 每一个植入的缺陷都被捕获，且经由其预期通道 |
| 可用运行 | **430 / 430**，零降级 |
| 模型原始输出要求把一个 SECURE 端点判为 `verified`、而闸门予以拒绝的次数 | **79 / 79** |

请再读一遍最后一行：在 **79** 次独立的运行中，AI 想要确认一个根本不存在的漏洞，而代码闸门阻止了全部 79 次，使它们没有一次抵达 `verified`。这就是护城河，并且是被测量出来的。

**这是一次在两个实验环境上进行的受控基准测试 —— 不是真实世界战果的统计。** 干净的真实世界确认确实非常罕见，而这个项目诚实的标题是*区分能力加上零 false positive 的纪律*，而不是满屏的 `CONFIRMED`。上面每一个数字都是从已提交的产物 `scripts/measure/results/sweep_highN.jsonl` 重新计算得出的——参见 [`RESULTS.md`](./RESULTS.md)。

## 在真实的公开目标上验证 —— 不只是我们自己的实验环境

上面的基准测试跑在我们自己搭建的实验环境上。因此我们把引擎带到了**两个并非我们编写的、故意设计成含有漏洞的公开目标**上——[crAPI](https://github.com/OWASP/crAPI) 与
[VAmPI](https://github.com/erev0s/VAmPI)——并针对它们已记录在案的 BOLA 运行。**九次引擎运行，确认了两个真实的跨用户 BOLA，零 false positive**——以及一个被发现、被修复、并在线上重新确认过的真实 false positive。下面每一次运行都以原样归档在
[`scripts/measure/real_targets/`](./scripts/measure/real_targets/)。

| 目标 | 端点 | Ground truth | 判定 | 结果 |
|---|---|---|---|---|
| **crAPI** | `GET /workshop/api/mechanic/mechanic_report?report_id=` | 真实 BOLA —— 泄露所有者的邮箱、电话、VIN 以及私密工单文本 | **`verified`** | ✅ **真阳性** |
| **VAmPI** | `GET /books/v1/{book_title}` | 真实 BOLA —— 归属者私有、带有 secret 的书目 | **`verified`** | ✅ **真阳性** |
| **crAPI** | `GET /community/api/v2/community/posts/{postId}` | 公开信息流 —— *这个端点曾经产生过一次 false positive* | `inconclusive`（公开） | ✅ **修复本身，在线上重新确认** |
| **crAPI** | `GET /workshop/api/mechanic/mechanic_report?report_id=`（加入 bystander） | 同一个真实 BOLA，但每一个已认证用户都能读取 | `inconclusive` | ⚠️ **按设计漏报** —— 见下文 |
| **crAPI** | `GET /workshop/api/shop/orders/{order_id}` | 公开 / 无需认证 —— 匿名请求即可读取整张订单，因此并非跨用户 BOLA | `inconclusive`（公开） | ✅ 真阴性 |
| **VAmPI** | `GET /users/v1/{username}` | 公开 / 无需认证 —— 并非跨用户 BOLA | `inconclusive`（公开） | ✅ 真阴性 |

两次确认都经由与实验环境运行相同的、由代码裁决的通道达成——owner-view 闸门佐证了攻击者确实收到了所有者的真实数据。其中 crAPI 那一例还额外覆盖了对象 id 位于 **query string** 而非路径参数的情形。

### 我们在自己身上发现的那个 false positive

在一次更早的真实目标运行中，crAPI 的**公开社区信息流**被确认为一次跨用户违规。它并不是——那些帖子按设计就是公开的。那是一个真实的 false positive，而且发生在最要命的地方：整个工具赖以成立的那条保证上。

于是它被修复了——一个公开资源探针，用一个不相关的第三身份去读取同一个对象，当那个第三方也能读到时就抑制这次确认。该修复先在 fixture 上得到验证，随后**针对线上的 crAPI 重新运行**，同一个端点如今返回 `inconclusive`。那次线上的重新确认与其余记录一并归档。

我们把这件事公开，是因为一个在公开场合从未出过错的工具，通常只是从未在公开场合被检验过。有意思的问题不是 false positive 是否曾经发生过——而是工具在第二次会怎么做。

### 它会漏掉什么 —— 以及为什么这是值得的取舍

那个修好了社区信息流 false positive 的探针，同时也带来了一次刻意的漏报。当**每一个已认证用户**都能读取某个资源时，引擎会拒绝确认它——哪怕它确实是一个真实的漏洞。crAPI 的 `mechanic_report`（泄露所有者的邮箱、电话、VIN 以及私密工单文本）和 VAmPI 的 `/books` 正是如此：它们是真实的 BOLA，但只要提供了一个 bystander token，判定就会翻转为 `inconclusive`。在这两个例子中，匿名请求都被干净地拒绝了——这些资源是真的坏了，而不是真的公开——但引擎依然不予确认。

这不是一个 bug，也无法靠更好的算法修掉。在黑盒条件下，**"每个已认证用户都能读到它，是因为授权坏了"与"每个已认证用户都能读到它，是按设计如此"会产生逐字节完全相同的响应。** 真正区分二者的事实是 API 作者的*意图*，而意图并不出现在任何一个 HTTP 响应里。OpenAPI 的 `security` 元数据同样无法裁决这一点——它声明的是*认证*要求，而不是行级的归属关系。靠内容去猜（例如"这里面有 PII，所以它应该是私有的"）只会制造 false positive：一份公开的员工通讯录本来就合法地暴露邮箱。

所以引擎刻意接受了这个取舍：**它宁可漏掉一个真实的发现，也不愿凭空造出一个。**

当你*确知*某个资源本应是归属者私有的，你可以自己把这个意图提供给它。在配置了 bystander token 的前提下，`--assert-owner-only`（用于 `scan`，或在 `run --config` 的 op 中写 `"assert_owner_only": true`）会让引擎发起匿名探测；如果每一个已认证身份都能读到该对象、而匿名请求被干净地拒绝，它就会把这个发现呈现为
**`inconclusive` —— broken-for-all，标记为需人工复核**。即便如此它也绝不会自动确认：操作者的意图可以把一个发现提交给人工复核，但永远无法制造出一个 `verified`。这一点已在两个目标上得到线上验证。

> **这一主张的适用范围。** 这是在两个目标上进行的九次经人工核验的运行——是一个工程信号，而不是实验环境基准测试所提供的那种统计意义上的零 false positive 纪录。此处的 ground truth 是人工建立的（每个端点的真实状态都在引擎运行之前经由手工核实）；而实验环境基准测试的 ground truth 是独立且可由机器校验的。请按它们本来的样子来理解：实验环境证明了这套纪律在规模上成立，真实目标则证明它在接触我们并未编写的软件时依然站得住。

## 快速开始

需要 Python 3.11+ 和一个 Gemini API key（`GEMINI_API_KEY`）：

```bash
pip install -e .          # installs the `aivist` command
aivist config             # choose provider, paste your API key (hidden), pick a model
aivist demo               # confirm a real BOLA on the built-in lab — zero setup
```

然后把它指向你**自己的**本地运行目标——最短的路径是交互式控制台：

```bash
aivist                    # opens the console: demo · config · target · verify · scan
```

……或者以非交互方式驱动它（见下文）。

## 安装与完整用法

```bash
git clone git@github.com:Aivist/Aivist-Verify.git
cd Aivist-Verify
pip install -e .          # registers the `aivist` command; config lives under ~/.aivist/
```

**`aivist verify` —— 确认单个发现。**

```bash
# LAB mode: confirm against a built-in ground-truth caseset
aivist verify --caseset <caseset.json> [--case <id>]

# EXTERNAL mode: a locally-run real target = base URL + OpenAPI spec + one operation
aivist verify --target http://localhost:8888 --spec ./openapi.json --op ./operation.json
# optional: --auth ./login.json for automatic re-login instead of static tokens
```

**`aivist scan` —— 非交互式自动发现 + 确认。** 可基于 OpenAPI spec，*也可*在没有 spec 的情况下进行：

```bash
aivist scan --target-file ./mytarget.txt
aivist scan --target-file ./mytarget.txt --endpoints-file ./endpoints.txt   # plain METHOD /path list
aivist scan --target-file ./mytarget.txt --traffic-file   ./capture.har     # browser/Burp HAR or raw-HTTP
aivist scan --target-file ./mytarget.txt --capture                          # live mitmproxy capture
aivist scan --target-file ./mytarget.txt --assert-owner-only                # surface "broken for all" for review
```

**`aivist run --config <json>` —— 完全非交互的入口（CI / 脚本化）。** JSON 进，结构化 JSON 输出到 stdout，token 只从环境变量读取——没有任何交互提示。**这是自动化使用的主要路径：**

```bash
aivist run --config ./config.json            # machine-readable JSON on stdout
aivist run --config ./config.json --pretty   # + a human summary on stderr (stdout stays pure JSON)
```

**`aivist target` / `aivist config`** —— 把一个可复用的目标保存为单个可编辑文件（`--dump-template` / `--from-file`，一次性报出全部错误的校验）；设置 AI 提供方 / key / 模型。

**Token** 来自环境变量（对 `scan` 而言，也可以用一个在使用时读取、且从不落盘持久化的 `--tokens-file`）：

```bash
export TARGET_ATTACKER_TOKEN=...    # the attacker (the attack is sent as this account)
export TARGET_OWNER_TOKEN=...       # the victim/owner (re-read only, as the owner)
export TARGET_BYSTANDER_TOKEN=...   # a third account that does NOT own the resource
```

`attacker == owner` 的冲突会在引擎运行之前就被 fail-closed 地拒绝；token 从不会被回显或写入日志。

## 自己复现

你不必相信一段终端记录——证据可以在三个彼此独立的层面上重新运行：

```bash
# Layer 1 — the labs' own ground truth, NO API key. The engine is graded against these, never the reverse.
python -m pytest vulnerable_target/test_vulns.py -q      # 31 tests
python -m pytest depot_target/test_vulns.py -q           # 23 tests

# Layer 2 — the committed result artifact, NO API key: one JSON row per run, raw verdict -> final verdict,
# which exemption fired, every anchor, a per-row regression check. Small and diffable.
#   scripts/measure/results/sweep_highN.jsonl

# Layer 3 — regenerate Layer 2 from Layer 1 with YOUR OWN Gemini key (~430 calls).
python scripts/measure/verdict_measure.py \
  --caseset scripts/measure/casesets/vulnerable_target.json \
  --caseset scripts/measure/casesets/depot.json \
  --n-safe 20 --n-vuln 10 --out scripts/measure/results/sweep_highN.jsonl
```

完整方法以及每条通道已记录在案的**边界**：[`REPRODUCE.md`](./REPRODUCE.md) 与 [`RESULTS.md`](./RESULTS.md)。

## ⚠️ 适用范围与安全须知

**在把它指向任何东西之前，请先读这一节。**

- **只对获得授权的目标使用。** 确认一个 BOLA/IDOR 会用真实凭据发出真实的跨用户请求。只能对你自己拥有、或已取得**明确书面许可**的系统运行。未经授权的测试可能违法。
- **本地 / 自托管目标。** 它是为你所控制的本地运行目标而构建和测试的。它不是一个用来扫描第三方或面向公网系统的工具，也不是一个批量扫描器。
- **它自身没有任何认证机制。** Aivist Verify 自身不带访问控制——请在本地运行它，绝不要把它作为一个服务暴露出去。
- **凭据由你提供。** 它只会以你提供了 token 的那些身份行事，并且只针对你所指向的那一个目标。

一个全部价值都建立在*诚实*之上的工具，必须对自己的边界同样诚实。范围越窄、越清晰，零 false positive 这一主张就越值得信任。

## 能力与诚实的局限

**已支持（在仓库内构建并经过审计）：** 基于 OpenAPI spec 以及无 spec 的发现（手工端点列表、HAR / 原始 HTTP 解析、实时 mitmproxy 抓包）；静态 token *以及*自动重新登录的认证方式；一个在遇到质询/限流时中止并转为 `NOT DATA`、而不是持续冲击目标的断路器；同一接缝之后的三家模型提供方（默认 Gemini、OpenAI 兼容、Anthropic）；以及面向 CI 的完全非交互 `run --config` 入口。

**局限，直说：** **统计意义上的**零 false positive 纪录来自**两个受控实验环境**；引擎另外还在**两个公开的真实目标**上得到了验证（crAPI 与 VAmPI —— 九次经人工核验的运行，[见上文](#在真实的公开目标上验证--不只是我们自己的实验环境)），但它**尚未**在多样化的生产系统上大规模运行过——"已支持"意味着该能力存在并经过审计，而不是说它已在真实环境中久经考验。读取语义确认闸门存在**已记录在案的边界**（参见 `RESULTS.md`），其中包括对 broken-for-all 资源的一次刻意漏报。该工具**没有任何认证机制**，且面向 **localhost**。

## 仓库结构

```
Aivist-Verify/
├─ run.py                    # CLI entry point (the `aivist` command)
├─ README.md · RESULTS.md · REPRODUCE.md · LICENSE
├─ backend/app/
│   ├─ services/             # the confirmation engine: differential oracle, deep verifier, exemption gates
│   └─ cli/                  # the command line and interactive console
├─ vulnerable_target/        # lab 1 (integer ids) + its independent ground-truth test suite
├─ depot_target/             # lab 2 (UUID ids) + ground-truth suite
├─ scripts/measure/          # the measurement harness + committed result artifacts (sweep_*.jsonl)
└─ docs/                     # architecture and engine documentation
```

## 文档

- [aivist.dev](https://aivist.dev) —— 项目站点：一眼看清工作机制、基准测试与真实目标运行结果。
- [`RESULTS.md`](./RESULTS.md) —— 完整的零 false positive 基准测试，逐个用例，并附每条通道已记录在案的边界。
- [`REPRODUCE.md`](./REPRODUCE.md) —— 自己复现这些证据，三个彼此独立的层面。
- [`docs/PROJECT_OVERVIEW.md`](./docs/PROJECT_OVERVIEW.md) —— 今天存在哪些东西，以及各部分如何组合。
- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) —— 深入讲解两层判定流水线。
- [`docs/VERIFY_ENGINE.md`](./docs/VERIFY_ENGINE.md) / [`docs/DEEP_VERIFY.md`](./docs/DEEP_VERIFY.md) —— 差分预言机、深度验证器，以及四条豁免通道。

## 许可

MIT © 2026 Lang Li —— 参见 [`LICENSE`](./LICENSE)。

---

<p align="center"><sub>Aivist Verify 给出确认，而不只是标记。AI 提出；代码裁决；而代码只能拿走一个结论，绝不会凭空造出一个。</sub></p>
