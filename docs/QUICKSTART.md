# QUICKSTART — open the confirmer

The BOLA/IDOR **confirmer** is the human-walkable front door: it runs the real verification
engine against a lab finding and prints whether the finding is a **CONFIRMED** cross-user
access-control bug or **REFUTED**.

## Prerequisites

- **Python 3.11+** with `python` on PATH.
- **Dependencies** (once, from the repo root):
  ```bash
  pip install -r backend/requirements.txt
  ```
- **`GEMINI_API_KEY`** — the confirmer calls the real model. Set it with `aivist config`, a shell
  environment variable, or a `GEMINI_API_KEY=<your key>` line in `backend/.env` (auto-loaded).

## Run it

Run everything from the repo root.

**CONFIRMED demo** — a real cross-user write BOLA:
```powershell
python run.py confirm --caseset "scripts\measure\casesets\vulnerable_target.json" --case B1-X-CROSS
```

**REFUTED demo** — a securely-handled look-alike:
```powershell
python run.py confirm --caseset "scripts\measure\casesets\vulnerable_target.json" --case X-EQUIV-SAFE
```

Also: omit `--case` to confirm the whole caseset (one result per case + a one-line tally).

**Exit codes:** `0` = nothing confirmed · `1` = at least one CONFIRMED · `2` = run/degraded error (NOT DATA).

### If `python` is "not found" or you hit `ModuleNotFound`
- Always run from the repo root — the relative caseset path is resolved from there.
- If `python` is not on PATH, invoke your interpreter explicitly (on Windows, e.g. `py -3.11 run.py …`).

## Confirm a REAL target — `verify` (one finding) and `scan` (auto-discover many)

The lab demo above uses a caseset. Against a **locally-run real target** you have two front doors. Both
need an API key first (run `config` once; see [`LLM_PROVIDERS.md`](./LLM_PROVIDERS.md)). The engine's
verdict is byte-identical to the lab path — a real target has **no ground truth**, so there is **no
zero-FP claim**; a timeout / 401 / 403 / 429 is reported as **NOT DATA**, never a verdict.

### `verify` — confirm ONE finding you already have (subcommand)

```powershell
python run.py verify --target http://localhost:8888 --spec path\to\openapi.json --op path\to\op.json
```

You paste the two Bearer tokens (attacker + owner, hidden). `--op` is one operation
`{method, baseline_path, body, payload, shape}` — see the worked template
[`examples/op.crapi_mechanic_report.json`](../examples/op.crapi_mechanic_report.json) (a crAPI
query-string IDOR, `report_id 7→6`). Add `--auth <login.json>` to log in / auto-refresh tokens instead
of pasting static ones.

### `scan` — auto-discover BOLA/IDOR candidates and confirm each

`scan` runs **either** inside the interactive console **or** as a non-interactive subcommand
(`python run.py scan --target-file <file> [--endpoints-file … | --traffic-file … | --capture]`, tokens
from env). For the interactive walk, launch the console with **no arguments**:

```powershell
python run.py          # no args → opens the interactive console
```

At the prompt: `config` (API key) → `target` (create one: base URL, OpenAPI spec **or a blank spec**,
and two accounts' ids) → `scan`. `scan` then:

1. builds an **endpoint catalog** from the target's spec, **or — if the target has no spec — from a plain
   `METHOD /path` endpoints file** you point it at (templated paths like `/orders/{id}` detect best);
2. asks the model to **propose BOLA/IDOR candidates**, which **code vets twice** before anything runs;
3. **sources each candidate's ids** — from an optional id-source JSON
   (`{"ids": {…}, "collections": {…}}`: tier a = ids you supply, tier b = a "list my objects" endpoint
   harvested **per-account**), or a code-fenced AI-proposed collection (tier c); **no sourceable id →
   that candidate is SKIPPED**, never guessed;
4. runs each vetted op through the **same confirm** `verify` uses and prints one **tier-grouped report**
   (`[CONFIRMED]` / `[SIGNAL]` / `[INCONCLUSIVE broken-for-all]` / `[REFUTED]` / `[NOT DATA]` /
   `[SKIPPED]`).

Optional prompts during `scan`: a **login file** (`--auth`, so a token expiring mid-scan is refreshed
per-account), a **bystander / third-account token** (public-resource discrimination), and
**owner-private assertion** (`assert_owner_only`, surfaces broken-for-all findings for human review).

> **Red lines (why this is safe):** the AI only *proposes* candidates; **code fences every op twice** and
> the **zero-FP engine judges** each; id harvesting is **per-account, never cross-account, never
> fabricated** (→ SKIP).

### `run` — non-interactive, one config file → JSON (CI / scripting)

The programmatic path: no prompts, no color, no getpass — everything from a JSON file (+ tokens from env),
structured JSON out. Use this in CI or scripts (and while the **interactive** console's remaining polish is
still being worked).

```powershell
$env:TARGET_ATTACKER_TOKEN="Bearer …"; $env:TARGET_OWNER_TOKEN="Bearer …"   # tokens: env ONLY, never the file
python run.py run --config path\to\config.json            # JSON verdict/report to stdout
python run.py run --config path\to\config.json --pretty   # + a one-line human summary to stderr
```

`config.json` carries `mode` (`"verify"` single-op OR `"scan"` auto-discover), `base_url`, and either the
endpoint + ids (verify) or a catalog source `spec_path` / `endpoints` / `endpoints_file` / `traffic_file`
(scan). Tokens come from `TARGET_ATTACKER_TOKEN` / `_OWNER_TOKEN` / `_BYSTANDER_TOKEN` **only** (a missing
one → a clear JSON error, never a prompt; `attacker == owner` is refused). Exit code: **0** when a
verdict/report is produced, **non-zero** on NOT DATA / setup error (so CI can branch); no token value ever
appears in the JSON.
