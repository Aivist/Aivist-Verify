# Reproducing the access-control verifier's zero-false-positive evidence

The zero-false-positive claim rests on **three independently verifiable layers**. Each can
be checked on its own; together they mean the claim does not require trusting a transcript.

## Layer 1 — the targets and their independent ground truth (zero API key)

Two self-contained vulnerable labs, each with an **independent** ground-truth test suite
that proves — against the live target's real bytes, with **no involvement from the verifier
engine** — that every case labelled REAL is genuinely exploitable cross-account and every
case labelled SECURE genuinely resists that attack.

```bash
python -m pytest vulnerable_target/test_vulns.py -q     # 31 tests
python -m pytest depot_target/test_vulns.py -q          # 23 tests
```

These require **no Gemini key**. They are the oracle: the engine is graded against them,
never the reverse, and a label is never edited to make the engine agree.

## Layer 2 — the structured result artifacts (readable, diffable, no API key)

`scripts/measure/results/*.jsonl` — one JSON row per measured run: case id, ground truth,
shape, `ai_verdict_raw → final_verdict`, the exemption channel that fired, every anchor
result, owner-view similarity (read-semantic cases), and a per-row regression check against
the caseset's known-good baseline. Small and diffable, so a reviewer can read the evidence
directly:

- `sweep_n1.jsonl` — the N=1 regression baseline across all 28 cases on both targets.
- `sweep_highN.jsonl` — the high-N zero-FP record (SAFE/control N=20, VULN N=10).

Inspect with any JSON tool, e.g.:

```bash
python - <<'PY'
import json, collections
rows=[json.loads(l) for l in open("scripts/measure/results/sweep_highN.jsonl")]
by=collections.defaultdict(collections.Counter)
for r in rows: by[r["case_id"]][f'{r["ai_verdict_raw"]}->{r["final_verdict"]}']+=1
for cid,dist in by.items(): print(cid, dict(dist))
PY
```

## Layer 3 — the measurement tool (re-runnable with the reader's own key)

`scripts/measure/verdict_measure.py` regenerates Layer 2 from Layer 1. It drives the **real**
`execute_deep_verification` against a fresh-seeded target and writes the structured artifact.
It needs the reader's **own `GEMINI_API_KEY`** (environment or `backend/.env`).

```bash
# the full high-N zero-FP pass — SAFE/control N=20, VULN N=10, both targets
python scripts/measure/verdict_measure.py \
    --caseset scripts/measure/casesets/vulnerable_target.json \
    --caseset scripts/measure/casesets/depot.json \
    --n-safe 20 --n-vuln 10 --out scripts/measure/results/sweep_highN.jsonl
```

**Call count:** ≈ **430** Gemini calls for the full pass
(vulnerable_target 7×20 + 7×10 = 210; depot 8×20 + 6×10 = 220). The N=1 sweep is ≈ 28 calls.
The tool prints the planned count before starting and flags any degraded/truncated run as
**NOT DATA** (excluded from the claim) rather than silently reporting a smaller N.

Runtime flags (`AI_DEEP_VERIFY_ENABLED`, `AI_DEEP_VERIFY_OWNER_AUTH`) are set in-process by
the tool; the committed config defaults stay off/unset.

## What is deliberately NOT committed

Full verbose per-run transcripts (raw model text, every HTTP body) are noise and stay
gitignored under `scripts/audit/`. Only the structured artifacts and curated transcripts are
committed. The evidence is the diffable JSONL, not a wall of prose.
