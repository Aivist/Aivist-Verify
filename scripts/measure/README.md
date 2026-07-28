# verdict_measure — measurement harness for the access-control verifier

A first-class, committed tool that measures the deep verifier's real behaviour and emits a
**structured, diffable evidence artifact**. It replaces the throwaway one-off drivers that
used to live (gitignored) under `scripts/audit/`.

It exists because the zero-false-positive claim is only as good as the evidence behind it,
and that evidence should be a committed, reviewable artifact — not a transcript someone has
to trust.

## What it does

For each selected case it drives the **real** `execute_deep_verification` against a
**fresh-seeded** local target and records one structured row per run:

`case_id, ground_truth, shape, ai_verdict_raw → final_verdict, guard_override / exemption
channel, the anchor results (caller_identity, payload_causality, state_jump,
negative_assertion, anchoring_result), owner-view similarity (read-semantic cases),
follow-up path, degraded/error flags, model, timestamp`, plus a per-row **regression check**
against the known-good baseline stored in the caseset.

It also prints a human-readable summary + an acceptance block (SEV-1 / SEV-2 / non-read-shape
movement / degraded counts).

## Requirements & cost

- **Your own Gemini key.** Set `GEMINI_API_KEY` in the environment or `backend/.env`. The
  harness flips `AI_DEEP_VERIFY_ENABLED` / `AI_DEEP_VERIFY_OWNER_AUTH` **in-process only**;
  the committed config defaults stay `False`/unset.
- **Cost ≈ Σ(N over selected cases) model calls.** The full two-lab case set is **28 cases**,
  so `--n 1` ≈ **28 calls**, `--n 10` ≈ **280**, etc. The harness prints the planned call
  count before it starts.
- `mitmproxy` is **not** needed; only the two local targets, booted automatically.

## Reproduce the measurement

```bash
# N=1 regression sweep across both labs -> structured artifact
python scripts/measure/verdict_measure.py \
    --caseset scripts/measure/casesets/vulnerable_target.json \
    --caseset scripts/measure/casesets/depot.json \
    --n 1 --out run.jsonl

# a single case with a committable curated transcript
python scripts/measure/verdict_measure.py \
    --caseset scripts/measure/casesets/depot.json \
    --cases DP-READ-SAFE \
    --curated-transcript curated_DP-READ-SAFE.txt --curated-cases DP-READ-SAFE
```

## Flags

| flag | meaning |
|---|---|
| `--caseset PATH` | caseset JSON (repeatable) |
| `--n N` | runs per case (default 1) |
| `--model NAME` | override `GEMINI_PRO_MODEL` |
| `--seed-policy per-run\|per-case` | `per-run` (default) reboots + reseeds the target before **every** run — required for mutating cases at N>1; `per-case` boots once per case |
| `--cases id1,id2` | restrict to named cases |
| `--out PATH` | structured JSONL artifact (one row per run) |
| `--curated-transcript PATH` + `--curated-cases ids` | write a committable transcript for named cases only |

## Case sets (`casesets/*.json`)

Each caseset carries the target's launch config (`module`, `port`, `db_env`), the attacker
and **owner** credentials (the two-account baseline), and one entry per case. Every case
declares its `ground_truth`, `shape`, request spec, BOLA/mass payload, and the **known-good
baseline** (`baseline_final` / `baseline_channel`) the harness checks each run against. The
specs mirror the historical drivers exactly, so a sweep is a true regression check.

`$UNIQUE` in a request body is replaced per run with a fresh high-entropy value (so a
present-value check can only mean *this* run's write).

**Ground truth is human-owned.** The `ground_truth` labels here are the same ones proven
independently by `vulnerable_target/test_vulns.py` and `depot_target/test_vulns.py`; the
harness is graded against them and never the reverse. Do not edit a label to make a run pass.

## Output hygiene

The structured `--out` artifact and any `--curated-transcript` are meant to be **committed**
(small, diffable). Full verbose per-run logs are noise and stay out of git. Do **not** commit
raw `*.out.txt` transcripts — `scripts/audit/` remains the gitignored home for those.
