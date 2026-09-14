# Authorized-Remote Path — Result Capture

**Authorized remote path, controlled non-loopback target — engineering signal, NOT a
statistical-benchmark entry.** This capture is deliberately kept OUT of the 430-run zero-false-positive
benchmark (`scripts/measure/results/sweep_highN.jsonl`) and out of the third-party matrix
(`REAL_TARGET_RESULTS.md`). It exists to show ONE thing: the confirmer's verdict path runs, unchanged,
against a target reached over a **non-loopback network interface** — the authorized-remote posture the
scope-lock + preflight rails protect — not only over loopback.

## What this run was

- **Target:** the committed `vulnerable_target` lab, booted on this machine's **non-loopback LAN
  interface** `192.168.3.23:8001` (a private RFC1918 address — `classify_target` flags it `is_remote=True`,
  so the scope lock is LOCKED and the remote-safety preflight runs, NOT the unlocked loopback pass-through).
  It is a **controlled lab bound to a non-loopback socket**, not a third-party internet host.
- **Path:** the human golden path `aivist verify --target-file <file>` — the op is built from the target
  file and the spec is synthesized (no hand-authored `--op` / `--spec`).
- **Finding:** a read-semantic BOLA — the attacker (`alice`) reads the victim's (`bob`) statement across
  the user boundary; the deterministic D24 owner-view gate corroborates it
  (`guard_override=read_semantic_owner_view_gate`, `owner_view_corroborated=True`).
- **Model / proposer:** DeepSeek `deepseek-chat` via the OpenAI-compatible seam
  (`LLM_PROVIDER=openai`, `LLM_BASE_URL=https://api.deepseek.com/v1`). As in `REAL_TARGET_RESULTS.md`,
  model attribution rests on the operator's record of how the run was configured, not on the capture
  itself; the verdict is decided by the deterministic code gate, not the model. Tokens are the lab's
  non-secret fixtures, supplied via env and never persisted; the render redacts them (`***REDACTED***`).

## Honesty boundary

A real target has **no ground truth**, so there is **no zero-false-positive claim** on this run — the tool
prints that line itself. Zero-FP is a lab-measured property of the 430-run benchmark; this is an
**engineering signal** that the remote path works end to end. The rails that make the remote path safe are
locked by committed tests — `backend/tests/test_remote_safety_lock.py` (scope lock + preflight refusals:
SSRF / DNS-rebinding / link-local+metadata / unresolvable) and `backend/tests/test_remote_e2e_lock.py`
(a real-socket non-loopback enforcement test + the full `verify --target-file` CLI over the remote path).

## Reproduce

```bash
# 1) boot the committed lab on a non-loopback interface (substitute your own LAN IP):
VULN_TARGET_DATABASE_URL="sqlite+aiosqlite:///<tmp>/vuln_remote.db" \
  python -m uvicorn vulnerable_target.main:app --host 192.168.3.23 --port 8001
# 2) a target file (no op.json, no spec):  base_url = http://192.168.3.23:8001,
#    GET /api/statements/{statement_id}, id in path, attacker_id=1 victim_id=2
# 3) tokens from env (lab fixtures), model from env, then:
export TARGET_ATTACKER_TOKEN="Bearer alice-token-aaaa" TARGET_OWNER_TOKEN="Bearer bob-token-bbbb"
export LLM_PROVIDER=openai LLM_BASE_URL=https://api.deepseek.com/v1 LLM_MODEL=deepseek-chat LLM_API_KEY=<your key>
python run.py verify --target-file <remote_target.toml>
```

## Captured output (verbatim)

```text
  Using attacker token from environment (TARGET_ATTACKER_TOKEN, masked).
  Using owner token from environment (TARGET_OWNER_TOKEN, masked).
[real target: http://192.168.3.23:8001]  (no ground truth - an engineering signal, NOT a zero-FP claim)
[CONFIRMED]  console:remote-statements - GET /api/statements/1
  Verdict: verified  (confirming channel: same-resource verdict)  (guard_override=read_semantic_owner_view_gate)
  Basis: a deterministic code gate authorized this (write-then-independent-read proof), not the model's opinion alone.
  What the engine proved:
    The engine verified a cross-user effect on the same resource that was
    attacked (no cross-resource read-back was required).
  Here's what happened - the Evidence chain (physical bytes the engine actually exchanged):
    1. Sent as the attacker:
       GET http://192.168.3.23:8001/api/statements/2
       Authorization: ***REDACTED***
    2. Attack response received:
       -> HTTP 200 | Content-Length: 109
       {"id":2,"owner_id":2,"account_ref":"22222222-2222-2222-2222-222222222222","period":"2026-Q1","status":"OPEN"}
    3. The SAME object re-read AS THE VICTIM (owner-view - a different identity than the attack):
       -> HTTP 200
       {"id":2,"owner_id":2,"account_ref":"22222222-2222-2222-2222-222222222222","period":"2026-Q1","status":"OPEN"}
    4. What decided it (byte-level):
       - the attack response and the victim's owner-view read-back carried the SAME object bytes - the attacker read the victim's private data across the boundary  (owner_view_corroborated=True)
       - the read-back object belongs to the victim, not the attacker (a genuine cross-user target)  (caller_identity=confirmed)
       - a code-side anchor in the response matched the victim (corroborating, observe-only)  (anchoring_result=confirmed)
    5. Not taken as proof:
       - the model's raw opinion alone did NOT decide this - the deterministic code channel did  (ai_verdict_raw=verified)
  Real target: no ground truth. The deterministic gate fired (on the two labs
  that meant zero false positives), but zero-FP is a lab-measured property and
  is NOT claimed on this target.
  Re-runnable evidence package (fill <REDACTED> from YOUR config; never a live token):
    # 1) The attack request - reproduces the cross-user access AS THE ATTACKER:
    curl -X GET 'http://192.168.3.23:8001/api/statements/2' \
    -H 'Authorization: <REDACTED>'
    # 2) The owner-view read-back - the SAME resource read AS THE VICTIM (proves whose data it is):
    curl -X GET 'http://192.168.3.23:8001/api/statements/2' \
      -H 'Authorization: <REDACTED>'    # the VICTIM/owner's own token
  So what / Next step:
    A real cross-user access bug: the attacker could access the victim's object.
    It is reproducible (the request above).
    Next: report it, or fix by enforcing an ownership check on this endpoint.
  [lab oracle] (no ground_truth on this record; nothing to compare)
```

Process exit code: **1** (a CONFIRMED). Run date: 2026-09-14 (UTC).
