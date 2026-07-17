# Anti-Gravity — AI Penetration Testing Platform

A locally-run, AI-assisted web-application penetration-testing platform. Its
differentiated core is an **access-control (BOLA/IDOR) verification engine** that
does not just *flag* a candidate bug but actively **confirms** whether it is a
real, exploitable access-control flaw and backs the verdict with reproducible
evidence.

> Single-tenant local prototype. **No authentication yet** — keep it bound to
> localhost / trusted networks. See the security notes before pointing it at
> anything else.

## All documentation lives in [`docs/`](./docs/)

Start at the docs index — [`docs/README.md`](./docs/README.md) — which gives the
full reading order. The fastest orientation:

| If you want… | Read |
|---|---|
| Where the project stands *right now* (progress, what's in flight) | [`docs/STATUS.md`](./docs/STATUS.md) |
| Why the project exists / where it's going (strategy, non-goals) | [`docs/ROADMAP.md`](./docs/ROADMAP.md) |
| What exists today + how to run & verify it (acceptance snapshot, 中文) | [`docs/PROJECT_OVERVIEW.md`](./docs/PROJECT_OVERVIEW.md) |
| How it's built (engineering entry point) | [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) |
| Known gaps, risks, and priorities | [`docs/TECH_DEBT.md`](./docs/TECH_DEBT.md) |

## Quick start

```powershell
# From the repo root
pip install -r backend/requirements.txt
pip install -r backend/requirements-dev.txt   # to run the tests
copy backend\.env.example backend\.env         # then fill in real values
python backend/run.py                          # http://127.0.0.1:8000/api/docs
```

Then open [`preview_dashboard.html`](./preview_dashboard.html) (the canonical
single-file frontend) in a browser. Full setup, configuration, and the
manual end-to-end recipe are in [`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md).

## Repository layout

```
anti gravity/
├─ README.md                 # ← you are here (pointer)
├─ preview_dashboard.html    # canonical single-file frontend (talks to :8000)
├─ backend/                  # FastAPI app, services, tests
├─ vulnerable_target/        # standalone ground-truth practice target (:8001)
├─ scripts/                  # audit / measurement harnesses (not product code)
├─ frontend/                 # legacy Vite app (mock data — NOT the baseline)
└─ docs/                     # all project documentation
```
