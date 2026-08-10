# Development

Contributor setup for the `aivist` CLI. For **using** the tool see [`QUICKSTART.md`](./QUICKSTART.md);
for **reproducing the benchmark evidence** see [`../REPRODUCE.md`](../REPRODUCE.md).

## Setup

Python 3.11+.

```bash
# from the repo root
pip install -e .                          # installs the `aivist` command + dependencies
# optional: extra LLM SDKs (openai / anthropic) if you use a non-Gemini provider
pip install -r backend/requirements-llm.txt
```

Provide a model key with `aivist config`, a `GEMINI_API_KEY` environment variable, or a
`GEMINI_API_KEY=<key>` line in `backend/.env` (auto-loaded). The confirmation engine and the
non-interactive `run` path need a key; the ground-truth lab suites (below) do not.

## Layout

```
run.py                    # the `aivist` CLI entry (dispatch + orchestration)
backend/app/services/     # the engine: fuzzer.py (differential oracle), deep_verifier.py (guard + channels)
backend/app/cli/          # the command line + interactive console + renderer
vulnerable_target/        # lab 1 (integer ids) + independent ground-truth suite
depot_target/             # lab 2 (UUID ids)   + independent ground-truth suite
scripts/measure/          # the measurement harness + committed result artifacts
```

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for how these fit together.

## Running the tests

```bash
# the backend suite (offline, no API key)
python -m pytest backend/tests -q

# the two labs' independent ground-truth suites (no API key)
python -m pytest vulnerable_target/test_vulns.py -q
python -m pytest depot_target/test_vulns.py -q
```

The backend suite is offline by design (the renderer/engine are driven by committed golden rows,
so there is zero API cost). Regenerating the benchmark artifact from scratch **does** call the
model and needs your own key — that path is documented in [`../REPRODUCE.md`](../REPRODUCE.md).

## Notes

- **Windows / PowerShell.** Quote paths that contain spaces. Colour output auto-disables when
  stdout is not a TTY (piping / CI stay clean); set `NO_COLOR=1` to force plain text.
- **The labs are FastAPI apps** run only as local test targets (e.g.
  `python -m uvicorn vulnerable_target.main:app --port 8001`); they are **not** part of the
  `aivist` tool and the tool never imports them. Leave them and their tests untouched.
