# QUICKSTART — open the confirmer

The BOLA/IDOR **confirmer** is the human-walkable front door: it runs the real verification
engine against a lab finding and prints whether the finding is a **CONFIRMED** cross-user
access-control bug or **REFUTED**.

## Prerequisites

- **Python 3.11.** On this machine the system interpreter is used (no virtualenv):
  `C:\Users\Lang\AppData\Local\Programs\Python\Python311\python.exe`, and `python` is on PATH.
- **Dependencies** (once, from the project root):
  ```powershell
  cd "C:\Users\Lang\Desktop\anti gravity"
  python -m pip install -r backend/requirements.txt
  ```
- **`GEMINI_API_KEY`** — the confirmer calls the real model. On this machine it is already
  provided via `backend/.env` (auto-loaded); you do **not** need to set a shell variable. On a
  fresh checkout, add a line `GEMINI_API_KEY=<your key>` to `backend/.env`.

## Run it (Windows PowerShell)

Run from the project root — the path has a space, so keep it quoted:

```powershell
cd "C:\Users\Lang\Desktop\anti gravity"
```

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
- Always `cd` into the project root first (above) — the relative caseset path is resolved from there.
- If `python` is not on PATH in your shell, call the interpreter by full path:
  ```powershell
  & "C:\Users\Lang\AppData\Local\Programs\Python\Python311\python.exe" run.py confirm --caseset "scripts\measure\casesets\vulnerable_target.json" --case B1-X-CROSS
  ```
