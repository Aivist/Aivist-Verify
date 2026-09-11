#!/usr/bin/env python
# ==============================================================================
# Deterministic OpenAI-compatible LLM stub — SELF-TEST FIXTURE ONLY.
#
# It implements just enough of the OpenAI Chat Completions API for the engine's
# documented `LLM_PROVIDER=openai` + `LLM_BASE_URL` seam (see
# backend/app/services/llm/openai_compat.py) to run WITHOUT a live model key.
#
# It ALWAYS returns the model's most permissive raw opinion:
#     {"decision": "verdict", "verdict": "verified", "next_request": null, ...}
#
# That is deliberate. It removes the (stochastic) model as a variable and leaves
# the DETERMINISTIC CODE GATE the only thing that can decide the final verdict —
# so the self-test proves the zero-false-positive property directly: even when the
# model always says "verified", the gate still REFUTES the SAFE case (its owner-view
# / cross-resource / negative-assertion checks are not satisfied) and CONFIRMS the
# REAL one (they are). It touches NO engine code.
#
# It is NOT used by the production Action path, which calls a real provider with a
# real key. Do not point production traffic at it.
# ==============================================================================
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_MODEL_JSON = json.dumps({
    "decision": "verdict",
    "verdict": "verified",
    "next_request": None,
    "evidence_path": None,
    "reasoning": "stub: always-verified raw opinion; the deterministic code gate decides the final verdict",
})


def _completion(model: str) -> bytes:
    body = {
        "id": "chatcmpl-stub",
        "object": "chat.completion",
        "created": 0,
        "model": model or "aivist-stub",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": _MODEL_JSON},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
    return json.dumps(body).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    def _json(self, payload: bytes, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        model = "aivist-stub"
        try:
            req = json.loads(raw or b"{}")
            model = req.get("model") or model
        except (ValueError, TypeError):
            pass
        if self.path.rstrip("/").endswith("/chat/completions"):
            self._json(_completion(model))
        else:
            self._json(json.dumps({"error": f"unhandled path {self.path}"}).encode("utf-8"), code=404)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            self._json(json.dumps({
                "object": "list",
                "data": [{"id": "aivist-stub", "object": "model", "created": 0, "owned_by": "aivist"}],
            }).encode("utf-8"))
        else:
            self._json(json.dumps({"status": "ok", "stub": "aivist-verify-llm"}).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:  # keep the test log quiet
        return


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic OpenAI-compatible LLM stub (self-test only).")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9099)
    args = ap.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    print(f"[llm-stub] always-verified OpenAI-compatible stub on http://{args.host}:{args.port}/v1",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
