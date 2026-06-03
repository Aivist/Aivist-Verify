# ==============================================================================
# AI-in-the-loop Deep Verification  (Architecture Choice A — isolated component)
# ==============================================================================
#
# A NEW, isolated, *serial* deep-verification component. It is PURELY ADDITIVE:
# it does NOT modify or call the parallel engine's verdict path
# (execute_parallel_fuzzing / execute_differential_fuzzing / _differential_verdict).
# It reuses ONLY the stable, side-effect-free request primitives from fuzzer.py
# (mutate_request, _send_request, host helpers, ScopeViolationError) — so the
# existing 73 tests are unaffected.
#
# Purpose: resolve AMBIGUOUS access-control cases that a single-shot differential
# oracle cannot (e.g. a silent BOLA whose write endpoint always returns an opaque
# 200 {"status":"ok"}). It runs the two-turn AI-in-the-loop write-then-read we
# validated empirically:
#
#   Turn 1  : send a baseline (authorized/self) request and an attack
#             (cross-object) request; present BOTH real responses to the model;
#             the model may deliver a verdict now OR request exactly ONE follow-up
#             HTTP request.
#   Execute : if it asks for a follow-up, run it for real — SCOPE-LOCKED to the
#             approved host — and capture the raw response.
#   Turn 2  : feed the real follow-up response back IN THE SAME conversation and
#             obtain the final verdict.
#
# The returned result keeps the FULL evidence trail (baseline, attack, the exact
# follow-up requested, and its raw response) side-by-side with the AI verdict —
# the AI verdict is NEVER the sole field. On any Gemini timeout / error /
# invalid-JSON the function degrades gracefully (never crashes) and records why.
#
# Gated behind settings.AI_DEEP_VERIFY_ENABLED (default False): when disabled the
# function returns a clearly-marked "disabled" result and never touches the
# network. NOT wired into any API endpoint or existing flow — integration later.
# ==============================================================================

import json
import asyncio
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import httpx

from backend.app.core.config import settings
# Reuse ONLY stable request primitives from the existing engine (no verdict-path
# functions are imported, called, or modified).
from backend.app.services.fuzzer import (
    mutate_request,
    _send_request,
    _reconstruct_url,
    _host_of,
    ScopeViolationError,
)

logger = logging.getLogger("app.services.deep_verifier")

# Max characters of a response body embedded in the prompt / evidence trail.
_EVIDENCE_BODY_MAX = 2000
# Transient-503 retry budget for the Gemini call (still degrades after this).
_GEMINI_503_RETRIES = 3


SYSTEM_PROMPT = (
    "You are an autonomous web application security verification agent. Your job "
    "is to judge whether a possible broken-access-control vulnerability is real, "
    "based on observed HTTP evidence. You are rigorous and avoid both false "
    "positives and false negatives. You may gather more evidence before concluding "
    "if the current evidence is ambiguous."
)

_OPTIONS_BLOCK = """\
## Your options THIS TURN
You may EITHER:
  (A) deliver a FINAL verdict now, OR
  (B) request exactly ONE additional HTTP request to gather more evidence before deciding.
The follow-up (if any) will be executed against the SAME target host and fed back
to you. You may request only ONE request, and only a relative path on this host.

## Required output
Respond with ONLY a JSON object of EXACTLY this shape (no markdown, no extra text):
{
  "decision": "verdict" | "request_more",
  "next_request": { "method": "...", "path": "/...", "body": {...} | null, "reason": "..." } | null,
  "verdict": "verified" | "suspicious" | "failed" | null,
  "confidence": 0.0-1.0,
  "reasoning": "..."
}

Rules:
- If decision is "request_more", "next_request" MUST be populated and "verdict" MUST be null.
- If decision is "verdict", "verdict" MUST be populated and "next_request" MUST be null.
- "verified" = the vulnerability is real/exploitable; "failed" = NOT vulnerable
  (the server correctly enforced authorization); "suspicious" = cannot tell yet.
"""

_TURN2_TEMPLATE = """\
I have executed the ONE follow-up request you asked for, against the live target. Verbatim result:

## Follow-up request sent
{req_line}{body_line}

## Verbatim raw response received
{raw_response}

Now deliver your FINAL verdict. You may NOT request more information this turn.
Respond with ONLY a JSON object of EXACTLY this shape (no markdown, no extra text):
{{
  "decision": "verdict",
  "next_request": null,
  "verdict": "verified" | "suspicious" | "failed",
  "confidence": 0.0-1.0,
  "reasoning": "..."
}}
"""


# ==============================================================================
# Structured, auditable result — AI verdict is NEVER the sole field.
# ==============================================================================
@dataclass
class DeepVerificationResult:
    status: str                              # "completed" | "degraded" | "disabled"
    ai_verdict: Optional[str]                # "verified" | "suspicious" | "failed" | None
    ai_confidence: Optional[float]
    ai_reasoning: str
    ai_requested_follow_up: bool
    follow_up_request: Optional[Dict[str, Any]]   # {method, path, body, reason}
    follow_up_response: Optional[Dict[str, Any]]  # {status_code, content_length, body, url}
    baseline: Dict[str, Any]                 # {request, response}
    attack: Dict[str, Any]                   # {request, response}
    model: str
    approved_host: str
    turns_raw: List[str] = field(default_factory=list)   # verbatim model JSON per turn
    degraded_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Mask auth secrets in the evidence trail / prompt (request still uses the real value)."""
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "cookie", "x-token"):
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def _summarize_response(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status_code": result.get("status_code"),
        "content_length": result.get("content_length"),
        "body": (result.get("response_body") or "")[:_EVIDENCE_BODY_MAX],
        "url": result.get("url"),
    }


def _fmt_exchange(label: str, method: str, url: str, headers: dict, body: Any, result: Dict[str, Any]) -> str:
    lines = [f"{label}:", f"{method} {url}"]
    for k, v in _redact_headers(headers).items():
        lines.append(f"{k}: {v}")
    if body is not None:
        lines.append("Body: " + (json.dumps(body) if not isinstance(body, str) else body))
    lines.append(
        f"-> HTTP {result.get('status_code')} | Content-Length: {result.get('content_length')}"
    )
    lines.append((result.get("response_body") or "")[:_EVIDENCE_BODY_MAX])
    return "\n".join(lines)


def _build_turn1_prompt(context_note: str, evidence_block: str,
                        available_endpoints: Optional[List[str]]) -> str:
    parts = [
        "# Broken-access-control verification scenario\n",
        "You are verifying a POSSIBLE broken-access-control vulnerability on a target API.\n",
    ]
    if context_note:
        parts.append("## Context\n" + context_note.strip() + "\n")
    if available_endpoints:
        # The discoverable API surface a real integration would have (from the API
        # spec / HAR / proxy capture). Giving the model the catalog lets it request
        # the CORRECT read-back endpoint instead of guessing a path.
        cat = "\n".join(f"  - {e}" for e in available_endpoints)
        parts.append("## Available endpoints (you may request ONE of these as a follow-up)\n" + cat + "\n")
    parts.append("## Evidence collected so far (REAL responses just captured from the live target)\n")
    parts.append(evidence_block + "\n")
    parts.append(_OPTIONS_BLOCK)
    return "\n".join(parts)


async def _gemini_generate(client, types, model_name: str, contents, cfg):
    """One generate_content call with transient-503 retry; raises on final failure."""
    from google.genai import errors as genai_errors

    last_exc: Any = None
    for attempt in range(_GEMINI_503_RETRIES):
        try:
            return await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=model_name, contents=contents, config=cfg
                ),
                timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS,
            )
        except genai_errors.ServerError as e:
            last_exc = e
            if getattr(e, "status_code", None) == 503 or "503" in str(e):
                await asyncio.sleep(3 * (attempt + 1))
                continue
            raise
    raise last_exc


def _parse_model_json(text: str) -> Dict[str, Any]:
    """Parse the model's JSON; raise ValueError on anything unusable."""
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("Model JSON was not an object")
    return obj


async def execute_deep_verification(
    parsed_request: Dict[str, Any],
    payload: Optional[Dict[str, Any]],
    base_url: str,
    *,
    approved_host: Optional[str] = None,
    auth_context: Optional[Dict[str, str]] = None,
    context_note: str = "",
    available_endpoints: Optional[List[str]] = None,
    model_name: Optional[str] = None,
) -> DeepVerificationResult:
    """
    Run the isolated, serial AI-in-the-loop write-then-read deep verification.

    Args:
        parsed_request: the BASELINE (authorized/self) request dict
            {method, path, query_params, headers, body}.
        payload: a mutation instruction (same shape the fuzzer's mutate_request
            consumes, e.g. {"location":"path_segment","target_param":"1",
            "payload_string":"2","type":"BOLA"}) producing the ATTACK request.
            Pass None for read-only cases (no mutation; baseline == attack, e.g.
            a vertical-priv-esc GET).
        base_url: scheme://host[:port] anchor for all requests.
        approved_host: scope lock; defaults to the host of base_url. Any follow-up
            the model requests is REFUSED unless it resolves to this host.
        auth_context: extra headers (e.g. {"Authorization": "Bearer ..."}) merged
            into every request, including the model's follow-up.
        context_note: optional factual context (identity + intended authz policy)
            the model needs but cannot infer (e.g. "endpoint is admin-only").
        available_endpoints: optional discoverable API surface (e.g.
            ["GET /api/users/{id}/avatar", ...]) so the model can request the
            CORRECT read-back endpoint for its one follow-up instead of guessing.
        model_name: override the Gemini model; defaults to settings.GEMINI_PRO_MODEL.

    Returns:
        DeepVerificationResult — the AI verdict alongside the full evidence trail.
        Never raises for expected failure modes; degrades gracefully instead.
    """
    approved = (approved_host or _host_of(base_url) or "").lower()
    auth_context = auth_context or {}

    def _disabled_or_degraded(status: str, reason: str,
                              baseline=None, attack=None, turns=None) -> DeepVerificationResult:
        return DeepVerificationResult(
            status=status,
            ai_verdict=None,
            ai_confidence=None,
            ai_reasoning="",
            ai_requested_follow_up=False,
            follow_up_request=None,
            follow_up_response=None,
            baseline=baseline or {},
            attack=attack or {},
            model=model_name or settings.GEMINI_PRO_MODEL,
            approved_host=approved,
            turns_raw=turns or [],
            degraded_reason=reason,
        )

    # --- Feature gate: default behavior unchanged unless explicitly enabled ---
    if not settings.AI_DEEP_VERIFY_ENABLED:
        logger.info("[DEEP-VERIFY] Skipped: AI_DEEP_VERIFY_ENABLED is False.")
        return _disabled_or_degraded("disabled", "AI_DEEP_VERIFY_ENABLED is False")

    # Resolve / sanitize model name (mirror hunter.py)
    resolved_model = model_name or settings.GEMINI_PRO_MODEL
    if resolved_model.startswith("models/"):
        resolved_model = resolved_model[len("models/"):]

    # Merge auth context into the baseline request headers.
    baseline_req = dict(parsed_request)
    baseline_req["headers"] = {**(parsed_request.get("headers") or {}), **auth_context}

    timeout = httpx.Timeout(
        connect=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
        read=settings.FUZZER_HTTP_TIMEOUT_READ,
        write=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
        pool=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
    )

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # ---------------- Step 1: real baseline + attack ----------------
        try:
            baseline_result = await _send_request(client, baseline_req, base_url)
            if payload:
                attack_req = await mutate_request(baseline_req, payload)
            else:
                attack_req = baseline_req  # read-only case: no mutation
            attack_result = await _send_request(client, attack_req, base_url)
        except Exception as e:
            logger.warning(f"[DEEP-VERIFY] Baseline/attack send failed: {e}")
            return _disabled_or_degraded("degraded", f"baseline/attack request failed: {e}")

        baseline_url = _reconstruct_url(baseline_req, base_url)
        attack_url = _reconstruct_url(attack_req, base_url)
        baseline_trail = {
            "request": {"method": baseline_req.get("method", "GET"), "url": baseline_url,
                        "headers": _redact_headers(baseline_req.get("headers", {})),
                        "body": baseline_req.get("body")},
            "response": _summarize_response(baseline_result),
        }
        attack_trail = {
            "request": {"method": attack_req.get("method", "GET"), "url": attack_url,
                        "headers": _redact_headers(attack_req.get("headers", {})),
                        "body": attack_req.get("body")},
            "response": _summarize_response(attack_result),
        }

        # Build the evidence block (single exchange for read-only cases).
        if payload:
            evidence_block = (
                "1. BASELINE (authorized / self) request:\n"
                + _fmt_exchange("   request", baseline_req.get("method", "GET"), baseline_url,
                                baseline_req.get("headers", {}), baseline_req.get("body"), baseline_result)
                + "\n\n2. ATTACK (cross-object) request:\n"
                + _fmt_exchange("   request", attack_req.get("method", "GET"), attack_url,
                                attack_req.get("headers", {}), attack_req.get("body"), attack_result)
                + "\n"
            )
        else:
            evidence_block = (
                "1. Observed request (the suspected access-control attempt):\n"
                + _fmt_exchange("   request", attack_req.get("method", "GET"), attack_url,
                                attack_req.get("headers", {}), attack_req.get("body"), attack_result)
                + "\n"
            )

        # ---------------- Need an API key to run the AI step ----------------
        if not settings.GEMINI_API_KEY:
            return _disabled_or_degraded(
                "degraded", "GEMINI_API_KEY not configured", baseline_trail, attack_trail
            )

        # ---------------- AI turn 1 ----------------
        turns_raw: List[str] = []
        try:
            from google import genai
            from google.genai import types
        except ImportError:
            return _disabled_or_degraded(
                "degraded", "google-genai SDK not installed", baseline_trail, attack_trail
            )

        client_ai = genai.Client(api_key=settings.GEMINI_API_KEY)
        cfg = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            temperature=0.4,
        )

        turn1_prompt = _build_turn1_prompt(context_note, evidence_block, available_endpoints)
        contents = [types.Content(role="user", parts=[types.Part(text=turn1_prompt)])]

        try:
            resp1 = await _gemini_generate(client_ai, types, resolved_model, contents, cfg)
            turn1_text = resp1.text
            turns_raw.append(turn1_text)
            turn1_obj = _parse_model_json(turn1_text)
        except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
            return _disabled_or_degraded(
                "degraded", f"Gemini turn-1 failed: {type(e).__name__}: {e}",
                baseline_trail, attack_trail, turns_raw,
            )
        except Exception as e:  # SDK ServerError, network, etc. — never crash
            return _disabled_or_degraded(
                "degraded", f"Gemini turn-1 error: {type(e).__name__}: {e}",
                baseline_trail, attack_trail, turns_raw,
            )

        # ---------------- If verdict now, we're done ----------------
        decision = turn1_obj.get("decision")
        next_request = turn1_obj.get("next_request") or {}
        if decision != "request_more" or not next_request.get("path"):
            return DeepVerificationResult(
                status="completed",
                ai_verdict=turn1_obj.get("verdict"),
                ai_confidence=turn1_obj.get("confidence"),
                ai_reasoning=turn1_obj.get("reasoning", ""),
                ai_requested_follow_up=False,
                follow_up_request=None,
                follow_up_response=None,
                baseline=baseline_trail,
                attack=attack_trail,
                model=resolved_model,
                approved_host=approved,
                turns_raw=turns_raw,
            )

        # ---------------- Execute the follow-up (scope-locked) ----------------
        fu_method = str(next_request.get("method", "GET")).upper()
        fu_path = str(next_request.get("path", ""))
        fu_body = next_request.get("body")
        fu_request_record = {
            "method": fu_method, "path": fu_path, "body": fu_body,
            "reason": next_request.get("reason", ""),
        }

        follow_up_response = None
        follow_up_feedback = None
        if not fu_path.startswith("/"):
            # Refuse absolute URLs / anything that could leave the host.
            follow_up_feedback = (
                f"REFUSED: follow-up path must be a relative path on the approved host "
                f"'{approved}'. Got: {fu_path!r}. No request was executed."
            )
        else:
            fu_parsed = {
                "method": fu_method, "path": fu_path, "query_params": {},
                "headers": dict(auth_context), "body": fu_body,
            }
            fu_url = _reconstruct_url(fu_parsed, base_url)
            if approved and _host_of(fu_url) != approved:
                follow_up_feedback = (
                    f"REFUSED (scope lock): follow-up host '{_host_of(fu_url)}' is outside the "
                    f"approved scope '{approved}'. No request was executed."
                )
            else:
                try:
                    fu_result = await _send_request(client, fu_parsed, base_url)
                    follow_up_response = _summarize_response(fu_result)
                    follow_up_feedback = (
                        f"HTTP {fu_result.get('status_code')} | "
                        f"Content-Length: {fu_result.get('content_length')}\n\n"
                        + (fu_result.get("response_body") or "")[:_EVIDENCE_BODY_MAX]
                    )
                except ScopeViolationError as sve:
                    follow_up_feedback = f"REFUSED (scope lock): {sve}. No request was executed."
                except Exception as e:
                    follow_up_feedback = f"ERROR executing follow-up: {type(e).__name__}: {e}"

        # ---------------- AI turn 2 (same conversation) ----------------
        body_line = f"\nBody: {json.dumps(fu_body)}" if fu_body is not None else ""
        turn2_msg = _TURN2_TEMPLATE.format(
            req_line=f"{fu_method} {base_url}{fu_path}",
            body_line=body_line,
            raw_response=follow_up_feedback or "(no response captured)",
        )
        contents.append(types.Content(role="model", parts=[types.Part(text=turn1_text)]))
        contents.append(types.Content(role="user", parts=[types.Part(text=turn2_msg)]))

        try:
            resp2 = await _gemini_generate(client_ai, types, resolved_model, contents, cfg)
            turn2_text = resp2.text
            turns_raw.append(turn2_text)
            turn2_obj = _parse_model_json(turn2_text)
        except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
            return DeepVerificationResult(
                status="degraded",
                ai_verdict=None, ai_confidence=None,
                ai_reasoning="", ai_requested_follow_up=True,
                follow_up_request=fu_request_record,
                follow_up_response=follow_up_response,
                baseline=baseline_trail, attack=attack_trail,
                model=resolved_model, approved_host=approved,
                turns_raw=turns_raw,
                degraded_reason=f"Gemini turn-2 failed: {type(e).__name__}: {e}",
            )
        except Exception as e:
            return DeepVerificationResult(
                status="degraded",
                ai_verdict=None, ai_confidence=None,
                ai_reasoning="", ai_requested_follow_up=True,
                follow_up_request=fu_request_record,
                follow_up_response=follow_up_response,
                baseline=baseline_trail, attack=attack_trail,
                model=resolved_model, approved_host=approved,
                turns_raw=turns_raw,
                degraded_reason=f"Gemini turn-2 error: {type(e).__name__}: {e}",
            )

        return DeepVerificationResult(
            status="completed",
            ai_verdict=turn2_obj.get("verdict"),
            ai_confidence=turn2_obj.get("confidence"),
            ai_reasoning=turn2_obj.get("reasoning", ""),
            ai_requested_follow_up=True,
            follow_up_request=fu_request_record,
            follow_up_response=follow_up_response,
            baseline=baseline_trail,
            attack=attack_trail,
            model=resolved_model,
            approved_host=approved,
            turns_raw=turns_raw,
        )
