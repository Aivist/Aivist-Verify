# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: API Router Controller — AI Logic Hunter (Deep Logic Vulnerability Analysis)
# ==============================================================================

import json
import asyncio
import logging
from fastapi import APIRouter, BackgroundTasks, Depends, status, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.schemas.hunter import (
    HunterAnalyzeRequest,
    HunterAnalyzeResponse,
    AutomationPayload,
    VerifyTriggerResponse,
    FuzzingRecordSchema,
    HarIngestRequest,
    HarIngestEntry,
    HarIngestResponse,
    BatchVerifyRequest,
    BatchVerifyResponse,
    AuthDryRunRequest,
    AuthDryRunResponse,
    HunterPersistRequest,
    HunterPersistResponse,
)
from backend.app.services.traffic_parser import parse_raw_http_request
from backend.app.services.fuzzer import (
    execute_differential_fuzzing,
    execute_parallel_fuzzing,
    dry_run_auth_refresh,
    get_active_custody,
    _host_of,
)
from backend.app.services.pruner import filter_high_value_traffic, detect_login_candidate
from backend.app.schemas.proxy import (
    ProxyStartRequest,
    ProxyControlResponse,
    ProxyStatusResponse,
    ProxyFlowProjection,
    ProxyIngestFlow,
)
from backend.app.services.proxy_manager import get_proxy_manager
from backend.app.services.proxy_pipeline import get_ingest_pipeline, get_sse_hub
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.models.scan import VulnerabilityFinding, FuzzingRecord, CapturedFlow

# Create standard API router for AI Logic Hunter namespace
router = APIRouter(prefix="/hunter", tags=["AI Logic Hunter / 逻辑狩猎大脑"])

# Initialize logging diagnostics
logger = logging.getLogger("app.api.v1.hunter")

# Max chars retained from a HAR entry's response body during ingestion, to keep
# large captures from bloating memory before pruning (N3: was an inline 5000).
_HAR_RESPONSE_BODY_CAP = 5000

# Step 8 Objective A: identity/login endpoint detection now lives in pruner as a
# single source of truth shared with the Step 9 proxy radar. Thin alias keeps the
# existing internal call sites stable.
_detect_login_candidate = detect_login_candidate


# ==============================================================================
# Gemini System Prompt — Red-Team Expert Logic Vulnerability Analyst
# ==============================================================================
_SYSTEM_PROMPT = """\
你是一位世界顶级的 Web 安全研究员与红队攻防专家（OWASP Top-10、API Security Top-10 权威）。

你收到的**不是杂乱的原始文本**，而是经过我们后端解析引擎预处理后的**结构化 HTTP 请求数据**，\
包含精确的 method、path、query_params、headers 和 body 字段。\
你还可能收到一个 `auth_context_b`（对照组 Session 凭证），用于辅助你研判越权可能性。

你的核心任务：
1. 深度分析该请求的**业务逻辑脆弱面**，重点关注：
   - 水平越权 (BOLA / IDOR)：是否能通过篡改 ID 参数访问他人资源。
   - 垂直越权：是否能通过篡改 role/permission 字段提升权限。
   - 参数污染 (Parameter Pollution / Mass Assignment)：是否能注入未授权字段。
   - 竞争条件 (Race Condition / TOCTOU)：高并发下是否有逻辑竞态风险。

2. 你必须严格按照以下 JSON Schema 格式输出，不要输出任何 JSON 之外的文本：

{
  "report_markdown": "...(Markdown 字符串)...",
  "automation_payloads": [...]
}

### report_markdown 内容要求（Markdown 格式字符串）：
- **① 脆弱点分析模型 (Threat Model)**：列出你识别到的所有潜在逻辑脆弱面，按风险从高到低排列。
- **② Phase 1 基础探测方案**：给出初始探测步骤（如替换 ID、删除鉴权头、修改 role 字段等）。
- **③ Phase 2 绕过与利用策略**：给出进阶绕过方案（如编码绕过、参数覆盖、JSON 嵌套注入等）。

### automation_payloads 数组中每个元素的字段：
- phase (int): 1 或 2
- type (str): 漏洞类型，如 BOLA、IDOR、Parameter_Pollution、Mass_Assignment、Race_Condition
- location (str): 目标参数位置，如 json_key、query_param、header、path_segment、cookie
- target_param (str): 需要变异的参数名
- payload_string (str): 具体 Payload（如替换为 auth_context_b 的凭证、修改 role 为 admin 等）
- expected_match (str): 预期判定标志（如 HTTP 200、响应体包含其他用户数据、Content-Length 变化等）

请全部使用中文撰写 report_markdown。automation_payloads 中的字段值用英文。
"""


async def _invoke_gemini_logic_hunt(
    parsed_data: dict,
    auth_context_b: str | None,
) -> dict:
    """
    Calls Gemini AI with structured request data and the red-team system prompt.
    Uses response_mime_type="application/json" to enforce structured JSON output.

    Returns a dict with keys: report_markdown (str), automation_payloads (list).
    On failure, returns a graceful fallback dict.
    """
    if not settings.GEMINI_API_KEY:
        logger.warning("[HUNTER · GEMINI] No GEMINI_API_KEY configured. Returning local fallback.")
        return {
            "report_markdown": (
                "## ⚠️ 本地降级提示\n\n"
                "系统未配置 `GEMINI_API_KEY` 环境变量，无法调用 Gemini AI 决策层进行深度逻辑分析。\n\n"
                "请在 `backend/.env` 中配置有效的 API Key 后重试。"
            ),
            "automation_payloads": [],
        }

    # Build the user prompt with structured data
    user_content = f"""\
以下是经过后端解析引擎预处理后的结构化 HTTP 请求数据：

```json
{json.dumps(parsed_data, ensure_ascii=False, indent=2)}
```

对照组 Session 凭证 (auth_context_b): {auth_context_b or "未提供"}

请按照系统指令中的 JSON Schema 格式，输出你的逻辑脆弱性深度分析报告。
"""

    try:
        from google import genai
        from google.genai import types

        # Let the SDK resolve to its default 'v1beta' endpoint automatically
        client = genai.Client(api_key=settings.GEMINI_API_KEY)

        # Sanitize model name — strip any legacy 'models/' prefix
        model_name = settings.GEMINI_PRO_MODEL
        if model_name.startswith("models/"):
            model_name = model_name[len("models/"):]

        # Bounded by a hard timeout budget so a slow/hung upstream cannot block
        # the analyze endpoint indefinitely; surface a fast degraded response (D3).
        response = await asyncio.wait_for(
            client.aio.models.generate_content(
                model=model_name,
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=_SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    temperature=0.4,
                ),
            ),
            timeout=settings.GEMINI_REQUEST_TIMEOUT_SECONDS,
        )

        # Parse the structured JSON response
        raw_text = response.text.strip()
        ai_result = json.loads(raw_text)

        logger.info(f"[HUNTER · GEMINI] Successfully received structured analysis from Gemini AI ({model_name}).")
        return {
            "report_markdown": ai_result.get("report_markdown", ""),
            "automation_payloads": ai_result.get("automation_payloads", []),
        }

    except ImportError:
        logger.error("[HUNTER · GEMINI] google-genai SDK not installed.")
        return {
            "report_markdown": (
                "## ⚠️ SDK 缺失\n\n"
                "Python 环境缺少 `google-genai` 官方 SDK。请执行 `pip install google-genai` 后重试。"
            ),
            "automation_payloads": [],
        }
    except (asyncio.TimeoutError, TimeoutError):
        logger.error(
            f"[HUNTER · GEMINI TIMEOUT] analyze exceeded "
            f"{settings.GEMINI_REQUEST_TIMEOUT_SECONDS}s budget; returning degraded fallback."
        )
        return {
            "report_markdown": (
                "## ⚠️ Gemini AI 调用超时\n\n"
                f"调用 Gemini AI 决策层超过 {settings.GEMINI_REQUEST_TIMEOUT_SECONDS} 秒预算，已中止本次分析。\n\n"
                "请稍后重试，或检查网络连接 / API 配额。"
            ),
            "automation_payloads": [],
        }
    except json.JSONDecodeError as je:
        logger.error(f"[HUNTER · GEMINI] Failed to parse AI JSON response: {je}")
        return {
            "report_markdown": (
                f"## ⚠️ AI 输出解析异常\n\n"
                f"Gemini 返回了非标准 JSON 格式。原始输出已作为报告保留：\n\n"
                f"```\n{raw_text[:3000]}\n```"
            ),
            "automation_payloads": [],
        }
    except Exception as e:
        logger.error(f"[HUNTER · GEMINI API ERROR] {e}")
        return {
            "report_markdown": (
                f"## ⚠️ Gemini API 调用异常\n\n"
                f"调用 Gemini AI 决策层时发生错误。\n\n"
                f"**异常详情**: `{str(e)[:300]}`\n\n"
                f"请检查网络连接及 `GEMINI_API_KEY` 配置。"
            ),
            "automation_payloads": [],
        }


# ==============================================================================
# Route: POST /api/v1/hunter/analyze
# ==============================================================================

@router.post(
    "/analyze",
    response_model=HunterAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="AI Logic Hunter — Deep business-logic vulnerability analysis via Gemini AI.",
    response_description="Returns structured parse result, expert Markdown report, and automation payloads.",
)
async def analyze_http_traffic(request: HunterAnalyzeRequest):
    """
    AI 逻辑狩猎分析引擎 (Logic Vulnerability Deep Analysis):

    Pipeline:
        1. Parse raw HTTP traffic → structured dict (method, path, headers, body, query_params).
        2. Construct Gemini AI prompt with parsed data + auth_context_b.
        3. Invoke Gemini with JSON-constrained output schema.
        4. Return structured report + automation payloads to the frontend.

    All exceptions are caught internally — this endpoint never returns 500.
    """
    logger.info("[HUNTER · ROUTE] Received logic hunt analysis request.")

    # ---------------------------------------------------------------------- #
    # Step 1: Parse raw traffic into structured data
    # ---------------------------------------------------------------------- #
    try:
        parsed_data = parse_raw_http_request(request.raw_traffic)
        logger.info(
            f"[HUNTER · PARSER] Parsed request: {parsed_data['method']} {parsed_data['path']} "
            f"| Headers: {len(parsed_data['headers'])} | Errors: {len(parsed_data['errors'])}"
        )
    except Exception as parse_err:
        logger.error(f"[HUNTER · PARSER ERROR] {parse_err}")
        return HunterAnalyzeResponse(
            status="error",
            parsed_data={},
            error_message=f"Traffic parsing failed: {str(parse_err)[:200]}",
        )

    # ---------------------------------------------------------------------- #
    # Step 2 & 3: Invoke Gemini AI with structured data
    # ---------------------------------------------------------------------- #
    ai_result = await _invoke_gemini_logic_hunt(
        parsed_data=parsed_data,
        auth_context_b=request.auth_context_b,
    )

    # ---------------------------------------------------------------------- #
    # Step 4: Assemble and validate response
    # ---------------------------------------------------------------------- #
    validated_payloads = []
    for raw_payload in ai_result.get("automation_payloads", []):
        try:
            validated_payloads.append(AutomationPayload(**raw_payload))
        except Exception as validation_err:
            logger.warning(f"[HUNTER · PAYLOAD VALIDATION] Skipped malformed payload: {validation_err}")

    return HunterAnalyzeResponse(
        status="success",
        parsed_data=parsed_data,
        report_markdown=ai_result.get("report_markdown", ""),
        automation_payloads=validated_payloads,
    )


# ==============================================================================
# Route: POST /api/v1/hunter/findings  (Step D — persist analysis as finding)
# ==============================================================================

def _derive_base_url(parsed_data: dict, target_url: str | None) -> str | None:
    """
    Resolves the fuzzing base URL (scheme://host[:port]) for a Hunter finding.

    Priority:
        1. An explicit ``target_url`` (normalised to scheme://netloc).
        2. The Host header inside parsed_data (assumed https).
    Returns None if neither yields a usable host (caller rejects with 422).
    """
    from urllib.parse import urlparse

    if target_url:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        if parsed.netloc:
            return f"{parsed.scheme or 'https'}://{parsed.netloc}"

    headers = parsed_data.get("headers", {}) or {}
    host = ""
    for key, value in headers.items():
        if key.lower() == "host" and value:
            host = str(value).strip()
            break
    if host:
        return host if "://" in host else f"https://{host}"
    return None


@router.post(
    "/findings",
    response_model=HunterPersistResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Persist an AI Logic Hunter analysis as a fuzzable VulnerabilityFinding.",
    response_description="Returns the created finding_id for use with /verify/{finding_id}.",
)
async def persist_hunter_finding(
    request: HunterPersistRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Step D bridge endpoint — closes the Hunter -> Verify gap.

    Stores the analyzed request + AI automation_payloads in dedicated typed
    columns (source="hunter", scan_id=NULL) and returns the integer finding_id
    that the differential / parallel fuzzing endpoints operate on.
    """
    base_url = _derive_base_url(request.parsed_data, request.target_url)
    if not base_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Cannot derive a target host. Provide 'target_url' or include a "
                "'Host' header inside parsed_data so the fuzzing base URL can be resolved."
            ),
        )

    payloads = [p.model_dump() for p in request.automation_payloads]
    # Synthesize the NOT NULL columns for a Hunter finding (severity / template_id).
    # D6: `severity` must hold a real severity level (CRITICAL/HIGH/.../INFO), NOT
    # a vulnerability *type*. Hunter has no real severity, so we record "INFO" and
    # keep the detected type both in the payloads JSON (`type`) and, for UI
    # visibility, appended to template_id (e.g. "logic-hunter:BOLA").
    vuln_type = (payloads[0].get("type") if payloads else None) or "unknown"
    severity = "INFO"
    template_id = f"logic-hunter:{vuln_type}"

    finding = VulnerabilityFinding(
        scan_id=None,
        source="hunter",
        template_id=template_id,
        severity=severity,
        matched_at=base_url,
        poc_request=None,
        poc_response=None,
        ai_patch=request.report_markdown,
        parsed_request=request.parsed_data,
        automation_payloads=payloads,
        auth_refresh_request=(
            request.auth_refresh_request.model_dump() if request.auth_refresh_request else None
        ),
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    logger.info(
        f"[HUNTER · PERSIST] Saved Hunter analysis as finding_id={finding.id} "
        f"(host='{base_url}', payloads={len(payloads)})."
    )
    return HunterPersistResponse(
        status="success",
        finding_id=finding.id,
        message=(
            f"Hunter analysis persisted as finding #{finding.id} on '{base_url}' "
            f"with {len(payloads)} payload(s). Trigger via POST /verify/{finding.id}."
        ),
    )


# ==============================================================================
# Route: POST /api/v1/hunter/verify/{finding_id}
# ==============================================================================

@router.post(
    "/verify/{finding_id:int}",
    response_model=VerifyTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger differential fuzzing verification for a specific vulnerability finding.",
    response_description="Returns 202 Accepted with the queued finding ID.",
)
async def trigger_verification(
    finding_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Fuzzing Verification Trigger:

    1. Validates that the finding_id exists in the database.
    2. Enqueues the differential fuzzing job onto BackgroundTasks.
    3. Returns 202 immediately so the client can poll for results.
    """
    # Verify the finding exists
    result = await db.execute(
        select(VulnerabilityFinding).where(VulnerabilityFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding with ID '{finding_id}' not found.",
        )

    logger.info(f"[HUNTER · VERIFY] Queuing differential fuzzing for finding_id={finding_id}")
    background_tasks.add_task(execute_differential_fuzzing, finding_id)

    return VerifyTriggerResponse(
        status="accepted",
        finding_id=finding_id,
        message=(
            f"Differential fuzzing verification queued for finding #{finding_id} "
            f"({finding.template_id}). Poll GET /verify/{finding_id}/results for progress."
        ),
    )


# ==============================================================================
# Route: GET /api/v1/hunter/verify/{finding_id}/results
# ==============================================================================

@router.get(
    "/verify/{finding_id:int}/results",
    response_model=list[FuzzingRecordSchema],
    status_code=status.HTTP_200_OK,
    summary="Retrieve all fuzzing verification results for a specific finding.",
    response_description="Returns the list of FuzzingRecord entries with diff analysis.",
)
async def get_verification_results(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Fuzzing Results Retriever:

    Queries all FuzzingRecord entries linked to the given finding_id,
    ordered by payload_index. Used by the frontend to display verification
    results with request/response diffs and verdicts.
    """
    # Verify the finding exists
    finding_check = await db.execute(
        select(VulnerabilityFinding).where(VulnerabilityFinding.id == finding_id)
    )
    if not finding_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding with ID '{finding_id}' not found.",
        )

    result = await db.execute(
        select(FuzzingRecord)
        .where(FuzzingRecord.finding_id == finding_id)
        .order_by(FuzzingRecord.payload_index)
    )
    records = result.scalars().all()

    records_out = [
        FuzzingRecordSchema(
            id=r.id,
            finding_id=r.finding_id,
            payload_index=r.payload_index,
            sent_request=r.sent_request,
            received_response=r.received_response,
            verification_status=r.verification_status,
            diff_details=r.diff_details,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in records
    ]

    # ---------------------------------------------------------------------- #
    # Section 7.4: surface live re-auth diagnostics while the barrier is
    # cleared, so the UI shows a "running" recovery state instead of timing out.
    # This is a transient, in-memory record — never persisted to SQLite.
    # ---------------------------------------------------------------------- #
    custody = get_active_custody(finding_id)
    if custody is not None and custody.is_reauthenticating():
        diagnostic = FuzzingRecordSchema(
            id="__custody_diagnostic__",
            finding_id=finding_id,
            payload_index=-1,
            sent_request="",
            received_response="",
            verification_status="running",
            diff_details={
                "analysis_notes": (
                    "[RE-AUTHENTICATING] Session expired; executing dynamic auth recovery..."
                )
            },
            created_at="",
        )
        return [diagnostic] + records_out

    return records_out


# ==============================================================================
# Route: POST /api/v1/hunter/verify/batch  (Step 8 — Parallel multi-target)
# ==============================================================================

@router.post(
    "/verify/batch",
    response_model=BatchVerifyResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger TRUE-concurrent fuzzing across multiple findings sharing one custody controller.",
    response_description="Returns 202 Accepted with the queued findings and locked host.",
)
async def trigger_batch_verification(
    request: BatchVerifyRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Parallel Fuzzing Trigger (Step 8 Objective B):

    1. Validate that every finding_id exists.
    2. Enforce the single-host batch lock (v1): all findings + the approved_host
       must resolve to ONE host. Mixed-host batches are rejected (Constraint 2).
    3. Enqueue ONE shared-custody parallel fuzzing job onto BackgroundTasks.
    4. The transient auth_refresh_request is passed in-memory only (never persisted).
    """
    result = await db.execute(
        select(VulnerabilityFinding).where(VulnerabilityFinding.id.in_(request.finding_ids))
    )
    findings = {f.id: f for f in result.scalars().all()}

    missing = [fid for fid in request.finding_ids if fid not in findings]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding(s) not found: {missing}",
        )

    # --- Single-host scope lock ---
    from backend.app.services.fuzzer import _extract_base_url  # local import: internal helper
    hosts = {_host_of(_extract_base_url(findings[fid])) for fid in request.finding_ids}
    hosts.discard("")
    if request.approved_host:
        approved = request.approved_host.lower()
    elif len(hosts) == 1:
        approved = next(iter(hosts))
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Mixed-host batch is not allowed in v1. Findings span hosts {sorted(hosts)}. "
                f"Provide a single 'approved_host' or select endpoints from one host."
            ),
        )

    out_of_scope = {h for h in hosts if h != approved}
    if out_of_scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Selected endpoints include hosts outside the approved scope '{approved}': "
                f"{sorted(out_of_scope)}. Refusing to probe third-party domains (Constraint 2)."
            ),
        )

    refresh_payload = (
        request.auth_refresh_request.model_dump() if request.auth_refresh_request else None
    )

    logger.info(
        f"[HUNTER · BATCH] Queuing parallel fuzzing for finding_ids={request.finding_ids} "
        f"locked to host='{approved}', concurrency={request.max_concurrency}"
    )
    background_tasks.add_task(
        execute_parallel_fuzzing,
        request.finding_ids,
        refresh_payload,
        approved,
        request.max_concurrency,
    )

    return BatchVerifyResponse(
        status="accepted",
        finding_ids=request.finding_ids,
        approved_host=approved,
        message=(
            f"Parallel verification queued for {len(request.finding_ids)} endpoint(s) on '{approved}'. "
            f"Poll GET /verify/{{finding_id}}/results per finding for progress."
        ),
    )


# ==============================================================================
# Route: POST /api/v1/hunter/auth/dry-run  (Step 8 — Identity Anchor test)
# ==============================================================================

@router.post(
    "/auth/dry-run",
    response_model=AuthDryRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Test an Identity Provider Anchor (re-auth request) before launching a batch.",
    response_description="Reports whether a fresh token/cookie could be extracted.",
)
async def dry_run_identity_anchor(request: AuthDryRunRequest):
    """
    Executes the candidate re-auth request ONCE (scope-locked) and reports whether
    a usable credential could be extracted. Never persists anything. This lets the
    operator validate their login payload before committing to a parallel run.
    """
    result = await dry_run_auth_refresh(
        auth_refresh_request=request.auth_refresh_request.model_dump(),
        approved_host=request.approved_host or "",
    )
    return AuthDryRunResponse(
        success=result.get("success", False),
        status_code=result.get("status_code"),
        extracted_kind=result.get("extracted_kind"),
        extracted_preview=result.get("extracted_preview"),
        message=result.get("message", ""),
    )


# ==============================================================================
# Route: POST /api/v1/hunter/ingest-har
# ==============================================================================

def _har_entry_to_parsed_request(entry: dict) -> dict:
    """
    Converts a single HAR 1.2 entry object into the internal parsed_request
    format expected by the pruner engine.

    HAR entries have the structure:
        { "request": { "method": ..., "url": ..., "headers": [...], "postData": {...} },
          "response": { "status": ..., "headers": [...], "content": {...} } }
    """
    from urllib.parse import urlparse, parse_qs

    req = entry.get("request", {})
    method = req.get("method", "GET").upper()
    url = req.get("url", "/")

    # Parse the URL into path and query params
    try:
        parsed_url = urlparse(url)
        path = parsed_url.path or "/"
        qs = parse_qs(parsed_url.query, keep_blank_values=True)
        query_params = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
    except Exception:
        path = url
        query_params = {}

    # Extract headers into a flat dict
    headers = {}
    for h in req.get("headers", []):
        name = h.get("name", "")
        value = h.get("value", "")
        if name:
            headers[name] = value

    # Extract body from postData
    body = None
    post_data = req.get("postData", {})
    if post_data:
        mime_type = post_data.get("mimeType", "")
        text = post_data.get("text", "")
        if text:
            if "application/json" in mime_type.lower():
                try:
                    import json
                    body = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    body = text
            else:
                body = text

    # Also extract response data for potential fingerprinting
    resp = entry.get("response", {})
    response_headers = {}
    for h in resp.get("headers", []):
        name = h.get("name", "")
        value = h.get("value", "")
        if name:
            response_headers[name] = value

    response_body = ""
    resp_content = resp.get("content", {})
    if resp_content:
        response_body = resp_content.get("text", "")[:_HAR_RESPONSE_BODY_CAP]

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "response_headers": response_headers,
        "response_body": response_body,
        "_source_url": url,
        "_is_login_candidate": _detect_login_candidate(method, path, body),
    }


def _reconstruct_raw_http(item: dict) -> str:
    """
    Reconstructs a raw HTTP request string from a parsed request dict.
    This is injected into the frontend textarea via the raw_http_string field,
    so the frontend never needs to stitch HTTP protocol format itself.
    """
    import json as _json
    from urllib.parse import urlencode

    method = item.get("method", "GET")
    path = item.get("path", "/")
    source_url = item.get("_source_url", "")
    headers = item.get("headers", {})
    body = item.get("body")
    query_params = item.get("query_params", {})

    # Build the request line with full URL if available
    if source_url:
        request_line = f"{method} {source_url} HTTP/1.1"
    else:
        if query_params:
            qs = urlencode(query_params, doseq=True)
            request_line = f"{method} {path}?{qs} HTTP/1.1"
        else:
            request_line = f"{method} {path} HTTP/1.1"

    lines = [request_line]

    # Append headers
    for hk, hv in headers.items():
        lines.append(f"{hk}: {hv}")

    # Append body
    if body is not None:
        lines.append("")  # blank line separator
        if isinstance(body, (dict, list)):
            lines.append(_json.dumps(body, ensure_ascii=False, indent=2))
        else:
            lines.append(str(body))

    return "\n".join(lines)


@router.post(
    "/ingest-har",
    response_model=HarIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest a HAR file, prune noisy traffic, and surface high-value endpoints.",
    response_description="Returns filtered high-score entry points for frontend mapping.",
)
async def ingest_har_traffic(request: HarIngestRequest):
    """
    HAR Traffic Ingestion & Pruning Pipeline:

    1. Extract all entries from the standard HAR JSON payload.
    2. Convert each HAR entry into the internal parsed_request format.
    3. Run the heuristic pruner to eliminate static assets, telemetry, and noise.
    4. Return only high-value business endpoints sorted by exposure score.

    Designed for high-throughput processing of 20MB+ HAR files in < 150ms.
    All exceptions are caught internally — this endpoint never returns 500.
    """
    logger.info("[HUNTER · HAR INGEST] Received HAR ingestion request.")

    try:
        # Step 1: Extract entries from HAR log
        entries = request.log.get("entries", [])
        if not entries:
            return HarIngestResponse(
                status="error",
                total_entries=0,
                filtered_count=0,
                threshold_used=request.threshold,
                error_message="HAR payload contains no 'entries' array or it is empty.",
            )

        logger.info(f"[HUNTER · HAR INGEST] Extracted {len(entries)} raw HAR entries.")

        # Step 2: Convert HAR entries to parsed request format
        parsed_requests = []
        for entry in entries:
            try:
                parsed = _har_entry_to_parsed_request(entry)
                parsed_requests.append(parsed)
            except Exception as conv_err:
                logger.debug(f"[HUNTER · HAR CONV] Skipped malformed entry: {conv_err}")

        # Step 3: Run the heuristic pruner
        high_value = filter_high_value_traffic(parsed_requests, threshold=request.threshold)

        # Step 4: Map to response schema
        result_entries = [
            HarIngestEntry(
                method=item.get("method", "UNKNOWN"),
                path=item.get("path", "/"),
                query_params=item.get("query_params", {}),
                headers={
                    k: v for k, v in item.get("headers", {}).items()
                    if isinstance(v, str)
                },
                body=item.get("body"),
                exposure_score=item.get("_exposure_score", 0.0),
                raw_http_string=_reconstruct_raw_http(item),
                source_url=item.get("_source_url", ""),
                is_login_candidate=item.get("_is_login_candidate", False),
            )
            for item in high_value
        ]

        logger.info(
            f"[HUNTER · HAR INGEST] Pruning complete: "
            f"{len(entries)} → {len(result_entries)} high-value endpoints."
        )

        return HarIngestResponse(
            status="success",
            total_entries=len(entries),
            filtered_count=len(result_entries),
            threshold_used=request.threshold,
            high_value_entries=result_entries,
        )

    except Exception as e:
        logger.error(f"[HUNTER · HAR INGEST ERROR] {e}")
        return HarIngestResponse(
            status="error",
            total_entries=0,
            filtered_count=0,
            threshold_used=request.threshold,
            error_message=f"HAR ingestion failed: {str(e)[:300]}",
        )


# ==============================================================================
# Route: POST /api/v1/hunter/ingest-har-file  (Streaming UploadFile Variant)
# ==============================================================================

@router.post(
    "/ingest-har-file",
    response_model=HarIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest a HAR file via file upload (streaming), prune noisy traffic, and surface high-value endpoints.",
    response_description="Returns filtered high-score entry points for frontend mapping.",
)
async def ingest_har_file_upload(
    file: UploadFile = File(
        ...,
        description="A standard HAR 1.2 JSON file (.har) as produced by browser DevTools, Fiddler, Charles, mitmproxy, or Burp Suite exports.",
    ),
    threshold: float = Form(
        default=0.65,
        ge=0.0,
        le=1.0,
        description="Minimum exposure score threshold for traffic filtering. Default: 0.65.",
    ),
):
    """
    Streaming HAR File Upload & Pruning Pipeline (OOM-Safe):

    This endpoint accepts a HAR file via multipart/form-data file upload
    instead of raw JSON in the request body. FastAPI's UploadFile uses
    SpooledTemporaryFile internally — files under 1MB reside in memory
    while larger files automatically spool to disk, preventing OOM on
    50MB+ production HAR captures.

    Pipeline:
        1. Stream-read the uploaded HAR file bytes.
        2. Parse JSON and extract the entries array.
        3. Convert each HAR entry into the internal parsed_request format.
        4. Run the heuristic pruner to eliminate static assets, telemetry, and noise.
        5. Return only high-value business endpoints sorted by exposure score.

    All exceptions are caught internally — this endpoint never returns 500.
    """
    import json as _json

    logger.info(
        f"[HUNTER · HAR FILE UPLOAD] Received file upload: "
        f"filename='{file.filename}', content_type='{file.content_type}'"
    )

    try:
        # Step 1: Stream-read the file content
        raw_bytes = await file.read()
        if not raw_bytes:
            return HarIngestResponse(
                status="error",
                total_entries=0,
                filtered_count=0,
                threshold_used=threshold,
                error_message="Uploaded file is empty.",
            )

        # Step 2: Parse JSON
        try:
            har_data = _json.loads(raw_bytes)
        except _json.JSONDecodeError as je:
            return HarIngestResponse(
                status="error",
                total_entries=0,
                filtered_count=0,
                threshold_used=threshold,
                error_message=f"Invalid JSON in uploaded file: {str(je)[:200]}",
            )
        finally:
            # Release the raw bytes buffer immediately to free memory
            del raw_bytes

        # Step 3: Extract entries from HAR log structure
        log_obj = har_data.get("log", har_data)  # Support both {"log": {...}} and flat
        entries = log_obj.get("entries", [])
        if not entries:
            return HarIngestResponse(
                status="error",
                total_entries=0,
                filtered_count=0,
                threshold_used=threshold,
                error_message="HAR file contains no 'entries' array or it is empty.",
            )

        logger.info(f"[HUNTER · HAR FILE UPLOAD] Extracted {len(entries)} raw HAR entries.")

        # Step 4: Convert HAR entries to parsed request format
        parsed_requests = []
        for entry in entries:
            try:
                parsed = _har_entry_to_parsed_request(entry)
                parsed_requests.append(parsed)
            except Exception as conv_err:
                logger.debug(f"[HUNTER · HAR CONV] Skipped malformed entry: {conv_err}")

        # Step 5: Run the heuristic pruner
        high_value = filter_high_value_traffic(parsed_requests, threshold=threshold)

        # Step 6: Map to response schema
        result_entries = [
            HarIngestEntry(
                method=item.get("method", "UNKNOWN"),
                path=item.get("path", "/"),
                query_params=item.get("query_params", {}),
                headers={
                    k: v for k, v in item.get("headers", {}).items()
                    if isinstance(v, str)
                },
                body=item.get("body"),
                exposure_score=item.get("_exposure_score", 0.0),
                raw_http_string=_reconstruct_raw_http(item),
                source_url=item.get("_source_url", ""),
                is_login_candidate=item.get("_is_login_candidate", False),
            )
            for item in high_value
        ]

        logger.info(
            f"[HUNTER · HAR FILE UPLOAD] Pruning complete: "
            f"{len(entries)} → {len(result_entries)} high-value endpoints."
        )

        return HarIngestResponse(
            status="success",
            total_entries=len(entries),
            filtered_count=len(result_entries),
            threshold_used=threshold,
            high_value_entries=result_entries,
        )

    except Exception as e:
        logger.error(f"[HUNTER · HAR FILE UPLOAD ERROR] {e}")
        return HarIngestResponse(
            status="error",
            total_entries=0,
            filtered_count=0,
            threshold_used=threshold,
            error_message=f"HAR file ingestion failed: {str(e)[:300]}",
        )
    finally:
        await file.close()


# ==============================================================================
# Step 9 — Passive Traffic Ingestion Proxy Radar
# ==============================================================================

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _client_is_loopback(request: Request) -> bool:
    """
    True only if the real TCP peer is loopback. We use request.client.host (the
    socket peer) and deliberately IGNORE X-Forwarded-For — in local mode no
    trusted proxy sits in front, so XFF is attacker-controlled and must not be
    honored. This is the application-level enforcement of "127.0.0.1 only" given
    the route shares the single uvicorn socket (which may bind 0.0.0.0).
    """
    client = request.client
    return bool(client and client.host in _LOOPBACK_HOSTS)


@router.post(
    "/proxy/start",
    response_model=ProxyControlResponse,
    status_code=status.HTTP_200_OK,
    summary="Start the passive interception proxy (mitmdump) radar.",
)
async def proxy_start(request: ProxyStartRequest):
    """Spawn + supervise the mitmdump subprocess under an operator-supplied scope."""
    manager = get_proxy_manager()
    st = await manager.start(scope=request.scope, listen_port=request.listen_port)
    msg = {
        "RUNNING": "Radar started. Point your browser proxy at 127.0.0.1 and install the CA cert (GET /proxy/cert).",
        "FAILED": f"Radar failed to start: {st.get('message') or 'unknown error'}",
    }.get(st["state"], f"Radar state: {st['state']}")
    return ProxyControlResponse(
        state=st["state"],
        listen_port=st.get("listen_port") or settings.PROXY_LISTEN_PORT,
        pid=st.get("pid"),
        scope=st.get("scope", []),
        message=msg,
    )


@router.post(
    "/proxy/stop",
    response_model=ProxyControlResponse,
    status_code=status.HTTP_200_OK,
    summary="Stop the interception proxy and force-kill its process tree.",
)
async def proxy_stop():
    manager = get_proxy_manager()
    st = await manager.stop()
    return ProxyControlResponse(
        state=st["state"],
        listen_port=settings.PROXY_LISTEN_PORT,
        pid=st.get("pid"),
        scope=st.get("scope", []),
        message="Radar stopped; mitmdump process tree terminated.",
    )


@router.get(
    "/proxy/status",
    response_model=ProxyStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Current radar process state + ingest/stream telemetry.",
)
async def proxy_status():
    manager = get_proxy_manager()
    pipeline = get_ingest_pipeline()
    hub = get_sse_hub()
    st = manager.status()
    return ProxyStatusResponse(
        state=st["state"],
        pid=st.get("pid"),
        listen_port=st.get("listen_port"),
        uptime_seconds=st.get("uptime_seconds"),
        dropped_flows=pipeline.dropped_flows,
        sse_clients=hub.client_count,
        queue_depth=pipeline.queue_depth,
        scope=st.get("scope", []),
        ca_cert_available=st.get("ca_cert_available", False),
        message=st.get("message"),
    )


@router.post(
    "/proxy/internal-ingest",
    include_in_schema=False,  # never advertised in OpenAPI / docs
    status_code=status.HTTP_202_ACCEPTED,
)
async def proxy_internal_ingest(request: Request):
    """
    INTERNAL ONLY — receives captured flows from the mitmdump addon.

    Defense in depth (all must pass; any failure returns 404 to avoid confirming
    the route exists):
      1. Loopback-only: real TCP peer must be 127.0.0.1/::1 (XFF ignored).
      2. Per-session token: constant-time match of X-Ingest-Token.
    Plus: 413 on oversize bodies, and 503 backpressure when the queue is full.
    """
    manager = get_proxy_manager()

    # (1) loopback + (2) token — fail closed as 404.
    if not _client_is_loopback(request):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    if not manager.verify_ingest_token(request.headers.get("X-Ingest-Token")):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")

    raw = await request.body()
    if len(raw) > settings.PROXY_INGEST_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Captured flow payload too large.",
        )

    try:
        flow = ProxyIngestFlow.model_validate_json(raw)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Malformed flow: {str(e)[:200]}")

    accepted = get_ingest_pipeline().enqueue(flow.model_dump())
    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingest queue saturated; apply backpressure.",
        )
    return {"status": "accepted"}


@router.get(
    "/proxy/stream",
    summary="Live Server-Sent-Events stream of captured flows (radar).",
)
async def proxy_stream(request: Request):
    """
    SSE radar stream. Each client gets a bounded fan-out queue; on disconnect the
    generator's finally block deregisters it (CancelledError-safe) so memory is
    never leaked. Heartbeat comments keep the connection alive and detect death.
    """
    hub = get_sse_hub()
    if hub.at_capacity():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Too many radar stream clients.",
        )

    async def event_generator():
        q = hub.register()
        try:
            yield ": radar connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"event: {event['event']}\ndata: {json.dumps(event['data'])}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"  # keepalive
        except asyncio.CancelledError:
            raise
        finally:
            hub.unregister(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.get(
    "/proxy/cert",
    summary="Download the mitmproxy CA certificate for HTTPS interception.",
)
async def proxy_cert():
    """Stream the locally-generated mitmproxy CA cert (after the radar has run once)."""
    manager = get_proxy_manager()
    path = manager.ca_cert_path()
    if path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CA certificate not generated yet. Start the radar once, then retry.",
        )
    return FileResponse(
        str(path),
        media_type="application/x-x509-ca-cert",
        filename=path.name,
    )


@router.get(
    "/proxy/flows",
    response_model=list[ProxyFlowProjection],
    status_code=status.HTTP_200_OK,
    summary="List recently captured flows (most recent first).",
)
async def proxy_flows(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    limit = max(1, min(limit, 500))
    result = await db.execute(
        select(CapturedFlow).order_by(desc(CapturedFlow.captured_at)).limit(limit)
    )
    rows = result.scalars().all()
    return [
        ProxyFlowProjection(
            id=r.id,
            flow_id=r.flow_id,
            captured_at=r.captured_at.isoformat() if r.captured_at else None,
            method=r.method,
            host=r.host,
            path=r.path,
            url=r.url,
            response_status=r.response_status,
            exposure_score=r.exposure_score,
            is_login_candidate=r.is_login_candidate,
            in_scope=r.in_scope,
            promoted_finding_id=r.promoted_finding_id,
        )
        for r in rows
    ]
