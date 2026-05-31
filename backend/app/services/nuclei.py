# ==============================================================================
# Commercial-Grade AI Penetration Testing & Vulnerability Audit Platform
# Module: Nuclei Subprocess Execution — 3-Phase Decoupled Architecture
#
# Phase 1 (Fast Ingest):   Parse JSONL → instant DB write, zero Gemini calls
# Phase 2 (State Transit): Nuclei exits → mark ScanTask as completed/failed
# Phase 3 (Batch AI):      Post-scan batch loop → Gemini patches with rate limiting
# ==============================================================================

import asyncio
import json
import logging
import re
import subprocess
import threading
import uuid
import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import select, and_

# Core Config, Database, and Model imports
from backend.app.core.config import settings
from backend.app.core.database import async_session_factory
from backend.app.models.scan import ScanTask, VulnerabilityFinding

# Configure service-specific logger for scanner diagnostics
logger = logging.getLogger("app.services.nuclei")



# =============================================================================
# Gemini AI — AI Remediation Patch Generator (Unchanged Core Logic)
# =============================================================================

async def generate_gemini_remediation_patch(
    template_id: str,
    severity: str,
    matched_at: str,
    poc_request: Optional[str] = None,
    poc_response: Optional[str] = None
) -> str:
    """
    Invokes the Google Gemini AI high-reasoning large language model
    to generate an industrial-grade vulnerability remediation patch and comparison.
    
    Core Principles Applied:
    1. Robust Authentication: Uses settings.GEMINI_API_KEY directly, preventing hardcoding.
    2. Model Partitioning: Dynamically loads model name from settings.GEMINI_PRO_MODEL.
    3. Fail-Safe Operations: Implements try-except to prevent pipeline crashes.
    """
    if not settings.GEMINI_API_KEY:
        logger.warning("[GEMINI AI] No API key configured in environment. Skipping AI remediation patch generation.")
        return "本地级联降级提示：系统未配置 `GEMINI_API_KEY` 环境变量。请在 `.env` 文件中补充配置，即可解锁 Gemini AI 自动生成漏洞自愈修复建议及对比代码栏功能。"

    logger.info(f"[GEMINI AI] Initializing AI Remediation Patch Generation for vulnerability: {template_id}")

    try:
        # Import the official new google-genai library as specified in SKILL.md
        from google import genai
        from google.genai import types
        
        # Let the SDK resolve to its default 'v1beta' endpoint automatically
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        
        # Sanitize model name — strip any legacy 'models/' prefix
        model_name = settings.GEMINI_PRO_MODEL
        if model_name.startswith("models/"):
            model_name = model_name[len("models/"):]
        
        # System instruction for the security expert role
        system_prompt = (
            "你是一位世界顶尖的\"网络安全专家\"兼\"资深全栈系统架构师\"。"
            "当收到漏洞上下文信息时，你将生成一份生产级别的代码修复方案及修复前后对比。"
            "你的输出严格包含以下三个模块：\n"
            "1. **漏洞根因剖析 (Root Cause Analysis)**：用简练、专业的安全术语阐明该漏洞之所以能被成功利用的代码级技术机理。\n"
            "2. **代码漏洞修复对比栏 (Markdown Diff)**：给出典型脆弱状态的伪代码 (Vulnerable Code) 和完全修复后的伪代码 (Secure Patched Code)。\n"
            "3. **安全自愈建议 (Mitigation Strategy)**：为企业研发和系统运维团队提供工业级的日常防御及配置层面的防御缓解措施。\n"
            "请全部使用中文回复，并以结构清晰的 Markdown 格式输出。"
        )

        # User-facing content with vulnerability context
        user_content = f"""\
【漏洞上下文】
- 漏洞特征模板 ID (Template ID): {template_id}
- 危害级别 (Severity): {severity.upper()}
- 触发漏洞的终端 URL: {matched_at}

【PoC 攻击请求报文】
{poc_request or "未捕获到请求报文上下文"}

【PoC 攻击响应报文】
{poc_response or "未捕获到响应报文上下文"}
"""
        
        # Call the Google GenAI SDK asynchronously.
        # system_instruction and temperature are wrapped in GenerateContentConfig.
        response = await client.aio.models.generate_content(
            model=model_name,
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
            ),
        )
        
        logger.info(f"[GEMINI AI] Successful patch analysis received for {template_id}")
        return response.text

    except ImportError:
        logger.error("[GEMINI AI] SDK ImportError: 'google-genai' library not installed correctly in Python path.")
        return "本地级联降级提示：本地 Python 运行环境缺少 `google-genai` 最新版官方 SDK。请执行 `pip install google-genai` 修复。"
    except Exception as e:
        logger.error(f"[GEMINI AI API ERROR] Failed calling Gemini AI ({settings.GEMINI_PRO_MODEL}): {e}")
        # Return elegant soft fallback rather than raising database transactions failure
        return f"本地级联降级提示：调用 Gemini AI 决策层时发生异常。\n异常细节: {str(e)}\n请检查网络连接及 API KEY 配置。"


# =============================================================================
# Phase 1 — JSONL Parser (Synchronous, High Throughput)
# =============================================================================

def _parse_jsonl_line(raw_line: str, scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single line of text stdout stream from Nuclei (synchronous version).
    
    :param raw_line: The text string read from process.stdout (text=True mode).
    :param scan_id: The tracking UUID of the scan.
    :return: A dictionary representing the parsed JSON finding, or None if invalid/empty.
    """
    if not raw_line:
        return None
        
    try:
        stripped_line = raw_line.strip()
        if not stripped_line:
            return None
            
        # Parse output directly. Nuclei -jsonl option outputs 1 independent JSON object per line.
        finding_data = json.loads(stripped_line)
        
        vulnerability_id = finding_data.get("template-id", "unknown-template")
        vulnerability_name = finding_data.get("info", {}).get("name", "Unnamed Vulnerability")
        severity = finding_data.get("info", {}).get("severity", "unknown")
        matched_uri = finding_data.get("matched-at", "unknown-target")
        
        log_msg = (
            f"[FINDING FOUND] [{scan_id}] Template: {vulnerability_id} | "
            f"Severity: {severity.upper()} | Name: '{vulnerability_name}' | Target: {matched_uri}"
        )
        if severity.lower() in ("critical", "high"):
            logger.warning(log_msg)
        else:
            logger.info(log_msg)
            
        return finding_data
        
    except json.JSONDecodeError:
        stripped = raw_line.strip()
        if stripped:
            logger.debug(f"[NUCLEI CONSOLE] [{scan_id}]: {stripped}")
    except Exception as e:
        logger.error(f"[STREAM PARSING ERROR] [{scan_id}] Failed parsing stdout line: {e}")
        
    return None


# =============================================================================
# Phase 1 — Fast DB Ingest (No Gemini, Maximum Throughput)
# =============================================================================

async def _persist_finding_fast(finding: Dict[str, Any], scan_id: str) -> None:
    """
    Phase 1 FAST-PATH: Instantly persists a vulnerability finding to the database
    WITHOUT triggering any Gemini API calls. The ai_patch field is left as None
    and will be populated in Phase 3 batch processing.
    
    This ensures the reader thread is never blocked by network I/O to external APIs.
    """
    template_id = finding.get("template-id", "unknown-template")
    severity = finding.get("info", {}).get("severity", "unknown")
    matched_at = finding.get("matched-at", "unknown-target")
    poc_request = finding.get("request", "")
    poc_response = finding.get("response", "")

    # Insert finding with ai_patch=None (deferred to Phase 3)
    async with async_session_factory() as db:
        try:
            vulnerability = VulnerabilityFinding(
                scan_id=scan_id,
                template_id=template_id,
                severity=severity.upper(),
                matched_at=matched_at,
                poc_request=poc_request,
                poc_response=poc_response,
                ai_patch=None,
                created_at=datetime.datetime.utcnow()
            )
            db.add(vulnerability)
            await db.commit()
            logger.info(f"[PHASE 1 · DB] Finding [{template_id}] persisted instantly for Scan [{scan_id}].")
        except Exception as db_err:
            logger.error(f"[PHASE 1 · DB ERROR] [{scan_id}] Failed to save finding: {db_err}")


# =============================================================================
# Phase 1 — Background Reader Thread (Sync Popen stdout → Async DB Write)
# =============================================================================

def _nuclei_reader_thread(
    process: subprocess.Popen,
    scan_id: str,
    loop: asyncio.AbstractEventLoop
) -> None:
    """
    Background daemon thread that synchronously reads Nuclei's stdout line-by-line
    and dispatches each parsed finding to the event loop for FAST DB persistence only.
    
    Key Design: NO Gemini API calls happen here. Each finding is written to DB
    in milliseconds, ensuring the reader thread is never blocked.
    """
    logger.info(f"[READER THREAD] [{scan_id}] Background reader thread started (TID: {threading.current_thread().ident}).")

    try:
        for raw_line in process.stdout:
            finding = _parse_jsonl_line(raw_line, scan_id)
            if finding:
                # Dispatch fast DB-only persistence (no Gemini)
                future = asyncio.run_coroutine_threadsafe(
                    _persist_finding_fast(finding, scan_id),
                    loop
                )
                try:
                    # DB writes are fast — 10s timeout is generous
                    future.result(timeout=10)
                except Exception as dispatch_err:
                    logger.error(
                        f"[DISPATCH ERROR] [{scan_id}] Failed dispatching finding to event loop: {dispatch_err}"
                    )
    except Exception:
        logger.exception(f"[READER THREAD ERROR] [{scan_id}] Unexpected error in reader thread")
    finally:
        logger.info(f"[READER THREAD] [{scan_id}] Background reader thread exiting.")


# =============================================================================
# Phase 3 — Batch AI Enrichment (Post-Scan, Rate-Limited)
# =============================================================================

async def _batch_enrich_with_gemini(scan_id: str) -> None:
    """
    Phase 3 POST-SCAN: After the scan is marked completed, queries all 
    critical/high severity findings that have ai_patch=None, then calls 
    Gemini AI sequentially with a cooldown delay between each call 
    to respect API rate limits.
    
    This runs entirely in the async event loop — no threading needed.
    """
    logger.info(f"[PHASE 3 · AI BATCH] [{scan_id}] Starting post-scan Gemini enrichment pipeline...")

    # Query all unpatched critical/high findings for this scan
    async with async_session_factory() as db:
        try:
            stmt = select(VulnerabilityFinding).where(
                and_(
                    VulnerabilityFinding.scan_id == scan_id,
                    VulnerabilityFinding.severity.in_(["CRITICAL", "HIGH"]),
                    VulnerabilityFinding.ai_patch.is_(None)
                )
            )
            result = await db.execute(stmt)
            pending_findings: List[VulnerabilityFinding] = list(result.scalars().all())
        except Exception as e:
            logger.error(f"[PHASE 3 · QUERY ERROR] [{scan_id}] Failed querying unpatched findings: {e}")
            return

    total = len(pending_findings)
    if total == 0:
        logger.info(f"[PHASE 3 · AI BATCH] [{scan_id}] No critical/high findings awaiting AI patches. Skipping.")
        return

    logger.info(f"[PHASE 3 · AI BATCH] [{scan_id}] Found {total} finding(s) requiring Gemini AI remediation patches.")

    for idx, finding in enumerate(pending_findings, start=1):
        logger.info(
            f"[PHASE 3 · AI BATCH] [{scan_id}] Processing {idx}/{total}: "
            f"template={finding.template_id}, severity={finding.severity}"
        )

        # Call Gemini to generate remediation patch
        try:
            ai_patch = await generate_gemini_remediation_patch(
                template_id=finding.template_id,
                severity=finding.severity,
                matched_at=finding.matched_at,
                poc_request=finding.poc_request,
                poc_response=finding.poc_response
            )
        except Exception as gemini_err:
            logger.error(f"[PHASE 3 · GEMINI ERROR] [{scan_id}] Failed generating patch for {finding.template_id}: {gemini_err}")
            ai_patch = f"本地级联降级提示：批处理阶段调用 Gemini AI 决策层失败。\n异常细节: {str(gemini_err)}"

        # Write the AI patch back to the database
        async with async_session_factory() as db:
            try:
                stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.id == finding.id)
                result = await db.execute(stmt)
                db_finding = result.scalar_one_or_none()
                if db_finding:
                    db_finding.ai_patch = ai_patch
                    await db.commit()
                    logger.info(f"[PHASE 3 · DB UPDATED] [{scan_id}] AI patch written for finding [{finding.template_id}] ({idx}/{total}).")
            except Exception as db_err:
                logger.error(f"[PHASE 3 · DB ERROR] [{scan_id}] Failed saving AI patch for {finding.template_id}: {db_err}")

        # Rate-limit cooldown between Gemini API calls (skip after last item)
        if idx < total:
            logger.info(f"[PHASE 3 · RATE LIMIT] Cooling down {settings.GEMINI_BATCH_COOLDOWN_SECONDS}s before next Gemini API call...")
            await asyncio.sleep(settings.GEMINI_BATCH_COOLDOWN_SECONDS)

    logger.info(f"[PHASE 3 · AI BATCH COMPLETE] [{scan_id}] All {total} AI remediation patches generated and persisted.")


# =============================================================================
# Target Profiler — Tech-Stack Fingerprinting & Adaptive Nuclei Selector
# =============================================================================

# Fingerprint signature map: pattern → (tag_list)
# Each entry maps a regex pattern (checked against response headers/body
# concatenation) to the Nuclei -tags values it implies.
_FINGERPRINT_SIGNATURES: Dict[str, List[str]] = {
    # WordPress
    r"wp-content|wp-json|wp-includes": ["wordpress", "wp"],
    # Laravel / PHP
    r"laravel_session|XSRF-TOKEN.*laravel": ["laravel", "php"],
    r"PHPSESSID": ["php"],
    # Django
    r"csrftoken|django": ["django", "python"],
    # Express / Node.js
    r"X-Powered-By:\s*Express": ["express", "nodejs"],
    # ASP.NET
    r"ASP\.NET_SessionId|X-AspNet-Version|X-Powered-By:\s*ASP\.NET": ["aspnet", "iis"],
    # Spring / Java
    r"JSESSIONID|X-Application-Context|Whitelabel Error Page": ["spring", "java"],
    # Ruby on Rails
    r"_rails_session|X-Runtime|X-Request-Id": ["rails", "ruby"],
    # Nginx
    r"Server:\s*nginx": ["nginx"],
    # Apache
    r"Server:\s*Apache": ["apache"],
}


async def _fingerprint_target(
    target_url: str,
    traffic_feed: Optional[List[Dict[str, Any]]] = None,
    approved_target_host: Optional[str] = None,
) -> List[str]:
    """
    Dual-Mode Tech-Stack Fingerprint Extractor with Scope-Lock Enforcement.

    1. PASSIVE mode: If the traffic feed contains entries with response data
       (headers/bodies), inspect them for known framework signatures.
    2. ACTIVE fallback: If no response data is available, execute a single
       benign GET probe to the target domain to harvest response headers
       **ONLY if the target domain matches the user-defined approved scope**.
       Probing third-party APIs (Stripe, AWS, Google, etc.) is strictly
       forbidden.

    :param target_url: The base URL of the scan target.
    :param traffic_feed: Optional list of parsed request/response dicts.
    :param approved_target_host: The user-approved target hostname for scope
                                  enforcement. If None, derived from target_url.
    :return: Deduplicated list of Nuclei tag strings (e.g., ["laravel", "php"]).
    """
    from urllib.parse import urlparse as _urlparse

    detected_tags: set = set()
    corpus_texts: List[str] = []

    # Derive approved scope host if not explicitly provided
    if not approved_target_host:
        try:
            approved_target_host = _urlparse(target_url).hostname or ""
        except Exception:
            approved_target_host = ""

    approved_target_host = approved_target_host.lower().strip()

    # --- Passive Mode: extract from traffic feed responses ---
    if traffic_feed:
        for entry in traffic_feed:
            # Check for response data in the traffic feed
            resp_headers = entry.get("response_headers", {})
            resp_body = entry.get("response_body", "")
            if resp_headers or resp_body:
                # Concatenate headers and body into a single searchable text
                header_text = "\n".join(
                    f"{k}: {v}" for k, v in resp_headers.items()
                ) if isinstance(resp_headers, dict) else str(resp_headers)
                corpus_texts.append(f"{header_text}\n{resp_body}")

    # --- Active Fallback: probe target if no response corpus available ---
    if not corpus_texts:
        # ============================================================
        # SCOPE-LOCK ENFORCEMENT: Only probe if the target domain
        # matches the user-approved scope. Never touch third-party hosts.
        # ============================================================
        try:
            probe_hostname = _urlparse(target_url).hostname or ""
        except Exception:
            probe_hostname = ""

        probe_hostname = probe_hostname.lower().strip()

        if not approved_target_host or not probe_hostname:
            logger.warning(
                f"[PROFILER · SCOPE-LOCK] Cannot resolve hostnames for scope check. "
                f"target_url='{target_url}', approved_host='{approved_target_host}'. "
                f"Skipping active probe — falling back to defaults."
            )
        elif probe_hostname != approved_target_host and not probe_hostname.endswith(f".{approved_target_host}"):
            logger.warning(
                f"[PROFILER · SCOPE-LOCK DENIED] Active probe BLOCKED: "
                f"probe target '{probe_hostname}' does NOT match approved scope "
                f"'{approved_target_host}'. Third-party probing is strictly forbidden."
            )
        else:
            logger.info(
                f"[PROFILER · SCOPE-LOCK OK] Domain '{probe_hostname}' matches approved scope "
                f"'{approved_target_host}'. Executing active GET probe to {target_url}"
            )
            try:
                import httpx
                # Reuse the centralized outbound HTTP tuning (settings) instead of
                # hardcoding probe timeout / body-truncation magic numbers (N2).
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(
                        settings.FUZZER_HTTP_TIMEOUT_READ,
                        connect=settings.FUZZER_HTTP_TIMEOUT_CONNECT,
                    ),
                    follow_redirects=True,
                    verify=False,
                ) as http_client:
                    probe_resp = await http_client.get(target_url)
                    header_text = "\n".join(
                        f"{k}: {v}" for k, v in probe_resp.headers.items()
                    )
                    body_excerpt = probe_resp.text[: settings.FUZZER_RESPONSE_BODY_MAX_LENGTH]
                    corpus_texts.append(f"{header_text}\n{body_excerpt}")
                    logger.info(f"[PROFILER] Active probe completed. Status: {probe_resp.status_code}")
            except ImportError:
                logger.warning("[PROFILER] httpx not installed — cannot perform active probe. Falling back to defaults.")
            except Exception as probe_err:
                logger.warning(f"[PROFILER] Active probe failed: {probe_err}. Falling back to defaults.")

    # --- Match signatures against corpus ---
    full_corpus = "\n".join(corpus_texts)
    if full_corpus:
        for pattern, tags in _FINGERPRINT_SIGNATURES.items():
            if re.search(pattern, full_corpus, re.IGNORECASE):
                detected_tags.update(tags)
                logger.info(f"[PROFILER] Signature match: pattern='{pattern}' → tags={tags}")

    result = sorted(detected_tags)
    logger.info(f"[PROFILER] Final fingerprint tags for {target_url}: {result or '(none — will use defaults)'}")
    return result


def _build_adaptive_nuclei_args(tags: List[str], base_args: List[str]) -> List[str]:
    """
    Appends optimized Nuclei execution flags based on fingerprinted tags.

    - If tags were detected: appends ``-tags tag1,tag2`` to restrict templates.
    - If no tags found: appends ``-tags cves,generic`` as a safe, pruned default
      rather than firing 4000+ global rules. (Severity filtering is applied
      separately via ``-severity`` in the base command args.)

    :param tags: List of detected tech-stack tags (may be empty).
    :param base_args: The existing Nuclei command argument list.
    :return: The augmented argument list (a new list; does not mutate base_args).
    """
    args = list(base_args)

    if tags:
        tags_csv = ",".join(tags)
        args.extend(["-tags", tags_csv])
        logger.info(f"[NUCLEI ARGS] Adaptive tags injected: -tags {tags_csv}")
    else:
        # Safe default: focus on known CVEs and generic checks at high severity
        args.extend(["-tags", "cves,generic"])
        logger.info("[NUCLEI ARGS] No fingerprint tags detected. Using safe defaults: -tags cves,generic")

    return args


# =============================================================================
# Main Orchestrator — 3-Phase Pipeline
# =============================================================================

async def execute_nuclei_scan_async(
    target_url: str, 
    cookie: Optional[str] = None,
    scan_id: Optional[str] = None,
    traffic_feed: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Main asynchronous orchestrator implementing the 3-Phase Decoupled Architecture
    for commercial-grade SaaS scanning performance.
    
    Phase 0 (Profiling):
        - Fingerprints the target tech stack via passive traffic analysis or
          active GET probe to dynamically restrict Nuclei templates.
    
    Phase 1 (Fast Ingest):
        - Spawns Nuclei via subprocess.Popen + threading.Thread
        - Reader thread parses JSONL and writes findings to DB instantly
        - ZERO Gemini API calls — maximum throughput
    
    Phase 2 (State Transition):
        - After Nuclei exits, marks ScanTask as completed/failed
        - Frontend polling detects completion and fetches findings
    
    Phase 3 (Batch AI Enrichment):
        - Queries all critical/high findings with ai_patch=None
        - Calls Gemini sequentially with rate-limit cooldown
        - Updates each finding's ai_patch in the database
    
    Core Principles Applied:
    1. Isolated Session Management: Spawns own independent async_session_factory
       avoiding FastAPI request-level session closures in background thread.
    2. Prevent Command Injections: CLI argument array passing (no shell=True).
    3. Full Windows Compatibility: Uses Popen instead of asyncio subprocess.
    4. Scan/AI Decoupling: Frontend sees 'completed' fast, AI patches arrive later.
    5. Adaptive Template Selection: Profiled tags reduce Nuclei runtime dramatically.
    """
    if not scan_id:
        scan_id = str(uuid.uuid4())
        
    logger.info(f"[SCAN PIPELINE STARTED] [{scan_id}] Auditing target: {target_url}")
    
    # Capture the running event loop for cross-thread dispatch
    loop = asyncio.get_running_loop()

    # =========================================================================
    # PHASE 0 — Target Profiling & Adaptive Template Selection
    # =========================================================================
    profiled_tags: List[str] = []
    try:
        profiled_tags = await _fingerprint_target(target_url, traffic_feed)
        logger.info(f"[PHASE 0 · PROFILER] [{scan_id}] Detected tags: {profiled_tags}")
    except Exception as prof_err:
        logger.warning(f"[PHASE 0 · PROFILER ERROR] [{scan_id}] Fingerprinting failed: {prof_err}. Proceeding with defaults.")

    # =========================================================================
    # PHASE 0.5 — Update ScanTask status to 'running'
    # =========================================================================
    async with async_session_factory() as db:
        try:
            result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
            task = result.scalar_one_or_none()
            if task:
                task.status = "running"
                task.updated_at = datetime.datetime.utcnow()
                await db.commit()
                logger.info(f"[DB STATE] Scan Task [{scan_id}] marked as RUNNING.")
            else:
                # Fallback: create task row if missing
                task = ScanTask(
                    id=scan_id,
                    target_url=target_url,
                    status="running",
                    cookie=cookie
                )
                db.add(task)
                await db.commit()
        except Exception as e:
            logger.error(f"[DB INITIALIZATION EXCEPTION] [{scan_id}] Failed updating start state: {e}")

    # =========================================================================
    # PHASE 1 — Spawn Nuclei + Fast DB Ingest
    # =========================================================================
    cmd_args = [
        settings.NUCLEI_BINARY_PATH,
        "-target", str(target_url),
        "-severity", settings.NUCLEI_DEFAULT_SEVERITY,
        "-jsonl",
        "-nc",                      # No color formatting for clean log parsing
        "-disable-update-check"     # Prevent interactive prompts blocking
    ]

    # Inject adaptive tags from profiler
    cmd_args = _build_adaptive_nuclei_args(profiled_tags, cmd_args)
    
    if cookie:
        cmd_args.extend(["-header", f"Cookie: {cookie}"])
        logger.info(f"[SCAN SETUP] [{scan_id}] Auth session cookie supplied.")
        
    logger.info(f"[EXECUTION ARGS] [{scan_id}] command sequence: {' '.join(cmd_args)}")

    process_error_occurred = False
    try:
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,              # Decode stdout/stderr as text strings automatically
            bufsize=1               # Line-buffered for real-time streaming
        )
        
        logger.info(f"[PROCESS SPAWNED] [{scan_id}] Nuclei running with PID: {process.pid}")

        # Launch daemon reader thread for non-blocking stdout consumption
        reader_thread = threading.Thread(
            target=_nuclei_reader_thread,
            args=(process, scan_id, loop),
            name=f"nuclei-reader-{scan_id[:8]}",
            daemon=True
        )
        reader_thread.start()

        # Await thread completion without blocking the event loop
        await loop.run_in_executor(None, reader_thread.join)

        # Wait for the process to fully terminate and collect stderr
        process.wait()
        exit_code = process.returncode
        
        if exit_code != 0:
            stderr_msg = process.stderr.read().strip() if process.stderr else ""
            logger.error(f"[SCAN PROCESS ERROR] [{scan_id}] Exit Code: {exit_code}. Details: {stderr_msg}")
            process_error_occurred = True
        else:
            logger.info(f"[SCAN PROCESS COMPLETE] [{scan_id}] Nuclei exited cleanly with code 0.")
            
    except FileNotFoundError:
        logger.critical(f"[SCAN SYSTEM CRITICAL] [{scan_id}] Nuclei binary was not found at: '{settings.NUCLEI_BINARY_PATH}'.")
        process_error_occurred = True
    except Exception:
        logger.exception(f"[{scan_id}] Unexpected pipeline error occurred")
        process_error_occurred = True

    # =========================================================================
    # PHASE 2 — Finalize ScanTask status (completed / failed)
    # =========================================================================
    final_status = "failed" if process_error_occurred else "completed"
    async with async_session_factory() as db:
        try:
            result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
            task = result.scalar_one_or_none()
            if task:
                task.status = final_status
                task.updated_at = datetime.datetime.utcnow()
                await db.commit()
                logger.info(f"[PHASE 2 · DB STATE] Scan Task [{scan_id}] status → {final_status.upper()}")
        except Exception as db_err:
            logger.error(f"[PHASE 2 · DB ERROR] [{scan_id}] Failed saving final task status: {db_err}")

    # =========================================================================
    # PHASE 3 — Batch AI Enrichment (only on successful scans)
    # =========================================================================
    if not process_error_occurred:
        try:
            await _batch_enrich_with_gemini(scan_id)
        except Exception:
            logger.exception(f"[PHASE 3 · FATAL] [{scan_id}] Batch AI enrichment pipeline crashed")
    else:
        logger.warning(f"[PHASE 3 · SKIPPED] [{scan_id}] Scan failed — skipping AI enrichment.")

    logger.info(f"[SCAN PIPELINE FINISHED] [{scan_id}] All 3 phases complete for target: {target_url}")
