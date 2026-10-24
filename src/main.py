import uuid
import time
import logging
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, Request, Response, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from src.config import settings
from src.database import db
from src.detector import dlp_detector
from src.stream_monitor import stream_monitor
from src.models import (
    InspectRequest,
    InspectResponse,
    RedactRequest,
    RedactResponse,
    StreamMonitorRequest,
    StreamMonitorResult,
    HealthResponse
)

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger("pii_firewall")


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        corr_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = corr_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = corr_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_sync_db()
    logger.info("PII Financial Leakage Firewall initialized.")
    yield


app = FastAPI(
    title="PII Financial Leakage Firewall",
    description="Real-time Data Loss Prevention (DLP) and credential leakage firewall protecting against credit card PANs, IBANs, SSNs, and API private keys.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(RequestCorrelationMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    count = await db.get_total_violations_count()
    return HealthResponse(
        status="HEALTHY",
        active_rules=[
            "LUHN_MOD10_VALIDATION",
            "ISO7064_IBAN_MOD97",
            "US_SSA_AREA_GROUP_RULES",
            "STRIPE_API_KEY_SCANNER",
            "AWS_AKIA_CREDENTIAL_SCANNER",
            "PEM_PRIVATE_KEY_BLOCK_SCANNER"
        ],
        total_violations_recorded=count
    )


@app.post("/api/inspect", response_model=InspectResponse)
async def inspect_payload(payload: InspectRequest, request: Request):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    t0 = time.perf_counter()
    findings = dlp_detector.scan_text(payload.text)
    exec_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if findings:
        await db.record_findings(findings, request_id=req_id, source="INSPECT_API")

    return InspectResponse(
        is_leaked=len(findings) > 0,
        total_findings=len(findings),
        findings=findings,
        execution_time_ms=exec_ms
    )


@app.post("/api/redact", response_model=RedactResponse)
async def redact_payload(payload: RedactRequest, request: Request):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    t0 = time.perf_counter()
    sanitized, findings = dlp_detector.redact_text(payload.text, mode=payload.mode)
    exec_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if findings:
        await db.record_findings(findings, request_id=req_id, source="REDACT_API")

    return RedactResponse(
        original_length=len(payload.text),
        redacted_text=sanitized,
        findings_count=len(findings),
        findings=findings,
        execution_time_ms=exec_ms
    )


@app.post("/api/stream/monitor", response_model=StreamMonitorResult)
async def monitor_public_event_stream(payload: StreamMonitorRequest, request: Request):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return await stream_monitor.scan_live_events(sample_count=payload.sample_count, request_id=req_id)


@app.get("/api/audit/violations")
async def get_audit_violations(limit: int = Query(default=50, ge=1, le=500)):
    return await db.get_recent_violations(limit=limit)
