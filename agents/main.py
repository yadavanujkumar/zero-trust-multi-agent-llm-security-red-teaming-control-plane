from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
import re
import logging
import time
import uuid
from typing import List

# ── Structured logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "service": "llm-agent", "msg": "%(message)s"}',
)
log = logging.getLogger(__name__)

app = FastAPI(
    title="LLM Security Agent Service",
    description="Multi-agent XAI-driven threat detection for LLM prompts",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Request/Response Models ────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    prompt: str

    @field_validator("prompt")
    @classmethod
    def prompt_must_not_be_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("prompt must not be empty")
        if len(v) > 32_000:
            raise ValueError("prompt exceeds maximum length of 32,000 characters")
        return v


class AnalyzeResponse(BaseModel):
    risk_score: float
    has_pii: bool
    xai_explanation: str
    requires_sandboxing: bool
    detected_threats: List[str]
    confidence_score: float
    request_id: str


# ── PII regex patterns ─────────────────────────────────────────────────────
PII_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "password_kw": re.compile(r"(?i)\bpassword\s*[:=]\s*\S+"),
}

# ── Injection / jailbreak patterns ─────────────────────────────────────────
INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"forget\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?previous\s+instructions",
        r"override\s+(the\s+)?system\s+prompt",
        r"you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|jailbreak)",
        r"do\s+anything\s+now",
        r"act\s+as\s+(?:if\s+you\s+are\s+)?(?:an?\s+)?(?:evil|unrestricted|jailbroken)",
        r"pretend\s+(?:you\s+are\s+)?(?:not|without)\s+(?:restrictions|guidelines|rules)",
        r"reveal\s+(?:your\s+)?(?:system\s+prompt|instructions|training data)",
        r"print\s+(?:your\s+)?(?:system\s+prompt|instructions)",
        r"what\s+(?:are|were)\s+(?:your\s+)?(?:initial|original)\s+instructions",
        r"<\s*\|?\s*(?:system|SYS|INST)\s*\|?\s*>",  # special token injection
    ]
]

# ── Obfuscation / sandboxing indicators ───────────────────────────────────
OBFUSCATION_PATTERNS = [
    re.compile(r"base64", re.IGNORECASE),
    re.compile(r"\\x[0-9a-fA-F]{2}"),      # hex escapes
    re.compile(r"\\u[0-9a-fA-F]{4}"),       # unicode escapes
    re.compile(r"(?:eval|exec|__import__)\s*\("),  # code execution
    re.compile(r"<script[\s>]", re.IGNORECASE),    # script tags
]

MAX_PROMPT_LEN_FOR_SANDBOX = 2_000


# ── Analysis endpoint ──────────────────────────────────────────────────────
@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(req: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    """
    Multi-agent threat analysis pipeline.

    Runs three parallel detection agents:
    1. PII Extraction Agent   — detects sensitive personal data
    2. Injection/Jailbreak Agent — detects adversarial instructions
    3. Obfuscation Agent      — detects encoding/evasion techniques
    """
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.time()

    prompt = req.prompt
    prompt_lower = prompt.lower()

    risk_score: float = 0.1
    has_pii: bool = False
    xai_parts: List[str] = []
    detected_threats: List[str] = []
    requires_sandboxing: bool = False
    confidence_score: float = 1.0

    # ── Agent 1: PII Detection ─────────────────────────────────────────────
    for pii_name, pattern in PII_PATTERNS.items():
        if pattern.search(prompt):
            has_pii = True
            risk_score = max(risk_score, 0.90)
            xai_parts.append(f"PII detected: {pii_name.upper()} pattern matched.")
            if "PII_EXFILTRATION" not in detected_threats:
                detected_threats.append("PII_EXFILTRATION")

    # ── Agent 2: Prompt Injection / Jailbreak Detection ──────────────────
    for pattern in INJECTION_PATTERNS:
        if pattern.search(prompt):
            risk_score = max(risk_score, 0.95)
            xai_parts.append(f"Prompt injection indicator matched: '{pattern.pattern[:60]}'.")
            if "PROMPT_INJECTION" not in detected_threats:
                detected_threats.append("PROMPT_INJECTION")
            if "JAILBREAK" not in detected_threats:
                detected_threats.append("JAILBREAK")

    # ── Agent 3: Obfuscation / Evasion Detection ──────────────────────────
    for pattern in OBFUSCATION_PATTERNS:
        if pattern.search(prompt):
            risk_score = max(risk_score, 0.65)
            requires_sandboxing = True
            xai_parts.append(f"Obfuscation indicator: '{pattern.pattern[:60]}'.")
            if "OBFUSCATION" not in detected_threats:
                detected_threats.append("OBFUSCATION")

    if len(prompt) > MAX_PROMPT_LEN_FOR_SANDBOX:
        risk_score = max(risk_score, 0.60)
        requires_sandboxing = True
        xai_parts.append(f"Payload length ({len(prompt)} chars) exceeds sandbox threshold.")

    if not detected_threats:
        detected_threats.append("NONE")

    xai_explanation = (
        " ".join(xai_parts) if xai_parts else "Prompt appears benign — no threat indicators detected."
    )

    elapsed_ms = round((time.time() - start) * 1000, 2)
    log.info(
        f"Analysis complete | request_id={request_id} risk={risk_score:.2f} "
        f"threats={detected_threats} elapsed_ms={elapsed_ms}"
    )

    return AnalyzeResponse(
        risk_score=round(risk_score, 4),
        has_pii=has_pii,
        xai_explanation=xai_explanation,
        requires_sandboxing=requires_sandboxing,
        detected_threats=detected_threats,
        confidence_score=confidence_score,
        request_id=request_id,
    )


# ── Health endpoints ──────────────────────────────────────────────────────
@app.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict:
    return {"status": "ok"}


@app.get("/ready", status_code=status.HTTP_200_OK)
async def ready() -> dict:
    return {"status": "ready"}


# ── Global exception handler ──────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    log.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal agent service error"},
    )

