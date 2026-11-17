"""CYBERMIND-NLP FastAPI backend.

Serves the analysis API and (when present) the static web application
from the ``frontend/`` directory at ``/ui/``.
"""

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.analyzer import CyberMindAnalyzer
from src.gmail_security.router import router as gmail_router


# --------------------------------------------------
# Configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

APP_NAME = "CYBERMIND-NLP"
APP_DISPLAY_NAME = "CYBERMIND"
APP_VERSION = "2.0.0"

MODEL_FILENAME = "cybermind_threat_classifier.joblib"

MAX_MESSAGE_LENGTH = int(
    os.getenv("CYBERMIND_MAX_MESSAGE_LENGTH", "5000")
)

DEFAULT_ALLOWED_ORIGINS = [
    f"http://{host}:{port}"
    for host in ("localhost", "127.0.0.1")
    for port in ("8000", "5500", "8080", "3000")
]


def load_allowed_origins() -> list[str]:
    """Read allowed CORS origins from the environment."""

    configured = os.getenv("CYBERMIND_ALLOWED_ORIGINS", "").strip()

    if not configured:
        return DEFAULT_ALLOWED_ORIGINS

    return [
        origin.strip()
        for origin in configured.split(",")
        if origin.strip()
    ]


logging.basicConfig(
    level=os.getenv("CYBERMIND_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("cybermind.api")


class GmailQueryRedactionFilter(logging.Filter):
    """Prevent OAuth codes and states from entering Uvicorn access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if (
            record.name == "uvicorn.access"
            and isinstance(record.args, tuple)
            and len(record.args) >= 3
        ):
            arguments = list(record.args)
            path = str(arguments[2]).partition("?")[0]
            if path.startswith("/gmail/"):
                arguments[2] = path
                record.args = tuple(arguments)
        return True


logging.getLogger("uvicorn.access").addFilter(
    GmailQueryRedactionFilter()
)


# --------------------------------------------------
# Request / response models
# --------------------------------------------------

class AnalysisRequest(BaseModel):
    """Text submitted for cybersecurity analysis."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
        description=(
            "Message, email, SMS, or other text to analyze. "
            f"Maximum {MAX_MESSAGE_LENGTH} characters."
        ),
    )

    @field_validator("text")
    @classmethod
    def validate_not_blank(cls, value: str) -> str:
        """Reject messages that are empty or whitespace only."""

        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "Message must not be empty or contain only whitespace."
            )

        return cleaned


class AnalysisResponse(BaseModel):
    """Successful analysis response envelope."""

    status: str
    result: dict[str, Any]


# --------------------------------------------------
# Analyzer initialization
# --------------------------------------------------

analyzer: CyberMindAnalyzer | None = None

try:
    analyzer = CyberMindAnalyzer()
    logger.info("CYBERMIND analyzer initialized successfully.")
except Exception:  # pragma: no cover - depends on local model files
    # Log the detailed error server-side only. Never expose stack
    # traces or filesystem paths to API consumers.
    logger.exception("CYBERMIND analyzer failed to initialize.")


def analyzer_ready() -> bool:
    return analyzer is not None


# --------------------------------------------------
# Application
# --------------------------------------------------

app = FastAPI(
    title="CYBERMIND-NLP API",
    description=(
        "AI-based cybersecurity text analysis API using NLP, "
        "heuristic analysis, URL inspection, and a trained "
        "machine-learning classifier."
    ),
    version=APP_VERSION,
)
app.include_router(gmail_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=load_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add conservative security headers to every response."""

    response = await call_next(request)

    response.headers.setdefault(
        "X-Content-Type-Options", "nosniff"
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Referrer-Policy", "no-referrer"
    )
    if request.url.path.startswith("/gmail/"):
        response.headers["Cache-Control"] = "no-store"

    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """Return a consistent JSON error envelope."""

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "detail": str(exc.detail),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a clean validation error without echoing user input."""

    detail = "Invalid request. Provide a non-empty 'text' field."

    errors = exc.errors()

    if errors:
        first = errors[0]
        location = ".".join(
            str(part)
            for part in first.get("loc", [])
            if part not in ("body", "query", "path")
        )
        message = first.get("msg", "Invalid value.")

        if location:
            detail = f"Invalid input ({location}): {message}"
        else:
            detail = f"Invalid input: {message}"

    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "detail": detail,
        },
    )


# --------------------------------------------------
# Routes
# --------------------------------------------------

@app.get("/", tags=["status"])
def root() -> dict[str, Any]:
    """Return application name and API status."""

    return {
        "application": APP_NAME,
        "name": APP_DISPLAY_NAME,
        "status": "running",
        "api_status": (
            "ready" if analyzer_ready() else "degraded"
        ),
        "version": APP_VERSION,
        "message": "AI-Powered Cyber Threat Detection API",
        "docs": "/docs",
        "health": "/health",
        "frontend": "/ui/",
        "max_message_length": MAX_MESSAGE_LENGTH,
    }


@app.get("/health", tags=["status"])
def health_check() -> JSONResponse:
    """Return backend and model readiness."""

    if not analyzer_ready():
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "analyzer": "not initialized",
                "model": MODEL_FILENAME,
                "detail": (
                    "The analysis engine could not be initialized. "
                    "Check the server logs for details."
                ),
            },
        )

    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "analyzer": "ready",
            "model": MODEL_FILENAME,
            "version": APP_VERSION,
            "max_message_length": MAX_MESSAGE_LENGTH,
        },
    )


@app.post(
    "/analyze",
    tags=["analysis"],
    response_model=AnalysisResponse,
)
def analyze_text(request: AnalysisRequest) -> AnalysisResponse:
    """Analyze a message using the CyberMind NLP engine."""

    if analyzer is not None:
        try:
            result = analyzer.analyze(request.text)

            # The submitted message is intentionally not logged.
            logger.info(
                "Analysis completed: threat=%s risk=%s",
                result["final_assessment"].get("final_threat"),
                result["final_assessment"].get("risk_score"),
            )

            return AnalysisResponse(
                status="success",
                result=result,
            )

        except Exception:
            logger.exception(
                "Analysis failed while processing a request."
            )

            raise HTTPException(
                status_code=500,
                detail=(
                    "The message could not be analyzed due to an "
                    "internal server error. Please try again later."
                ),
            )

    raise HTTPException(
        status_code=503,
        detail=(
            "The analysis engine is not available right now. "
            "Please try again later."
        ),
    )


# --------------------------------------------------
# Frontend hosting
# --------------------------------------------------

if FRONTEND_DIR.is_dir():
    app.mount(
        "/ui",
        StaticFiles(directory=str(FRONTEND_DIR), html=True),
        name="frontend",
    )
else:  # pragma: no cover - only when frontend is absent
    logger.warning(
        "Frontend directory not found at %s; /ui/ is disabled.",
        FRONTEND_DIR,
    )


@app.get("/app", include_in_schema=False)
def redirect_to_frontend() -> RedirectResponse:
    """Convenience redirect to the web application."""

    return RedirectResponse(url="/ui/", status_code=307)
