"""PhishNet API: receives email reports from the Gmail add-on and returns a verdict."""

import hashlib
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Path, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.engine.loader import EngineConfig, load_engine_config
from app.engine.scorer import ALWAYS_ON_RULES, analyze
from app.gauge import gauge_gif
from app.models import AnalysisResult, EmailReport, RuleInfo
from app.security import BodySizeLimitMiddleware, GoogleIdentityVerifier, google_key_resolver, require_google_user

settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("phishnet")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load and validate rules at startup, so a bad config fails the deploy, not a request.
    app.state.engine = load_engine_config(settings.rules_config_path)
    app.state.verifier = GoogleIdentityVerifier(settings.audience_list, settings.email_list, google_key_resolver())
    for rule in app.state.engine.rules:
        try:
            rule.warm_up()
        except Exception as exc:
            # Keep serving with the other rules; this one will be listed in rulesFailed.
            logger.error("Rule %s failed to load: %s: %s", rule.id, type(exc).__name__, exc)
    logger.info("Loaded %d rules: %s", len(app.state.engine.rules), [r.id for r in app.state.engine.rules])
    yield


# Interactive docs are disabled: this API has one client and no reason to advertise its schema.
app = FastAPI(title="PhishNet API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)


def get_engine(request: Request) -> EngineConfig:
    return request.app.state.engine


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default error echoes the offending input back. That input is email content,
    # so return only where and why validation failed.
    errors = [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/gauge/{score}.gif")
def gauge(score: int = Path(ge=0, le=100), engine: EngineConfig = Depends(get_engine)) -> Response:
    """Animated score ring for the card. Public on purpose: Gmail's image proxy fetches it without
    our token, and it encodes nothing but the number. Each score's image never changes, so cache it."""
    return Response(
        gauge_gif(score, engine.suspicious_threshold, engine.malicious_threshold),
        media_type="image/gif",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/rules", response_model=list[RuleInfo])
def list_rules(
    user: str = Depends(require_google_user),
    engine: EngineConfig = Depends(get_engine),
) -> list[RuleInfo]:
    """The active rules, for the add-on's settings card (so it never keeps its own copy)."""
    return [
        RuleInfo(id=r.id, title=r.title, description=r.description, category=r.category, score=r.score,
                 can_disable=r.id not in ALWAYS_ON_RULES)
        for r in sorted(engine.rules, key=lambda r: (r.category, -r.score, r.id))
    ]


@app.post("/analyze", response_model=AnalysisResult)
def analyze_email(
    report: EmailReport,
    user: str = Depends(require_google_user),
    engine: EngineConfig = Depends(get_engine),
) -> AnalysisResult:
    result = analyze(report, engine)
    # Never log email content. A hash of the message id is enough to correlate requests.
    message_ref = hashlib.sha256(report.message.id.encode()).hexdigest()[:12]
    logger.info(
        "user=%s message=%s score=%d verdict=%s rules=%s schema=%s sender_history=%s",
        user,
        message_ref,
        result.score,
        result.verdict,
        [f.rule_id for f in result.findings],
        report.schema_version,
        report.mailbox.sender_history or "missing",  # new/established/unknown: no mailbox content
    )
    return result
