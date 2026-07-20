
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from app.core.config import settings
# from app.db.redis_db import init_redis, close_redis
# from app.db.redis_db.agent_infra.heartbeat import init_vitality_tracker, close_vitality_tracker

# from app.db.redis_db.agent_infra.jobs import init_archival_job, close_archival_job
from app.db.nats_db import setup_nats, close_nats
from app.db.postgres.connection import async_engine, Base
from app.middleware.security import AuthRateLimitMiddleware, SecurityHeadersMiddleware
import app.db.postgres.models  # noqa: F401 — registers ORM metadata before create_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logging.getLogger("uvicorn.error").setLevel(logging.INFO)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)
logging.getLogger(__name__).setLevel(logging.INFO)

log_dir = Path(__file__).resolve().parents[1] / "logs"
log_dir.mkdir(parents=True, exist_ok=True)


def _has_rotating_handler(logger_obj: logging.Logger, log_path: Path) -> bool:
    target_path = str(log_path.resolve()).lower()
    for handler in logger_obj.handlers:
        handler_path = getattr(handler, "baseFilename", None)
        if isinstance(handler, RotatingFileHandler) and isinstance(handler_path, str):
            if handler_path.lower() == target_path:
                return True
    return False

auth_logger = logging.getLogger("app.auth")
auth_logger.setLevel(logging.INFO)
auth_logger.propagate = False
auth_log_path = log_dir / "auth.log"
if not _has_rotating_handler(auth_logger, auth_log_path):
    auth_log_handler = RotatingFileHandler(
        auth_log_path,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    auth_log_handler.setLevel(logging.INFO)
    auth_log_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    auth_logger.addHandler(auth_log_handler)

context_logger = logging.getLogger("app.context")
context_logger.setLevel(logging.INFO)
context_logger.propagate = False
context_log_path = log_dir / "context.log"
if not _has_rotating_handler(context_logger, context_log_path):
    context_log_handler = RotatingFileHandler(
        context_log_path,
        maxBytes=20 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    context_log_handler.setLevel(logging.INFO)
    context_log_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    context_logger.addHandler(context_log_handler)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Handles startup and shutdown of background services.
    
    Startup sequence:
    1. Initialize Redis cache
    2. Initialize agent vitality tracker (background heartbeat check)
    3. Initialize session archival job (background TTL enforcement)
    
    Shutdown sequence (reverse order):
    1. Stop archival job
    2. Stop vitality tracker
    3. Close Redis
    """
    # Startup
    logger.info("🚀 Backend startup sequence")

    # try:
    #     logger.info("Creating database tables...")
    #     async with async_engine.begin() as conn:
    #         await conn.run_sync(Base.metadata.create_all)
    #         await conn.execute(
    #             text(
    #                 "ALTER TABLE chats "
    #                 "ADD COLUMN IF NOT EXISTS ide_context_enabled BOOLEAN NOT NULL DEFAULT FALSE"
    #             )
    #         )
    #     logger.info("✅ Database tables ready")
    # except Exception as exc:
    #     logger.error(f"❌ Database table creation failed: {exc}")
    #     raise

    try:
        logger.info("Connecting to NATS...")
        await setup_nats(
            settings.nats_url,
            creds_file=settings.nats_creds_file,
            creds_content=settings.nats_creds_content
        )
        logger.info("✅ NATS connected")
    except Exception as exc:
        logger.error(f"❌ NATS connection failed: {exc}")
        raise
    
    # try:
    #     logger.info("Initializing agent vitality tracker...")
    #     await init_vitality_tracker()
    #     logger.info("✅ Agent vitality tracker initialized")
    # except Exception as exc:
    #     logger.error(f"❌ Vitality tracker initialization failed: {exc}")
    #     raise
    
    # try:
    #     logger.info("Initializing session archival job...")
    #     await init_archival_job()
    #     logger.info("✅ Session archival job initialized")
    # except Exception as exc:
    #     logger.error(f"❌ Archival job initialization failed: {exc}")
    #     raise
    
    logger.info("✅ All background services started")
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("🛑 Backend shutdown sequence")
    
    # try:
    #     logger.info("Stopping session archival job...")
    #     await close_archival_job()
    #     logger.info("✅ Archival job stopped")
    # except Exception as exc:
    #     logger.error(f"Error stopping archival job: {exc}")
    
    # try:
    #     logger.info("Stopping agent vitality tracker...")
    #     await close_vitality_tracker()
    #     logger.info("✅ Vitality tracker stopped")
    # except Exception as exc:
    #     logger.error(f"Error stopping vitality tracker: {exc}")
    
    try:
        logger.info("Disconnecting from NATS...")
        await close_nats()
        logger.info("✅ NATS disconnected")
    except Exception as exc:
        logger.error(f"Error disconnecting from NATS: {exc}")
    
    logger.info("✅ Shutdown complete")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    AuthRateLimitMiddleware,
    max_requests=settings.auth_rate_limit_max_requests,
    window_seconds=settings.auth_rate_limit_window_seconds,
)

static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "app": settings.app_name}


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Vertex Swarm Backend API", "version": settings.app_version}


# Include API routes
# from app.api.v1 import endpoints
from app.api.v1.auth import router as auth_router
from app.api.v1.oauth import router as oauth_router
# from app.api.v1.tools import router as tools_router
# app.include_router(endpoints.router)
app.include_router(auth_router)
app.include_router(oauth_router)
# app.include_router(tools_router)


@app.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks_endpoint():
    """
    Standard JWKS endpoint — broadcasts the RSA public key used to sign
    extension access/refresh tokens (RS256).  The local worker fetches this
    URL once per session so it never needs a hardcoded public key.
    """
    import base64
    import hashlib
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from fastapi import HTTPException

    raw = settings.app_auth_public_key.strip()
    if not raw:
        raise HTTPException(status_code=503, detail="Public key not configured")

    try:
        pub = load_pem_public_key(raw.encode())
        if not isinstance(pub, RSAPublicKey):
            raise HTTPException(status_code=503, detail="Configured key is not an RSA public key")

        pub_numbers = pub.public_key().public_numbers() if hasattr(pub, "public_key") else pub.public_numbers()

        def _b64url(n: int, byte_length: int) -> str:
            return base64.urlsafe_b64encode(
                n.to_bytes(byte_length, "big")
            ).rstrip(b"=").decode()

        key_size_bytes = (pub_numbers.n.bit_length() + 7) // 8
        kid = hashlib.sha256(raw.encode()).hexdigest()[:16]

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": settings.app_auth_algorithm,
            "kid": kid,
            "n": _b64url(pub_numbers.n, key_size_bytes),
            "e": _b64url(pub_numbers.e, 3),
        }
        return {"keys": [jwk]}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to build JWKS response: %s", exc)
        raise HTTPException(status_code=503, detail="Failed to build JWKS")

