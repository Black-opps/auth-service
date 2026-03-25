"""
Auth Service - Main application entry point (async-ready).
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, make_asgi_app
from sqlalchemy.exc import SQLAlchemyError

# Routers
from src.api.auth import router as auth_router
from src.api.keys import router as keys_router
from src.api.mfa import router as mfa_router

# Core
from src.core.config import settings
from src.core.database import AsyncSessionLocal, Base, engine, redis_client
from src.core.exceptions import AuthException

# Middleware
from src.middleware.rate_limit import RateLimitMiddleware

# Services
from src.services.session_service import SessionService

# -----------------------
# Logging Configuration
# -----------------------
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# -----------------------
# Sentry
# -----------------------
if settings.SENTRY_DSN:
    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        environment=settings.ENVIRONMENT,
        traces_sample_rate=0.1,
    )

# -----------------------
# Prometheus metrics
# -----------------------
request_count = Counter(
    "auth_service_requests_total",
    "Total requests",
    ["method", "endpoint", "status"],
)

request_duration = Histogram(
    "auth_service_request_duration_seconds",
    "Request duration",
    ["method", "endpoint"],
)

cleanup_task = None


# -----------------------
# Lifespan (startup / shutdown)
# -----------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Auth Service...")

    # Create DB tables (sync within async)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified")

    global cleanup_task
    cleanup_task = asyncio.create_task(scheduled_cleanup())

    yield

    logger.info("Shutting down Auth Service...")
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


# -----------------------
# Background cleanup
# -----------------------
async def scheduled_cleanup():
    """Runs background cleanup tasks every hour."""
    while True:
        try:
            await asyncio.sleep(3600)
            async with AsyncSessionLocal() as db:
                session_service = SessionService(db)
                await session_service.cleanup_expired_sessions()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


# -----------------------
# FastAPI App
# -----------------------
app = FastAPI(
    title="Auth Service",
    description="Authentication and authorization service for MPesa SaaS platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.add_middleware(RateLimitMiddleware)

# Prometheus endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# -----------------------
# Request logging & metrics
# -----------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    request_count.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code,
    ).inc()

    request_duration.labels(
        method=request.method,
        endpoint=request.url.path,
    ).observe(duration)

    logger.info(
        f"{request.method} {request.url.path} {response.status_code} {duration:.3f}s"
    )
    return response


# -----------------------
# Exception handlers
# -----------------------
@app.exception_handler(AuthException)
async def auth_exception_handler(request: Request, exc: AuthException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    content = (
        {"detail": str(exc)}
        if settings.ENVIRONMENT == "development"
        else {"detail": "Internal server error"}
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=content,
    )


# -----------------------
# Health check
# -----------------------
@app.get("/health")
async def health_check():
    """Service health endpoint."""
    db_status = "healthy"
    try:
        async with AsyncSessionLocal() as db:
            await db.execute("SELECT 1")
    except SQLAlchemyError:
        db_status = "unhealthy"

    redis_status = "healthy"
    try:
        redis_client.ping()
    except Exception:
        redis_status = "unhealthy"

    overall_status = (
        "healthy"
        if db_status == "healthy" and redis_status == "healthy"
        else "degraded"
    )
    return {
        "status": overall_status,
        "service": "auth-service",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "dependencies": {
            "database": db_status,
            "redis": redis_status,
        },
    }


# -----------------------
# Root
# -----------------------
@app.get("/")
async def root():
    return {
        "name": "Auth Service",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/health",
        "metrics": "/metrics",
    }


# -----------------------
# Routers
# -----------------------
app.include_router(auth_router, prefix="/api/v1")
app.include_router(keys_router, prefix="/api/v1")
app.include_router(mfa_router, prefix="/api/v1")

# -----------------------
# Uvicorn entrypoint
# -----------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=settings.API_PORT,
        reload=settings.DEBUG,
    )
