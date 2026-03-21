"""
Auth Service - Main application entry point.
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time
import asyncio
from prometheus_client import make_asgi_app, Counter, Histogram
import sentry_sdk

from .api import auth, tokens, keys, mfa, sessions, sso
from .core.config import settings
from .core.database import engine, Base
from .core.exceptions import AuthException
from .middleware.rate_limit import RateLimitMiddleware
from .services.session_service import SessionService

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Sentry if configured
if settings.SENTRY_DSN:
    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        environment=settings.ENVIRONMENT,
        traces_sample_rate=0.1
    )

# Prometheus metrics
request_count = Counter(
    'auth_service_requests_total',
    'Total requests',
    ['method', 'endpoint', 'status']
)
request_duration = Histogram(
    'auth_service_request_duration_seconds',
    'Request duration',
    ['method', 'endpoint']
)

# Background tasks
cleanup_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    logger.info("Starting Auth Service...")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")
    
    # Start background tasks
    global cleanup_task
    cleanup_task = asyncio.create_task(scheduled_cleanup())
    
    yield
    
    # Shutdown
    logger.info("Shutting down Auth Service...")
    
    if cleanup_task:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


async def scheduled_cleanup():
    """Run scheduled cleanup tasks."""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            
            # Clean up expired sessions
            async with SessionLocal() as db:
                session_service = SessionService(db)
                await session_service.cleanup_expired_sessions()
                
        except Exception as e:
            logger.error(f"Error in scheduled cleanup: {e}")


# Create FastAPI app
app = FastAPI(
    title="Auth Service",
    description="Authentication and authorization service for M-PESA SaaS platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)

# Add Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests and track metrics."""
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Update metrics
    request_count.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    request_duration.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)
    
    # Log request
    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} - "
        f"{duration:.3f}s"
    )
    
    return response


# Exception handlers
@app.exception_handler(AuthException)
async def auth_exception_handler(request: Request, exc: AuthException):
    """Handle custom auth exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unhandled exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    if settings.ENVIRONMENT == "development":
        content = {"detail": str(exc)}
    else:
        content = {"detail": "An internal server error occurred"}
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=content
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    from .core.database import redis_client
    
    # Check database
    db_status = "healthy"
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
    except:
        db_status = "unhealthy"
    
    # Check Redis
    redis_status = "healthy"
    try:
        redis_client.ping()
    except:
        redis_status = "unhealthy"
    
    return {
        "status": "healthy" if db_status == "healthy" and redis_status == "healthy" else "degraded",
        "service": "auth-service",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "dependencies": {
            "database": db_status,
            "redis": redis_status
        }
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with service info."""
    return {
        "name": "Auth Service",
        "version": "1.0.0",
        "description": "Authentication and authorization for M-PESA SaaS",
        "docs": "/api/docs",
        "health": "/health",
        "metrics": "/metrics"
    }


# Include routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(tokens.router, prefix="/api/v1")
app.include_router(keys.router, prefix="/api/v1")
app.include_router(mfa.router, prefix="/api/v1")
app.include_router(sessions.router, prefix="/api/v1")
app.include_router(sso.router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.API_PORT,
        reload=settings.DEBUG
    )