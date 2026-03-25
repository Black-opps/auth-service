"""
Database configuration and session management.
Supports async SQLAlchemy + Redis (sync + async).
"""

import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import redis as sync_redis
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from .config import settings

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# SQLAlchemy Async Engine Setup
# -------------------------------------------------------------------

DATABASE_URL = settings.DATABASE_URL

if "sqlite" in DATABASE_URL:
    # SQLite async does NOT support pooling
    engine = create_async_engine(
        DATABASE_URL,
        echo=False,
    )
else:
    # Production-ready config (PostgreSQL / MySQL)
    engine = create_async_engine(
        DATABASE_URL,
        echo=False,
        pool_size=10,
        max_overflow=20,
    )

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)

Base = declarative_base()

# -------------------------------------------------------------------
# FastAPI Dependency
# -------------------------------------------------------------------


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Async DB session dependency for FastAPI routes.
    """
    async with AsyncSessionLocal() as session:
        yield session


@asynccontextmanager
async def db_session():
    """
    Async context manager for manual DB transactions.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# -------------------------------------------------------------------
# Redis Clients
# -------------------------------------------------------------------

# Sync Redis (simple caching)
redis_client = sync_redis.Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=5,
)

# Async Redis (recommended for session handling)
async_redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
)

# -------------------------------------------------------------------
# Auth Cache Layer
# -------------------------------------------------------------------


class AuthCache:
    """Redis-backed authentication/session cache utilities."""

    @staticmethod
    def get_user_session(session_id: str):
        data = redis_client.get(f"session:{session_id}")
        return json.loads(data) if data else None

    @staticmethod
    def set_user_session(session_id: str, session_data: dict, ttl: int = None):
        ttl = ttl or settings.SESSION_TTL_SECONDS
        redis_client.setex(
            f"session:{session_id}",
            ttl,
            json.dumps(session_data, default=str),
        )

    @staticmethod
    def delete_user_session(session_id: str):
        redis_client.delete(f"session:{session_id}")

    @staticmethod
    def get_rate_limit(key: str) -> int:
        value = redis_client.get(f"ratelimit:{key}")
        return int(value) if value else 0

    @staticmethod
    def increment_rate_limit(key: str) -> int:
        return redis_client.incr(f"ratelimit:{key}")

    @staticmethod
    def set_rate_limit_expiry(key: str, ttl: int = 60):
        redis_client.expire(f"ratelimit:{key}", ttl)

    @staticmethod
    def store_login_attempt(identifier: str):
        key = f"login_attempts:{identifier}"
        attempts = redis_client.incr(key)
        redis_client.expire(
            key,
            settings.LOCKOUT_TIME_MINUTES * 60,
        )
        return attempts

    @staticmethod
    def get_login_attempts(identifier: str) -> int:
        value = redis_client.get(f"login_attempts:{identifier}")
        return int(value) if value else 0

    @staticmethod
    def reset_login_attempts(identifier: str):
        redis_client.delete(f"login_attempts:{identifier}")

    @staticmethod
    def store_refresh_token(jti: str, user_id: str, ttl: int):
        redis_client.setex(f"refresh:{jti}", ttl, user_id)

    @staticmethod
    def is_refresh_token_revoked(jti: str) -> bool:
        return redis_client.exists(f"refresh:{jti}") == 0

    @staticmethod
    def revoke_refresh_token(jti: str):
        redis_client.delete(f"refresh:{jti}")
