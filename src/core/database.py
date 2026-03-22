"""
Database configuration and session management.
"""

import json
import logging
from contextlib import contextmanager
from typing import Generator

import redis as sync_redis                 # ← Moved to top here
import redis.asyncio as redis

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from .config import settings

logger = logging.getLogger(__name__)

# SQLAlchemy setup
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
    echo=settings.DEBUG
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis setup (synchronous for simple operations)
redis_client = sync_redis.Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=5
)

# Async Redis for session management
async_redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True
)


def get_db() -> Generator[Session, None, None]:
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session():
    """Context manager for database sessions."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


class AuthCache:
    """Redis cache for auth data."""
    
    @staticmethod
    def get_user_session(session_id: str):
        """Get user session from cache."""
        data = redis_client.get(f"session:{session_id}")
        return json.loads(data) if data else None
    
    @staticmethod
    def set_user_session(session_id: str, session_data: dict, ttl: int = None):
        """Set user session in cache."""
        ttl = ttl or settings.SESSION_TTL_SECONDS
        redis_client.setex(
            f"session:{session_id}",
            ttl,
            json.dumps(session_data, default=str)
        )
    
    @staticmethod
    def delete_user_session(session_id: str):
        """Delete user session from cache."""
        redis_client.delete(f"session:{session_id}")
    
    @staticmethod
    def get_rate_limit(key: str) -> int:
        """Get rate limit count."""
        value = redis_client.get(f"ratelimit:{key}")
        return int(value) if value else 0
    
    @staticmethod
    def increment_rate_limit(key: str, ttl: int = 60) -> int:
        """Increment rate limit counter."""
        return redis_client.incr(f"ratelimit:{key}")
    
    @staticmethod
    def set_rate_limit_expiry(key: str, ttl: int = 60):
        """Set rate limit expiry."""
        redis_client.expire(f"ratelimit:{key}", ttl)
    
    @staticmethod
    def store_login_attempt(identifier: str):
        """Store failed login attempt."""
        key = f"login_attempts:{identifier}"
        attempts = redis_client.incr(key)
        redis_client.expire(key, settings.LOCKOUT_TIME_MINUTES * 60)
        return attempts
    
    @staticmethod
    def get_login_attempts(identifier: str) -> int:
        """Get number of failed login attempts."""
        value = redis_client.get(f"login_attempts:{identifier}")
        return int(value) if value else 0
    
    @staticmethod
    def reset_login_attempts(identifier: str):
        """Reset failed login attempts."""
        redis_client.delete(f"login_attempts:{identifier}")
    
    @staticmethod
    def store_refresh_token(jti: str, user_id: str, ttl: int):
        """Store refresh token for revocation."""
        redis_client.setex(f"refresh:{jti}", ttl, user_id)
    
    @staticmethod
    def is_refresh_token_revoked(jti: str) -> bool:
        """Check if refresh token is revoked."""
        return redis_client.exists(f"refresh:{jti}") == 0
    
    @staticmethod
    def revoke_refresh_token(jti: str):
        """Revoke refresh token."""
        redis_client.delete(f"refresh:{jti}")