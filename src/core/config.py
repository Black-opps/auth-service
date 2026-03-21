"""
Configuration management for auth service.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List, Dict
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings."""
    
    # API Settings
    API_VERSION: str = "v1"
    API_PORT: int = 8007
    DEBUG: bool = False
    ENVIRONMENT: str = "development"
    
    # Database
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    
    # Redis (for sessions and rate limiting)
    REDIS_URL: str = Field("redis://localhost:6379/0", env="REDIS_URL")
    REDIS_TTL: int = 3600  # 1 hour
    
    # JWT Configuration
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # 7 days
    JWT_ISSUER: str = "mpesa-saas-auth"
    JWT_AUDIENCE: str = "mpesa-saas-api"
    
    # API Key Configuration
    API_KEY_PREFIX: str = "mpesa_live_"
    API_KEY_LENGTH: int = 48
    API_KEY_EXPIRE_DAYS: Optional[int] = 365  # 1 year, None for no expiry
    
    # MFA Configuration
    MFA_ISSUER_NAME: str = "M-PESA SaaS"
    MFA_TOTP_DIGITS: int = 6
    MFA_TOTP_PERIOD: int = 30  # seconds
    MFA_BACKUP_CODES_COUNT: int = 8
    
    # Session Configuration
    SESSION_TTL_SECONDS: int = 3600  # 1 hour
    MAX_SESSIONS_PER_USER: int = 5
    SESSION_COOKIE_NAME: str = "session_id"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100  # requests per minute
    RATE_LIMIT_PERIOD: int = 60  # seconds
    
    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_MAX_AGE_DAYS: Optional[int] = 90  # None for no expiry
    PASSWORD_HISTORY_COUNT: int = 5  # Number of previous passwords to remember
    
    # Login Attempts
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_TIME_MINUTES: int = 30
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8003",
        "http://localhost:8004",
        "http://localhost:8005",
        "http://localhost:8006"
    ]
    
    # SSO Configuration
    GOOGLE_CLIENT_ID: Optional[str] = Field(None, env="GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(None, env="GOOGLE_CLIENT_SECRET")
    MICROSOFT_CLIENT_ID: Optional[str] = Field(None, env="MICROSOFT_CLIENT_ID")
    MICROSOFT_CLIENT_SECRET: Optional[str] = Field(None, env="MICROSOFT_CLIENT_SECRET")
    
    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = Field("localhost:9092", env="KAFKA_BOOTSTRAP_SERVERS")
    KAFKA_AUTH_TOPIC: str = "auth-events"
    
    # Monitoring
    SENTRY_DSN: Optional[str] = None
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings."""
    return Settings()


settings = get_settings()