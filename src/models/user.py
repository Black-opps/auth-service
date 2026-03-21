"""
User model for auth service.
"""
from sqlalchemy import Column, String, Boolean, DateTime, JSON, Enum, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
import enum

from ..core.database import Base
from ..core.security import hash_password


class UserStatus(str, enum.Enum):
    """User account status."""
    PENDING = "pending"  # Email not verified
    ACTIVE = "active"
    LOCKED = "locked"  # Too many failed attempts
    DISABLED = "disabled"
    DELETED = "deleted"


class UserRole(str, enum.Enum):
    """User roles."""
    SUPER_ADMIN = "super_admin"  # Platform admin
    ADMIN = "admin"  # Tenant admin
    MANAGER = "manager"  # Tenant manager
    ANALYST = "analyst"  # Tenant analyst
    VIEWER = "viewer"  # Read-only
    API = "api"  # Service account


class User(Base):
    """User model for authentication."""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=True, index=True)  # Null for super admins
    
    # Basic info
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=True, index=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    
    # Authentication
    password_hash = Column(String(255), nullable=True)  # Null for SSO users
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.PENDING, nullable=False)
    
    # Security
    email_verified = Column(Boolean, default=False)
    email_verified_at = Column(DateTime, nullable=True)
    email_verification_token = Column(String(255), unique=True, nullable=True)
    
    password_changed_at = Column(DateTime, nullable=True)
    password_reset_token = Column(String(255), unique=True, nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    
    # Login tracking
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(50), nullable=True)
    last_login_user_agent = Column(String(500), nullable=True)
    login_count = Column(Integer, default=0)
    
    # Failed attempts
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_backup_codes = Column(JSON, nullable=True)  # List of hashed backup codes
    
    # Profile
    profile = Column(JSON, default=dict)
    preferences = Column(JSON, default=dict)
    metadata = Column(JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    mfa_devices = relationship("MFADevice", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email} ({self.role.value})>"
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}".strip()
        return self.first_name or self.last_name or self.email
    
    @property
    def is_active(self) -> bool:
        """Check if user account is active."""
        if self.status != UserStatus.ACTIVE:
            return False
        if self.locked_until and self.locked_until > datetime.utcnow():
            return False
        return True
    
    @property
    def is_locked(self) -> bool:
        """Check if account is locked."""
        return self.locked_until and self.locked_until > datetime.utcnow()
    
    def set_password(self, password: str):
        """Set and hash password."""
        self.password_hash = hash_password(password)
        self.password_changed_at = datetime.utcnow()
    
    def verify_password(self, password: str) -> bool:
        """Verify password."""
        from ..core.security import verify_password
        if not self.password_hash:
            return False
        return verify_password(password, self.password_hash)
    
    def increment_failed_attempts(self):
        """Increment failed login attempts."""
        self.failed_login_attempts += 1
        from .config import settings
        if self.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(minutes=settings.LOCKOUT_TIME_MINUTES)
    
    def reset_failed_attempts(self):
        """Reset failed login attempts."""
        self.failed_login_attempts = 0
        self.locked_until = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary (safe version)."""
        return {
            "id": str(self.id),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "email": self.email,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "role": self.role.value,
            "status": self.status.value,
            "email_verified": self.email_verified,
            "mfa_enabled": self.mfa_enabled,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "preferences": self.preferences
        }


class UserSession(Base):
    """User session model."""
    
    __tablename__ = "user_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Session details
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), unique=True, nullable=True, index=True)
    refresh_token_jti = Column(String(255), unique=True, nullable=True, index=True)
    
    # Device info
    device_fingerprint = Column(String(255), nullable=True)
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(50), nullable=True)
    
    # Location (from IP)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    
    # Metadata
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=False)
    last_activity_at = Column(DateTime, default=datetime.utcnow)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<UserSession {self.session_id[:8]}...>"
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return self.expires_at < datetime.utcnow()