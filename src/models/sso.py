"""
SSO (Single Sign-On) models for OAuth providers.
"""
from enum import Enum
from sqlalchemy import UniqueConstraint
from sqlalchemy import Column, String, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

from ..core.database import Base


class SSOProvider(str, Enum):
    """Supported SSO providers."""
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    GITHUB = "github"
    LINKEDIN = "linkedin"
    CUSTOM = "custom"


class SSOConnection(Base):
    """SSO connection for a user."""
    
    __tablename__ = "sso_connections"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Provider details
    provider = Column(Enum(SSOProvider), nullable=False)
    provider_user_id = Column(String(255), nullable=False)  # ID from provider
    email = Column(String(255), nullable=True)
    
    # Tokens
    access_token = Column(String(1000), nullable=True)  # Encrypted
    refresh_token = Column(String(1000), nullable=True)  # Encrypted
    token_expires_at = Column(DateTime, nullable=True)
    
    # Profile data
    profile_data = Column(JSON, default=dict)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User")
    
    __table_args__ = (
        UniqueConstraint('provider', 'provider_user_id', name='uq_sso_provider_user'),
    )
    
    def __repr__(self):
        return f"<SSOConnection {self.provider.value}: {self.provider_user_id}>"


class TenantSSOConfig(Base):
    """SSO configuration for a tenant (Enterprise feature)."""
    
    __tablename__ = "tenant_sso_configs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    
    # Provider config
    provider = Column(Enum(SSOProvider), nullable=False)
    client_id = Column(String(255), nullable=False)
    client_secret = Column(String(1000), nullable=False)  # Encrypted
    issuer_url = Column(String(500), nullable=True)
    authorization_url = Column(String(500), nullable=True)
    token_url = Column(String(500), nullable=True)
    userinfo_url = Column(String(500), nullable=True)
    
    # Domain restrictions
    allowed_domains = Column(JSON, default=list)  # List of allowed email domains
    
    # Metadata
    metadata = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<TenantSSOConfig {self.tenant_id}: {self.provider.value}>"