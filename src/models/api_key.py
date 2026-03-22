"""
API Key model for programmatic access.
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..core.database import Base


class APIKey(Base):
    """API Key model."""

    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Key details
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False)
    key_preview = Column(String(20), nullable=False)  # Last 4 chars for display

    # Permissions
    permissions = Column(JSON, default=list)  # List of allowed permissions
    ip_restrictions = Column(JSON, default=list)  # List of allowed IPs

    # Status
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)

    # Usage tracking
    usage_count = Column(Integer, default=0)

    # Metadata
    metadata = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<APIKey {self.name}: {self.key_preview}>"

    @property
    def is_expired(self) -> bool:
        """Check if key is expired."""
        if not self.expires_at:
            return False
        return self.expires_at < datetime.utcnow()

    def record_usage(self):
        """Record API key usage."""
        self.usage_count += 1
        self.last_used_at = datetime.utcnow()

    def has_permission(self, permission: str) -> bool:
        """Check if key has specific permission."""
        return permission in self.permissions or "*" in self.permissions

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "key_preview": self.key_preview,
            "permissions": self.permissions,
            "ip_restrictions": self.ip_restrictions,
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat()
            if self.last_used_at
            else None,
            "usage_count": self.usage_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
