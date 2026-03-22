"""
Token models for JWT and refresh tokens.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..core.database import Base


class RefreshToken(Base):
    """Refresh token model."""

    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("user_sessions.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Token details
    jti = Column(String(255), unique=True, nullable=False, index=True)  # JWT ID
    token = Column(String(500), unique=True, nullable=False)  # Encrypted token

    # Metadata
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(50), nullable=True)

    # Status
    is_revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)

    # Expiry
    expires_at = Column(DateTime, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")
    session = relationship("UserSession")

    def __repr__(self):
        return f"<RefreshToken {self.jti[:8]}...>"

    @property
    def is_valid(self) -> bool:
        """Check if token is valid."""
        return not self.is_revoked and self.expires_at > datetime.utcnow()


class RevokedToken(Base):
    """Blacklisted/revoked tokens."""

    __tablename__ = "revoked_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    jti = Column(String(255), unique=True, nullable=False, index=True)
    token_type = Column(String(50), nullable=False)  # access, refresh

    # Metadata
    user_id = Column(UUID(as_uuid=True), nullable=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # When token would have expired

    def __repr__(self):
        return f"<RevokedToken {self.jti[:8]}...>"
