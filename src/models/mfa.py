"""
MFA (Multi-Factor Authentication) models.
"""
from sqlalchemy import Column, String, Boolean, DateTime, JSON, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

from ..core.database import Base


class MFADevice(Base):
    """MFA device model."""
    
    __tablename__ = "mfa_devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Device details
    device_type = Column(String(50), nullable=False)  # totp, sms, email, webauthn
    name = Column(String(100), nullable=True)  # User-friendly name
    
    # TOTP specific
    secret = Column(String(255), nullable=True)  # Encrypted TOTP secret
    
    # WebAuthn specific
    credential_id = Column(String(255), nullable=True)
    public_key = Column(Text, nullable=True)
    sign_count = Column(Integer, default=0)
    
    # SMS/Email specific
    phone_number = Column(String(50), nullable=True)
    email = Column(String(255), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_primary = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    
    # Metadata
    metadata = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="mfa_devices")
    
    def __repr__(self):
        return f"<MFADevice {self.device_type}: {self.name}>"


class MFAChallenge(Base):
    """MFA challenge for ongoing authentication."""
    
    __tablename__ = "mfa_challenges"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
       # Challenge details
    challenge_type = Column(String(50), nullable=False)  # totp, sms, email
    code = Column(String(10), nullable=False)  # The verification code (hashed)
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    
    # Status
    is_verified = Column(Boolean, default=False)
    is_expired = Column(Boolean, default=False)
    
    # Metadata
    metadata = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User")
    
    def __repr__(self):
        return f"<MFAChallenge {self.challenge_type}: {self.id}>"
    
    @property
    def is_valid(self) -> bool:
        """Check if challenge is still valid."""
        return not self.is_verified and not self.is_expired and self.expires_at > datetime.utcnow() and self.attempts < self.max_attempts
    
    def increment_attempts(self):
        """Increment attempt counter."""
        self.attempts += 1
        if self.attempts >= self.max_attempts:
            self.is_expired = True