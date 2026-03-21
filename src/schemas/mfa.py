"""
MFA (Multi-Factor Authentication) schemas.
"""
from pydantic import BaseModel
from typing import Optional, List
from uuid import UUID


class MFAEnableRequest(BaseModel):
    """Enable MFA request."""
    method: str = "totp"  # totp, sms, email


class MFAEnableResponse(BaseModel):
    """Enable MFA response."""
    secret: str
    qr_code: str  # Base64 encoded QR code
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    """Verify MFA code request."""
    code: str
    method: str = "totp"


class MFAVerifyResponse(BaseModel):
    """Verify MFA response."""
    verified: bool
    recovery_codes: Optional[List[str]] = None


class MFADisableRequest(BaseModel):
    """Disable MFA request."""
    password: str


class MFALoginRequest(BaseModel):
    """MFA login request."""
    email: str
    mfa_code: str
    mfa_method: str = "totp"


class MFAChallengeResponse(BaseModel):
    """MFA challenge response."""
    challenge_id: UUID
    method: str
    expires_in: int


class BackupCodeResponse(BaseModel):
    """Backup code response."""
    codes: List[str]
    message: str = "Store these backup codes safely. They won't be shown again."