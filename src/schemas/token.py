"""
Token schemas.
"""
from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from datetime import datetime


class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: str  # User ID
    jti: str  # JWT ID
    type: str  # access, refresh
    tenant_id: Optional[UUID] = None
    role: str
    permissions: list = []
    exp: datetime
    iat: datetime
    iss: str
    aud: str


class TokenIntrospect(BaseModel):
    """Token introspection response."""
    active: bool
    sub: Optional[str] = None
    tenant_id: Optional[UUID] = None
    role: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None


class RevokedTokenResponse(BaseModel):
    """Revoked token response."""
    jti: str
    revoked_at: datetime