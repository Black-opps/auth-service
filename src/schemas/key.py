"""
API Key schemas.
"""
from pydantic import BaseModel
from typing import Optional, List
from uuid import UUID
from datetime import datetime


class APIKeyCreate(BaseModel):
    """API key creation request."""
    name: str
    permissions: List[str] = []
    ip_restrictions: List[str] = []
    expires_in_days: Optional[int] = 365


class APIKeyResponse(BaseModel):
    """API key response."""
    id: UUID
    name: str
    key_preview: str
    permissions: List[str]
    ip_restrictions: List[str]
    is_active: bool
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    usage_count: int
    created_at: datetime
    
    class Config:
        orm_mode = True


class APIKeyWithSecret(APIKeyResponse):
    """API key response with secret (only shown once)."""
    key: str


class APIKeyUpdate(BaseModel):
    """API key update request."""
    name: Optional[str] = None
    permissions: Optional[List[str]] = None
    ip_restrictions: Optional[List[str]] = None
    is_active: Optional[bool] = None


class APIKeyRotateResponse(BaseModel):
    """API key rotation response."""
    id: UUID
    name: str
    new_key: str
    key_preview: str
    message: str = "Old key has been revoked. Save the new key now."