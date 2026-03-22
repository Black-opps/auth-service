"""
User schemas.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    LOCKED = "locked"
    DISABLED = "disabled"


class UserBase(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str
    tenant_id: Optional[UUID] = None
    invite_token: Optional[str] = None


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    preferences: Optional[Dict[str, Any]] = None


class UserResponse(UserBase):
    id: UUID
    tenant_id: Optional[UUID]
    status: UserStatus
    email_verified: bool
    mfa_enabled: bool
    last_login_at: Optional[datetime]
    created_at: datetime
    full_name: str
    preferences: Dict[str, Any]

    class Config:
        orm_mode = True


class UserSessionResponse(BaseModel):
    id: UUID
    session_id: str
    user_agent: Optional[str]
    ip_address: Optional[str]
    country: Optional[str]
    city: Optional[str]
    created_at: datetime
    last_activity_at: datetime
    is_current: bool = False

    class Config:
        orm_mode = True
