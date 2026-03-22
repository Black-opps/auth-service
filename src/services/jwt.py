"""
JWT token service.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from jose import JWTError, jwt

from ..core.config import settings

logger = logging.getLogger(__name__)


class JWTService:
    """JWT token creation and verification."""

    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.issuer = settings.JWT_ISSUER
        self.audience = settings.JWT_AUDIENCE

    def create_access_token(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
        role: str = "viewer",
        permissions: list = None,
        expires_delta: Optional[timedelta] = None,
    ) -> Tuple[str, datetime]:
        """
        Create a new access token.

        Args:
            user_id: User ID
            tenant_id: Tenant ID (if applicable)
            role: User role
            permissions: User permissions
            expires_delta: Token expiry

        Returns:
            Tuple of (token, expiry_datetime)
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
            )

        jti = str(uuid.uuid4())

        to_encode = {
            "sub": str(user_id),
            "jti": jti,
            "type": "access",
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": self.issuer,
            "aud": self.audience,
            "role": role,
            "permissions": permissions or [],
        }

        if tenant_id:
            to_encode["tenant_id"] = str(tenant_id)

        token = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

        return token, expire

    def create_refresh_token(
        self, user_id: str, expires_delta: Optional[timedelta] = None
    ) -> Tuple[str, datetime, str]:
        """
        Create a new refresh token.

        Args:
            user_id: User ID
            expires_delta: Token expiry

        Returns:
            Tuple of (token, expiry_datetime, jti)
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
            )

        jti = str(uuid.uuid4())

        to_encode = {
            "sub": str(user_id),
            "jti": jti,
            "type": "refresh",
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": self.issuer,
            "aud": self.audience,
        }

        token = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

        return token, expire, jti

    def verify_token(
        self, token: str, token_type: str = "access"
    ) -> Optional[Dict[str, Any]]:
        """
        Verify a JWT token.

        Args:
            token: JWT token
            token_type: Expected token type (access or refresh)

        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
            )

            # Check token type
            if payload.get("type") != token_type:
                logger.warning(
                    f"Token type mismatch: expected {token_type}, got {payload.get('type')}"
                )
                return None

            return payload

        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            return None

    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode token without verification (for debugging).

        Args:
            token: JWT token

        Returns:
            Decoded payload
        """
        try:
            return jwt.get_unverified_claims(token)
        except JWTError as e:
            logger.error(f"Token decode failed: {e}")
            return None

    def get_token_expiry(self, token: str) -> Optional[datetime]:
        """Get token expiry time."""
        payload = self.decode_token(token)
        if payload and "exp" in payload:
            return datetime.fromtimestamp(payload["exp"])
        return None
