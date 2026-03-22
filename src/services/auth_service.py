"""
Authentication service.
"""
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime
from typing import Tuple, Dict, Any
import logging
from uuid import UUID

from ..core.config import settings
from ..core.exceptions import (
    AuthenticationError, UserNotFoundError, UserLockedError,
    MFARequiredError, InvalidTokenError
)
from ..models.user import User, UserStatus
from ..models.token import RefreshToken
from ..models.session import UserSession
from ..services.jwt_service import JWTService
from ..services.mfa_service import MFAService
from ..services.session_service import SessionService
from ..utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class AuthService:
    """Authentication service."""
    
    def __init__(self, db: Session):
        self.db = db
        self.jwt_service = JWTService()
        self.mfa_service = MFAService(db)
        self.session_service = SessionService(db)
        self.rate_limiter = RateLimiter()
    
    async def authenticate(
        self,
        email: str,
        password: str,
        ip_address: str = None,
        user_agent: str = None
    ) -> Tuple[User, Dict[str, Any]]:
        """
        Authenticate user with email and password.
        
        Args:
            email: User email
            password: User password
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Tuple of (user, tokens)
            
        Raises:
            AuthenticationError: If authentication fails
            UserLockedError: If account is locked
            MFARequiredError: If MFA is required
        """
        # Check rate limiting
        await self.rate_limiter.check(f"login:{ip_address}")
        
        # Find user
        user = self.db.query(User).filter(
            or_(
                User.email == email,
                User.username == email
            )
        ).first()
        
        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            raise AuthenticationError("Invalid email or password")
        
        # Check if account is locked
        if user.is_locked:
            logger.warning(f"Login attempt on locked account: {user.id}")
            raise UserLockedError(
                f"Account locked until {user.locked_until}. Too many failed attempts."
            )
        
        # Verify password
        if not user.verify_password(password):
            # Increment failed attempts
            user.increment_failed_attempts()
            self.db.commit()
            
            logger.warning(f"Failed login attempt for user: {user.id}")
            
            # Check if account just got locked
            if user.is_locked:
                raise UserLockedError(
                    f"Account locked for {settings.LOCKOUT_TIME_MINUTES} minutes due to too many failed attempts"
                )
            
            attempts_left = settings.MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
            raise AuthenticationError(f"Invalid email or password. {attempts_left} attempts remaining.")
        
        # Check if account is active
        if user.status != UserStatus.ACTIVE:
            if user.status == UserStatus.PENDING:
                raise AuthenticationError("Email not verified. Please check your email.")
            elif user.status == UserStatus.DISABLED:
                raise AuthenticationError("Account has been disabled.")
            elif user.status == UserStatus.LOCKED:
                raise UserLockedError("Account is locked.")
        
        # Reset failed attempts on successful login
        user.reset_failed_attempts()
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = ip_address
        user.last_login_user_agent = user_agent
        user.login_count += 1
        
        # Check if MFA is required
        if user.mfa_enabled:
            # Create MFA challenge
            challenge = await self.mfa_service.create_challenge(user.id)
            self.db.commit()
            
            logger.info(f"MFA required for user: {user.id}")
            raise MFARequiredError(
                mfa_challenge_id=str(challenge.id),
                mfa_method="totp"
            )
        
        # Create session and tokens
        session = await self.session_service.create_session(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        tokens = await self.create_tokens(user, session)
        
        self.db.commit()
        
        logger.info(f"User logged in successfully: {user.id}")
        
        return user, tokens
    
    async def verify_mfa(
        self,
        user_id: UUID,
        challenge_id: UUID,
        code: str
    ) -> Tuple[User, Dict[str, Any]]:
        """
        Verify MFA code and complete authentication.
        
        Args:
            user_id: User ID
            challenge_id: MFA challenge ID
            code: MFA code
            
        Returns:
            Tuple of (user, tokens)
        """
        # Verify MFA code
        if not await self.mfa_service.verify_challenge(challenge_id, code):
            raise AuthenticationError("Invalid MFA code")
        
        # Get user
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        
        # Create session and tokens
        session = await self.session_service.create_session(
            user_id=user.id,
            ip_address=None,  # Would come from context
            user_agent=None
        )
        
        tokens = await self.create_tokens(user, session)
        
        self.db.commit()
        
        logger.info(f"MFA verified for user: {user.id}")
        
        return user, tokens
    
    async def create_tokens(self, user: User, session: UserSession = None) -> Dict[str, Any]:
        """
        Create access and refresh tokens for user.
        
        Args:
            user: User object
            session: User session
            
        Returns:
            Dictionary with tokens
        """
        # Create access token
        access_token, access_expires = self.jwt_service.create_access_token(
            user_id=user.id,
            tenant_id=user.tenant_id,
            role=user.role.value,
            permissions=[]  # Load from role/permissions
        )
        
        # Create refresh token
        refresh_token, refresh_expires, jti = self.jwt_service.create_refresh_token(
            user_id=user.id
        )
        
        # Store refresh token in database
        db_refresh = RefreshToken(
            user_id=user.id,
            session_id=session.id if session else None,
            jti=jti,
            token=refresh_token,  # Should encrypt this
            expires_at=refresh_expires,
            user_agent=session.user_agent if session else None,
            ip_address=session.ip_address if session else None
        )
        self.db.add(db_refresh)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Get new access token using refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New tokens
        """
        # Verify refresh token
        payload = self.jwt_service.verify_token(refresh_token, token_type="refresh")
        
        if not payload:
            raise InvalidTokenError("Invalid refresh token")
        
        # Check if token is revoked
        db_refresh = self.db.query(RefreshToken).filter(
            RefreshToken.jti == payload["jti"]
        ).first()
        
        if not db_refresh or db_refresh.is_revoked:
            raise InvalidTokenError("Refresh token has been revoked")
        
        # Get user
        user = self.db.query(User).filter(User.id == UUID(payload["sub"])).first()
        if not user or not user.is_active:
            raise UserNotFoundError("User not found or inactive")
        
        # Get or create session
        if db_refresh.session_id:
            session = self.db.query(UserSession).filter(
                UserSession.id == db_refresh.session_id
            ).first()
        else:
            session = None
        
        # Create new tokens
        tokens = await self.create_tokens(user, session)
        
        # Revoke old refresh token
        db_refresh.is_revoked = True
        db_refresh.revoked_at = datetime.utcnow()
        
        self.db.commit()
        
        return tokens
    
    async def logout(
        self,
        user_id: UUID,
        refresh_token: str = None,
        logout_all: bool = False
    ):
        """
        Logout user by revoking tokens.
        
        Args:
            user_id: User ID
            refresh_token: Specific refresh token to revoke
            logout_all: If True, revoke all user sessions
        """
        if logout_all:
            # Revoke all refresh tokens
            self.db.query(RefreshToken).filter(
                RefreshToken.user_id == user_id,
                not RefreshToken.is_revoked
            ).update({
                "is_revoked": True,
                "revoked_at": datetime.utcnow(),
                "revoked_reason": "logout_all"
            })
            
            # Delete all sessions
            self.db.query(UserSession).filter(
                UserSession.user_id == user_id
            ).delete()
            
            logger.info(f"User logged out from all devices: {user_id}")
            
        elif refresh_token:
            # Revoke specific refresh token
            payload = self.jwt_service.verify_token(refresh_token, token_type="refresh")
            if payload:
                db_refresh = self.db.query(RefreshToken).filter(
                    RefreshToken.jti == payload["jti"]
                ).first()
                
                if db_refresh:
                    db_refresh.is_revoked = True
                    db_refresh.revoked_at = datetime.utcnow()
                    db_refresh.revoked_reason = "logout"
                    
                    # Delete session if exists
                    if db_refresh.session_id:
                        self.db.query(UserSession).filter(
                            UserSession.id == db_refresh.session_id
                        ).delete()
                    
                    logger.info(f"User logged out from device: {user_id}")
        
        self.db.commit()