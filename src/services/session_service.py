"""
Session management service.
"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List
import logging
from uuid import UUID

from ..core.config import settings
from ..core.security import generate_session_id, generate_device_fingerprint
from ..models.session import UserSession
from ..core.database import AuthCache

logger = logging.getLogger(__name__)


class SessionService:
    """User session management service."""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def create_session(
        self,
        user_id: UUID,
        ip_address: str = None,
        user_agent: str = None
    ) -> UserSession:
        """
        Create a new user session.
        
        Args:
            user_id: User ID
            ip_address: Client IP
            user_agent: Client user agent
            
        Returns:
            Created session
        """
        # Check existing sessions count
        active_sessions = self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active
        ).count()
        
        # If max sessions reached, remove oldest
        if active_sessions >= settings.MAX_SESSIONS_PER_USER:
            oldest = self.db.query(UserSession).filter(
                UserSession.user_id == user_id,
                UserSession.is_active
            ).order_by(UserSession.last_activity_at.asc()).first()
            
            if oldest:
                oldest.is_active = False
                logger.info(f"Removed oldest session for user {user_id}")
        
        # Create session
        session_id = generate_session_id()
        device_fingerprint = generate_device_fingerprint(
            user_agent or "",
            ip_address or ""
        )
        
        session = UserSession(
            user_id=user_id,
            session_id=session_id,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=datetime.utcnow() + timedelta(seconds=settings.SESSION_TTL_SECONDS)
        )
        
        self.db.add(session)
        self.db.flush()
        
        # Cache session in Redis
        AuthCache.set_user_session(
            session_id,
            {
                "id": str(session.id),
                "user_id": str(user_id),
                "expires_at": session.expires_at.isoformat()
            },
            ttl=settings.SESSION_TTL_SECONDS
        )
        
        logger.info(f"Session created for user {user_id}: {session_id[:8]}...")
        
        return session
    
    async def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get session by ID."""
        # Try cache first
        cached = AuthCache.get_user_session(session_id)
        if cached:
            # Return session from cache
            return self.db.query(UserSession).filter(
                UserSession.id == UUID(cached["id"])
            ).first()
        
        # Get from database
        session = self.db.query(UserSession).filter(
            UserSession.session_id == session_id,
            UserSession.is_active
        ).first()
        
        if session and not session.is_expired():
            # Update cache
            AuthCache.set_user_session(
                session_id,
                {
                    "id": str(session.id),
                    "user_id": str(session.user_id),
                    "expires_at": session.expires_at.isoformat()
                },
                ttl=settings.SESSION_TTL_SECONDS
            )
            return session
        
        return None
    
    async def update_session_activity(self, session_id: str):
        """Update session last activity time."""
        session = await self.get_session(session_id)
        if session:
            session.last_activity_at = datetime.utcnow()
            self.db.commit()
            
            # Update cache
            AuthCache.set_user_session(
                session_id,
                {
                    "id": str(session.id),
                    "user_id": str(session.user_id),
                    "expires_at": session.expires_at.isoformat()
                },
                ttl=settings.SESSION_TTL_SECONDS
            )
    
    async def end_session(self, session_id: str):
        """End a session."""
        session = await self.get_session(session_id)
        if session:
            session.is_active = False
            self.db.commit()
            
            # Remove from cache
            AuthCache.delete_user_session(session_id)
            
            logger.info(f"Session ended: {session_id[:8]}...")
    
    async def get_user_sessions(self, user_id: UUID) -> List[UserSession]:
        """Get all active sessions for a user."""
        return self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active
        ).order_by(UserSession.created_at.desc()).all()
    
    async def end_all_user_sessions(self, user_id: UUID, exclude_session: str = None):
        """End all sessions for a user."""
        query = self.db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active
        )
        
        if exclude_session:
            query = query.filter(UserSession.session_id != exclude_session)
        
        sessions = query.all()
        
        for session in sessions:
            session.is_active = False
            AuthCache.delete_user_session(session.session_id)
        
        self.db.commit()
        
        logger.info(f"Ended {len(sessions)} sessions for user {user_id}")
    
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        expired = self.db.query(UserSession).filter(
            UserSession.expires_at < datetime.utcnow()
        ).all()
        
        for session in expired:
            session.is_active = False
            AuthCache.delete_user_session(session.session_id)
        
        self.db.commit()
        
        logger.info(f"Cleaned up {len(expired)} expired sessions")