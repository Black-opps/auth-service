"""
Session Service - handles user session operations and cleanup
"""

import logging
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.session import (  # Make sure you have a Session model in src/models/session.py
    Session,
)

logger = logging.getLogger(__name__)


class SessionService:
    """
    Service for managing user sessions and cleanup of expired sessions.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_session(self, session_id: str):
        """
        Retrieve a user session by ID.
        """
        result = await self.db.execute(select(Session).where(Session.id == session_id))
        session_obj = result.scalar_one_or_none()
        return session_obj

    async def create_session(self, session_obj: Session):
        """
        Create a new session.
        """
        self.db.add(session_obj)
        await self.db.commit()
        await self.db.refresh(session_obj)
        return session_obj

    async def delete_session(self, session_id: str):
        """
        Delete a session by ID.
        """
        await self.db.execute(delete(Session).where(Session.id == session_id))
        await self.db.commit()

    async def cleanup_expired_sessions(self):
        """
        Delete sessions that have expired.
        """
        now = datetime.utcnow()
        result = await self.db.execute(delete(Session).where(Session.expires_at <= now))
        deleted_count = result.rowcount
        await self.db.commit()
        logger.info(f"Cleaned up {deleted_count} expired sessions")
        return deleted_count
