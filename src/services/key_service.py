"""
API Key management service.
"""
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List
import logging
from uuid import UUID

from ..core.config import settings
from ..core.security import generate_api_key, verify_api_key, mask_sensitive_data
from ..core.exceptions import APIKeyError, PermissionDeniedError
from ..models.api_key import APIKey
from ..models.user import User

logger = logging.getLogger(__name__)


class KeyService:
    """API Key management service."""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def create_key(
        self,
        user_id: UUID,
        tenant_id: UUID,
        name: str,
        permissions: List[str] = None,
        ip_restrictions: List[str] = None,
        expires_in_days: Optional[int] = 365
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID
            name: Key name
            permissions: List of permissions
            ip_restrictions: List of allowed IPs
            expires_in_days: Days until expiry (None for no expiry)
            
        Returns:
            Tuple of (APIKey object, raw_key)
        """
        # Generate key
        raw_key, key_hash = generate_api_key()
        
        # Calculate expiry
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Create key record
        api_key = APIKey(
            user_id=user_id,
            tenant_id=tenant_id,
            name=name,
            key_hash=key_hash,
            key_preview=raw_key[-8:],  # Last 8 chars for preview
            permissions=permissions or [],
            ip_restrictions=ip_restrictions or [],
            expires_at=expires_at
        )
        
        self.db.add(api_key)
        self.db.commit()
        self.db.refresh(api_key)
        
        logger.info(f"API key created: {api_key.id} - {mask_sensitive_data(raw_key)}")
        
        return api_key, raw_key
    
    async def verify_key(self, raw_key: str, ip_address: str = None) -> Optional[APIKey]:
        """
        Verify an API key.
        
        Args:
            raw_key: Raw API key
            ip_address: Client IP for IP restriction check
            
        Returns:
            APIKey if valid, None otherwise
        """
        # Hash the key for lookup
        import hashlib
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Find key
        api_key = self.db.query(APIKey).filter(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True
        ).first()
        
        if not api_key:
            logger.warning(f"API key not found or inactive: {mask_sensitive_data(raw_key)}")
            return None
        
        # Check expiry
        if api_key.is_expired:
            logger.warning(f"API key expired: {api_key.id}")
            return None
        
        # Check IP restrictions
        if ip_address and api_key.ip_restrictions:
            if ip_address not in api_key.ip_restrictions:
                logger.warning(f"API key IP restriction failed: {ip_address} not in {api_key.ip_restrictions}")
                return None
        
        # Update usage
        api_key.record_usage()
        self.db.commit()
        
        return api_key
    
    async def list_keys(self, tenant_id: UUID) -> List[APIKey]:
        """List all API keys for a tenant."""
        return self.db.query(APIKey).filter(
            APIKey.tenant_id == tenant_id
        ).order_by(APIKey.created_at.desc()).all()
    
    async def get_key(self, key_id: UUID, tenant_id: UUID) -> Optional[APIKey]:
        """Get API key by ID."""
        return self.db.query(APIKey).filter(
            APIKey.id == key_id,
            APIKey.tenant_id == tenant_id
        ).first()
    
    async def update_key(
        self,
        key_id: UUID,
        tenant_id: UUID,
        name: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        ip_restrictions: Optional[List[str]] = None,
        is_active: Optional[bool] = None
    ) -> Optional[APIKey]:
        """Update API key."""
        api_key = await self.get_key(key_id, tenant_id)
        
        if not api_key:
            return None
        
        if name is not None:
            api_key.name = name
        if permissions is not None:
            api_key.permissions = permissions
        if ip_restrictions is not None:
            api_key.ip_restrictions = ip_restrictions
        if is_active is not None:
            api_key.is_active = is_active
        
        api_key.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(api_key)
        
        logger.info(f"API key updated: {api_key.id}")
        
        return api_key
    
    async def revoke_key(self, key_id: UUID, tenant_id: UUID) -> bool:
        """Revoke an API key."""
        api_key = await self.get_key(key_id, tenant_id)
        
        if not api_key:
            return False
        
        api_key.is_active = False
        api_key.updated_at = datetime.utcnow()
        self.db.commit()
        
        logger.info(f"API key revoked: {api_key.id}")
        
        return True
    
    async def rotate_key(
        self,
        key_id: UUID,
        tenant_id: UUID,
        expires_in_days: Optional[int] = 365
    ) -> tuple[APIKey, str]:
        """
        Rotate an API key (create new, revoke old).
        
        Args:
            key_id: Old key ID
            tenant_id: Tenant ID
            expires_in_days: Expiry for new key
            
        Returns:
            Tuple of (new_key, raw_key)
        """
        old_key = await self.get_key(key_id, tenant_id)
        
        if not old_key:
            raise APIKeyError("API key not found")
        
        # Create new key with same permissions
        new_key, raw_key = await self.create_key(
            user_id=old_key.user_id,
            tenant_id=tenant_id,
            name=f"{old_key.name} (rotated)",
            permissions=old_key.permissions,
            ip_restrictions=old_key.ip_restrictions,
            expires_in_days=expires_in_days
        )
        
        # Revoke old key
        old_key.is_active = False
        old_key.metadata["rotated_to"] = str(new_key.id)
        self.db.commit()
        
        logger.info(f"API key rotated: {old_key.id} -> {new_key.id}")
        
        return new_key, raw_key
    
    def check_permission(self, api_key: APIKey, required_permission: str) -> bool:
        """
        Check if API key has required permission.
        
        Args:
            api_key: API Key object
            required_permission: Permission to check
            
        Returns:
            True if permission granted
        """
        if "*" in api_key.permissions:
            return True
        
        return required_permission in api_key.permissions