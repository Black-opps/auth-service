"""
MFA (Multi-Factor Authentication) service.
"""
from sqlalchemy.orm import Session
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import List, Tuple
import logging
import secrets
from uuid import UUID

from ..core.config import settings
from ..core.security import hash_password, verify_password
from ..models.mfa import MFADevice, MFAChallenge
from ..models.user import User

logger = logging.getLogger(__name__)


class MFAService:
    """Multi-Factor Authentication service."""
    
    def __init__(self, db: Session):
        self.db = db
        self.issuer_name = settings.MFA_ISSUER_NAME
    
    async def setup_totp(self, user_id: UUID, device_name: str = "Default") -> Tuple[str, str, List[str]]:
        """
        Setup TOTP for a user.
        
        Args:
            user_id: User ID
            device_name: Name for the device
            
        Returns:
            Tuple of (secret, qr_code_base64, backup_codes)
        """
        # Generate TOTP secret
        secret = pyotp.random_base32()
        
        # Get user for email
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        
        # Create provisioning URI for QR code
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        hashed_backup_codes = [hash_password(code) for code in backup_codes]
        
        # Create MFA device
        device = MFADevice(
            user_id=user_id,
            device_type="totp",
            name=device_name,
            secret=secret,  # Should encrypt this
            is_active=True,
            is_primary=True
        )
        self.db.add(device)
        
        # Store backup codes (hashed)
        user.mfa_backup_codes = hashed_backup_codes
        user.mfa_enabled = True
        user.mfa_secret = secret  # Store primary secret
        
        self.db.commit()
        
        logger.info(f"TOTP setup completed for user: {user_id}")
        
        return secret, qr_code_base64, backup_codes
    
    async def verify_totp(self, user_id: UUID, code: str) -> bool:
        """Verify TOTP code."""
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user or not user.mfa_secret:
            return False
        
        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(code)
    
    async def create_challenge(self, user_id: UUID) -> MFAChallenge:
        """Create an MFA challenge."""
        # Generate random 6-digit code
        code = ''.join(secrets.choice('0123456789') for _ in range(6))
        
        challenge = MFAChallenge(
            user_id=user_id,
            challenge_type="totp",
            code=hash_password(code),  # Store hashed
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        
        self.db.add(challenge)
        self.db.flush()
        
        # In production, send code via SMS/email based on challenge_type
        logger.info(f"MFA challenge created for user: {user_id}")
        
        return challenge
    
    async def verify_challenge(self, challenge_id: UUID, code: str) -> bool:
        """Verify an MFA challenge."""
        challenge = self.db.query(MFAChallenge).filter(
            MFAChallenge.id == challenge_id
        ).first()
        
        if not challenge or not challenge.is_valid:
            return False
        
        challenge.increment_attempts()
        
        # Verify code
        if verify_password(code, challenge.code):
            challenge.is_verified = True
            challenge.verified_at = datetime.utcnow()
            self.db.commit()
            return True
        
        self.db.commit()
        return False
    
    async def verify_backup_code(self, user_id: UUID, code: str) -> bool:
        """Verify a backup code."""
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user or not user.mfa_backup_codes:
            return False
        
        # Check each backup code
        for i, stored_hash in enumerate(user.mfa_backup_codes):
            if verify_password(code, stored_hash):
                # Remove used backup code
                codes = list(user.mfa_backup_codes)
                codes.pop(i)
                user.mfa_backup_codes = codes
                self.db.commit()
                return True
        
        return False
    
    async def disable_mfa(self, user_id: UUID, password: str) -> bool:
        """Disable MFA for a user."""
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user:
            return False
        
        # Verify password
        if not user.verify_password(password):
            return False
        
        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_backup_codes = None
        
        # Deactivate devices
        self.db.query(MFADevice).filter(
            MFADevice.user_id == user_id
        ).update({"is_active": False})
        
        self.db.commit()
        
        logger.info(f"MFA disabled for user: {user_id}")
        
        return True
    
    def _generate_backup_codes(self, count: int = 8) -> List[str]:
        """Generate backup codes."""
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice('0123456789ABCDEF') for _ in range(10))
            codes.append(code)
        return codes