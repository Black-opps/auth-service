"""
Security utilities for auth service.
"""

import hashlib
import hmac
import logging
import secrets
import string
from typing import List, Tuple

import bcrypt

from .config import settings

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored password hash

    Returns:
        True if password matches
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Token length in bytes (will be hex encoded)

    Returns:
        Hex encoded token
    """
    return secrets.token_hex(length)


def generate_api_key() -> Tuple[str, str]:
    """
    Generate a new API key and its hash.

    Returns:
        Tuple of (raw_key, key_hash)
    """
    # Generate random bytes
    random_bytes = secrets.token_bytes(32)

    # Create raw key with prefix
    raw_key = f"{settings.API_KEY_PREFIX}{random_bytes.hex()}"

    # Hash for storage
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    return raw_key, key_hash


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """
    Verify an API key against its stored hash.

    Args:
        provided_key: API key to verify
        stored_hash: Stored hash

    Returns:
        True if key matches
    """
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return hmac.compare_digest(provided_hash, stored_hash)


def generate_password_reset_token() -> str:
    """Generate a password reset token."""
    return secrets.token_urlsafe(48)


def generate_email_verification_token() -> str:
    """Generate an email verification token."""
    return secrets.token_urlsafe(48)


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Validate password against security policy.

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Check length
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(
            f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"
        )

    # Check for uppercase
    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    # Check for lowercase
    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    # Check for numbers
    if settings.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")

    # Check for special characters
    if settings.PASSWORD_REQUIRE_SPECIAL:
        special_chars = set(string.punctuation)
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character")

    return len(errors) == 0, errors


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data (like API keys) for logging.

    Args:
        data: String to mask
        visible_chars: Number of characters to leave visible

    Returns:
        Masked string
    """
    if len(data) <= visible_chars:
        return "***"

    visible = data[:visible_chars]
    masked = "*" * (len(data) - visible_chars)
    return f"{visible}{masked}"


def generate_device_fingerprint(user_agent: str, ip: str) -> str:
    """
    Generate a device fingerprint from request data.

    Args:
        user_agent: User agent string
        ip: IP address

    Returns:
        Device fingerprint hash
    """
    data = f"{user_agent}|{ip}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return secrets.token_urlsafe(32)
