"""Security utilities and authentication functions.

This module provides centralized security functionality including:
- Password hashing and verification
- JWT token creation and validation
- Security utility functions
- Rate limiting helpers
"""

import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union, List

from jose import jwt, JWTError
from passlib.context import CryptContext
from passlib.exc import InvalidHashError

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ValidationError

# Configure password hashing with environment-appropriate settings
bcrypt_rounds = 4 if settings.ENVIRONMENT == "development" else 12

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=bcrypt_rounds,
    # Additional security settings
    bcrypt__ident="2b",  # Use 2b variant for better security
)


class TokenManager:
    """JWT token management utilities."""
    
    @staticmethod
    def create_access_token(
        subject: Union[str, int],
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a JWT access token.
        
        Args:
            subject: Token subject (usually user ID)
            expires_delta: Custom expiration time
            additional_claims: Extra claims to include in token
            
        Returns:
            str: Encoded JWT token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        # Base token payload
        payload = {
            "exp": expire,
            "sub": str(subject),
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),  # Unique token ID
            "typ": "access",  # Token type
        }
        
        # Add additional claims if provided
        if additional_claims:
            payload.update(additional_claims)
        
        return jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
    
    @staticmethod
    def create_refresh_token(
        subject: Union[str, int],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT refresh token.
        
        Args:
            subject: Token subject (usually user ID)
            expires_delta: Custom expiration time
            
        Returns:
            str: Encoded JWT refresh token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            )
        
        # Refresh token payload with additional entropy
        payload = {
            "exp": expire,
            "sub": str(subject),
            "iat": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),
            "typ": "refresh",
            "nonce": secrets.token_hex(16),  # Additional entropy
        }
        
        return jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
    
    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """Decode and validate a JWT token.
        
        Args:
            token: JWT token to decode
            
        Returns:
            Dict containing token payload
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            return payload
            
        except JWTError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    @staticmethod
    def verify_token_type(payload: Dict[str, Any], expected_type: str) -> None:
        """Verify token type matches expected type.
        
        Args:
            payload: Token payload
            expected_type: Expected token type
            
        Raises:
            AuthenticationError: If token type doesn't match
        """
        token_type = payload.get("typ")
        if token_type != expected_type:
            raise AuthenticationError(f"Invalid token type. Expected {expected_type}, got {token_type}")
    
    @staticmethod
    def is_token_expired(payload: Dict[str, Any]) -> bool:
        """Check if token is expired.
        
        Args:
            payload: Token payload
            
        Returns:
            bool: True if token is expired
        """
        exp = payload.get("exp")
        if not exp:
            return True
        
        return datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc)


class PasswordManager:
    """Password hashing and verification utilities."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
            
        Raises:
            ValidationError: If password is invalid
        """
        if not password:
            raise ValidationError("Password cannot be empty")
        
        if len(password) < 8:  # Default minimum length
            raise ValidationError(
                f"Password must be at least 8 characters"
            )
        
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password to verify against
            
        Returns:
            bool: True if password matches
        """
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except (InvalidHashError, ValueError):
            return False
    
    @staticmethod
    def generate_password(length: int = 12) -> str:
        """Generate a secure random password.
        
        Args:
            length: Password length
            
        Returns:
            str: Generated password
        """
        # Use a mix of letters, numbers, and symbols
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def validate_password_strength(password: str) -> List[str]:
        """Validate password strength and return issues.
        
        Args:
            password: Password to validate
            
        Returns:
            List of validation issues (empty if password is strong)
        """
        issues = []
        
        if len(password) < 8:  # Default minimum length
            issues.append(f"Password must be at least 8 characters")
        
        if not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one number")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Password must contain at least one special character")
        
        # Check for common weak passwords
        weak_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon"
        ]
        
        if password.lower() in weak_passwords:
            issues.append("Password is too common")
        
        return issues


class SecurityUtils:
    """General security utility functions."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            str: Hex-encoded secure token
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate a UUID4 string.
        
        Returns:
            str: UUID4 string
        """
        return str(uuid.uuid4())
    
    @staticmethod
    def hash_string(data: str, salt: Optional[str] = None) -> str:
        """Hash a string using SHA-256.
        
        Args:
            data: String to hash
            salt: Optional salt
            
        Returns:
            str: Hex-encoded hash
        """
        if salt:
            data = f"{data}{salt}"
        
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """Compare two strings in constant time to prevent timing attacks.
        
        Args:
            val1: First string
            val2: Second string
            
        Returns:
            bool: True if strings are equal
        """
        return secrets.compare_digest(val1, val2)
    
    @staticmethod
    def get_client_ip(headers: Dict[str, str]) -> str:
        """Extract client IP from request headers.
        
        Args:
            headers: Request headers
            
        Returns:
            str: Client IP address
        """
        # Check common proxy headers
        forwarded_for = headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to remote address
        return headers.get("remote-addr", "unknown")


# Convenience instances and functions for backward compatibility
token_manager = TokenManager()
password_manager = PasswordManager()
security_utils = SecurityUtils()

# Legacy function aliases
create_access_token = token_manager.create_access_token
create_refresh_token = token_manager.create_refresh_token
decode_token = token_manager.decode_token
verify_password = password_manager.verify_password
get_password_hash = password_manager.hash_password


# Export commonly used items
__all__ = [
    "TokenManager",
    "PasswordManager", 
    "SecurityUtils",
    "token_manager",
    "password_manager",
    "security_utils",
    # Legacy exports
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "verify_password",
    "get_password_hash",
]