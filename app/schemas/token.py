from datetime import datetime
from typing import Optional, Union

from pydantic import BaseModel
from app.schemas.user import UserOut


class TokenBase(BaseModel):
    token: str
    token_type: str


class TokenCreate(TokenBase):
    expires_at: int  # Epoch timestamp
    user_id: int
    jti: Optional[str] = None  # JWT ID for uniqueness


class TokenInDB(TokenBase):
    id: int
    user_id: int
    jti: Optional[str] = None
    expires_at: int  # Epoch timestamp
    is_revoked: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """JWT token payload structure for validation"""
    exp: int  # Expiration timestamp (required)
    sub: str  # Subject/User ID (required)
    jti: Optional[str] = None  # JWT ID (used for token revocation)
    iat: Optional[int] = None  # Issued at timestamp
    typ: Optional[str] = None  # Token type (access/refresh)


class TokenData(BaseModel):
    user_id: int
    jti: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    access_token_expires_in: Optional[int] = None
    refresh_token_expires_in: Optional[int] = None
    access_token_expires_at: Optional[int] = None  # Epoch timestamp
    refresh_token_expires_at: Optional[int] = None  # Epoch timestamp
    is_revoked: Optional[bool] = False


class LoginResponse(TokenResponse):
    user: Optional[UserOut] = None
    is_verified: Optional[bool] = None  # User's email verification status
    message: Optional[str] = None  # For verification messages and other notifications