from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserSignup(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        if v is None:
            return v
        if not v.strip():
            raise ValueError("Full name cannot be empty")
        return v.strip()


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class OAuthProvider(BaseModel):
    provider: Literal["google", "microsoft", "apple"]
    code: str
    redirect_uri: str
    id_token: Optional[str] = None  # Required for Apple Sign In


class OAuthResponse(BaseModel):
    access_token: str
    token_type: str
    user_info: dict


class OAuthState(BaseModel):
    provider: Literal["google", "microsoft", "apple"]
    redirect_uri: str


class AppleSignInPayload(BaseModel):
    code: Optional[str] = None
    id_token: str
    user: Optional[dict] = None
    state: Optional[str] = None


class GoogleChromeTokenRequest(BaseModel):
    """Schema for Google Chrome extension token authentication"""
    token: str
    client_id: Optional[str] = None