"""Application configuration settings.

This module provides centralized configuration management using Pydantic settings
with validation and environment-aware defaults.
"""

import logging
from functools import lru_cache
from typing import List, Optional, Dict, Any
from pathlib import Path

from pydantic import (
    EmailStr,
    HttpUrl,
    field_validator,
    Field,
    computed_field
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Literal

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Main application settings with validation and documentation."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    # ===== BASIC APPLICATION SETTINGS =====
    PROJECT_NAME: str = Field(..., description="Project name")
    VERSION: str = Field(default="1.0.0", description="Application version")
    API_V1_STR: str = Field(default="/api/v1", description="API v1 prefix")
    ENVIRONMENT: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Application environment"
    )
    
    # ===== DATABASE SETTINGS =====
    DATABASE_URL: str = Field(..., description="Database connection URL")
    
    # ===== SECURITY SETTINGS =====
    SECRET_KEY: str = Field(..., description="Secret key for JWT signing")
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=1440, 
        description="Access token expiration in minutes"
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7, 
        description="Refresh token expiration in days"
    )
    MAX_LOGIN_ATTEMPTS: int = Field(
        default=5, 
        description="Maximum login attempts before lockout"
    )
    
    # Apple OAuth settings (optional)
    APPLE_CLIENT_ID: Optional[str] = Field(default=None, description="Apple OAuth client ID")
    APPLE_TEAM_ID: Optional[str] = Field(default=None, description="Apple OAuth team ID")
    APPLE_KEY_ID: Optional[str] = Field(default=None, description="Apple OAuth key ID")
    APPLE_PRIVATE_KEY: Optional[str] = Field(default=None, description="Apple OAuth private key")
    
    # Microsoft OAuth settings (optional)
    MICROSOFT_CLIENT_ID: Optional[str] = Field(default=None, description="Microsoft OAuth client ID")
    MICROSOFT_CLIENT_SECRET: Optional[str] = Field(default=None, description="Microsoft OAuth client secret")
    
    # ===== EMAIL SETTINGS =====
    EMAIL_ENABLED: bool = Field(default=True, description="Enable email functionality")
    RESEND_API_KEY: str = Field(..., description="Resend API key")
    EMAILS_FROM_EMAIL: EmailStr = Field(..., description="From email address")
    EMAILS_FROM_NAME: str = Field(..., description="From name")
    
    # ===== URL SETTINGS =====
    FRONTEND_URL: HttpUrl = Field(..., description="Frontend URL")
    BACKEND_URL: HttpUrl = Field(..., description="Backend URL")
    BACKEND_CORS_ORIGINS: str = Field(..., description="Allowed CORS origins (comma-separated)")
    
    # ===== CSRF SETTINGS =====
    CSRF_ENABLED: bool = Field(default=False, description="Enable CSRF protection")
    CSRF_COOKIE_SECURE: Optional[bool] = Field(default=None, description="CSRF cookie secure flag")
    CSRF_COOKIE_HTTP_ONLY: bool = Field(default=True, description="CSRF cookie HTTP only")
    CSRF_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = Field(
        default="lax", 
        description="CSRF cookie SameSite policy"
    )
    CSRF_COOKIE_MAX_AGE: int = Field(default=3600, description="CSRF cookie max age")
    CSRF_EXCLUDED_PATHS: List[str] = Field(
        default=[
            "/api/v1/auth/login",
            "/api/v1/auth/refresh", 
            "/api/v1/auth/signup",
            "/api/v1/auth/reset-password",
            "/api/docs",
            "/api/redoc",
            "/api/openapi.json"
        ],
        description="Paths excluded from CSRF protection"
    )
    
    # ===== COMPUTED PROPERTIES =====
    @computed_field
    @property
    def debug(self) -> bool:
        """Check if running in debug mode (development environment)."""
        return self.ENVIRONMENT == "development"
    
    @computed_field
    @property
    def cors_origins(self) -> List[str]:
        """Convert comma-separated origins to list."""
        if self.BACKEND_CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.BACKEND_CORS_ORIGINS.split(",") if origin.strip()]
    
    @computed_field
    @property
    def csrf_cookie_secure(self) -> bool:
        """Determine CSRF cookie secure flag based on environment."""
        if self.CSRF_COOKIE_SECURE is not None:
            return self.CSRF_COOKIE_SECURE
        return self.ENVIRONMENT != "development"
    
    # ===== VALIDATION METHODS =====
    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Validate database URL format."""
        if not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError("Database URL must be PostgreSQL")
        return v
    
    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate secret key strength."""
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v
    
    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment value."""
        valid_envs = ["development", "staging", "production"]
        if v not in valid_envs:
            raise ValueError(f"Environment must be one of {valid_envs}")
        return v
    
    def model_post_init(self, __context: Any) -> None:
        """Post-initialization validation and setup."""
        # Validate CSRF settings in production
        if self.ENVIRONMENT == "production" and not self.CSRF_ENABLED:
            logger.warning("CSRF protection is disabled in production environment")
        
        # Log configuration summary
        logger.info(f"Application configured for {self.ENVIRONMENT} environment")
        logger.info(f"Database URL: {self.DATABASE_URL[:20]}...")
        logger.info(f"CORS origins: {self.cors_origins}")


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance.
    
    Returns:
        Settings: Application settings instance
    """
    return Settings()


# Global settings instance
settings = get_settings()


# Export commonly used items
__all__ = [
    "Settings",
    "get_settings", 
    "settings"
]