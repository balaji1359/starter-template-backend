from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, BigInteger, func, UniqueConstraint
from sqlalchemy.orm import relationship

from app.core.database import Base

class TokenDB(Base):
    __tablename__ = "tokens"
    __table_args__ = {"schema": "beekeeper"}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    token = Column(String(500), nullable=False, index=True)  # Removed unique constraint, increased length
    jti = Column(String(255), unique=True, nullable=True, index=True)  # Added JWT ID as unique identifier
    token_type = Column(String(50), nullable=False)  # 'access', 'refresh', etc.
    expires_at = Column(BigInteger, nullable=False)  # Store epoch timestamp
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # No relationships for now - simplified model

class VerificationToken(Base):
    __tablename__ = "verification_tokens"
    __table_args__ = {"schema": "beekeeper"}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # No relationships for now - simplified model

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = {"schema": "beekeeper"}

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # No relationships for now - simplified model

class SocialAccount(Base):
    __tablename__ = "social_accounts"
    __table_args__ = (
        UniqueConstraint('user_id', 'provider', 'provider_user_id', name='unique_user_provider_account'),
        {"schema": "beekeeper"}
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    provider = Column(String(50), nullable=False)  # 'google', 'github', etc.
    provider_user_id = Column(String(255), nullable=False)
    access_token = Column(String(500), nullable=True)
    refresh_token = Column(String(500), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # No relationships for now - simplified model