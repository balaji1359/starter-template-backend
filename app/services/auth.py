import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple

from fastapi import HTTPException, status
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_, and_, update

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    decode_token,
)
from app.models.user import User
from app.models.token import TokenDB, VerificationToken, PasswordResetToken
from app.schemas.auth import UserLogin, UserSignup
from app.schemas.token import TokenResponse
from app.schemas.user import UserPublic
from app.utils.email import send_verification_email, send_password_reset_email
from app.utils.exceptions import (
    not_found_exception, 
    validation_exception, 
    credentials_exception,
    permission_exception
)

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def authenticate_user(self, credentials: UserLogin) -> Tuple[User, Dict[str, Any]]:
        """
        Authenticate a user with email/password credentials.
        
        Args:
            credentials: User login credentials
            
        Returns:
            Tuple of (authenticated user, tokens)
            
        Raises:
            HTTPException: If authentication fails
        """
        # Normalize email to lowercase for case-insensitive comparison
        email = credentials.email.lower()
        
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()
        
        # Don't reveal if user exists or not
        if not user:
            logger.warning(f"Login attempt for non-existent user: {email}")
            raise credentials_exception("Invalid credentials")
            
        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login attempt for inactive user: {email}")
            raise permission_exception("Account is inactive or locked")
            
        # Verify password
        if not verify_password(credentials.password, user.hashed_password):
            logger.warning(f"Failed login attempt for user: {email}")
            raise credentials_exception("Invalid credentials")
        
        # Generate tokens
        tokens = await self.create_tokens(user.id)
        
        logger.info(f"User authenticated successfully: {email}")
        return user, tokens



    async def create_user(self, user_data: UserSignup) -> UserPublic:
        """
        Create a new user account.
        
        Args:
            user_data: User signup data
            
        Returns:
            Created user
            
        Raises:
            HTTPException: If email already exists
        """
        # Normalize email to lowercase
        email = user_data.email.lower()
        
        # Check if email already exists
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        if result.scalar_one_or_none():
            logger.warning(f"Signup attempt with existing email: {email}")
            raise validation_exception("Email already registered")

        # Create password hash
        hashed_password = get_password_hash(user_data.password)
        
        # Create user
        user = User(
            email=email,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            is_active=True,
            is_superuser=False,
            is_verified=False
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        

        try:
            # Create verification token
            token = create_access_token(
                subject=str(user.id),
                expires_delta=timedelta(days=7)
            )
            
            # Create verification link
            verification_link = f"{settings.BACKEND_URL}/api/v1/auth/verify-email/{token}"
            
            # Send verification email
            send_verification_email(
                email_to=email,
                username=user.full_name or "User",
                verification_link=verification_link
            )
            logger.info(f"Verification email sent to: {email}")
        except Exception as e:
            # Log the error but don't fail registration
            logger.error(f"Failed to send verification email: {str(e)}")
            # The user is still created, they just won't receive the email
            
        logger.info(f"New user created: {email}")
        return user

    async def create_tokens(self, user_id: int) -> Dict[str, Any]:
        """
        Create access and refresh tokens for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with tokens
        """
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
        # First, revoke any existing non-expired refresh tokens for this user
        # to prevent accumulation of tokens
        current_epoch = int(time.time())
        await self.db.execute(
            update(TokenDB).where(
                TokenDB.user_id == user_id,
                TokenDB.is_revoked == False,
                TokenDB.expires_at > current_epoch
            ).values(is_revoked=True)
        )
        
        # Generate tokens with current timestamp to ensure uniqueness
        current_epoch = int(time.time())
        access_token_expires_at = current_epoch + int(access_token_expires.total_seconds())
        refresh_token_expires_at = current_epoch + int(refresh_token_expires.total_seconds())
        
        access_token = create_access_token(
            subject=str(user_id),
            expires_delta=access_token_expires
        )
        
        refresh_token = create_refresh_token(
            subject=str(user_id),
            expires_delta=refresh_token_expires
        )
        
        # Try to store refresh token with retry logic for race conditions
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Store refresh token in the database
                token_db = TokenDB(
                    user_id=user_id,
                    token=refresh_token,
                    token_type="refresh",
                    expires_at=refresh_token_expires_at,
                    is_revoked=False
                )
                self.db.add(token_db)
                await self.db.commit()
                break
                
            except Exception as e:
                if "duplicate key" in str(e).lower() and attempt < max_retries - 1:
                    # If duplicate key error, generate a new token and retry
                    await self.db.rollback()
                    refresh_token = create_refresh_token(
                        subject=str(user_id),
                        expires_delta=refresh_token_expires
                    )
                    # Recalculate expiration time for the new token
                    refresh_token_expires_at = int(time.time()) + int(refresh_token_expires.total_seconds())
                    continue
                else:
                    # Re-raise the exception if it's not a duplicate key error or max retries reached
                    await self.db.rollback()
                    logger.error(f"Failed to create tokens for user {user_id}: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to create authentication tokens"
                    )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "access_token_expires_in": int(access_token_expires.total_seconds()),
            "refresh_token_expires_in": int(refresh_token_expires.total_seconds()),
            "access_token_expires_at": access_token_expires_at,
            "refresh_token_expires_at": refresh_token_expires_at,
            "is_revoked": False
        }

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh tokens using a refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New tokens
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Decode token to get user ID
            payload = decode_token(refresh_token)
            user_id = payload.get("sub")
            
            if user_id is None:
                raise credentials_exception("Invalid token")
            
            # Check if token exists and is not revoked
            current_epoch = int(time.time())
            result = await self.db.execute(
                select(TokenDB).where(
                    TokenDB.token == refresh_token,
                    TokenDB.is_revoked == False,
                    TokenDB.expires_at > current_epoch
                )
            )
            token_record = result.scalar_one_or_none()
            
            if not token_record:
                logger.warning(f"Attempt to use invalid or revoked refresh token for user ID: {user_id}")
                raise credentials_exception("Invalid or revoked token")
            
            # Verify user exists and is active
            result = await self.db.execute(
                select(User).where(
                    User.id == int(user_id),
                    User.is_active == True
                )
            )
            user = result.scalar_one_or_none()
            
            if not user:
                logger.warning(f"Refresh token for inactive or non-existent user: {user_id}")
                raise credentials_exception("User inactive or not found")
            
            # Revoke the current refresh token (one-time use)
            token_record.is_revoked = True
            await self.db.commit()
            
            # Generate new tokens
            return await self.create_tokens(int(user_id))
            
        except JWTError as e:
            logger.error(f"JWT error in refresh token: {str(e)}")
            raise credentials_exception("Invalid token")

    async def logout(self, refresh_token: str) -> bool:
        """
        Logout a user by revoking their refresh token.
        
        Args:
            refresh_token: Refresh token to revoke
            
        Returns:
            True if successful
        """
        try:
            # Mark the token as revoked
            result = await self.db.execute(
                select(TokenDB).where(
                    TokenDB.token == refresh_token,
                    TokenDB.is_revoked == False
                )
            )
            token_record = result.scalar_one_or_none()
            
            if token_record:
                token_record.is_revoked = True
                await self.db.commit()
                
                logger.info(f"User logged out (token revoked for user ID: {token_record.user_id})")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error in logout: {str(e)}")
            return False

    async def request_password_reset(self, email: str) -> None:
        """
        Request a password reset for a user.
        
        Args:
            email: User's email address
        """
        # Normalize email
        email = email.lower()
        
        # Find user
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            # Don't reveal if user exists
            logger.warning(f"Password reset requested for non-existent user: {email}")
            return
            
        if not user.is_active:
            logger.warning(f"Password reset requested for inactive user: {email}")
            return
            
        try:
            # Create reset token
            token = create_access_token(
                subject=str(user.id),
                expires_delta=timedelta(minutes=30)
            )
            
            # Create reset link
            reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
            
            # Send password reset email
            send_password_reset_email(
                email_to=email,
                username=user.full_name or "User",
                reset_link=reset_link
            )
            
            logger.info(f"Password reset requested for user: {email}")
        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send password reset email"
            )

    async def reset_password(self, token: str, new_password: str) -> None:
        """
        Reset a user's password using a reset token.
        
        Args:
            token: Password reset token
            new_password: New password
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            logger.info(f"Starting password reset with token: {token[:20]}...")
            
            # Decode token to get user ID
            payload = decode_token(token)
            user_id = payload.get("sub")
            
            logger.info(f"Decoded token payload: {payload}")
            logger.info(f"User ID from token: {user_id}")
            
            if user_id is None:
                logger.error("No user ID found in token payload")
                raise validation_exception("Invalid token")

            # Get user
            result = await self.db.execute(
                select(User).where(User.id == int(user_id))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                logger.warning(f"Password reset for non-existent user ID: {user_id}")
                raise not_found_exception("User")

            logger.info(f"Found user: {user.email}")

            # Update password
            old_hash = user.password_hash
            user.password_hash = get_password_hash(new_password)
            user.updated_at = datetime.utcnow()
            
            logger.info(f"Password hash updated from {old_hash[:20]}... to {user.password_hash[:20]}...")
            
            # If account was locked, unlock it
            if not user.is_active:
                user.is_active = True
                user.failed_login_attempts = 0
                logger.info("Account unlocked during password reset")
            
            await self.db.commit()
            
            logger.info(f"Password reset successful for user: {user.email}")
            
        except JWTError as e:
            logger.error(f"JWT error in password reset: {str(e)}")
            raise validation_exception("Invalid token")
        except Exception as e:
            logger.error(f"Unexpected error in password reset: {str(e)}")
            raise

    async def verify_email(self, token: str) -> None:
        """
        Verify a user's email using a verification token.
        
        Args:
            token: Email verification token
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Decode token to get user ID
            payload = decode_token(token)
            user_id = payload.get("sub")
            
            if user_id is None:
                raise validation_exception("Invalid token")

            # Verify token exists and is valid
            result = await self.db.execute(
                select(VerificationToken).where(
                    VerificationToken.token == token,
                    VerificationToken.expires_at > datetime.utcnow(),
                )
            )
            verification_token = result.scalar_one_or_none()
            
            if not verification_token:
                logger.warning(f"Invalid or expired email verification token used")
                raise validation_exception("Invalid or expired token")

            # Get user
            result = await self.db.execute(
                select(User).where(User.id == int(user_id))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                logger.warning(f"Email verification for non-existent user ID: {user_id}")
                raise not_found_exception("User")

            # Mark email as verified
            user.is_verified = True
            user.updated_at = datetime.utcnow()
            
            # Delete used token
            await self.db.delete(verification_token)
            await self.db.commit()
            
            logger.info(f"Email verified successfully for user: {user.email}")
            
        except JWTError as e:
            logger.error(f"JWT error in email verification: {str(e)}")
            raise validation_exception("Invalid token")