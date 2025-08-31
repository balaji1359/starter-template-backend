from typing import Dict, Optional, Tuple
import logging
from datetime import datetime

import firebase_admin
from firebase_admin import auth, credentials
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.models.user import User
from app.models.token import SocialAccount
from app.services.auth import AuthService

logger = logging.getLogger(__name__)

# Initialize Firebase Admin SDK
try:
    # Try to get existing app first
    firebase_admin.get_app()
except ValueError:
    # Initialize new app if none exists
    cred = credentials.Certificate("firebase-service-account.json")
    firebase_admin.initialize_app(cred)

class FirebaseAuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.auth_service = AuthService(db)
        
    def verify_firebase_token(self, token: str) -> Optional[Dict]:
        """Verify Firebase ID token and return decoded user info"""
        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token
        except Exception as e:
            logger.error(f"Firebase token verification failed: {str(e)}")
            return None

    async def get_or_create_user(self, firebase_user_info: Dict) -> Tuple[User, Dict[str, str]]:
        """Get existing user or create new one from Firebase profile"""
        # Check if user exists with Firebase UID
        result = await self.db.execute(
            select(User).join(
                SocialAccount, 
                User.id == SocialAccount.user_id
            ).where(
                SocialAccount.provider == "firebase",
                SocialAccount.provider_user_id == firebase_user_info["uid"]
            )
        )
        user = result.scalar_one_or_none()
        
        if user:
            # Update user info
            user.full_name = firebase_user_info.get("name")
            user.profile_image_url = firebase_user_info.get("picture")
            user.updated_at = datetime.utcnow()
            await self.db.commit()
        else:
            # Check if user exists with same email
            result = await self.db.execute(
                select(User).where(User.email == firebase_user_info["email"])
            )
            user = result.scalar_one_or_none()
            
            if not user:
                # Create new user
                user = User(
                    email=firebase_user_info["email"],
                    full_name=firebase_user_info.get("name"),
                    profile_image_url=firebase_user_info.get("picture"),
                    is_active=True,
                    is_verified=True,
                    password_hash="",  # No password for social auth
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                self.db.add(user)
                await self.db.commit()
                await self.db.refresh(user)
            
            # Check if social account link already exists
            result = await self.db.execute(
                select(SocialAccount).where(
                    SocialAccount.user_id == user.id,
                    SocialAccount.provider == "firebase",
                    SocialAccount.provider_user_id == firebase_user_info["uid"]
                )
            )
            existing_social_account = result.scalar_one_or_none()
            
            if not existing_social_account:
                # Create social account link
                social_account = SocialAccount(
                    provider="firebase",
                    provider_user_id=firebase_user_info["uid"],
                    user_id=user.id
                )
                self.db.add(social_account)
                await self.db.commit()
        
        # Generate auth tokens
        tokens = await self.auth_service.create_tokens(user.id)
        
        return user, tokens
