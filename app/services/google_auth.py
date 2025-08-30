from typing import Dict, Optional, Tuple
import json
from datetime import datetime
import logging

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import httpx

from app.core.config import settings
from app.models.user import User
from app.models.token import SocialAccount
from app.services.auth import AuthService

logger = logging.getLogger(__name__)

class GoogleAuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.auth_service = AuthService(db)
        self.client_id = settings.GOOGLE_CLIENT_ID
        self.client_secret = settings.GOOGLE_CLIENT_SECRET
        self.redirect_uri = settings.GOOGLE_REDIRECT_URI
        
        logger.info(f"Initialized GoogleAuthService with redirect_uri: {self.redirect_uri}")
        
    async def get_google_auth_url(self) -> str:
        """Generate Google OAuth URL for client-side redirect"""
        base_url = "https://accounts.google.com/o/oauth2/v2/auth"
        scope = "email profile"
        
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": scope,
            "access_type": "offline",
            "include_granted_scopes": "true",
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        auth_url = f"{base_url}?{query_string}"
        logger.info(f"Generated Google auth URL: {auth_url}")
        return auth_url

    async def exchange_code_for_token(self, code: str) -> Dict:
        """Exchange authorization code for access token"""
        token_url = "https://oauth2.googleapis.com/token"
        
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri
        }
        
        logger.info(f"Attempting to exchange code for token")
        logger.info(f"Using redirect_uri: {self.redirect_uri}")
        logger.info(f"Using client_id: {self.client_id}")
        logger.debug(f"Token exchange request data: {json.dumps({k: v for k, v in data.items() if k != 'client_secret'})}")
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(token_url, data=data)
                logger.info(f"Token exchange response status: {response.status_code}")
                
                if response.status_code != 200:
                    error_detail = response.text
                    logger.error(f"Token exchange failed. Status: {response.status_code}, Response: {error_detail}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to exchange code for token: {error_detail}"
                    )
                
                token_data = response.json()
                logger.info("Successfully exchanged code for token")
                logger.debug(f"Token response: {json.dumps({k: v for k, v in token_data.items() if k != 'access_token'})}")
                return token_data
                
            except httpx.RequestError as e:
                logger.error(f"Request error during token exchange: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error during token exchange: {str(e)}"
                )

    async def get_google_user_info(self, access_token: str) -> Dict:
        """Get user info from Google using access token"""
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        
        logger.info("Attempting to fetch Google user info")
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    user_info_url,
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                logger.info(f"User info response status: {response.status_code}")
                
                if response.status_code != 200:
                    error_detail = response.text
                    logger.error(f"Failed to get user info. Status: {response.status_code}, Response: {error_detail}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to get user info from Google: {error_detail}"
                    )
                
                user_info = response.json()
                logger.info(f"Successfully fetched user info for email: {user_info.get('email')}")
                return user_info
                
            except httpx.RequestError as e:
                logger.error(f"Request error during user info fetch: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error fetching user info: {str(e)}"
                )

    async def get_or_create_user(self, google_user_info: Dict) -> Tuple[User, Dict[str, str]]:
        """Get existing user or create new one from Google profile"""
        # Check if user exists with Google ID
        result = await self.db.execute(
            select(User).join(SocialAccount).where(
                SocialAccount.provider == "google",
                SocialAccount.provider_user_id == google_user_info["id"]
            )
        )
        user = result.scalar_one_or_none()
        
        if user:
            # Update user info
            user.full_name = google_user_info.get("name")
            user.profile_image_url = google_user_info.get("picture")
            user.updated_at = datetime.utcnow()
            await self.db.commit()
        else:
            # Check if user exists with same email
            result = await self.db.execute(
                select(User).where(User.email == google_user_info["email"])
            )
            user = result.scalar_one_or_none()
            
            if not user:
                # Create new user
                user = User(
                    email=google_user_info["email"],
                    full_name=google_user_info.get("name"),
                    profile_image_url=google_user_info.get("picture"),
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
                    SocialAccount.provider == "google",
                    SocialAccount.provider_user_id == google_user_info["id"]
                )
            )
            existing_social_account = result.scalar_one_or_none()
            
            if not existing_social_account:
                # Create social account link
                social_account = SocialAccount(
                    provider="google",
                    provider_user_id=google_user_info["id"],
                    user_id=user.id
                )
                self.db.add(social_account)
                await self.db.commit()
        
        # Generate auth tokens
        tokens = await self.auth_service.create_tokens(user.id)
        
        return user, tokens 
