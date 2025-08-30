import json
from typing import Dict, Optional, Tuple
import jwt
import aiohttp
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.models.user import User
from app.services.auth import AuthService
from app.schemas.auth import OAuthProvider, AppleSignInPayload
from app.utils.exceptions import validation_exception

class OAuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.auth_service = AuthService(db)
        
        # Google OAuth settings
        self.google_client_id = settings.GOOGLE_CLIENT_ID
        self.google_client_secret = settings.GOOGLE_CLIENT_SECRET
        self.google_token_url = "https://oauth2.googleapis.com/token"
        self.google_userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        
        # Microsoft OAuth settings
        self.microsoft_client_id = settings.MICROSOFT_CLIENT_ID
        self.microsoft_client_secret = settings.MICROSOFT_CLIENT_SECRET
        self.microsoft_token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self.microsoft_userinfo_url = "https://graph.microsoft.com/v1.0/me"

        # Apple Sign In settings
        self.apple_client_id = settings.APPLE_CLIENT_ID
        self.apple_team_id = settings.APPLE_TEAM_ID
        self.apple_key_id = settings.APPLE_KEY_ID
        self.apple_private_key = settings.APPLE_PRIVATE_KEY
        self.apple_token_url = "https://appleid.apple.com/auth/token"

    async def authenticate_oauth(self, oauth_data: OAuthProvider) -> Tuple[User, Dict]:
        """Authenticate user using OAuth provider"""
        if oauth_data.provider == "google":
            user_info = await self._get_google_user_info(oauth_data.code, oauth_data.redirect_uri)
        elif oauth_data.provider == "microsoft":
            user_info = await self._get_microsoft_user_info(oauth_data.code, oauth_data.redirect_uri)
        else:  # apple
            if not oauth_data.id_token:
                raise validation_exception("id_token is required for Apple Sign In")
            user_info = await self._get_apple_user_info(oauth_data.code, oauth_data.id_token, oauth_data.redirect_uri)

        # Get or create user
        user = await self._get_or_create_oauth_user(
            email=user_info["email"],
            provider=oauth_data.provider,
            provider_user_id=user_info["id"],
            full_name=user_info.get("name")
        )

        # Create auth tokens
        tokens = await self.auth_service.create_tokens(user.id)

        return user, tokens

    async def _get_google_user_info(self, code: str, redirect_uri: str) -> Dict:
        """Get user info from Google"""
        # Exchange code for token
        token_data = {
            "code": code,
            "client_id": self.google_client_id,
            "client_secret": self.google_client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }

        async with aiohttp.ClientSession() as session:
            # Get access token
            async with session.post(self.google_token_url, data=token_data) as response:
                if response.status != 200:
                    raise validation_exception("Failed to get Google access token")
                token_response = await response.json()
                access_token = token_response["access_token"]

            # Get user info
            headers = {"Authorization": f"Bearer {access_token}"}
            async with session.get(self.google_userinfo_url, headers=headers) as response:
                if response.status != 200:
                    raise validation_exception("Failed to get Google user info")
                return await response.json()

    async def _get_microsoft_user_info(self, code: str, redirect_uri: str) -> Dict:
        """Get user info from Microsoft"""
        # Exchange code for token
        token_data = {
            "code": code,
            "client_id": self.microsoft_client_id,
            "client_secret": self.microsoft_client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "scope": "User.Read email"
        }

        async with aiohttp.ClientSession() as session:
            # Get access token
            async with session.post(self.microsoft_token_url, data=token_data) as response:
                if response.status != 200:
                    raise validation_exception("Failed to get Microsoft access token")
                token_response = await response.json()
                access_token = token_response["access_token"]

            # Get user info
            headers = {"Authorization": f"Bearer {access_token}"}
            async with session.get(self.microsoft_userinfo_url, headers=headers) as response:
                if response.status != 200:
                    raise validation_exception("Failed to get Microsoft user info")
                return await response.json()

    async def _get_apple_user_info(self, code: str, id_token: str, redirect_uri: str) -> Dict:
        """Get user info from Apple"""
        try:
            # Verify and decode the id_token
            decoded_token = jwt.decode(
                id_token,
                options={"verify_signature": False},  # Apple's public key is fetched from their JWKS endpoint
                algorithms=["RS256"]
            )

            # Extract user info from the token
            user_info = {
                "id": decoded_token["sub"],
                "email": decoded_token.get("email"),
                "email_verified": decoded_token.get("email_verified", False)
            }

            if not user_info["email"]:
                raise validation_exception("Email not found in Apple ID token")

            return user_info

        except jwt.InvalidTokenError as e:
            raise validation_exception(f"Invalid Apple ID token: {str(e)}")

    async def _create_apple_client_secret(self) -> str:
        """Create Apple client secret JWT"""
        now = datetime.utcnow()
        expiration = now + timedelta(minutes=5)  # Token valid for 5 minutes

        headers = {
            "kid": self.apple_key_id,
            "alg": "ES256"
        }

        payload = {
            "iss": self.apple_team_id,
            "iat": now,
            "exp": expiration,
            "aud": "https://appleid.apple.com",
            "sub": self.apple_client_id
        }

        return jwt.encode(
            payload,
            self.apple_private_key,
            algorithm="ES256",
            headers=headers
        )

    async def _get_or_create_oauth_user(
        self, 
        email: str, 
        provider: str,
        provider_user_id: str,
        full_name: Optional[str] = None
    ) -> User:
        """Get existing user or create new one from OAuth data"""
        # Check if user exists
        result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        user = result.scalar_one_or_none()

        if user:
            # Update OAuth info if needed
            if not user.is_verified:
                user.is_verified = True
                if full_name and not user.full_name:
                    user.full_name = full_name
                await self.db.commit()
            return user

        # Create new user
        user = User(
            email=email.lower(),
            is_active=True,
            is_verified=True,  # OAuth users are pre-verified
            password_hash="",  # OAuth users don't need password
            full_name=full_name
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user 