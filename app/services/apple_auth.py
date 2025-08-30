import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import httpx
import jwt
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.models.token import SocialAccount
from app.models.user import User
from app.services.auth import AuthService

logger = logging.getLogger(__name__)

class AppleAuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.auth_service = AuthService(db)
        self.client_id = settings.APPLE_CLIENT_ID
        self.team_id = settings.APPLE_TEAM_ID
        self.key_id = settings.APPLE_KEY_ID
        self.private_key_path = settings.APPLE_PRIVATE_KEY_PATH

        # Check if Apple Sign In is configured
        if not all([self.client_id, self.team_id, self.key_id, self.private_key_path]):
            logger.warning("Apple Sign In not fully configured. Some Apple auth methods will not work.")
        else:
            logger.info(f"Initialized AppleAuthService with client_id: {self.client_id}")

    def _load_private_key(self) -> str:
        """Load Apple private key from file"""
        try:
            key_path = Path(self.private_key_path)
            if not key_path.exists():
                raise FileNotFoundError(f"Apple private key file not found at: {self.private_key_path}")

            with open(key_path, 'r') as f:
                private_key = f.read()

            logger.info("Successfully loaded Apple private key")
            return private_key
        except Exception as e:
            logger.error(f"Error loading Apple private key: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to load Apple private key: {str(e)}"
            )

    def _generate_client_secret(self) -> str:
        """Generate Apple client secret JWT"""
        try:
            private_key = self._load_private_key()

            # Create JWT payload
            now = int(time.time())
            payload = {
                'iss': self.team_id,
                'iat': now,
                'exp': now + 86400 * 180,  # 6 months expiration
                'aud': 'https://appleid.apple.com',
                'sub': self.client_id,
            }

            # Create JWT headers
            headers = {
                'alg': 'ES256',
                'kid': self.key_id,
            }

            # Generate the client secret
            client_secret = jwt.encode(
                payload,
                private_key,
                algorithm='ES256',
                headers=headers
            )

            logger.info("Successfully generated Apple client secret")
            return client_secret

        except Exception as e:
            logger.error(f"Error generating Apple client secret: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate Apple client secret: {str(e)}"
            )

    async def get_apple_auth_url(self, redirect_uri: str, state: Optional[str] = None) -> str:
        """Generate Apple OAuth URL for client-side redirect"""
        base_url = "https://appleid.apple.com/auth/authorize"
        scope = "email name"

        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "response_mode": "form_post",
        }

        if state:
            params["state"] = state

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        auth_url = f"{base_url}?{query_string}"
        logger.info(f"Generated Apple auth URL: {auth_url}")
        return auth_url

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> Dict:
        """Exchange authorization code for access token"""
        token_url = "https://appleid.apple.com/auth/token"
        client_secret = self._generate_client_secret()

        data = {
            "client_id": self.client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }

        logger.info("Attempting to exchange Apple code for token")
        logger.debug(f"Token exchange request data: {json.dumps({k: v for k, v in data.items() if k != 'client_secret'})}")

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(token_url, data=data)
                logger.info(f"Apple token exchange response status: {response.status_code}")

                if response.status_code != 200:
                    error_detail = response.text
                    logger.error(f"Apple token exchange failed. Status: {response.status_code}, Response: {error_detail}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Failed to exchange code for token: {error_detail}"
                    )

                token_data = response.json()
                logger.info("Successfully exchanged Apple code for token")
                return token_data

            except httpx.RequestError as e:
                logger.error(f"Request error during Apple token exchange: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error during token exchange: {str(e)}"
                )

    async def _get_apple_public_keys(self) -> Dict:
        """Fetch Apple's public keys for JWT verification"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("https://appleid.apple.com/auth/keys")
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch Apple public keys: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to verify Apple token"
            )

    def _decode_apple_identity_token(self, identity_token: str) -> Dict:
        """Decode and verify Apple identity token"""
        try:
            # TODO: Implement proper signature verification with Apple's public keys
            # For now, decode without verification (UNSAFE for production)
            decoded_token = jwt.decode(
                identity_token, 
                options={"verify_signature": False}
            )
            
            # Validate required claims
            if decoded_token.get("iss") != "https://appleid.apple.com":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token issuer"
                )
            
            if decoded_token.get("aud") != self.client_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token audience"
                )
            
            # Check token expiration
            import time
            if decoded_token.get("exp", 0) < time.time():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token has expired"
                )
            
            logger.info(f"Successfully decoded Apple identity token for subject: {decoded_token.get('sub')}")
            return decoded_token
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error decoding Apple identity token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Apple identity token"
            )

    async def process_apple_signin(self, identity_token: str, user_data: Optional[Dict] = None) -> Tuple[User, Dict[str, str]]:
        """Process Apple Sign In with identity token and optional user data"""
        logger.info(f"Processing Apple Sign In with user_data: {user_data}")
        
        # Decode the identity token to get user info
        token_payload = self._decode_apple_identity_token(identity_token)
        logger.info(f"Token payload: {token_payload}")

        apple_user_id = token_payload.get("sub") if token_payload else None
        email = token_payload.get("email") if token_payload else None
        
        logger.info(f"Extracted apple_user_id: {apple_user_id}, email: {email}")

        if not apple_user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Apple identity token: no user ID found"
            )

        # For Apple Sign In, email might not always be present in subsequent logins
        # Use the provided user_data if email is not in token
        if not email and user_data and isinstance(user_data, dict):
            email = user_data.get("email")

        # Check if user exists with Apple ID
        result = await self.db.execute(
            select(User).join(SocialAccount).where(
                SocialAccount.provider == "apple",
                SocialAccount.provider_user_id == apple_user_id
            )
        )
        user = result.scalar_one_or_none()

        if user:
            # Update user info if provided
            if user_data and isinstance(user_data, dict):
                name_data = user_data.get("name", {}) if isinstance(user_data.get("name"), dict) else {}
                if name_data.get("firstName") or name_data.get("lastName"):
                    full_name_parts = []
                    if name_data.get("firstName"):
                        full_name_parts.append(name_data["firstName"])
                    if name_data.get("lastName"):
                        full_name_parts.append(name_data["lastName"])
                    user.full_name = " ".join(full_name_parts)

                user.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                await self.db.commit()
        else:
            # Check if user exists with same email (if email is available)
            if email:
                result = await self.db.execute(
                    select(User).where(User.email == email)
                )
                user = result.scalar_one_or_none()

            if not user:
                # Create new user
                if not email:
                    # If no email is provided, we can't create a user account
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email is required for account creation"
                    )

                # Extract name from user_data if provided
                full_name = None
                if user_data and isinstance(user_data, dict) and isinstance(user_data.get("name"), dict):
                    name_data = user_data["name"]
                    name_parts = []
                    if name_data.get("firstName"):
                        name_parts.append(name_data["firstName"])
                    if name_data.get("lastName"):
                        name_parts.append(name_data["lastName"])
                    full_name = " ".join(name_parts) if name_parts else None

                user = User(
                    email=email,
                    full_name=full_name,
                    is_active=True,
                    is_verified=True,  # Apple accounts are pre-verified
                    password_hash="",  # No password for social auth
                    created_at=datetime.now(timezone.utc).replace(tzinfo=None),
                    updated_at=datetime.now(timezone.utc).replace(tzinfo=None)
                )
                self.db.add(user)
                await self.db.commit()
                await self.db.refresh(user)

            # Check if social account link already exists
            result = await self.db.execute(
                select(SocialAccount).where(
                    SocialAccount.user_id == user.id,
                    SocialAccount.provider == "apple",
                    SocialAccount.provider_user_id == apple_user_id
                )
            )
            existing_social_account = result.scalar_one_or_none()

            if not existing_social_account:
                # Create social account link
                social_account = SocialAccount(
                    provider="apple",
                    provider_user_id=apple_user_id,
                    user_id=user.id
                )
                self.db.add(social_account)
                await self.db.commit()

        # Generate auth tokens
        tokens = await self.auth_service.create_tokens(user.id)

        return user, tokens
