import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_token
from app.dependencies.auth import get_current_active_user
from app.models.token import SocialAccount
from app.models.user import User
from app.schemas.auth import (
    AppleSignInPayload,
    FirebaseSignInPayload,
    PasswordResetConfirm,
    PasswordResetRequest,
    UserLogin,
    UserSignup,
)
from app.schemas.token import LoginResponse, TokenResponse
from app.schemas.user import UserInDB, UserOut
from app.services.apple_auth import AppleAuthService
from app.services.auth import AuthService
from app.services.firebase_auth import FirebaseAuthService


from app.utils.exceptions import (
    conflict_exception,
    credentials_exception,
    validation_exception,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize templates
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

@router.post("/signup", response_model=LoginResponse)
@router.post("/signup/", response_model=LoginResponse)
async def signup(
    user_data: UserSignup,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new user and return tokens with user information.
    The user will need to verify their email before gaining full access.
    
    Args:
        user_data: User registration data including email and password
        db: Database session
        
    Returns:
        LoginResponse containing access token and user information
        
    Raises:
        HTTPException: 
            - 400: Invalid input data
            - 409: Email already registered
            - 500: Server error during registration
    """
    try:
        auth_service = AuthService(db)
        user = await auth_service.create_user(user_data)
        tokens = await auth_service.create_tokens(user.id)

        return LoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            access_token_expires_in=tokens["access_token_expires_in"],
            refresh_token_expires_in=tokens["refresh_token_expires_in"],
            access_token_expires_at=tokens["access_token_expires_at"],
            refresh_token_expires_at=tokens["refresh_token_expires_at"],
            is_revoked=tokens["is_revoked"],
            user=UserOut.model_validate(user),
            is_verified=user.is_verified,
            message="Please check your email to verify your account"
        )

    except HTTPException as e:
        # Re-raise HTTP exceptions with their original status codes
        raise e
    except ValueError as e:
        # Handle validation errors (e.g., password requirements not met)
        raise validation_exception(str(e))
    except Exception as e:
        # Log unexpected errors and return a generic error message
        logger.error(f"Signup error: {str(e)}")
        if "duplicate key" in str(e).lower():
            raise conflict_exception("User", "email")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during registration"
        )

@router.get("/verify-email/{token}", response_class=HTMLResponse)
async def verify_email(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Verify user email address"""
    try:
        # Decode token
        payload = decode_token(token)
        user_id = int(payload.get("sub"))  # Convert string to integer
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid verification token")

        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if already verified
        if user.is_verified:
            return templates.TemplateResponse(
                "email_verified.html",
                {"request": request, "frontend_url": settings.FRONTEND_URL}
            )

        # Update user verification status
        user.is_verified = True
        await db.commit()

        return templates.TemplateResponse(
            "email_verified.html",
            {"request": request, "frontend_url": settings.FRONTEND_URL}
        )

    except (JWTError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid verification token")

@router.post("/signin", response_model=LoginResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate a user and return tokens with user information.
    
    Args:
        form_data: OAuth2 form containing username (email) and password
        db: Database session
        
    Returns:
        LoginResponse containing access token and user information
        
    Raises:
        HTTPException: 
            - 401: Invalid credentials
            - 403: Account inactive or locked
            - 400: Invalid request format
    """
    print(form_data)
    try:
        auth_service = AuthService(db)
        credentials = UserLogin(email=form_data.username, password=form_data.password)

        # The authenticate_user method now returns (user, tokens)
        user, tokens = await auth_service.authenticate_user(credentials)

        logger.debug(f"Login endpoint received tokens: {tokens}")

        # Return both token and user information, regardless of verification status
        login_response = LoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            access_token_expires_in=tokens["access_token_expires_in"],
            refresh_token_expires_in=tokens["refresh_token_expires_in"],
            access_token_expires_at=tokens["access_token_expires_at"],
            refresh_token_expires_at=tokens["refresh_token_expires_at"],
            is_revoked=tokens["is_revoked"],
            user=UserOut.model_validate(user),
            is_verified=user.is_verified,
            message="Please verify your email to access all features" if not user.is_verified else None
        )

        logger.debug(f"LoginResponse created: {login_response.model_dump()}")
        return login_response

    except HTTPException as e:
        # Re-raise HTTP exceptions with their original status codes
        raise e
    except ValueError as e:
        # Handle validation errors
        raise validation_exception(str(e))
    except Exception as e:
        # Log unexpected errors and return a generic error message
        logger.error(f"Login error: {str(e)}")
        raise credentials_exception("An error occurred during authentication")





@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_token: str = None,
    db: AsyncSession = Depends(get_db),
    token_from_query: str = Query(None, alias="refresh_token")
):
    """
    Refresh access token using a refresh token.
    Accepts token either from request body or query parameter.
    """
    auth_service = AuthService(db)
    # Use token from body if provided, otherwise use from query
    token = refresh_token or token_from_query
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required"
        )
    tokens = await auth_service.refresh_token(token)
    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type="bearer",
        access_token_expires_in=tokens["access_token_expires_in"],
        refresh_token_expires_in=tokens["refresh_token_expires_in"],
        access_token_expires_at=tokens["access_token_expires_at"],
        refresh_token_expires_at=tokens["refresh_token_expires_at"],
        is_revoked=tokens["is_revoked"]
    )

@router.post("/signout", status_code=status.HTTP_200_OK)
async def logout(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Logout a user by revoking their refresh token.
    
    Args:
        refresh_token: The refresh token to revoke
        
    Returns:
        Success message if logout was successful
    """
    auth_service = AuthService(db)
    success = await auth_service.logout(refresh_token)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already revoked token"
        )

    return {"message": "Successfully logged out"}

@router.post("/request-password-reset", status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset(
    request: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    auth_service = AuthService(db)
    await auth_service.request_password_reset(request.email)
    return {"message": "Password reset link sent to email if account exists"}

@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
    request: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    auth_service = AuthService(db)
    await auth_service.reset_password(request.token, request.new_password)
    return {"message": "Password reset successfully"}

# Social Auth Routes
@router.get("/providers", response_model=Dict[str, Any])
async def list_providers() -> Dict[str, Any]:
    """List available social auth providers."""
    return {
        "providers": [

            {
                "name": "apple",
                "enabled": bool(settings.APPLE_CLIENT_ID),
                "url": "/api/v1/auth/apple/login"
            }
        ]
    }





# Apple Auth Routes
@router.get("/apple/login")
async def apple_login(
    redirect_uri: str,
    state: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, str]:
    """Get Apple OAuth URL for client-side redirect."""
    if not settings.APPLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Apple Sign In is not configured"
        )
    
    apple_auth = AppleAuthService(db)
    auth_url = await apple_auth.get_apple_auth_url(redirect_uri, state)
    return {"url": auth_url}

@router.post("/apple/callback", response_model=LoginResponse)
async def apple_callback(
    apple_data: AppleSignInPayload,
    db: AsyncSession = Depends(get_db)
) -> LoginResponse:
    """Handle Apple Sign In callback with identity token."""
    logger.info("Received Apple Sign In callback")

    try:
        apple_auth = AppleAuthService(db)

        # Process Apple Sign In with identity token and user data
        user, auth_tokens = await apple_auth.process_apple_signin(
            identity_token=apple_data.id_token,
            user_data=apple_data.user
        )

        logger.info(f"Successfully processed Apple Sign In for user: {user.email}")

        return LoginResponse(
            access_token=auth_tokens["access_token"],
            refresh_token=auth_tokens["refresh_token"],
            token_type="bearer",
            access_token_expires_in=auth_tokens["access_token_expires_in"],
            refresh_token_expires_in=auth_tokens["refresh_token_expires_in"],
            access_token_expires_at=auth_tokens.get("access_token_expires_at"),
            refresh_token_expires_at=auth_tokens.get("refresh_token_expires_at"),
            is_revoked=auth_tokens["is_revoked"],
            user=UserOut.model_validate(user),
            is_verified=user.is_verified,
            message="Successfully logged in with Apple"
        )

    except HTTPException as he:
        logger.error(f"HTTP error in Apple Sign In: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Unexpected error in Apple Sign In: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during Apple Sign In"
        )

@router.post("/firebase/verify", response_model=LoginResponse)
async def firebase_verify(
    firebase_data: FirebaseSignInPayload,
    db: AsyncSession = Depends(get_db)
) -> LoginResponse:
    """Handle Firebase Sign In with ID token."""
    logger.info("Received Firebase Sign In verification")

    try:
        firebase_auth = FirebaseAuthService(db)

        # Verify Firebase ID token
        firebase_user_info = firebase_auth.verify_firebase_token(firebase_data.firebase_token)
        if not firebase_user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Firebase ID token"
            )

        # Get or create user from Firebase profile
        user, auth_tokens = await firebase_auth.get_or_create_user(firebase_user_info)

        logger.info(f"Successfully processed Firebase Sign In for user: {user.email}")

        return LoginResponse(
            access_token=auth_tokens["access_token"],
            refresh_token=auth_tokens["refresh_token"],
            token_type="bearer",
            access_token_expires_in=auth_tokens["access_token_expires_in"],
            refresh_token_expires_in=auth_tokens["refresh_token_expires_in"],
            access_token_expires_at=auth_tokens.get("access_token_expires_at"),
            refresh_token_expires_at=auth_tokens.get("refresh_token_expires_at"),
            is_revoked=auth_tokens["is_revoked"],
            user=UserOut.model_validate(user),
            is_verified=user.is_verified,
            message="Successfully logged in with Firebase"
        )

    except HTTPException as he:
        logger.error(f"HTTP error in Firebase Sign In: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Unexpected error in Firebase Sign In: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during Firebase Sign In"
        )

@router.get("/accounts", response_model=Dict[str, Any])
async def list_social_accounts(
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
) -> Dict[str, Any]:
    """List connected social accounts for the current user."""
    result = await db.execute(
        select(SocialAccount).where(SocialAccount.user_id == current_user.id)
    )
    accounts = result.scalars().all()

    return {
        "accounts": [
            {
                "provider": account.provider,
                "connected_at": account.created_at
            }
            for account in accounts
        ]
    }

@router.delete("/accounts/{provider}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect_social_account(
    provider: str,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
) -> None:
    """Disconnect a social account from the current user."""
    result = await db.execute(
        select(SocialAccount).where(
            SocialAccount.user_id == current_user.id,
            SocialAccount.provider == provider
        )
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No connected {provider} account found"
        )

    await db.delete(account)
    await db.commit()


