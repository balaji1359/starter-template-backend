from datetime import datetime
from typing import Optional
import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.schemas.token import TokenPayload
from app.schemas.user import UserInDB
from app.utils.exceptions import permission_exception, not_found_exception

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> UserInDB:
    """
    Get the current authenticated user from the JWT token.
    
    Args:
        db: Database session
        token: JWT token from OAuth2 scheme
        
    Returns:
        UserInDB object representing the authenticated user
        
    Raises:
        HTTPException: If the token is invalid or the user is not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check if token is None or empty
    if not token:
        logger.warning("No token provided in request")
        raise credentials_exception
    
    logger.debug(f"Token received: {token[:20]}..." if len(token) > 20 else token)
    
    try:
        # Decode the JWT token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.JWT_ALGORITHM]
        )
        token_data = TokenPayload(**payload)
        
        # Verify token has not expired
        if token_data.exp < datetime.now().timestamp():
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    # Convert user_id to integer before querying
    try:
        user_id_int = int(token_data.sub)
    except (ValueError, TypeError):
        raise credentials_exception
    
    # Get the user from database with properly typed user_id
    user_query = select(User).where(User.id == user_id_int)
    result = await db.execute(user_query)
    user = result.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    
    # Convert user to a UserInDB model
    try:
        # Handle different model structures between DB and Pydantic
        user_dict = {
            "id": user.id,
            "email": user.email,
            "hashed_password": user.hashed_password,  # Fixed: using correct attribute name
            "full_name": getattr(user, "full_name", None),
            "is_active": getattr(user, "is_active", True),
            "is_superuser": getattr(user, "is_superuser", False),  # Fixed: using correct field name
            "account_status": "active",  # Default value since model doesn't have this
            "created_at": user.created_at,
            "updated_at": getattr(user, "updated_at", user.created_at),
            "is_verified": getattr(user, "is_verified", False),
            "last_login": None,  # Default value since model doesn't have this
            "permissions": []  # Default value since model doesn't have this
        }
        return UserInDB(**user_dict)
    except Exception as e:
        print(f"Error creating UserInDB: {str(e)}")
        raise credentials_exception
        

async def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Get the current authenticated user and verify they are active.
    
    Args:
        current_user: User from get_current_user dependency
        
    Returns:
        The active authenticated user
        
    Raises:
        HTTPException: If the user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


async def get_current_user_optional(
    db: AsyncSession = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[UserInDB]:
    """
    Get the current authenticated user if token is provided, otherwise return None.
    This allows for optional authentication.

    Args:
        db: Database session
        token: JWT token from OAuth2 scheme (optional)

    Returns:
        UserInDB object if authenticated, None otherwise
    """
    if not token:
        return None

    try:
        return await get_current_user(db, token)
    except HTTPException:
        return None


async def get_admin_user(
    current_user: UserInDB = Depends(get_current_active_user)
) -> UserInDB:
    """
    Get the current authenticated user and verify they are an admin.
    
    Args:
        current_user: User from get_current_active_user dependency
        
    Returns:
        The active authenticated admin user
        
    Raises:
        HTTPException: If the user is not an admin
    """
    if not current_user.is_superuser:  # Fixed: using is_superuser from UserInDB
        raise permission_exception("Administrator privileges required")
    return current_user


async def get_user_with_permissions(
    *required_permissions: str,
    current_user: UserInDB = Depends(get_current_active_user)
) -> UserInDB:
    """
    Get the current authenticated user and verify they have the required permissions.
    
    Args:
        *required_permissions: Permission strings that the user must have
        current_user: User from get_current_active_user dependency
        
    Returns:
        The active authenticated user with required permissions
        
    Raises:
        HTTPException: If the user does not have the required permissions
    """
    # Admins have all permissions
    if current_user.is_superuser:  # Fixed: using is_superuser from UserInDB
        return current_user
    
    # Check if user has all required permissions
    if not all(perm in current_user.permissions for perm in required_permissions):
        raise permission_exception("User does not have required permissions")
    
    return current_user