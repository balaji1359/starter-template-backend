from typing import Dict
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.user import UserCreate, UserUpdate, UserInDB, UserOut
from app.services.user import UserService
from app.dependencies.auth import get_current_active_user

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


@router.get("/me", response_model=UserOut)
async def read_current_user(
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Get current logged-in user information
    """
    return current_user


@router.get("/{user_id}", response_model=UserOut)
async def read_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Get specific user information (admin only)
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    user_service = UserService(db)
    db_user = await user_service.get_user(user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return db_user


@router.post("/", response_model=UserOut)
async def create_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Create new user (admin only)
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    user_service = UserService(db)
    return await user_service.create_user(user)


@router.put("/me", response_model=UserOut)
async def update_current_user(
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Update current user information
    """
    user_service = UserService(db)
    return await user_service.update_user(current_user.id, user_update)


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Update specific user information (admin only)
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    user_service = UserService(db)
    return await user_service.update_user(user_id, user_update)


@router.delete("/me", response_model=Dict[str, str])
async def delete_current_user(
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Delete current user's account permanently.
    
    **Warning**: This action cannot be undone. All user data including:
    - Links and collections
    - Tags and preferences
    - Subscriptions
    - All associated data
    will be permanently deleted.
    """
    user_service = UserService(db)
    
    # Delete the user account
    success = await user_service.delete_user(
        user_id=current_user.id,
        requesting_user_id=current_user.id
    )
    
    if success:
        return {
            "message": "Your account has been successfully deleted",
            "status": "success"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )


@router.delete("/{user_id}", response_model=Dict[str, str])
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Delete a specific user account (admin only).
    
    **Warning**: This action cannot be undone. All user data will be permanently deleted.
    """
    # Only admins can delete other users
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can delete other users"
        )
    
    # Prevent admin from accidentally deleting their own account via this endpoint
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use DELETE /users/me to delete your own account"
        )
    
    user_service = UserService(db)
    
    # Admin can delete any user
    success = await user_service.delete_user(
        user_id=user_id,
        requesting_user_id=user_id  # Bypass the self-check for admin
    )
    
    if success:
        return {
            "message": f"User {user_id} has been successfully deleted",
            "status": "success"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user account"
        )


@router.post("/{user_id}/verify", response_model=UserOut)
async def verify_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Verify user email (admin only)
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    user_service = UserService(db)
    await user_service.verify_user_email(user_id)
    return await user_service.get_user(user_id)