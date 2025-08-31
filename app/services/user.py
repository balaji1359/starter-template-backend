import logging
from datetime import datetime
from typing import Optional, List

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, and_

from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate, UserInDB, UserOut
from app.utils.exceptions import not_found_exception, validation_exception

logger = logging.getLogger(__name__)

class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user(self, user_id: int) -> Optional[UserInDB]:
        """
        Get a user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User if found
            
        Raises:
            HTTPException: If user not found
        """
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise not_found_exception("User")
        
        return user

    async def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """
        Get a user by email.
        
        Args:
            email: User email
            
        Returns:
            User if found, None otherwise
        """
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_users(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        is_active: Optional[bool] = None
    ) -> List[UserOut]:
        """
        Get a list of users with filtering options.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            is_active: Filter by active status if provided
            
        Returns:
            List of users
        """
        query = select(User)
        
        if is_active is not None:
            query = query.where(User.is_active == is_active)
            
        query = query.offset(skip).limit(limit)
        result = await self.db.execute(query)
        
        return result.scalars().all()

    async def create_user(self, user_create: UserCreate) -> UserInDB:
        """
        Create a new user.
        
        Args:
            user_create: User creation data
            
        Returns:
            Created user
            
        Raises:
            HTTPException: If email already registered
        """
        # Check if user already exists
        existing_user = await self.get_user_by_email(user_create.email)
        if existing_user:
            raise validation_exception("Email already registered")

        # Validate data
        if not user_create.email or not user_create.password:
            raise validation_exception("Email and password are required")
            
        hashed_password = get_password_hash(user_create.password)
        
        db_user = User(
            email=user_create.email.lower(),  # Store emails in lowercase
            hashed_password=hashed_password,
            full_name=user_create.full_name,
            is_active=True,
            is_verified=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            failed_login_attempts=0,
            last_login=None
        )
        
        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        
        logger.info(f"Created new user: {db_user.email}")
        return db_user

    async def update_user(
        self, 
        user_id: int, 
        user_update: UserUpdate
    ) -> Optional[UserInDB]:
        """
        Update a user.
        
        Args:
            user_id: User ID
            user_update: User update data
            
        Returns:
            Updated user
            
        Raises:
            HTTPException: If user not found
        """
        # Get the user first to ensure it exists
        user = await self.get_user(user_id)
        
        # Prepare update data
        update_data = user_update.dict(exclude_unset=True)
        
        # Handle password update specially
        if "password" in update_data:
            hashed_password = get_password_hash(update_data["password"])
            del update_data["password"]
            update_data["hashed_password"] = hashed_password
        
        # Handle email update - ensure lowercase and check uniqueness
        if "email" in update_data:
            update_data["email"] = update_data["email"].lower()
            existing_user = await self.get_user_by_email(update_data["email"])
            if existing_user and existing_user.id != user_id:
                raise validation_exception("Email already registered")
        
        # Update the user if there's data to update
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            
            # Apply updates to the user object
            for field, value in update_data.items():
                setattr(user, field, value)
            
            await self.db.commit()
            await self.db.refresh(user)
            
            logger.info(f"Updated user {user_id}: {', '.join(update_data.keys())}")
        
        return user

    async def deactivate_user(self, user_id: int) -> bool:
        """
        Deactivate a user.
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
            
        Raises:
            HTTPException: If user not found
        """
        user = await self.get_user(user_id)
        
        user.is_active = False
        user.updated_at = datetime.utcnow()
        
        await self.db.commit()
        logger.info(f"Deactivated user: {user_id}")
        
        return True

    async def verify_user_email(self, user_id: int) -> bool:
        """
        Mark a user's email as verified.
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
            
        Raises:
            HTTPException: If user not found
        """
        user = await self.get_user(user_id)
        
        user.is_verified = True
        user.updated_at = datetime.utcnow()
        
        await self.db.commit()
        logger.info(f"Verified email for user: {user_id}")
        
        return True
        
    async def delete_user(self, user_id: int, requesting_user_id: int) -> bool:
        """
        Delete a user account and all associated data.
        
        Args:
            user_id: ID of the user to delete
            requesting_user_id: ID of the user making the request
            
        Returns:
            True if successful
            
        Raises:
            HTTPException: If user not found or unauthorized
        """
        # Verify the user exists
        user = await self.get_user(user_id)
        
        # Ensure users can only delete their own account
        if user_id != requesting_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own account"
            )
        
        try:
            # Use raw SQL to delete the user - let the database handle cascade
            from sqlalchemy import text
            
            await self.db.execute(
                text("DELETE FROM beekeeper.users WHERE id = :user_id"),
                {"user_id": user_id}
            )
            await self.db.commit()
            
            logger.info(f"User {user_id} ({user.email}) has been permanently deleted")
            return True
            
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Failed to delete user {user_id}: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete user account: {str(e)}"
            )
        
    async def record_login_attempt(self, user_id: int, success: bool) -> None:
        """
        Record a login attempt for a user.
        
        Args:
            user_id: User ID
            success: Whether the login was successful
            
        Raises:
            HTTPException: If user not found
        """
        user = await self.get_user(user_id)
        
        if success:
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
        else:
            # Increment failed attempts
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.is_active = False
                logger.warning(f"User account locked due to failed login attempts: {user_id}")
        
        user.updated_at = datetime.utcnow()
        await self.db.commit()

    async def change_password(
        self, 
        user_id: int, 
        current_password: str, 
        new_password: str
    ) -> bool:
        """
        Change a user's password.
        
        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password
            
        Returns:
            True if successful
            
        Raises:
            HTTPException: If user not found or current password is incorrect
        """
        user = await self.get_user(user_id)
        
        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Set new password
        user.hashed_password = get_password_hash(new_password)
        user.updated_at = datetime.utcnow()
        
        await self.db.commit()
        logger.info(f"Password changed for user: {user_id}")
        
        return True