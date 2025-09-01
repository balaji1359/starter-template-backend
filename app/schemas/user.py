from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID

# Base User model with shared properties
class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    is_active: Optional[bool] = False
    is_superuser: Optional[bool] = False
    
    # Account status compatibility field
    # If your DB model uses account_status but your Pydantic model expects is_active
    account_status: Optional[str] = "active"

# User creation model (for registration)
class UserCreate(UserBase):
    password: str
    
    class Config:
        from_attributes = True

# User update model
class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    
    class Config:
        from_attributes = True

# Model for user in DB (internal use)
class UserInDB(UserBase):
    id: int
    hashed_password: str
    created_at: datetime
    updated_at: datetime
    is_verified: bool = False
    last_login: Optional[datetime] = None
    permissions: List[str] = []
    
    # Add a conversion for is_active if account_status is present
    @classmethod
    def from_orm(cls, obj):
        # If the obj has account_status but no is_active field,
        # convert account_status to is_active boolean
        if hasattr(obj, 'account_status') and not hasattr(obj, 'is_active'):
            setattr(obj, 'is_active', obj.account_status == 'active')
        
        return super().from_orm(obj)
    
    class Config:
        from_attributes = True

# Model for user output (public API)
class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None
    is_active: Optional[bool] = False
    is_verified: bool
    is_superuser: Optional[bool] = False
    created_at: datetime
    
    class Config:
        from_attributes = True

# User model with public profile data
class UserPublic(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None
    
    class Config:
        from_attributes = True

class UserFollowUser(BaseModel):
    id: int
    user_id: int
    follower_id: int
    created_at: Optional[datetime]
    status: Optional[str]
    
    class Config:
        from_attributes = True