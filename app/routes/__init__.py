from fastapi import APIRouter, Depends
from app.dependencies.auth import get_current_active_user

from . import auth
from . import users


api_router = APIRouter()

# Include routers with their prefixes
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])








