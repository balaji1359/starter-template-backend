"""
Models initialization with careful handling of circular dependencies.
"""

# Import models - order matters for SQLAlchemy initialization
# Explicitly importing models helps with dependency resolution
from app.models.user import User
from app.models.token import TokenDB, VerificationToken, PasswordResetToken, SocialAccount


# Export all models
__all__ = [
    # User and auth models
    'User',
    'TokenDB', 'VerificationToken', 'PasswordResetToken', 'SocialAccount',
]
