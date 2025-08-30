# Import all the models, so that Alembic can detect them
from app.core.database import Base
from app.models.user import User
from app.models.token import TokenDB, VerificationToken, PasswordResetToken, SocialAccount