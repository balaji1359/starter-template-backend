from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, func

from app.core.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "beekeeper"}

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=True)
    is_active = Column(Boolean, nullable=True)
    is_superuser = Column(Boolean, nullable=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # No relationships for now - simplified model

    def __repr__(self):
        return f"<User {self.email}>"
