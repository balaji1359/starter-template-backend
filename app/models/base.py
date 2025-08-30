"""Base model classes and mixins.

This module provides common functionality for all database models including:
- Base model class with common fields and methods
- Timestamp mixins for created/updated tracking
- Soft delete functionality
- Audit logging capabilities
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, func, event
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import declarative_mixin, Mapped, mapped_column

from app.core.database import Base


@declarative_mixin
class TimestampMixin:
    """Mixin for adding timestamp columns to models."""
    
    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        """Timestamp when record was created."""
        return mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
            doc="Timestamp when record was created"
        )
    
    @declared_attr
    def updated_at(cls) -> Mapped[datetime]:
        """Timestamp when record was last updated."""
        return mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
            doc="Timestamp when record was last updated"
        )


@declarative_mixin
class SoftDeleteMixin:
    """Mixin for soft delete functionality."""
    
    @declared_attr
    def deleted_at(cls) -> Mapped[Optional[datetime]]:
        """Timestamp when record was soft deleted."""
        return mapped_column(
            DateTime(timezone=True),
            nullable=True,
            doc="Timestamp when record was soft deleted (NULL if not deleted)"
        )
    
    @declared_attr
    def is_deleted(cls) -> Mapped[bool]:
        """Boolean flag indicating if record is soft deleted."""
        return mapped_column(
            Boolean,
            default=False,
            nullable=False,
            doc="Boolean flag indicating if record is soft deleted"
        )
    
    def soft_delete(self) -> None:
        """Mark record as soft deleted."""
        self.is_deleted = True
        self.deleted_at = datetime.now(timezone.utc)
    
    def restore(self) -> None:
        """Restore soft deleted record."""
        self.is_deleted = False
        self.deleted_at = None


@declarative_mixin  
class AuditMixin:
    """Mixin for audit logging functionality."""
    
    @declared_attr
    def created_by_id(cls) -> Mapped[Optional[int]]:
        """ID of user who created this record."""
        return mapped_column(
            Integer,
            nullable=True,
            doc="ID of user who created this record"
        )
    
    @declared_attr
    def updated_by_id(cls) -> Mapped[Optional[int]]:
        """ID of user who last updated this record."""
        return mapped_column(
            Integer,
            nullable=True,
            doc="ID of user who last updated this record"
        )


class BaseModel(Base, TimestampMixin):
    """Base model class with common functionality.
    
    Provides:
    - Primary key
    - Timestamp tracking
    - Common utility methods
    - String representation
    """
    
    __abstract__ = True
    
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
        doc="Primary key"
    )
    
    def to_dict(self, exclude_fields: Optional[set] = None) -> Dict[str, Any]:
        """Convert model instance to dictionary.
        
        Args:
            exclude_fields: Set of field names to exclude from output
            
        Returns:
            Dict representation of model instance
        """
        exclude_fields = exclude_fields or set()
        result = {}
        
        for column in self.__table__.columns:
            if column.name not in exclude_fields:
                value = getattr(self, column.name)
                # Convert datetime objects to ISO format strings
                if isinstance(value, datetime):
                    value = value.isoformat()
                result[column.name] = value
        
        return result
    
    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update model instance from dictionary.
        
        Args:
            data: Dictionary of field names to values
        """
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @classmethod
    def get_table_name(cls) -> str:
        """Get the table name for this model.
        
        Returns:
            Table name string
        """
        return cls.__tablename__
    
    def __repr__(self) -> str:
        """String representation of model instance."""
        class_name = self.__class__.__name__
        if hasattr(self, 'name'):
            identifier = getattr(self, 'name')
        elif hasattr(self, 'email'):
            identifier = getattr(self, 'email')
        elif hasattr(self, 'title'):
            identifier = getattr(self, 'title')
        else:
            identifier = f"id={self.id}"
        
        return f"<{class_name}({identifier})>"


class BaseModelWithSoftDelete(BaseModel, SoftDeleteMixin):
    """Base model class with soft delete functionality."""
    
    __abstract__ = True


class BaseModelWithAudit(BaseModel, AuditMixin):
    """Base model class with audit logging."""
    
    __abstract__ = True


class BaseModelFull(BaseModel, SoftDeleteMixin, AuditMixin):
    """Base model class with all mixins (timestamps, soft delete, audit)."""
    
    __abstract__ = True


# Event listeners for automatic timestamp updates
@event.listens_for(BaseModel, 'before_update', propagate=True)
def receive_before_update(mapper, connection, target):
    """Update the updated_at timestamp before any update."""
    if hasattr(target, 'updated_at'):
        target.updated_at = datetime.now(timezone.utc)


# Export commonly used items
__all__ = [
    "BaseModel",
    "BaseModelWithSoftDelete", 
    "BaseModelWithAudit",
    "BaseModelFull",
    "TimestampMixin",
    "SoftDeleteMixin",
    "AuditMixin"
]