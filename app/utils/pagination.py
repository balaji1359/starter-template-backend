from typing import Generic, List, Optional, Type, TypeVar
from fastapi import Query
from pydantic import BaseModel, create_model

# Generic type for database objects
T = TypeVar('T')

class PaginationParams:
    """
    Standard pagination parameters used across API endpoints.
    """
    def __init__(
        self, 
        skip: int = Query(0, ge=0, description="Number of items to skip"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum number of items to return")
    ):
        self.skip = skip
        self.limit = limit

class PaginatedResponse(Generic[T]):
    """
    Standard response format for paginated results.
    """
    def __init__(
        self, 
        items: List[T], 
        total: int, 
        skip: int, 
        limit: int
    ):
        self.items = items
        self.total = total
        self.skip = skip
        self.limit = limit
        
    @property
    def has_more(self) -> bool:
        """
        Returns True if there are more items available beyond this page.
        """
        return self.total > (self.skip + len(self.items))

def create_paginated_response_model(item_model: Type[BaseModel]) -> Type[BaseModel]:
    """
    Creates a Pydantic model for a paginated response containing items of the given type.
    
    Args:
        item_model: The Pydantic model class for individual items
        
    Returns:
        A new Pydantic model class for the paginated response
    """
    return create_model(
        f"PaginatedResponse[{item_model.__name__}]",
        items=(List[item_model], ...),
        total=(int, ...),
        skip=(int, ...),
        limit=(int, ...),
        has_more=(bool, ...)
    )