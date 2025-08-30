from fastapi import HTTPException, status
from typing import Any, Dict, Optional

class CustomException(HTTPException):
    """Base exception class for custom application exceptions"""
    def __init__(
        self,
        status_code: int,
        detail: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)

class AuthenticationError(CustomException):
    """Raised when authentication fails"""
    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

class AuthorizationError(CustomException):
    """Raised when user doesn't have permission to perform an action"""
    def __init__(self, detail: str = "Not enough permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )

class NotFoundError(CustomException):
    """Raised when a requested resource is not found"""
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail
        )

class ValidationError(CustomException):
    """Raised when input validation fails"""
    def __init__(self, detail: str = "Validation error"):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )

class ConflictError(CustomException):
    """Raised when there's a conflict with existing data"""
    def __init__(self, detail: str = "Resource conflict"):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail
        )

class RateLimitError(CustomException):
    """Raised when rate limit is exceeded"""
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail
        )

class DatabaseError(CustomException):
    """Raised when database operations fail"""
    def __init__(self, detail: str = "Database error"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class ExternalServiceError(CustomException):
    """Raised when external service calls fail"""
    def __init__(self, detail: str = "External service error"):
        super().__init__(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=detail
        )
