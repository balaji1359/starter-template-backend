"""FastAPI exception handlers for application-wide error handling.

This module provides centralized exception handling for the FastAPI application.
It includes handlers for:
- Custom application exceptions
- HTTP exceptions
- Validation errors
- Database errors
- Unhandled exceptions

The handlers ensure consistent error response format across the API and
provide appropriate logging for debugging and monitoring.
"""

import logging
import traceback
from typing import Dict, Any, Union

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.exceptions import (
    BaseApplicationError,
    DatabaseError,
    ValidationError,
    ResourceAlreadyExistsError,
    RateLimitError
)

logger = logging.getLogger(__name__)


def create_error_response(
    status_code: int,
    error_code: str,
    message: str,
    details: str = None,
    field_errors: Dict[str, Any] = None,
    extra_data: Dict[str, Any] = None
) -> JSONResponse:
    """Create standardized error response.
    
    Args:
        status_code: HTTP status code
        error_code: Application-specific error code
        message: Human-readable error message
        details: Optional additional details
        field_errors: Optional field-specific validation errors
        extra_data: Optional additional data to include in response
        
    Returns:
        JSONResponse: Formatted error response
    """
    error_data = {
        "error": error_code,
        "message": message,
        "status_code": status_code
    }
    
    if details:
        error_data["details"] = details
    
    if field_errors:
        error_data["field_errors"] = field_errors
    
    if extra_data:
        error_data.update(extra_data)
    
    return JSONResponse(
        status_code=status_code,
        content=error_data
    )


async def application_error_handler(
    request: Request, 
    exc: BaseApplicationError
) -> JSONResponse:
    """Handle custom application exceptions.
    
    Args:
        request: FastAPI request object
        exc: Application exception
        
    Returns:
        JSONResponse: Formatted error response
    """
    logger.error(
        f"Application error: {exc.error_code} - {exc.message} - "
        f"Path: {request.url.path} - Method: {request.method}",
        extra={
            "error_code": exc.error_code,
            "status_code": exc.status_code,
            "path": request.url.path,
            "method": request.method,
            "details": exc.details
        }
    )
    
    # Extract additional data for specific exception types
    extra_data = {}
    
    if isinstance(exc, RateLimitError) and hasattr(exc, 'retry_after'):
        extra_data["retry_after"] = exc.retry_after
    
    if isinstance(exc, ValidationError) and hasattr(exc, 'field_errors'):
        field_errors = exc.field_errors
    else:
        field_errors = None
    
    return create_error_response(
        status_code=exc.status_code,
        error_code=exc.error_code,
        message=exc.message,
        details=exc.details,
        field_errors=field_errors,
        extra_data=extra_data
    )


async def http_exception_handler(
    request: Request, 
    exc: Union[HTTPException, StarletteHTTPException]
) -> JSONResponse:
    """Handle HTTP exceptions.
    
    Args:
        request: FastAPI request object
        exc: HTTP exception
        
    Returns:
        JSONResponse: Formatted error response
    """
    # Log HTTP errors
    if exc.status_code >= 500:
        logger.error(
            f"HTTP error {exc.status_code}: {exc.detail} - "
            f"Path: {request.url.path} - Method: {request.method}"
        )
    elif exc.status_code >= 400:
        logger.warning(
            f"HTTP error {exc.status_code}: {exc.detail} - "
            f"Path: {request.url.path} - Method: {request.method}"
        )
    
    # Handle structured error details
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail
        )
    
    # Standard HTTP error mapping
    error_codes = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED", 
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        422: "UNPROCESSABLE_ENTITY",
        429: "TOO_MANY_REQUESTS",
        500: "INTERNAL_SERVER_ERROR",
        502: "BAD_GATEWAY",
        503: "SERVICE_UNAVAILABLE"
    }
    
    error_code = error_codes.get(exc.status_code, "HTTP_ERROR")
    
    return create_error_response(
        status_code=exc.status_code,
        error_code=error_code,
        message=str(exc.detail) if exc.detail else "HTTP error occurred"
    )


async def validation_error_handler(
    request: Request, 
    exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors from FastAPI.
    
    Args:
        request: FastAPI request object
        exc: Validation error
        
    Returns:
        JSONResponse: Formatted error response
    """
    logger.warning(
        f"Validation error: {exc.errors()} - "
        f"Path: {request.url.path} - Method: {request.method}"
    )
    
    # Format field-specific errors
    field_errors = {}
    for error in exc.errors():
        field_name = ".".join(str(loc) for loc in error["loc"][1:])  # Skip 'body'
        if not field_name:
            field_name = "request"
        
        error_message = error["msg"]
        if error["type"] == "missing":
            error_message = "This field is required"
        
        if field_name not in field_errors:
            field_errors[field_name] = []
        field_errors[field_name].append(error_message)
    
    return create_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        error_code="VALIDATION_ERROR",
        message="Request validation failed",
        field_errors=field_errors
    )


async def pydantic_validation_error_handler(
    request: Request, 
    exc: PydanticValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors.
    
    Args:
        request: FastAPI request object
        exc: Pydantic validation error
        
    Returns:
        JSONResponse: Formatted error response
    """
    logger.warning(
        f"Pydantic validation error: {exc.errors()} - "
        f"Path: {request.url.path} - Method: {request.method}"
    )
    
    # Format field-specific errors
    field_errors = {}
    for error in exc.errors():
        field_name = ".".join(str(loc) for loc in error["loc"])
        error_message = error["msg"]
        
        if field_name not in field_errors:
            field_errors[field_name] = []
        field_errors[field_name].append(error_message)
    
    return create_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        error_code="VALIDATION_ERROR", 
        message="Data validation failed",
        field_errors=field_errors
    )


async def sqlalchemy_error_handler(
    request: Request, 
    exc: SQLAlchemyError
) -> JSONResponse:
    """Handle SQLAlchemy database errors.
    
    Args:
        request: FastAPI request object
        exc: SQLAlchemy error
        
    Returns:
        JSONResponse: Formatted error response
    """
    logger.error(
        f"Database error: {type(exc).__name__}: {str(exc)} - "
        f"Path: {request.url.path} - Method: {request.method}",
        extra={
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "path": request.url.path,
            "method": request.method
        }
    )
    
    # Handle specific SQLAlchemy errors
    if isinstance(exc, IntegrityError):
        # Check for common integrity constraint violations
        error_message = str(exc.orig).lower()
        
        if "duplicate key" in error_message or "unique constraint" in error_message:
            return create_error_response(
                status_code=status.HTTP_409_CONFLICT,
                error_code="RESOURCE_ALREADY_EXISTS",
                message="Resource with this identifier already exists",
                details="A record with these values already exists in the database"
            )
        elif "foreign key" in error_message:
            return create_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="INVALID_REFERENCE",
                message="Invalid reference to related resource",
                details="The referenced resource does not exist"
            )
        elif "not null" in error_message:
            return create_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="MISSING_REQUIRED_FIELD",
                message="Required field is missing or null"
            )
    
    # Generic database error
    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code="DATABASE_ERROR",
        message="A database error occurred"
    )


async def database_error_handler(
    request: Request, 
    exc: DatabaseError
) -> JSONResponse:
    """Handle custom database errors.
    
    Args:
        request: FastAPI request object
        exc: Database error
        
    Returns:
        JSONResponse: Formatted error response
    """
    logger.error(
        f"Database error: {exc.message} - "
        f"Path: {request.url.path} - Method: {request.method}",
        extra={
            "error_code": exc.error_code,
            "path": request.url.path,
            "method": request.method,
            "details": exc.details
        }
    )
    
    return create_error_response(
        status_code=exc.status_code,
        error_code=exc.error_code,
        message=exc.message,
        details=exc.details
    )


async def unhandled_exception_handler(
    request: Request, 
    exc: Exception
) -> JSONResponse:
    """Handle unhandled exceptions.
    
    Args:
        request: FastAPI request object
        exc: Unhandled exception
        
    Returns:
        JSONResponse: Formatted error response
    """
    # Log the full traceback for debugging
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)} - "
        f"Path: {request.url.path} - Method: {request.method}",
        exc_info=True,
        extra={
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "path": request.url.path,
            "method": request.method,
            "traceback": traceback.format_exc()
        }
    )
    
    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code="INTERNAL_SERVER_ERROR",
        message="An unexpected error occurred"
    )


def register_exception_handlers(app) -> None:
    """Register all exception handlers with the FastAPI app.
    
    Args:
        app: FastAPI application instance
    """
    # Custom application exceptions
    app.add_exception_handler(BaseApplicationError, application_error_handler)
    app.add_exception_handler(DatabaseError, database_error_handler)
    
    # HTTP exceptions
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    
    # Validation errors
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(PydanticValidationError, pydantic_validation_error_handler)
    
    # Database errors
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_error_handler)
    
    # Catch-all for unhandled exceptions
    app.add_exception_handler(Exception, unhandled_exception_handler)
    
    logger.info("Exception handlers registered successfully")


# Error response schemas for documentation
ERROR_RESPONSES = {
    400: {
        "description": "Bad Request",
        "content": {
            "application/json": {
                "example": {
                    "error": "BAD_REQUEST",
                    "message": "Invalid request data",
                    "status_code": 400
                }
            }
        }
    },
    401: {
        "description": "Unauthorized",
        "content": {
            "application/json": {
                "example": {
                    "error": "UNAUTHORIZED",
                    "message": "Authentication required",
                    "status_code": 401
                }
            }
        }
    },
    403: {
        "description": "Forbidden",
        "content": {
            "application/json": {
                "example": {
                    "error": "FORBIDDEN",
                    "message": "Access denied",
                    "status_code": 403
                }
            }
        }
    },
    404: {
        "description": "Not Found",
        "content": {
            "application/json": {
                "example": {
                    "error": "NOT_FOUND",
                    "message": "Resource not found",
                    "status_code": 404
                }
            }
        }
    },
    422: {
        "description": "Validation Error",
        "content": {
            "application/json": {
                "example": {
                    "error": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "status_code": 422,
                    "field_errors": {
                        "email": ["Invalid email format"],
                        "password": ["Password is too weak"]
                    }
                }
            }
        }
    },
    429: {
        "description": "Too Many Requests",
        "content": {
            "application/json": {
                "example": {
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded",
                    "status_code": 429,
                    "retry_after": 60
                }
            }
        }
    },
    500: {
        "description": "Internal Server Error",
        "content": {
            "application/json": {
                "example": {
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred",
                    "status_code": 500
                }
            }
        }
    }
}