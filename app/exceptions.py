"""Application-wide exception handling and custom exception classes.

This module provides a comprehensive exception hierarchy and error handling
system for the application. It includes:
- Custom exception classes for different error types
- HTTP status code mapping
- Error response formatting
- Integration with FastAPI exception handlers

Exceptions are organized hierarchically to allow for granular error handling
while maintaining consistency across the application.
"""

from typing import Optional, Dict, Any, List
from fastapi import HTTPException, status


class BaseApplicationError(Exception):
    """Base exception class for all application errors.
    
    Provides common functionality for all custom exceptions including:
    - Error message and details
    - HTTP status code mapping
    - Structured error response
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[str] = None,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code: Optional[str] = None
    ):
        self.message = message
        self.details = details
        self.status_code = status_code
        self.error_code = error_code or self.__class__.__name__
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        error_dict = {
            "error": self.error_code,
            "message": self.message
        }
        if self.details:
            error_dict["details"] = self.details
        return error_dict


# Authentication and Authorization Exceptions
class AuthenticationError(BaseApplicationError):
    """Base class for authentication-related errors."""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[str] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="AUTHENTICATION_ERROR"
        )


class InvalidCredentialsError(AuthenticationError):
    """Raised when user provides invalid credentials."""
    
    def __init__(self, message: str = "Invalid email or password"):
        super().__init__(
            message=message,
            error_code="INVALID_CREDENTIALS"
        )


class TokenError(AuthenticationError):
    """Base class for JWT token-related errors."""
    
    def __init__(self, message: str = "Token error", details: Optional[str] = None):
        super().__init__(
            message=message,
            details=details,
            error_code="TOKEN_ERROR"
        )


class InvalidTokenError(TokenError):
    """Raised when JWT token is invalid or malformed."""
    
    def __init__(self, message: str = "Invalid or malformed token"):
        super().__init__(
            message=message,
            error_code="INVALID_TOKEN"
        )


class ExpiredTokenError(TokenError):
    """Raised when JWT token has expired."""
    
    def __init__(self, message: str = "Token has expired"):
        super().__init__(
            message=message,
            error_code="EXPIRED_TOKEN"
        )


class RevokedTokenError(TokenError):
    """Raised when JWT token has been revoked."""
    
    def __init__(self, message: str = "Token has been revoked"):
        super().__init__(
            message=message,
            error_code="REVOKED_TOKEN"
        )


class AuthorizationError(BaseApplicationError):
    """Base class for authorization-related errors."""
    
    def __init__(self, message: str = "Access denied", details: Optional[str] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AUTHORIZATION_ERROR"
        )


class InsufficientPermissionsError(AuthorizationError):
    """Raised when user lacks required permissions."""
    
    def __init__(self, message: str = "Insufficient permissions to access this resource"):
        super().__init__(
            message=message,
            error_code="INSUFFICIENT_PERMISSIONS"
        )


# Database and Resource Exceptions
class DatabaseError(BaseApplicationError):
    """Base class for database-related errors."""
    
    def __init__(self, message: str = "Database error", details: Optional[str] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="DATABASE_ERROR"
        )


class ResourceNotFoundError(BaseApplicationError):
    """Raised when a requested resource is not found."""
    
    def __init__(self, resource: str = "Resource", resource_id: Optional[str] = None):
        message = f"{resource} not found"
        if resource_id:
            message += f" with ID: {resource_id}"
        
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="RESOURCE_NOT_FOUND"
        )


class ResourceAlreadyExistsError(BaseApplicationError):
    """Raised when attempting to create a resource that already exists."""
    
    def __init__(self, resource: str = "Resource", identifier: Optional[str] = None):
        message = f"{resource} already exists"
        if identifier:
            message += f": {identifier}"
        
        super().__init__(
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            error_code="RESOURCE_ALREADY_EXISTS"
        )


# Validation and Input Errors
class ValidationError(BaseApplicationError):
    """Base class for validation errors."""
    
    def __init__(
        self, 
        message: str = "Validation error", 
        field_errors: Optional[Dict[str, List[str]]] = None,
        details: Optional[str] = None
    ):
        self.field_errors = field_errors or {}
        super().__init__(
            message=message,
            details=details,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Override to include field-specific errors."""
        error_dict = super().to_dict()
        if self.field_errors:
            error_dict["field_errors"] = self.field_errors
        return error_dict


class InvalidInputError(ValidationError):
    """Raised when user input fails validation."""
    
    def __init__(self, field: str, message: str):
        super().__init__(
            message=f"Invalid input for {field}: {message}",
            field_errors={field: [message]},
            error_code="INVALID_INPUT"
        )


class MissingFieldError(ValidationError):
    """Raised when required field is missing."""
    
    def __init__(self, field: str):
        super().__init__(
            message=f"Required field missing: {field}",
            field_errors={field: ["This field is required"]},
            error_code="MISSING_FIELD"
        )


# User-specific Exceptions
class UserError(BaseApplicationError):
    """Base class for user-related errors."""
    
    def __init__(self, message: str, details: Optional[str] = None, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(
            message=message,
            details=details,
            status_code=status_code,
            error_code="USER_ERROR"
        )


class UserNotFoundError(ResourceNotFoundError):
    """Raised when user is not found."""
    
    def __init__(self, identifier: Optional[str] = None):
        super().__init__(resource="User", resource_id=identifier)
        self.error_code = "USER_NOT_FOUND"


class UserAlreadyExistsError(ResourceAlreadyExistsError):
    """Raised when user already exists."""
    
    def __init__(self, email: str):
        super().__init__(resource="User", identifier=email)
        self.error_code = "USER_ALREADY_EXISTS"


class UserNotVerifiedError(UserError):
    """Raised when user account is not verified."""
    
    def __init__(self, message: str = "User account is not verified"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="USER_NOT_VERIFIED"
        )


class UserInactiveError(UserError):
    """Raised when user account is inactive."""
    
    def __init__(self, message: str = "User account is inactive"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="USER_INACTIVE"
        )


class WeakPasswordError(ValidationError):
    """Raised when password doesn't meet security requirements."""
    
    def __init__(self, requirements: List[str]):
        message = "Password does not meet security requirements"
        details = "Requirements: " + ", ".join(requirements)
        
        super().__init__(
            message=message,
            details=details,
            field_errors={"password": requirements},
            error_code="WEAK_PASSWORD"
        )


# Rate Limiting and Security Exceptions
class RateLimitError(BaseApplicationError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        self.retry_after = retry_after
        super().__init__(
            message=message,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE_LIMIT_EXCEEDED"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Override to include retry_after information."""
        error_dict = super().to_dict()
        if self.retry_after:
            error_dict["retry_after"] = self.retry_after
        return error_dict


class SecurityError(BaseApplicationError):
    """Base class for security-related errors."""
    
    def __init__(self, message: str = "Security error", details: Optional[str] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="SECURITY_ERROR"
        )


class CSRFError(SecurityError):
    """Raised when CSRF token validation fails."""
    
    def __init__(self, message: str = "CSRF token validation failed"):
        super().__init__(
            message=message,
            error_code="CSRF_ERROR"
        )


# Email and Communication Exceptions
class EmailError(BaseApplicationError):
    """Base class for email-related errors."""
    
    def __init__(self, message: str = "Email error", details: Optional[str] = None):
        super().__init__(
            message=message,
            details=details,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="EMAIL_ERROR"
        )


class EmailDeliveryError(EmailError):
    """Raised when email delivery fails."""
    
    def __init__(self, recipient: str, message: str = "Failed to deliver email"):
        super().__init__(
            message=message,
            details=f"Recipient: {recipient}",
            error_code="EMAIL_DELIVERY_ERROR"
        )


# External Service Exceptions
class ExternalServiceError(BaseApplicationError):
    """Base class for external service integration errors."""
    
    def __init__(self, service: str, message: str = "External service error", details: Optional[str] = None):
        self.service = service
        super().__init__(
            message=f"{service}: {message}",
            details=details,
            status_code=status.HTTP_502_BAD_GATEWAY,
            error_code="EXTERNAL_SERVICE_ERROR"
        )


class OAuth2Error(ExternalServiceError):
    """Raised when OAuth2 authentication fails."""
    
    def __init__(self, provider: str, message: str = "OAuth2 authentication failed", details: Optional[str] = None):
        super().__init__(
            service=provider,
            message=message,
            details=details,
            error_code="OAUTH2_ERROR"
        )


# Utility function to convert exceptions to HTTPException
def to_http_exception(error: BaseApplicationError) -> HTTPException:
    """Convert application exception to FastAPI HTTPException.
    
    Args:
        error: Application exception to convert
        
    Returns:
        HTTPException: FastAPI-compatible exception
    """
    return HTTPException(
        status_code=error.status_code,
        detail=error.to_dict()
    )


# Exception mapping for easy lookup
EXCEPTION_MAP = {
    "authentication_error": AuthenticationError,
    "invalid_credentials": InvalidCredentialsError,
    "token_error": TokenError,
    "invalid_token": InvalidTokenError,
    "expired_token": ExpiredTokenError,
    "revoked_token": RevokedTokenError,
    "authorization_error": AuthorizationError,
    "insufficient_permissions": InsufficientPermissionsError,
    "database_error": DatabaseError,
    "resource_not_found": ResourceNotFoundError,
    "resource_already_exists": ResourceAlreadyExistsError,
    "validation_error": ValidationError,
    "invalid_input": InvalidInputError,
    "missing_field": MissingFieldError,
    "user_error": UserError,
    "user_not_found": UserNotFoundError,
    "user_already_exists": UserAlreadyExistsError,
    "user_not_verified": UserNotVerifiedError,
    "user_inactive": UserInactiveError,
    "weak_password": WeakPasswordError,
    "rate_limit_error": RateLimitError,
    "security_error": SecurityError,
    "csrf_error": CSRFError,
    "email_error": EmailError,
    "email_delivery_error": EmailDeliveryError,
    "external_service_error": ExternalServiceError,
    "oauth2_error": OAuth2Error
}