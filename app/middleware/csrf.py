import secrets
import time
from typing import Callable, Dict, Optional

from fastapi import Request, Response, HTTPException, status, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.security import APIKeyCookie
from pydantic import BaseModel, Field

from app.core.config import settings


class CSRFConfig(BaseModel):
    """Configuration for CSRF protection."""
    secret_key: str = Field(..., min_length=32)
    cookie_name: str = "csrf_token"
    header_name: str = "X-CSRF-Token"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = "lax"
    cookie_max_age: int = 3600  # 1 hour in seconds
    safe_methods: tuple = ("GET", "HEAD", "OPTIONS")
    excluded_paths: tuple = ()
    token_bytes_length: int = 32  # 256 bits


# Global CSRF configuration
csrf_config = CSRFConfig(
    secret_key=settings.SECRET_KEY,
    cookie_secure=settings.csrf_cookie_secure,
    cookie_httponly=settings.CSRF_COOKIE_HTTP_ONLY,
    cookie_samesite=settings.CSRF_COOKIE_SAMESITE,
    cookie_max_age=settings.CSRF_COOKIE_MAX_AGE,
    excluded_paths=tuple(settings.CSRF_EXCLUDED_PATHS)
)


# Cookie security scheme for retrieving the CSRF token from cookies
csrf_cookie_scheme = APIKeyCookie(name=csrf_config.cookie_name, auto_error=False)


def get_csrf_token(csrf_token: Optional[str] = Depends(csrf_cookie_scheme)) -> Optional[str]:
    """
    Dependency to get the CSRF token from cookie.
    
    Args:
        csrf_token: The CSRF token from cookie
        
    Returns:
        The CSRF token if present
    """
    return csrf_token


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware for CSRF protection.
    
    This middleware:
    1. Generates a CSRF token and sets it in a cookie for all responses
    2. Validates the CSRF token for non-safe methods (POST, PUT, DELETE, etc.)
    3. Checks that the token in the header matches the token in the cookie
    """
    
    def __init__(self, app, config: CSRFConfig = csrf_config):
        super().__init__(app)
        self.config = config
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip CSRF check if disabled in settings
        if not settings.CSRF_ENABLED:
            return await call_next(request)
        
        # Skip CSRF check for safe methods and excluded paths
        if request.method in self.config.safe_methods or request.url.path in self.config.excluded_paths:
            response = await call_next(request)
            # Set a CSRF token in the response if the path is not excluded
            if request.url.path not in self.config.excluded_paths:
                response = self._set_csrf_cookie(response)
            return response
        
        # For unsafe methods, verify the CSRF token
        cookie_token = request.cookies.get(self.config.cookie_name)
        if not cookie_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing"
            )
        
        # Check the header token
        header_token = request.headers.get(self.config.header_name)
        if not header_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"CSRF token not found in {self.config.header_name} header"
            )
        
        # Verify tokens match
        if not secrets.compare_digest(cookie_token, header_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token invalid"
            )
        
        # If everything is valid, process the request
        response = await call_next(request)
        
        # Refresh the CSRF token
        response = self._set_csrf_cookie(response)
        
        return response
    
    def _set_csrf_cookie(self, response: Response) -> Response:
        """
        Generate and set a new CSRF token in a cookie.
        
        Args:
            response: The response to modify
            
        Returns:
            The modified response with the CSRF cookie
        """
        # Generate a new random token
        token = secrets.token_hex(self.config.token_bytes_length)
        
        # Set the cookie
        response.set_cookie(
            key=self.config.cookie_name,
            value=token,
            max_age=self.config.cookie_max_age,
            httponly=self.config.cookie_httponly,
            secure=self.config.cookie_secure,
            samesite=self.config.cookie_samesite
        )
        
        return response


# Utility functions for frontend/client usage

def get_csrf_token_frontend(request: Request) -> Dict[str, str]:
    """
    Get the CSRF token that should be sent in subsequent requests.
    
    Args:
        request: The current request
        
    Returns:
        A dict with the token header name and value
    """
    token = request.cookies.get(csrf_config.cookie_name)
    return {
        "header_name": csrf_config.header_name,
        "token": token
    }


def generate_csrf_meta_tag(request: Request) -> str:
    """
    Generate HTML meta tag with CSRF token for use in templates.
    
    Args:
        request: The current request
        
    Returns:
        HTML meta tag with CSRF token
    """
    token = request.cookies.get(csrf_config.cookie_name, "")
    return f'<meta name="csrf-token" content="{token}" data-header-name="{csrf_config.header_name}">'