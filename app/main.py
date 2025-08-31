"""Main FastAPI application entry point.

This module configures and initializes the FastAPI application with:
- CORS and security middleware
- Database connection management
- Request logging and monitoring
- API route registration
- Application lifecycle management
"""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

from app.core.config import settings
from app.core.database import db_manager, create_all_tables
from app.middleware.csrf import csrf_config
from app.middleware.security import SecurityMiddleware
from app.models.initialize import initialize_models
from app.routes import api_router
from app.error_handlers import register_exception_handlers
from app.utils.logging import configure_logging, RequestLoggingMiddleware
from app.utils.monitoring import health_checker, get_monitoring_summary

# Configure application logging using our advanced logging system
configure_logging()
logger = logging.getLogger(__name__)


def _configure_additional_logging() -> None:
    """Configure additional logging for application components."""
    logger.info("Application logging configured")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"API Version: {settings.VERSION}")
    logger.info(f"CORS Origins: {settings.cors_origins}")


def _configure_middleware(app: FastAPI) -> None:
    """Configure application middleware in the correct order.
    
    Args:
        app: FastAPI application instance
    """
    # Request logging middleware
    @app.middleware("http")
    async def log_request_middleware(request: Request, call_next):
        """Log incoming requests and response times."""
        if request.url.path == "/favicon.ico":
            return await call_next(request)
        
        logger.info(f"Request: {request.method} {request.url.path}")
        logger.debug(f"Headers: {dict(request.headers)}")
        
        if request.query_params:
            logger.debug(f"Query params: {dict(request.query_params)}")
        
        start_time = datetime.utcnow()
        response = await call_next(request)
        process_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        logger.info(
            f"Response: {request.method} {request.url.path} - "
            f"Status: {response.status_code} - Time: {process_time:.2f}ms"
        )
        
        return response

    # Request logging middleware (first to capture all requests)
    app.add_middleware(RequestLoggingMiddleware)
    
    # Security middleware
    app.add_middleware(
        SecurityMiddleware,
        rate_limit_per_minute=60,
        rate_limit_per_hour=600,
        block_duration_minutes=30
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=[
            "Content-Type", "Authorization", "Accept", "Origin",
            "X-Requested-With", "X-CSRF-Token", "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods", "Access-Control-Allow-Headers",
            "Access-Control-Allow-Credentials"
        ],
        expose_headers=["Content-Length"],
        max_age=600
    )
    
    # Session middleware (required for CSRF)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie="session",
        max_age=settings.CSRF_COOKIE_MAX_AGE,
        same_site=settings.CSRF_COOKIE_SAMESITE,
        https_only=settings.csrf_cookie_secure,
    )
    
    logger.info("Application middleware configured")


def _configure_lifecycle_events(app: FastAPI) -> None:
    """Configure application startup and shutdown events.
    
    Args:
        app: FastAPI application instance
    """
    @app.on_event("startup")
    async def startup_event():
        """Initialize application resources on startup."""
        try:
            logger.info("Initializing SQLAlchemy models")
            initialize_models()
            
            logger.info("Initializing database connection")
            db_manager.initialize()
            
            # logger.info("Creating/validating database tables")
            # await create_all_tables()
            
            logger.info("Application startup completed successfully")
        except Exception as e:
            logger.error(f"Application startup failed: {e}")
            raise
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Clean up application resources on shutdown."""
        try:
            logger.info("Closing database connections")
            await db_manager.close()
            logger.info("Application shutdown completed")
        except Exception as e:
            logger.error(f"Error during application shutdown: {e}")


def _add_utility_endpoints(app: FastAPI) -> None:
    """Add utility endpoints to the application.
    
    Args:
        app: FastAPI application instance
    """
    @app.get("/")
    async def root() -> Dict[str, str]:
        """Root endpoint with welcome message."""
        return {"message": "Welcome to Beekeeper API"}
    
    @app.get("/favicon.ico")
    async def favicon() -> Response:
        """Handle favicon requests to prevent 404 errors."""
        return Response(status_code=204)
    
    @app.get("/api/v1/health")
    async def health_check() -> Dict[str, Any]:
        """Health check endpoint to verify API and database status.
        
        Returns:
            Dict containing service health information
        """
        try:
            db_manager.get_session()
            db_status = "healthy"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_status = f"unhealthy: {str(e)}"
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "Beekeeper API",
            "version": settings.VERSION,
            "database": db_status
        }
    
    @app.get("/api/csrf-token")
    async def get_csrf_token(request: Request) -> Dict[str, str]:
        """Get CSRF token configuration for frontend.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Dict containing CSRF configuration
        """
        return {
            "csrf_header_name": csrf_config.header_name,
            "csrf_cookie_name": csrf_config.cookie_name,
        }


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.
    
    Returns:
        FastAPI: Configured application instance
    """
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        swagger_ui_parameters={"defaultModelsExpandDepth": -1},
        redirect_slashes=False
    )
    
    # Configure logging levels for various components
    # _configure_additional_logging()
    
    # Add middleware in correct order
    _configure_middleware(app)
    
    # Add event handlers
    _configure_lifecycle_events(app)
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Add utility endpoints
    _add_utility_endpoints(app)
    
    # Register exception handlers
    register_exception_handlers(app)
    
    logger.info("FastAPI application configured successfully")
    return app


# Create the application instance
app = create_app()