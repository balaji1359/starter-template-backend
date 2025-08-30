"""Advanced logging configuration and utilities.

This module provides comprehensive logging configuration for the application,
including:
- Structured logging with JSON formatting
- Request correlation IDs
- Performance monitoring
- Security audit logging
- Log filtering and formatting
- Integration with monitoring services
"""

import json
import logging
import logging.config
import sys
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, Optional, Callable, Union
from pathlib import Path

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

# Context variables for request tracking
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar('user_id', default=None)


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs."""
    
    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            str: JSON-formatted log message
        """
        log_data = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add request context if available
        request_id = request_id_var.get()
        if request_id:
            log_data["request_id"] = request_id
        
        user_id = user_id_var.get()
        if user_id:
            log_data["user_id"] = user_id
        
        # Add exception information
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields from log record
        if self.include_extra:
            extra_data = {}
            for key, value in record.__dict__.items():
                if key not in {
                    'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                    'filename', 'module', 'lineno', 'funcName', 'created',
                    'msecs', 'relativeCreated', 'thread', 'threadName',
                    'processName', 'process', 'getMessage', 'exc_info',
                    'exc_text', 'stack_info', 'message'
                }:
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        extra_data[key] = value
                    except (TypeError, ValueError):
                        extra_data[key] = str(value)
            
            if extra_data:
                log_data["extra"] = extra_data
        
        return json.dumps(log_data, ensure_ascii=False)


class SecurityAuditFilter(logging.Filter):
    """Filter for security audit logs."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter security-related log records.
        
        Args:
            record: Log record to filter
            
        Returns:
            bool: True if record should be logged
        """
        # Define security-related events
        security_keywords = [
            'authentication', 'authorization', 'login', 'logout', 
            'password', 'token', 'csrf', 'rate_limit', 'security',
            'audit', 'suspicious', 'blocked', 'failed_login'
        ]
        
        message = record.getMessage().lower()
        return any(keyword in message for keyword in security_keywords)


class PerformanceFilter(logging.Filter):
    """Filter for performance-related logs."""
    
    def __init__(self, min_duration_ms: float = 1000.0):
        super().__init__()
        self.min_duration_ms = min_duration_ms
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter performance logs based on duration.
        
        Args:
            record: Log record to filter
            
        Returns:
            bool: True if record should be logged
        """
        if hasattr(record, 'duration_ms'):
            return record.duration_ms >= self.min_duration_ms
        return True


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to add request context to logs."""
    
    async def dispatch(self, request: Request, call_next):
        """Process request and add context to logs.
        
        Args:
            request: FastAPI request
            call_next: Next middleware in chain
            
        Returns:
            Response from next middleware
        """
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request_id_var.set(request_id)
        
        # Add request ID to request state for access in routes
        request.state.request_id = request_id
        
        # Extract user ID from token if available
        user_id = None
        auth_header = request.headers.get("authorization")
        if auth_header:
            try:
                # This would typically extract user ID from JWT token
                # For now, just placeholder
                user_id = "extracted_from_token"
                user_id_var.set(user_id)
            except Exception:
                pass
        
        start_time = time.time()
        
        try:
            response = await call_next(request)
            
            # Log successful request
            duration_ms = (time.time() - start_time) * 1000
            
            logger = logging.getLogger("app.requests")
            logger.info(
                f"Request completed: {request.method} {request.url.path}",
                extra={
                    "request_id": request_id,
                    "user_id": user_id,
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "request_size": request.headers.get("content-length", 0),
                    "response_size": response.headers.get("content-length", 0),
                    "user_agent": request.headers.get("user-agent", ""),
                    "client_ip": request.client.host if request.client else None
                }
            )
            
            return response
            
        except Exception as exc:
            # Log failed request
            duration_ms = (time.time() - start_time) * 1000
            
            logger = logging.getLogger("app.requests")
            logger.error(
                f"Request failed: {request.method} {request.url.path} - {str(exc)}",
                exc_info=True,
                extra={
                    "request_id": request_id,
                    "user_id": user_id,
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": dict(request.query_params),
                    "duration_ms": duration_ms,
                    "error_type": type(exc).__name__,
                    "user_agent": request.headers.get("user-agent", ""),
                    "client_ip": request.client.host if request.client else None
                }
            )
            
            raise
        finally:
            # Clean up context variables
            request_id_var.set(None)
            user_id_var.set(None)


def performance_monitor(
    logger_name: str = "app.performance",
    min_duration_ms: float = 100.0
):
    """Decorator to monitor function performance.
    
    Args:
        logger_name: Name of logger to use
        min_duration_ms: Minimum duration to log
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            logger = logging.getLogger(logger_name)
            
            try:
                result = await func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                if duration_ms >= min_duration_ms:
                    logger.info(
                        f"Function executed: {func.__name__}",
                        extra={
                            "function": func.__name__,
                            "module": func.__module__,
                            "duration_ms": duration_ms,
                            "args_count": len(args),
                            "kwargs_count": len(kwargs)
                        }
                    )
                
                return result
                
            except Exception as exc:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(
                    f"Function failed: {func.__name__} - {str(exc)}",
                    exc_info=True,
                    extra={
                        "function": func.__name__,
                        "module": func.__module__,
                        "duration_ms": duration_ms,
                        "error_type": type(exc).__name__
                    }
                )
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            logger = logging.getLogger(logger_name)
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                if duration_ms >= min_duration_ms:
                    logger.info(
                        f"Function executed: {func.__name__}",
                        extra={
                            "function": func.__name__,
                            "module": func.__module__,
                            "duration_ms": duration_ms,
                            "args_count": len(args),
                            "kwargs_count": len(kwargs)
                        }
                    )
                
                return result
                
            except Exception as exc:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(
                    f"Function failed: {func.__name__} - {str(exc)}",
                    exc_info=True,
                    extra={
                        "function": func.__name__,
                        "module": func.__module__,
                        "duration_ms": duration_ms,
                        "error_type": type(exc).__name__
                    }
                )
                raise
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def get_logging_config() -> Dict[str, Any]:
    """Get logging configuration based on environment.
    
    Returns:
        dict: Logging configuration
    """
    log_level = "DEBUG" if settings.debug else "INFO"
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "detailed": {
                "format": (
                    "%(asctime)s | %(levelname)s | %(name)s | %(funcName)s:%(lineno)d | "
                    "%(message)s"
                ),
                "datefmt": "%Y-%m-%d %H:%M:%S"
            },
            "structured": {
                "()": StructuredFormatter,
                "include_extra": True
            }
        },
        "filters": {
            "security_audit": {
                "()": SecurityAuditFilter
            },
            "performance": {
                "()": PerformanceFilter,
                "min_duration_ms": 1000.0
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level,
                "formatter": "structured" if settings.ENVIRONMENT == "production" else "detailed",
                "stream": sys.stdout
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": log_level,
                "formatter": "structured",
                "filename": log_dir / "app.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf-8"
            },
            "security_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "structured",
                "filename": log_dir / "security.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 10,
                "encoding": "utf-8",
                "filters": ["security_audit"]
            },
            "performance_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "structured",
                "filename": log_dir / "performance.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf-8",
                "filters": ["performance"]
            },
            "error_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": "structured",
                "filename": log_dir / "errors.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 10,
                "encoding": "utf-8"
            }
        },
        "loggers": {
            "app": {
                "level": log_level,
                "handlers": ["console", "file"],
                "propagate": False
            },
            "app.security": {
                "level": "INFO",
                "handlers": ["console", "security_file"],
                "propagate": False
            },
            "app.performance": {
                "level": "INFO",
                "handlers": ["console", "performance_file"],
                "propagate": False
            },
            "app.requests": {
                "level": "INFO",
                "handlers": ["console", "file"],
                "propagate": False
            },
            "fastapi": {
                "level": "INFO",
                "handlers": ["console", "file"],
                "propagate": False
            },
            "uvicorn": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False
            },
            "uvicorn.access": {
                "level": "WARNING",  # Reduce uvicorn access logs
                "handlers": ["console"],
                "propagate": False
            },
            "sqlalchemy.engine": {
                "level": "WARNING",  # Reduce SQL query logs
                "handlers": ["console", "file"],
                "propagate": False
            }
        },
        "root": {
            "level": "WARNING",
            "handlers": ["console", "error_file"]
        }
    }
    
    return config


def configure_logging() -> None:
    """Configure application logging."""
    config = get_logging_config()
    logging.config.dictConfig(config)
    
    # Create application logger
    logger = logging.getLogger("app.logging")
    logger.info("Logging configured successfully")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Log level: {'DEBUG' if settings.debug else 'INFO'}")


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        logging.Logger: Configured logger
    """
    return logging.getLogger(f"app.{name}")


def audit_log(
    event: str,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: str = "INFO"
) -> None:
    """Log security audit event.
    
    Args:
        event: Audit event name
        user_id: User ID associated with event
        details: Additional event details
        severity: Log severity level
    """
    logger = logging.getLogger("app.security")
    
    extra_data = {
        "audit_event": event,
        "user_id": user_id or user_id_var.get(),
        "request_id": request_id_var.get()
    }
    
    if details:
        extra_data["details"] = details
    
    log_func = getattr(logger, severity.lower(), logger.info)
    log_func(f"Security audit: {event}", extra=extra_data)


# Export commonly used items
__all__ = [
    "configure_logging",
    "get_logger",
    "audit_log",
    "performance_monitor",
    "RequestLoggingMiddleware",
    "StructuredFormatter"
]