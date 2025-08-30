"""Database configuration and session management.

This module provides centralized database connection management with support for:
- Async SQLAlchemy sessions
- Connection pooling optimized for Supabase/PgBouncer
- Proper transaction handling
- Health monitoring
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional, Dict, Any

from sqlalchemy import MetaData, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.exceptions import DatabaseError

logger = logging.getLogger(__name__)

# Create declarative base with schema
metadata = MetaData(schema="beekeeper")
Base = declarative_base(metadata=metadata)




class DatabaseManager:
    """Database connection and session management."""
    
    def __init__(self) -> None:
        self.engine: Optional[AsyncEngine] = None
        self.sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None
        self._initialized = False
    
    @property
    def is_initialized(self) -> bool:
        """Check if database manager is initialized."""
        return self._initialized and self.engine is not None
    
    def initialize(self) -> None:
        """Initialize database engine and session factory.
        
        Raises:
            DatabaseError: If initialization fails
        """
        try:
            logger.info("Initializing database connection")
            
            # Convert to asyncpg URL format
            db_url = self._prepare_database_url(settings.DATABASE_URL)
            
            # Create engine with optimized settings
            self.engine = self._create_engine(db_url)
            
            # Create session factory
            self.sessionmaker = async_sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
                autocommit=False,
            )
            
            self._initialized = True
            logger.info("Database connection initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise DatabaseError(f"Database initialization failed: {e}") from e
    
    def _prepare_database_url(self, url: str) -> str:
        """Prepare database URL for asyncpg.
        
        Args:
            url: Original database URL
            
        Returns:
            str: Prepared URL for asyncpg
        """
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgresql+asyncpg://"):
            return url
        else:
            raise ValueError(f"Unsupported database URL format: {url}")
    
    def _create_engine(self, db_url: str) -> AsyncEngine:
        """Create async database engine with appropriate configuration.
        
        Args:
            db_url: Database connection URL
            
        Returns:
            AsyncEngine: Configured async database engine
        """
        # Parse connection arguments for PostgreSQL
        connect_args = {}
        
        # Handle SSL for production databases
        if "supabase.com" in db_url or "amazonaws.com" in db_url:
            connect_args["ssl"] = "require"
            logger.info("SSL enabled for cloud database")
        
        # Configure pool based on environment
        if settings.ENVIRONMENT == "production":
            # Use NullPool for production (connection per request)
            poolclass = NullPool
            pool_kwargs = {}
            logger.info("Using NullPool for production environment")
        else:
            # Use AsyncAdaptedQueuePool for development (async-compatible)
            poolclass = AsyncAdaptedQueuePool
            pool_kwargs = {
                "pool_size": 10,
                "max_overflow": 20,
                "pool_timeout": 30,
                "pool_recycle": 3600,
            }
            logger.info("Using AsyncAdaptedQueuePool for development environment")
        
        return create_async_engine(
            db_url,
            poolclass=poolclass,
            connect_args=connect_args,
            pool_pre_ping=True,
            echo=settings.debug,  # Log SQL queries in debug mode
            future=True,
            **pool_kwargs
        )
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session with proper transaction handling.
        
        Yields:
            AsyncSession: Database session
            
        Raises:
            DatabaseError: If session creation or operation fails
        """
        if not self.is_initialized:
            raise DatabaseError("Database manager not initialized")
        
        async with self.sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Database transaction failed: {e}")
                raise DatabaseError(f"Database operation failed: {e}") from e
            finally:
                await session.close()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check.
        
        Returns:
            Dict containing health check results
        """
        if not self.is_initialized:
            return {"status": "unhealthy", "error": "Database not initialized"}
        
        try:
            async with self.get_session() as session:
                # Simple query to test connection
                result = await session.execute(text("SELECT 1 as health_check"))
                row = result.fetchone()
                
                if row and row[0] == 1:
                    return {
                        "status": "healthy",
                        "database": "connected",
                        "schema": metadata.schema
                    }
                else:
                    return {"status": "unhealthy", "error": "Invalid response"}
                    
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}
    
    async def close(self) -> None:
        """Close database connections and cleanup resources."""
        if self.engine:
            logger.info("Closing database connections")
            try:
                await self.engine.dispose()
                logger.info("Database connections closed successfully")
            except Exception as e:
                logger.error(f"Error closing database connections: {e}")
            finally:
                self.engine = None
                self.sessionmaker = None
                self._initialized = False


# Global database manager instance
db_manager = DatabaseManager()


# Dependency injection functions
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency to get database session.
    
    Yields:
        AsyncSession: Database session
    """
    async with db_manager.get_session() as session:
        yield session


async def get_db_session() -> AsyncSession:
    """Get database session for direct use.
    
    Returns:
        AsyncSession: Database session
        
    Note:
        This method should be used carefully as it doesn't provide
        automatic transaction management. Prefer get_db() for FastAPI routes.
    """
    if not db_manager.is_initialized:
        raise DatabaseError("Database manager not initialized")
    
    return db_manager.sessionmaker()


# Table creation utilities
async def create_all_tables() -> None:
    """Create all database tables defined in SQLAlchemy models.
    
    Raises:
        DatabaseError: If table creation fails
    """
    if not db_manager.is_initialized:
        raise DatabaseError("Database manager not initialized")
    
    try:
        logger.info("Creating database tables")
        async with db_manager.engine.begin() as conn:
            # Create schema if it doesn't exist
            if metadata.schema:
                await conn.execute(
                    text(f"CREATE SCHEMA IF NOT EXISTS {metadata.schema}")
                )
            
            # Create all tables
            await conn.run_sync(metadata.create_all)
            
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise DatabaseError(f"Table creation failed: {e}") from e


async def drop_all_tables() -> None:
    """Drop all database tables (use with caution).
    
    Raises:
        DatabaseError: If table deletion fails
    """
    if not db_manager.is_initialized:
        raise DatabaseError("Database manager not initialized")
    
    if settings.ENVIRONMENT == "production":
        raise DatabaseError("Cannot drop tables in production environment")
    
    try:
        logger.warning("Dropping all database tables")
        async with db_manager.engine.begin() as conn:
            await conn.run_sync(metadata.drop_all)
        logger.warning("All database tables dropped")
        
    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}")
        raise DatabaseError(f"Table deletion failed: {e}") from e


# Export commonly used items
__all__ = [
    "Base",
    "DatabaseManager", 
    "DatabaseError",
    "db_manager",
    "get_db",
    "get_db_session",
    "create_all_tables",
    "drop_all_tables"
]