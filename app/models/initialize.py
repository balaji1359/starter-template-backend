"""
This module ensures all models are properly loaded and initialized
to prevent circular dependency issues.
"""
from sqlalchemy import event
from sqlalchemy.orm import configure_mappers

# Import all models to ensure they're in the registry
from app.models import *

def initialize_models():
    """
    Call this function to ensure all models are properly initialized
    before any database operations are performed.
    """
    # Configure all mappers at once, which will detect and resolve any issues
    # This is useful for catching circular dependencies early
    try:
        configure_mappers()
        return True
    except Exception as e:
        print(f"Error configuring mappers: {e}")
        return False