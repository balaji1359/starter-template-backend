from fastapi import HTTPException, status

def not_found_exception(entity_name: str) -> HTTPException:
    """
    Returns a standardized 404 Not Found exception with appropriate detail message.
    
    Args:
        entity_name: The name of the entity that was not found (e.g. "User", "Token")
        
    Returns:
        HTTPException with 404 status code and standardized message
    """
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"{entity_name} not found"
    )

def validation_exception(message: str) -> HTTPException:
    """
    Returns a standardized 400 Bad Request exception for validation issues.
    
    Args:
        message: The validation error message
        
    Returns:
        HTTPException with 400 status code
    """
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=message
    )

def credentials_exception(message: str = "Could not validate credentials") -> HTTPException:
    """
    Returns a standardized 401 Unauthorized exception for authentication issues.
    
    Args:
        message: The error message
        
    Returns:
        HTTPException with 401 status code and WWW-Authenticate header
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"}
    )

def permission_exception(message: str = "Not enough permissions") -> HTTPException:
    """
    Returns a standardized 403 Forbidden exception for permission issues.
    
    Args:
        message: The error message
        
    Returns:
        HTTPException with 403 status code
    """
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=message
    )

def conflict_exception(entity_name: str, identifier: str) -> HTTPException:
    """
    Returns a standardized 409 Conflict exception for duplicate resource issues.
    
    Args:
        entity_name: The name of the entity type (e.g. "User", "Email")
        identifier: The identifying field that has a conflict (e.g. "email", "username")
        
    Returns:
        HTTPException with 409 status code
    """
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"{entity_name} with this {identifier} already exists"
    )

def throttling_exception(message: str = "Too many requests") -> HTTPException:
    """
    Returns a standardized 429 Too Many Requests exception for rate limiting.
    
    Args:
        message: The error message
        
    Returns:
        HTTPException with 429 status code
    """
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=message
    )