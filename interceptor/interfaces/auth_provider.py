"""
Authentication provider interface.

Defines the contract for authentication implementations.
Standalone version uses no-auth, Enterprise uses SSO/JWT.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class AuthProvider(ABC):
    """Abstract authentication provider interface"""
    
    @abstractmethod
    def authenticate(self, headers: Dict[str, str], cookies: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Authenticate a request based on headers and cookies.
        
        Args:
            headers: Request headers (may contain X-ZT-Session, Authorization, etc.)
            cookies: Parsed cookies (may contain zt_sess, etc.)
            
        Returns:
            Session dict with user info if authenticated, None otherwise
            Example: {"user_id": "user@example.com", "authenticated": True, "session_id": "abc123"}
        """
        pass
    
    @abstractmethod
    def is_required(self) -> bool:
        """
        Whether authentication is required for this edition.
        
        Returns:
            True if requests must be authenticated (enterprise)
            False if authentication is optional/disabled (standalone)
        """
        pass
    
    @abstractmethod
    def get_login_url(self) -> Optional[str]:
        """
        Get the SSO/login URL for authentication.
        
        Returns:
            URL string for enterprise SSO, None for standalone
        """
        pass
    
    @abstractmethod
    def create_session(self, user_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new session for a user.
        
        Args:
            user_id: User identifier
            auth_token: Optional JWT or auth token
            
        Returns:
            Session dict with session_id and other metadata
        """
        pass
    
    @abstractmethod
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a JWT or auth token.
        
        Args:
            token: Token string to validate
            
        Returns:
            Decoded token data if valid, None otherwise
        """
        pass
