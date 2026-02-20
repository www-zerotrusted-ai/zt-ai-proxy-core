"""
Settings provider interface.

Defines how user-specific settings are retrieved.
Standalone uses local defaults, Enterprise fetches from API.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class SettingsProvider(ABC):
    """Abstract settings provider interface"""
    
    @abstractmethod
    def get_user_settings(self, user_id: str, auth_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get user-specific settings.
        
        Args:
            user_id: User identifier
            auth_token: Optional JWT token for API authentication
            
        Returns:
            Settings dictionary or None if not found
            Example: {
                "filter_mode": "post-chat-pii",
                "enforcement_mode": "block",
                "pii_threshold": 3,
                "allowed_domains": ["example.com"]
            }
        """
        pass
    
    @abstractmethod
    def get_blocklist(self, api_key: Optional[str] = None, **kwargs) -> list:
        """
        Get list of blocked domains.
        
        Args:
            api_key: Optional API key for remote blocklist
            **kwargs: Additional parameters (bearer_token, etc.)
            
        Returns:
            List of domain strings to block
        """
        pass
    
    @abstractmethod
    def get_whitelist(self, api_key: Optional[str] = None, **kwargs) -> list:
        """
        Get list of whitelisted domains.
        
        Args:
            api_key: Optional API key for remote whitelist
            **kwargs: Additional parameters (bearer_token, etc.)
            
        Returns:
            List of domain strings to allow
        """
        pass
    
    @abstractmethod
    def refresh_lists(self) -> bool:
        """
        Refresh blocklist/whitelist from source.
        
        Returns:
            True if refresh successful, False otherwise
        """
        pass
