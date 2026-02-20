"""
Configuration provider interface.

Defines how configuration is loaded and persisted.
Standalone uses local files, Enterprise uses remote API + local cache.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class ConfigProvider(ABC):
    """Abstract configuration provider interface"""
    
    @abstractmethod
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from source (file, API, etc.).
        
        Returns:
            Configuration dictionary with keys like:
            - filter_mode: str
            - enforcement_mode: str
            - use_remote_blocklist: bool
            - etc.
        """
        pass
    
    @abstractmethod
    def save_config(self, config: Dict[str, Any]) -> bool:
        """
        Save configuration to persistent storage.
        
        Args:
            config: Configuration dictionary to save
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a specific configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any) -> bool:
        """
        Set a specific configuration value.
        
        Args:
            key: Configuration key
            value: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def refresh(self) -> bool:
        """
        Refresh configuration from source (for remote configs).
        
        Returns:
            True if refresh successful, False otherwise
        """
        pass
