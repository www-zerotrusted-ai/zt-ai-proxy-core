"""
Standalone configuration provider.

Uses local JSON file for configuration.
No remote API calls.
"""

import json
import os
import sys
from typing import Dict, Any, Optional

# Add core to path for interface import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from core.interceptor.interfaces.config_provider import ConfigProvider


class StandaloneConfigProvider(ConfigProvider):
    """File-based configuration provider for standalone edition"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize standalone config provider.
        
        Args:
            config_path: Path to config file (default: ztproxy_config.json in current dir)
        """
        if config_path is None:
            # Default to ztproxy_config.json in working directory
            config_path = os.path.join(os.getcwd(), 'ztproxy_config.json')
        
        self.config_path = config_path
        self._config = self._load_from_file()
        self._apply_env_overrides()
    
    def _load_from_file(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        default_config = {
            "filter_mode": "post-chat-pii",
            "enforcement_mode": "block",
            "use_remote_blocklist": False,  # Standalone uses local lists only
            "include_request_body": False,
            "debug": False,
            "edition": "standalone"
        }
        
        if not os.path.exists(self.config_path):
            # Create default config file
            try:
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
            except Exception:
                pass
            return default_config
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Merge with defaults
                return {**default_config, **config}
        except Exception:
            return default_config
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides"""
        # ZT_ENFORCEMENT_MODE overrides config
        if os.getenv('ZT_ENFORCEMENT_MODE'):
            self._config['enforcement_mode'] = os.getenv('ZT_ENFORCEMENT_MODE')
        
        # ZT_FILTER_MODE overrides config
        if os.getenv('ZT_FILTER_MODE'):
            self._config['filter_mode'] = os.getenv('ZT_FILTER_MODE')
        
        # ZT_DEBUG enables debug mode
        if os.getenv('ZT_DEBUG', '').lower() in ('1', 'true', 'yes', 'on'):
            self._config['debug'] = True
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration (already loaded in __init__)"""
        return self._config.copy()
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file"""
        try:
            # Merge with existing config
            self._config.update(config)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Failed to save config: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a specific configuration value"""
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any) -> bool:
        """Set a specific configuration value"""
        try:
            self._config[key] = value
            return self.save_config({key: value})
        except Exception:
            return False
    
    def refresh(self) -> bool:
        """Refresh configuration from file"""
        try:
            self._config = self._load_from_file()
            self._apply_env_overrides()
            return True
        except Exception:
            return False
