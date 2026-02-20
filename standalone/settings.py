"""
Standalone settings provider.

Uses local static lists for blocklist/whitelist.
No remote API calls for user settings.
"""

import os
import sys
import json
from typing import Dict, Any, Optional, List

# Add core to path for interface import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from core.interceptor.interfaces.settings_provider import SettingsProvider


class StandaloneSettingsProvider(SettingsProvider):
    """Local file-based settings provider for standalone edition"""
    
    def __init__(self, blocklist_file: Optional[str] = None, whitelist_file: Optional[str] = None):
        """
        Initialize standalone settings provider.
        
        Args:
            blocklist_file: Path to blocklist JSON file
            whitelist_file: Path to whitelist JSON file
        """
        if blocklist_file is None:
            blocklist_file = os.path.join(os.getcwd(), 'config', 'blocklist.json')
        if whitelist_file is None:
            whitelist_file = os.path.join(os.getcwd(), 'config', 'whitelist.json')
        
        self.blocklist_file = blocklist_file
        self.whitelist_file = whitelist_file
        
        # Default AI domains to monitor
        self.default_blocklist = [
            "openai.com",
            "anthropic.com",
            "claude.ai",
            "chat.openai.com",
            "chatgpt.com",
            "gemini.google.com",
            "bard.google.com",
            "copilot.microsoft.com",
            "perplexity.ai",
            "poe.com",
            "you.com",
            "character.ai",
            "midjourney.com",
            "stability.ai",
            "huggingface.co",
            "replicate.com",
            "cohere.ai",
            "ai21.com",
            "together.xyz",
            "groq.com"
        ]
        
        self.default_whitelist = []
        
        # Load lists from files
        self._blocklist = self._load_list(self.blocklist_file, self.default_blocklist)
        self._whitelist = self._load_list(self.whitelist_file, self.default_whitelist)
    
    def _load_list(self, file_path: str, default_list: List[str]) -> List[str]:
        """Load a domain list from JSON file"""
        if not os.path.exists(file_path):
            # Create default file
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(default_list, f, indent=2)
            except Exception:
                pass
            return default_list.copy()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return default_list.copy()
    
    def _save_list(self, file_path: str, domain_list: List[str]) -> bool:
        """Save a domain list to JSON file"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(domain_list, f, indent=2)
            return True
        except Exception:
            return False
    
    def get_user_settings(self, user_id: str, auth_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Return default settings for standalone (no per-user settings).
        """
        return {
            "filter_mode": "post-chat-pii",
            "enforcement_mode": "block",
            "pii_threshold": 1,
            "edition": "standalone"
        }
    
    def get_blocklist(self, api_key: Optional[str] = None, **kwargs) -> List[str]:
        """Get local blocklist"""
        return self._blocklist.copy()
    
    def get_whitelist(self, api_key: Optional[str] = None, **kwargs) -> List[str]:
        """Get local whitelist"""
        return self._whitelist.copy()
    
    def refresh_lists(self) -> bool:
        """Refresh lists from files"""
        try:
            self._blocklist = self._load_list(self.blocklist_file, self.default_blocklist)
            self._whitelist = self._load_list(self.whitelist_file, self.default_whitelist)
            return True
        except Exception:
            return False
    
    def add_to_blocklist(self, domain: str) -> bool:
        """Add a domain to blocklist"""
        if domain not in self._blocklist:
            self._blocklist.append(domain)
            return self._save_list(self.blocklist_file, self._blocklist)
        return True
    
    def add_to_whitelist(self, domain: str) -> bool:
        """Add a domain to whitelist"""
        if domain not in self._whitelist:
            self._whitelist.append(domain)
            return self._save_list(self.whitelist_file, self._whitelist)
        return True
    
    def remove_from_blocklist(self, domain: str) -> bool:
        """Remove a domain from blocklist"""
        if domain in self._blocklist:
            self._blocklist.remove(domain)
            return self._save_list(self.blocklist_file, self._blocklist)
        return True
    
    def remove_from_whitelist(self, domain: str) -> bool:
        """Remove a domain from whitelist"""
        if domain in self._whitelist:
            self._whitelist.remove(domain)
            return self._save_list(self.whitelist_file, self._whitelist)
        return True
