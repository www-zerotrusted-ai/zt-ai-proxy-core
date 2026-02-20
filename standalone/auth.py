"""
Standalone authentication provider.

No authentication required for standalone edition.
All requests treated as coming from anonymous local user.
"""

from typing import Optional, Dict, Any
import sys
import os

# Add core to path for interface import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from core.interceptor.interfaces.auth_provider import AuthProvider


class StandaloneAuthProvider(AuthProvider):
    """No-authentication provider for standalone edition"""
    
    def __init__(self):
        self.local_user = {
            "user_id": "local_user",
            "authenticated": True,
            "session_id": "standalone_session",
            "edition": "standalone"
        }
    
    def authenticate(self, headers: Dict[str, str], cookies: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Always return authenticated local user for standalone.
        No actual authentication performed.
        """
        return self.local_user.copy()
    
    def is_required(self) -> bool:
        """Authentication not required for standalone"""
        return False
    
    def get_login_url(self) -> Optional[str]:
        """No SSO URL for standalone"""
        return None
    
    def create_session(self, user_id: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
        """Create a simple local session"""
        return {
            "user_id": user_id or "local_user",
            "authenticated": True,
            "session_id": "standalone_session",
            "auth_token": None,
            "edition": "standalone"
        }
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """No token validation for standalone"""
        return self.local_user.copy()
