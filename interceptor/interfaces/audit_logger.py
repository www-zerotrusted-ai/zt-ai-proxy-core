"""
Audit logger interface.

Defines how audit events are logged.
Standalone logs to local files only, Enterprise forwards to API.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class AuditLogger(ABC):
    """Abstract audit logger interface"""
    
    @abstractmethod
    def log_request(
        self,
        host: str,
        path: str,
        url: str,
        method: str,
        headers: Dict[str, str],
        user_id: Optional[str] = None,
        decision: str = "unknown",
        **kwargs
    ) -> bool:
        """
        Log a request/decision event.
        
        Args:
            host: Request host
            path: Request path
            url: Full URL
            method: HTTP method
            headers: Request headers
            user_id: User identifier (if authenticated)
            decision: Decision made (allowed, blocked, etc.)
            **kwargs: Additional metadata
            
        Returns:
            True if logged successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def log_block(
        self,
        host: str,
        path: str,
        url: str,
        method: str,
        headers: Dict[str, str],
        block_reason: str,
        block_type: str,
        user_id: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Log a block event.
        
        Args:
            host: Request host
            path: Request path
            url: Full URL
            method: HTTP method
            headers: Request headers
            block_reason: Why request was blocked
            block_type: Type of block (pii, auth, blocklist, etc.)
            user_id: User identifier (if authenticated)
            **kwargs: Additional metadata
            
        Returns:
            True if logged successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def log_pii_detection(
        self,
        host: str,
        path: str,
        pii_count: int,
        pii_types: Dict[str, int],
        user_id: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Log a PII detection event.
        
        Args:
            host: Request host
            path: Request path
            pii_count: Total PII items detected
            pii_types: Dict of PII types and counts
            user_id: User identifier (if authenticated)
            **kwargs: Additional metadata
            
        Returns:
            True if logged successfully, False otherwise
        """
        pass
