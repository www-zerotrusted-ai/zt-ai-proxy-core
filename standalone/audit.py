"""
Standalone audit logger.

Logs to local file only, no remote API calls.
"""

import os
import sys
import json
from typing import Dict, Any, Optional
from datetime import datetime

# Add core to path for interface import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from core.interceptor.interfaces.audit_logger import AuditLogger


class StandaloneAuditLogger(AuditLogger):
    """Local file-based audit logger for standalone edition"""
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize standalone audit logger.
        
        Args:
            log_file: Path to log file (default: intercepted_requests.log)
        """
        if log_file is None:
            log_file = os.path.join(os.getcwd(), 'interceptor', 'intercepted_requests.log')
        
        self.log_file = log_file
        
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                pass
    
    def _write_log(self, message: str) -> bool:
        """Write a log message to file"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                timestamp = datetime.utcnow().isoformat()
                f.write(f"[{timestamp}] {message}\n")
            return True
        except Exception as e:
            print(f"Failed to write log: {e}")
            return False
    
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
        """Log a request event to local file"""
        log_entry = {
            "type": "request",
            "host": host,
            "path": path,
            "url": url,
            "method": method,
            "user_id": user_id or "local_user",
            "decision": decision,
            **kwargs
        }
        
        message = f"[REQUEST] {method} {url} | user={user_id or 'local_user'} | decision={decision}"
        return self._write_log(message)
    
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
        """Log a block event to local file"""
        log_entry = {
            "type": "block",
            "host": host,
            "path": path,
            "url": url,
            "method": method,
            "user_id": user_id or "local_user",
            "block_reason": block_reason,
            "block_type": block_type,
            **kwargs
        }
        
        message = f"[BLOCK] {method} {url} | type={block_type} | reason={block_reason} | user={user_id or 'local_user'}"
        return self._write_log(message)
    
    def log_pii_detection(
        self,
        host: str,
        path: str,
        pii_count: int,
        pii_types: Dict[str, int],
        user_id: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Log a PII detection event to local file"""
        log_entry = {
            "type": "pii_detection",
            "host": host,
            "path": path,
            "user_id": user_id or "local_user",
            "pii_count": pii_count,
            "pii_types": pii_types,
            **kwargs
        }
        
        pii_summary = ", ".join([f"{k}={v}" for k, v in pii_types.items()])
        message = f"[PII] {host}{path} | total={pii_count} | types=({pii_summary}) | user={user_id or 'local_user'}"
        return self._write_log(message)
