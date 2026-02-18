import os
import json
from typing import Any, Optional


class FileStore:
    """Centralized path mapping and basic file I/O helpers.

    - Resolves persistent config path (env override, AppData, home).
    - Exposes default log path anchored at repo base.
    - Provides safe JSON read/write and text tail utilities.
    """

    def __init__(self, base_dir: Optional[str] = None) -> None:
        # base_dir is the repo root (interceptor/..)
        self._base_dir = base_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # --- Path mapping ---
    def get_config_path(self) -> str:
        override = os.getenv('ZT_CONFIG_PATH')
        if override:
            try:
                os.makedirs(os.path.dirname(override), exist_ok=True)
            except Exception:
                pass
            return override
        # Windows preferred: %APPDATA% or %LOCALAPPDATA%
        try:
            if os.name == 'nt':
                root = os.environ.get('APPDATA') or os.environ.get('LOCALAPPDATA')
                if root:
                    path = os.path.join(root, 'ZeroTrusted', 'ZTProxy', 'ztproxy_config.json')
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    return path
            # POSIX fallback
            home = os.path.expanduser('~')
            path = os.path.join(home, '.zerotrusted', 'ztproxy', 'ztproxy_config.json')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            return path
        except Exception:
            # Last resort: repo root
            return os.path.join(self._base_dir, 'ztproxy_config.json')

    def get_log_path(self) -> str:
        return os.path.join(self._base_dir, 'intercepted_requests.log')

    # --- I/O helpers ---
    def read_json(self, path: str) -> Any:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def write_json(self, path: str, data: Any) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def tail_text(self, path: str, n: int = 300) -> str:
        if not os.path.exists(path):
            return ''
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-max(1, int(n)):]
            return ''.join(lines)
        except Exception:
            return ''
    
    def rotate_log_if_needed(self, path: str, max_size_mb: float = 5.0, keep_lines: int = 1000) -> bool:
        """
        Rotate log file if it exceeds max_size_mb, keeping only the last keep_lines lines.
        
        Args:
            path: Path to the log file
            max_size_mb: Maximum file size in MB before rotation (default 5MB)
            keep_lines: Number of lines to keep after rotation (default 1000)
            
        Returns:
            True if rotation occurred, False otherwise
        """
        if not os.path.exists(path):
            return False
        
        try:
            # Check file size
            size_bytes = os.path.getsize(path)
            size_mb = size_bytes / (1024 * 1024)
            
            if size_mb < max_size_mb:
                return False
            
            # File is too large, rotate it
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Keep only last N lines
            lines_to_keep = lines[-keep_lines:] if len(lines) > keep_lines else lines
            
            # Write back
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"[LOG ROTATED] Kept last {len(lines_to_keep)} of {len(lines)} lines (file was {size_mb:.2f}MB)\n")
                f.writelines(lines_to_keep)
            
            return True
        except Exception as e:
            # Don't fail if rotation fails, just log to stderr
            import sys
            print(f"⚠️ Log rotation failed: {e}", file=sys.stderr)
            return False


default_store = FileStore()
