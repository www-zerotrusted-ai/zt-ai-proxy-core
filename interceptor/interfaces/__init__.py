"""
Provider interfaces for pluggable architecture.

This module defines abstract interfaces that allow the interceptor to work
with different implementations (standalone vs enterprise) without tight coupling.
"""

from .auth_provider import AuthProvider
from .config_provider import ConfigProvider
from .audit_logger import AuditLogger
from .settings_provider import SettingsProvider

__all__ = [
    'AuthProvider',
    'ConfigProvider',
    'AuditLogger',
    'SettingsProvider',
]
