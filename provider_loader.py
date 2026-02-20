"""
Provider loader - dynamically selects providers based on edition.

This module handles the runtime selection of provider implementations
based on the ZT_EDITION environment variable.
"""

import os
import sys
from typing import Tuple

# Import interfaces
from core.interceptor.interfaces import (
    AuthProvider,
    ConfigProvider,
    AuditLogger,
    SettingsProvider
)

from core.environment import env_config


def load_providers() -> Tuple[AuthProvider, ConfigProvider, AuditLogger, SettingsProvider]:
    """
    Load provider implementations based on edition.
    
    Returns:
        Tuple of (auth_provider, config_provider, audit_logger, settings_provider)
    
    Raises:
        ImportError: If enterprise edition requested but modules not available
    """
    edition = env_config.EDITION.lower()
    
    print(f"[ZTProxy] Loading providers for edition: {edition}")
    
    if edition == 'enterprise':
        try:
            # Try to import enterprise providers
            from enterprise.auth.enterprise_auth import EnterpriseAuthProvider
            from enterprise.services.enterprise_config import EnterpriseConfigProvider
            from enterprise.services.enterprise_audit import EnterpriseAuditLogger
            from enterprise.services.enterprise_settings import EnterpriseSettingsProvider
            
            print("[ZTProxy] ✓ Enterprise providers loaded successfully")
            
            # Initialize enterprise providers
            auth_provider = EnterpriseAuthProvider()
            config_provider = EnterpriseConfigProvider(
                config_path=env_config.CONFIG_PATH if env_config.CONFIG_PATH != './ztproxy_config.json' else None
            )
            audit_logger = EnterpriseAuditLogger(
                log_file=env_config.LOG_PATH if env_config.LOG_PATH != './interceptor/intercepted_requests.log' else None
            )
            settings_provider = EnterpriseSettingsProvider()
            
            return auth_provider, config_provider, audit_logger, settings_provider
            
        except ImportError as e:
            print(f"[ZTProxy] ⚠️ Enterprise modules not found: {e}")
            print("[ZTProxy] ⚠️ Falling back to standalone edition")
            edition = 'standalone'  # Fall back to standalone
    
    if edition == 'standalone':
        # Import standalone providers
        from core.standalone import (
            StandaloneAuthProvider,
            StandaloneConfigProvider,
            StandaloneAuditLogger,
            StandaloneSettingsProvider
        )
        
        print("[ZTProxy] ✓ Standalone providers loaded successfully")
        
        # Initialize standalone providers
        auth_provider = StandaloneAuthProvider()
        config_provider = StandaloneConfigProvider(config_path=env_config.CONFIG_PATH)
        audit_logger = StandaloneAuditLogger(log_file=env_config.LOG_PATH)
        settings_provider = StandaloneSettingsProvider(
            blocklist_file=env_config.BLOCKLIST_PATH,
            whitelist_file=env_config.WHITELIST_PATH
        )
        
        return auth_provider, config_provider, audit_logger, settings_provider
    
    raise ValueError(f"Unknown edition: {edition}. Must be 'standalone' or 'enterprise'")


# Global provider instances (loaded on first import)
# These will be used throughout the interceptor
auth_provider, config_provider, audit_logger, settings_provider = load_providers()


def get_auth_provider() -> AuthProvider:
    """Get the current auth provider"""
    return auth_provider


def get_config_provider() -> ConfigProvider:
    """Get the current config provider"""
    return config_provider


def get_audit_logger() -> AuditLogger:
    """Get the current audit logger"""
    return audit_logger


def get_settings_provider() -> SettingsProvider:
    """Get the current settings provider"""
    return settings_provider


def get_edition() -> str:
    """Get the current edition (standalone or enterprise)"""
    return env_config.EDITION.lower()


def is_enterprise() -> bool:
    """Check if running enterprise edition"""
    return env_config.is_enterprise()


def is_standalone() -> bool:
    """Check if running standalone edition"""
    return env_config.is_standalone()
