"""
Environment variable configuration for ZTProxy editions.

This module defines all environment variables used by the proxy,
organized by edition (standalone vs enterprise).

===============================================================================
EDITION CONTROL
===============================================================================
ZT_EDITION                  Edition to run: 'standalone' or 'enterprise'
                            Default: 'standalone' if enterprise modules unavailable
                            Used by: Provider loader

===============================================================================
COMMON VARIABLES (Both Editions)
===============================================================================
ZT_ENFORCEMENT_MODE         Override enforcement mode: 'auto', 'observe', 'block'
                            Default: From config file
                            Used by: Config providers

ZT_FILTER_MODE              Override filter mode: 'all', 'post-only', 'post-chat', 'post-chat-pii'
                            Default: From config file
                            Used by: Config providers

ZT_DEBUG                    Enable debug logging: '1', 'true', 'yes', 'on'
                            Default: '0' (disabled)
                            Used by: All components

ZT_DISABLE_BLOCKING         Force allow all requests (bypass mode): '1', 'true'
                            Default: '0' (blocking enabled)
                            Used by: Interceptor

ZT_FEATURES_URL             URL for guardrails/PII service
                            Default: 'http://0.0.0.0:8000'
                            Used by: PII detection

ZT_PII_THRESHOLD            PII detection threshold (number of items to trigger block)
                            Default: 1
                            Used by: PII gate

===============================================================================
STANDALONE EDITION ONLY
===============================================================================
ZT_CONFIG_PATH              Path to config JSON file
                            Default: './ztproxy_config.json'
                            Used by: StandaloneConfigProvider

ZT_LOG_PATH                 Path to audit log file
                            Default: './interceptor/intercepted_requests.log'
                            Used by: StandaloneAuditLogger

ZT_BLOCKLIST_PATH           Path to blocklist JSON file
                            Default: './config/blocklist.json'
                            Used by: StandaloneSettingsProvider

ZT_WHITELIST_PATH           Path to whitelist JSON file
                            Default: './config/whitelist.json'
                            Used by: StandaloneSettingsProvider

===============================================================================
ENTERPRISE EDITION ONLY
===============================================================================
ZT_PROXY_API_KEY            API key for remote blocklist/settings
                            Required for: Remote blocklist, user settings
                            Used by: EnterpriseSettingsProvider

ZT_SSO_URL                  SSO login endpoint URL
                            Default: 'https://identity.zerotrusted.ai/sso'
                            Used by: EnterpriseAuthProvider

ZT_SETTINGS_API_URL         User settings API URL
                            Default: 'https://settings.zerotrusted.ai'
                            Used by: EnterpriseSettingsProvider

ZT_AUDIT_API_URL            Audit log forwarding API URL
                            Default: 'https://history.zerotrusted.ai'
                            Used by: EnterpriseAuditLogger

ZT_PROXY_URL                Public proxy URL (for block pages)
                            Default: 'https://ai-proxy.zerotrusted.ai'
                            Used by: Block page rendering

ZT_BYPASS_HOSTS             Semicolon-separated list of hosts to bypass
                            Default: zerotrusted.ai domains
                            Used by: Internal API

===============================================================================
RUNTIME CONFIGURATION
===============================================================================
These variables are read at runtime and can be changed without restart:

- ZT_ENFORCEMENT_MODE: Changes take effect on config reload
- ZT_FILTER_MODE: Changes take effect on config reload
- ZT_DEBUG: Changes take effect immediately
- ZT_DISABLE_BLOCKING: Changes take effect immediately

These variables require restart:

- ZT_EDITION: Must be set before import
- ZT_PROXY_API_KEY: Cached on startup
- ZT_CONFIG_PATH: Read once at init

===============================================================================
USAGE EXAMPLES
===============================================================================

Windows PowerShell (Standalone):
    $Env:ZT_EDITION = "standalone"
    $Env:ZT_FILTER_MODE = "post-chat-pii"
    $Env:ZT_DEBUG = "1"
    mitmdump -s interceptor/interceptor_addon.py --listen-port 8081

Windows PowerShell (Enterprise):
    $Env:ZT_EDITION = "enterprise"
    $Env:ZT_PROXY_API_KEY = "your-api-key-here"
    $Env:ZT_ENFORCEMENT_MODE = "block"
    mitmdump -s interceptor/interceptor_addon.py --listen-port 8081

Linux/Mac (Standalone):
    export ZT_EDITION=standalone
    export ZT_FILTER_MODE=post-chat-pii
    mitmdump -s interceptor/interceptor_addon.py --listen-port 8081

Linux/Mac (Enterprise):
    export ZT_EDITION=enterprise
    export ZT_PROXY_API_KEY=your-api-key-here
    mitmdump -s interceptor/interceptor_addon.py --listen-port 8081

===============================================================================
"""

import os
from typing import Optional


class EnvironConfig:
    """Environment variable configuration helper"""
    
    # Edition control
    EDITION = os.getenv('ZT_EDITION', 'standalone')  # 'standalone' or 'enterprise'
    
    # Common variables
    ENFORCEMENT_MODE = os.getenv('ZT_ENFORCEMENT_MODE')  # Optional override
    FILTER_MODE = os.getenv('ZT_FILTER_MODE')  # Optional override
    DEBUG = os.getenv('ZT_DEBUG', '0').lower() in ('1', 'true', 'yes', 'on')
    DISABLE_BLOCKING = os.getenv('ZT_DISABLE_BLOCKING', '0').lower() in ('1', 'true', 'yes', 'on')
    FEATURES_URL = os.getenv('ZT_FEATURES_URL', 'http://0.0.0.0:8000')
    PII_THRESHOLD = int(os.getenv('ZT_PII_THRESHOLD', '1'))
    
    # Standalone-specific
    CONFIG_PATH = os.getenv('ZT_CONFIG_PATH', './ztproxy_config.json')
    LOG_PATH = os.getenv('ZT_LOG_PATH', './interceptor/intercepted_requests.log')
    BLOCKLIST_PATH = os.getenv('ZT_BLOCKLIST_PATH', './config/blocklist.json')
    WHITELIST_PATH = os.getenv('ZT_WHITELIST_PATH', './config/whitelist.json')
    
    # Enterprise-specific
    PROXY_API_KEY = os.getenv('ZT_PROXY_API_KEY', 'MISSING')
    SSO_URL = os.getenv('ZT_SSO_URL', 'https://identity.zerotrusted.ai/sso')
    SETTINGS_API_URL = os.getenv('ZT_SETTINGS_API_URL', 'https://settings.zerotrusted.ai')
    AUDIT_API_URL = os.getenv('ZT_AUDIT_API_URL', 'https://history.zerotrusted.ai')
    PROXY_URL = os.getenv('ZT_PROXY_URL', 'https://ai-proxy.zerotrusted.ai')
    BYPASS_HOSTS = os.getenv('ZT_BYPASS_HOSTS', '')
    
    @classmethod
    def is_enterprise(cls) -> bool:
        """Check if running in enterprise edition"""
        return cls.EDITION.lower() == 'enterprise'
    
    @classmethod
    def is_standalone(cls) -> bool:
        """Check if running in standalone edition"""
        return cls.EDITION.lower() == 'standalone'
    
    @classmethod
    def get_edition_info(cls) -> dict:
        """Get edition information for logging/debugging"""
        return {
            'edition': cls.EDITION,
            'debug': cls.DEBUG,
            'enforcement_mode': cls.ENFORCEMENT_MODE,
            'filter_mode': cls.FILTER_MODE,
            'features_url': cls.FEATURES_URL,
        }


# Export singleton instance
env_config = EnvironConfig()
