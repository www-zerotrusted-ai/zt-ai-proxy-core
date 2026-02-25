import os
import json
import re
from time import time as _time
import threading
import asyncio

from mitmproxy import http, ctx

from tools.file_store import default_store
from tools.request_filters import is_chat_path, extract_chat_text, run_pii_gate, handle_post_only_block, extract_attachments_text
from tools.provider_openai import host_is_openai, is_openai_chat_path, extract_openai_chat_text
from tools.runtime_helpers import (
    load_config,
    run_async_in_thread,
    domain_matches,
    get_cached_blocklist,
    get_cached_whitelist,
    get_cached_enforcement_type,
    features_refresh_loop,
    get_features_cache_info,
    get_blocklist_cache_info,
    clear_all_in_memory_caches,
    BLOCKLIST_TTL_SEC,
)
from internal_api import handle_internal_request, get_bypass_hosts, has_internal_token
from services.shadow_ai_detector import is_shadow_ai_request
from auth.session_store import GLOBAL_SESSION_STORE
from services.zt_log_forwarder import send_log_to_api, send_block_audit_log
from services.session_manager import SessionManager
from services.user_settings import get_user_settings, clear_user_settings_cache
from tools.config_cache import get_config_cache

# Edition detection: standalone vs enterprise
# Set by build scripts or deployment environment via ZT_EDITION environment variable
# Defaults to 'standalone' for local/standalone builds
# Enterprise deployments should set ZT_EDITION=enterprise in their K8s ConfigMap/env
EDITION = os.getenv('ZT_EDITION', 'standalone').lower()
IS_STANDALONE = (EDITION == 'standalone')
IS_ENTERPRISE = (EDITION == 'enterprise')

class Interceptor:
    def __init__(self):
        # Use direct file paths for standalone mode
        self.CONFIG_FILE_PATH = os.path.join(os.getcwd(), 'ztproxy_config.json')
        self.INTERCEPTED_LOG_FILE = os.path.join(os.getcwd(), 'intercepted_requests.log')
        self.UI_HTML = None  # UI HTML loader can be added if needed
        self.CONFIG_LAST_UPDATED = None
        self.features_started = False
        self.session_manager = SessionManager(GLOBAL_SESSION_STORE, self.INTERCEPTED_LOG_FILE)
        self.metrics = {
            'requests_total': 0,
            'blocked_total': 0,
            'allowed_total': 0,
            'errors_total': 0,
            'pii_detected_total': 0,
            'post_chat_total': 0,
        }

    def _get_config(self):
        return load_config(self.CONFIG_FILE_PATH)

    def _get_blocklist(self, *args, **kwargs):
        return []

    def _get_whitelist(self, *args, **kwargs):
        return []

    def _get_features_cache_info(self):
        return {}

    def _set_features_started(self, val):
        self.features_started = val

    def request(self, flow):
        req = flow.request
        method = req.method.upper()
        host_header = req.headers.get('Host') or req.pretty_host
        host = (host_header or '').split(':')[0]
        path = req.path or '/'
        url = req.url
        headers = dict(req.headers) if req.headers else {}
        host_lower = host.lower()
        is_internal_host = host_lower in {'localhost', '127.0.0.1', '0.0.0.0'}

        # --- DEBUG: Always log POST and is_chat_path at the very top ---
        if method == 'POST':
            print(f"[ZT-DEBUG] POST received: host={host}, path={path}")
            # Use the same logic as below for is_chat_path
            from tools.request_filters import is_chat_path
            chat_path_result_dbg = False
            if 'openai' in host_lower or 'chatgpt' in host_lower or 'claude' in host_lower or 'bard' in host_lower or 'gemini' in host_lower:
                chat_path_result_dbg = is_chat_path(path)
            print(f"[ZT-DEBUG] is_chat_path({path}) result: {chat_path_result_dbg}")

        # BYPASS: Google conversion/analytics APIs should not be blocked or inspected
        from tools.request_filters import is_conversion_api
        if is_conversion_api(host, path):
            return  # Allow these requests to pass through uninspected
        if is_internal_host:
            origin_hdr = headers.get('Origin') or headers.get('origin')
            cors_headers = {
                "Access-Control-Allow-Origin": origin_hdr if origin_hdr else '*',
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-ZT-Auth",
                "Vary": "Origin",
            }
            handled = handle_internal_request(
                flow,
                internal_only=True,
                path=path,
                url=url,
                method=method,
                headers=headers,
                cors_headers=cors_headers,
                ctx=None,
                metrics=self.metrics,
                INTERCEPTED_LOG_FILE=self.INTERCEPTED_LOG_FILE,
                CONFIG_FILE_PATH=self.CONFIG_FILE_PATH,
                UI_HTML=self.UI_HTML,
                CONFIG_LAST_UPDATED=self.CONFIG_LAST_UPDATED,
                api_key=os.getenv('ZT_PROXY_API_KEY') or "MISSING",
                get_config=self._get_config,
                session_manager=self.session_manager,
                get_blocklist=self._get_blocklist,
                get_whitelist=self._get_whitelist,
                get_features_cache_info=self._get_features_cache_info,
                debug_log=None,
                features_started=self.features_started,
                set_features_started=self._set_features_started,
                BLOCKLIST_TTL_SEC=BLOCKLIST_TTL_SEC,
                get_blocklist_cache_info=None,
            )
            if handled:
                return
            else:
                flow.response = http.Response.make(404, b"Not Found", {"Content-Type": "text/plain; charset=utf-8"})
                return

        # --- PII detection for chat POSTs (standalone, local only) ---
        # Only block POSTs to specific chat endpoints (OpenAI/ChatGPT/Claude/Bard/Gemini) and only on chat paths
        if method == 'POST':
            # Only run PII detection on specific chat endpoint paths (OpenAI, ChatGPT, Claude, Bard, Gemini)
            # This matches the outside-core logic for performance
            if host_is_openai(host_lower) and is_openai_chat_path(path):
                chat_path_match = True
            elif (
                ('openai' in host_lower or 'chatgpt' in host_lower or 'claude' in host_lower or 'bard' in host_lower or 'gemini' in host_lower)
                and is_chat_path(path)
            ):
                chat_path_match = True
            else:
                chat_path_match = False
            if chat_path_match:
                try:
                    content_type = headers.get('Content-Type', '')
                    body = req.get_text()
                    data = {}
                    chat_text = ''
                    if 'application/json' in content_type:
                        import json
                        data = json.loads(body) if body else {}
                        chat_text = extract_chat_text(data) if data else body
                    elif 'application/x-www-form-urlencoded' in content_type:
                        from urllib.parse import parse_qs, unquote
                        form = parse_qs(body)
                        f_req = form.get('f.req')
                        if f_req:
                            try:
                                import json
                                f_req_val = f_req[0]
                                if '%' in f_req_val:
                                    f_req_val = unquote(f_req_val)
                                parsed = json.loads(f_req_val)
                                if isinstance(parsed, list) and len(parsed) > 1:
                                    inner = parsed[1]
                                    if isinstance(inner, list) and len(inner) > 0 and isinstance(inner[0], str):
                                        chat_text = inner[0]
                                    else:
                                        chat_text = str(parsed)
                                else:
                                    chat_text = str(parsed)
                            except Exception as e:
                                print(f"[ZT DEBUG] Gemini f.req parse error: {e}")
                                chat_text = body
                        else:
                            chat_text = body
                    else:
                        chat_text = body
                    print(f"[ZT DEBUG] Extracted chat_text for PII: {chat_text[:200]}")
                except Exception as e:
                    print(f"[ZT DEBUG] Error extracting chat text: {e}")
                    chat_text = req.get_text()

                # Log Gemini chat POST details to console for debugging
                print(f"[ZT GEMINI] Host: {host} Path: {path}")
                print(f"[ZT GEMINI] Chat Text: {chat_text}")
                pii_found = run_pii_gate(chat_text)
                print(f"[ZT GEMINI] PII Detected: {pii_found}")
                if pii_found:
                    print(f"[ZT DEBUG] Block triggered. IS_ENTERPRISE={IS_ENTERPRISE}, IS_STANDALONE={IS_STANDALONE}, EDITION={EDITION}")
                    # Enterprise mode: show detailed popup with PII findings
                    if IS_ENTERPRISE:
                        print("[ZT DEBUG] ENTERPRISE block page branch hit.")
                        from tools.request_filters import extract_pii_keywords
                        pii_keywords = extract_pii_keywords(chat_text)
                        print(f"[ZT DEBUG] PII keywords detected: {pii_keywords}")
                        threshold = 3  # Example threshold, can be loaded from config
                        block_html = f"""
                        <html lang='en'>
                        <head>
                            <meta charset='UTF-8'>
                            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                            <title>Request Blocked by ZeroTrusted.ai</title>
                            <style>
                                body {{ background: #181c24; color: #fff; font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; height: 100vh; }}
                                .zt-block-container {{ background: #23283a; border-radius: 12px; box-shadow: 0 4px 24px #0008; padding: 36px 32px; max-width: 440px; text-align: center; }}
                                .zt-block-logo {{ width: 56px; height: 56px; margin-bottom: 18px; }}
                                .zt-block-title {{ font-size: 1.5rem; font-weight: 600; margin-bottom: 10px; color: #eab308; }}
                                .zt-block-msg {{ font-size: 1.1rem; margin-bottom: 18px; color: #e0e0e0; }}
                                .zt-block-details {{ margin-bottom: 18px; color: #e0e0e0; font-size: 1rem; }}
                                .zt-block-footer {{ font-size: 0.95rem; color: #aaa; margin-top: 18px; }}
                                .zt-block-btns {{ margin-top: 18px; display: flex; gap: 10px; justify-content: flex-end; }}
                                .zt-block-btn {{ background: #eab308; color: #000; font-weight: 600; border: none; border-radius: 4px; padding: 7px 16px; font-size: 14px; cursor: pointer; }}
                                .zt-block-btn:hover {{ background: #fbbf24; }}
                                .zt-block-btn-dismiss {{ background: #23283a; color: #fff; border: 1px solid #444; }}
                                .zt-block-btn-dismiss:hover {{ background: #444; }}
                                a {{ color: #7ecfff; text-decoration: none; }}
                                a:hover {{ text-decoration: underline; }}
                            </style>
                        </head>
                        <body>
                            <div class='zt-block-container'>
                                <img class='zt-block-logo' src='https://dev-identity.zerotrusted.ai/img/logo-with-tagline-white.png' alt='ZT'>
                                <div class='zt-block-title'>Request Blocked by ZeroTrusted.ai: PII threshold met ({len(pii_keywords)} findings)</div>
                                <div class='zt-block-details'>Sensitive Keywords Detected:<br>{'<br>'.join(['PII:' + k for k in pii_keywords])}</div>
                                <div class='zt-block-msg'>Your message was blocked because it contains sensitive information. Please remove PII and try again.</div>
                                <div class='zt-block-footer'>If you believe this is a mistake, contact your administrator or visit <a href='https://zerotrusted.ai' target='_blank'>zerotrusted.ai</a>.</div>
                                <div class='zt-block-btns'>
                                    <button onclick='window.close();' class='zt-block-btn zt-block-btn-dismiss'>Dismiss</button>
                                </div>
                            </div>
                        </body>
                        </html>
                        """
                        flow.response = http.Response.make(
                            403,
                            block_html.encode('utf-8'),
                            {
                                "Content-Type": "text/html; charset=utf-8",
                                "X-ZT-Blocked": "1",
                                "X-ZT-Mode": "post-chat",
                                "X-ZT-Mode-Detail": "post-chat-pii",
                                "X-ZT-PII": "1",
                                "X-ZT-Toast": "1",
                                "X-ZT-PII-Keywords": ','.join(pii_keywords),
                                "X-ZT-PII-Threshold": str(threshold),
                            }
                        )
                        print("[ZT DEBUG] ENTERPRISE block response sent.")
                        return
                    else:
                        print("[ZT DEBUG] STANDALONE block page branch hit.")
                        # Standalone mode: generic block page
                        block_html = """
                        <html lang='en'>
                        <head>
                            <meta charset='UTF-8'>
                            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                            <title>Sensitive Information Detected</title>
                            <style>
                                body { background: #181c24; color: #fff; font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; height: 100vh; }
                                .zt-block-container { background: #23283a; border-radius: 12px; box-shadow: 0 4px 24px #0008; padding: 36px 32px; max-width: 440px; text-align: center; }
                                .zt-block-logo { width: 56px; height: 56px; margin-bottom: 18px; }
                                .zt-block-title { font-size: 1.5rem; font-weight: 600; margin-bottom: 10px; color: #eab308; }
                                .zt-block-msg { font-size: 1.1rem; margin-bottom: 18px; color: #e0e0e0; }
                                .zt-block-upgrade { margin-top: 10px; padding: 10px; background: rgba(234,179,8,.15); border-left: 3px solid #eab308; border-radius: 4px; font-size: 13px; }
                                .zt-block-upgrade b { color: #fbbf24; }
                                .zt-block-footer { font-size: 0.95rem; color: #aaa; margin-top: 18px; }
                                .zt-block-btns { margin-top: 18px; display: flex; gap: 10px; justify-content: flex-end; }
                                .zt-block-btn { background: #eab308; color: #000; font-weight: 600; border: none; border-radius: 4px; padding: 7px 16px; font-size: 14px; cursor: pointer; }
                                # DEBUG: Log every POST request's host and path at the very start
                                if method == 'POST':
                                    print(f"[ZT-DEBUG] POST received: host={flow.request.host}, path={flow.request.path}")
                                .zt-block-btn:hover { background: #fbbf24; }
                                .zt-block-btn-dismiss { background: #23283a; color: #fff; border: 1px solid #444; }
                                .zt-block-btn-dismiss:hover { background: #444; }
                                a { color: #7ecfff; text-decoration: none; }
                                a:hover { text-decoration: underline; }
                            </style>
                        </head>
                        <body>
                            <div class='zt-block-container'>
                                <img class='zt-block-logo' src='https://dev-identity.zerotrusted.ai/img/logo-with-tagline-white.png' alt='ZT'>
                                <div class='zt-block-title'>🛡️ Sensitive Information Detected</div>
                                <div class='zt-block-msg'>Your message was blocked because it contains potentially sensitive information such as names, email addresses, phone numbers, or financial data.</div>
                                <div class='zt-block-upgrade'>
                                    <b>⚡ Upgrade to Enterprise</b>
                                    <div style='margin-top:4px;opacity:.9'>Get custom policies, audit logs, team management, and priority support.<br>Sign up to unlock advanced features.</div>
                                </div>
                                <div class='zt-block-footer'>If you believe this is a mistake, contact your administrator or visit <a href='https://zerotrusted.ai' target='_blank'>zerotrusted.ai</a>.</div>
                                <div class='zt-block-btns'>
                                    <a href='https://zerotrusted.ai/enterprise' target='_blank' class='zt-block-btn'>Sign Up for Enterprise</a>
                                    <button onclick='window.close();' class='zt-block-btn zt-block-btn-dismiss'>Dismiss</button>
                                </div>
                            </div>
                        </body>
                        </html>
                        """
                        flow.response = http.Response.make(
                            403,
                            block_html.encode('utf-8'),
                            {
                                "Content-Type": "text/html; charset=utf-8",
                                "X-ZT-Blocked": "1",
                                "X-ZT-Mode": "post-chat",
                                "X-ZT-Mode-Detail": "post-chat-pii",
                                "X-ZT-PII": "1",
                                "X-ZT-Toast": "1",
                            }
                        )
                        print("[ZT DEBUG] STANDALONE block response sent.")
                        return
        # --- End of PII detection for chat POSTs ---

# Ensure mitmproxy loads the Interceptor addon
addons = [Interceptor()]
