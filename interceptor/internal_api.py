import os
import json
import re
import subprocess
import sys
import requests
import threading
import time
from mitmproxy import http
from auth.session_store import GLOBAL_SESSION_STORE
from services.session_manager import SessionManager

# Edition detection
EDITION = os.getenv('ZT_EDITION', 'standalone').lower()
IS_STANDALONE = (EDITION == 'standalone')
IS_ENTERPRISE = (EDITION == 'enterprise')

# Default ZeroTrusted service hosts that should bypass filtering/enforcement
BYPASS_HOSTS_DEFAULT = {
    'zerotrusted.ai',
    'dev-settings.zerotrusted.ai',
    'dev-gliner.zerotrusted.ai',
    'dev-history.zerotrusted.ai',
    'identity.zerotrusted.ai',
}


def get_bypass_hosts() -> set:
    hosts = set(BYPASS_HOSTS_DEFAULT)
    env_bypass = os.getenv('ZT_BYPASS_HOSTS')
    if env_bypass:
        for bh in re.split(r'[;,]', env_bypass):
            if bh and bh.strip():
                hosts.add(bh.strip().lower())
    return hosts


def has_internal_token(headers: dict) -> bool:
    try:
        return ('X-Custom-Token' in headers) or ('x-custom-token' in headers)
    except Exception:
        return False

# ------------------------------------------------------------
# Privacy service auto-restart helpers
# ------------------------------------------------------------
_privacy_watch_started = False
_privacy_watch_lock = threading.Lock()

def _launch_privacy_service(detached: bool = True) -> bool:
    """Attempt to start guardrails service using CLI or python -m.
    Returns True if any method launches without immediate FileNotFoundError."""
    candidates_cli = ["zt-guardrails-lib"]
    candidates_mod = ["zt_guardrails_lib"]
    creation_flags = 0
    if detached and sys.platform == 'win32':
        creation_flags = subprocess.DETACHED_PROCESS
    # Try CLIs
    for exe in candidates_cli:
        try:
            subprocess.Popen([exe], creationflags=creation_flags)
            return True
        except FileNotFoundError:
            continue
        except Exception:
            continue
    # Try python -m modules
    for mod in candidates_mod:
        try:
            subprocess.Popen([sys.executable, "-m", mod], creationflags=creation_flags)
            return True
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return False


def _privacy_service_healthy(base: str) -> bool:
    try:
        import requests as _r
        url_docs = base.rstrip('/') + '/docs'
        try:
            r = _r.get(url_docs, timeout=2, proxies={"http": None, "https": None})
            if r.status_code == 200:
                return True
        except Exception:
            r = _r.get(base, timeout=2, proxies={"http": None, "https": None})
            return 200 <= r.status_code < 500
    except Exception:
        return False
    return False

def _start_privacy_watcher(get_config_fn):
    global _privacy_watch_started
    with _privacy_watch_lock:
        if _privacy_watch_started:
            return
        _privacy_watch_started = True

    def _loop():
        base_env = os.getenv('ZT_FEATURES_URL') or 'http://0.0.0.0:8000'
        backoff = 5
        while True:
            try:
                cfg = {}
                try:
                    cfg = get_config_fn() or {}
                except Exception:
                    cfg = {}
                enabled_env = str(os.getenv('ZT_PRIVACY_AUTORESTART') or '').lower() in ('1','true','yes','on')
                enabled_cfg = str(cfg.get('auto_restart_privacy_service')).lower() in ('1','true','yes','on')
                if not (enabled_env or enabled_cfg):
                    time.sleep(10)
                    continue
                base = (cfg.get('features_url') or base_env)
                if not _privacy_service_healthy(base):
                    _launch_privacy_service(detached=True)
                    time.sleep(3)
                    backoff = min(backoff * 2, 60)
                else:
                    backoff = 5
                    time.sleep(15)
                    continue
            except Exception:
                time.sleep(backoff)
                continue
            time.sleep(backoff)

    t = threading.Thread(target=_loop, name='privacy-watchdog', daemon=True)
    t.start()


def handle_internal_request(
    flow: http.HTTPFlow,
    *,
    internal_only: bool,
    path: str,
    url: str,
    method: str,
    headers: dict,
    cors_headers: dict,
    ctx,
    metrics: dict,
    INTERCEPTED_LOG_FILE: str,
    CONFIG_FILE_PATH: str,
    UI_HTML: str,
    CONFIG_LAST_UPDATED,
    api_key: str,
    get_config,
    session_manager: SessionManager,
    get_blocklist,
    get_whitelist,
    get_features_cache_info,
    debug_log,
    features_started: bool,
    set_features_started,
    BLOCKLIST_TTL_SEC: int,
    get_blocklist_cache_info,
):
    """Handle all internal API/UI endpoints. If a response is written, return True.

    This consolidates UI, config, logs, metrics, blocklist, routing, whitelist-request,
    and features-health/start endpoints in one place.
    """


    # Ensure privacy watcher running (best-effort)
    try:
        _start_privacy_watcher(get_config)
    except Exception:
        pass

    # Root landing
    if internal_only and path == '/':
        body = (
            "<html><head><title>ZTProxy</title></head><body>"
            "<h3>ZT AI Proxy</h3>"

            "<p>Console: <a href='/zt-ui#status'>/zt-ui</a></p>"
            "</body></html>"
        )
        flow.response = http.Response.make(200, body.encode('utf-8'), {"Content-Type": "text/html; charset=utf-8"})
        return True

    # Favicon
    if internal_only and path == '/favicon.ico':
        flow.response = http.Response.make(204, b"", {"Content-Type": "image/x-icon"})
        return True

    # UI
    if internal_only and path.startswith('/zt-ui'):
        flow.response = http.Response.make(200, UI_HTML.encode('utf-8'), {"Content-Type": "text/html; charset=utf-8"})
        return True
    # Note: No /ui route. Console is only at /zt-ui to avoid collisions with vendor routes.

    # API Testing UI (Swagger-like interface)
    if internal_only and path.startswith('/api-test'):
        try:
            api_test_path = os.path.join(os.path.dirname(__file__), 'ui', 'api-test.html')
            with open(api_test_path, 'r', encoding='utf-8') as f:
                api_test_html = f.read()
            flow.response = http.Response.make(200, api_test_html.encode('utf-8'), {"Content-Type": "text/html; charset=utf-8"})
        except Exception as e:
            flow.response = http.Response.make(500, f"Error loading API test UI: {e}".encode('utf-8'), {"Content-Type": "text/plain; charset=utf-8"})
        return True

    # Debug endpoint to check API key status
    if internal_only and path.startswith('/debug/api-key'):
        cfg = get_config()
        cfg_key = cfg.get('proxy_api_key')
        env_key = os.getenv('ZT_PROXY_API_KEY')
        
        # Mask keys for security (show first/last 4 chars only)
        def mask_key(k):
            if not k or k == "MISSING":
                return k
            k = str(k)
            if len(k) <= 8:
                return "***"
            return f"{k[:4]}...{k[-4:]}"
        
        debug_info = {
            "api_key_parameter": mask_key(api_key),
            "api_key_parameter_raw": api_key if api_key == "MISSING" else ("present" if api_key else "empty"),
            "config_file_path": CONFIG_FILE_PATH,
            "config_key_present": bool(cfg_key),
            "config_key_value": mask_key(cfg_key),
            "env_key_present": bool(env_key),
            "env_key_value": mask_key(env_key),
            "final_resolution": mask_key(api_key)
        }
        
        flow.response = http.Response.make(
            200,
            json.dumps(debug_info, indent=2).encode('utf-8'),
            {**cors_headers, "Content-Type": "application/json"}
        )
        return True

    # Proxy endpoint for testing /shadow-ai API (avoids CORS issues)
    if internal_only and path.startswith('/test-shadow-ai'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'GET':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
            return True
        
        if not (api_key and api_key != "MISSING"):
            flow.response = http.Response.make(
                400,
                json.dumps({"error": "missing_api_key", "message": "Set ZT_PROXY_API_KEY"}).encode(),
                {**cors_headers, "Content-Type": "application/json"}
            )
            return True
        
        try:
            # Server-side request (no CORS issues)
            import requests
            response = requests.get(
                'https://dev-settings.zerotrusted.ai/api/v3/shadow-ai',
                headers={
                    'Accept': 'application/json',
                    'X-Custom-Token': api_key
                },
                timeout=10
            )
            
            # Forward the response
            flow.response = http.Response.make(
                response.status_code,
                response.content,
                {**cors_headers, "Content-Type": response.headers.get('Content-Type', 'application/json')}
            )
        except Exception as e:
            flow.response = http.Response.make(
                500,
                json.dumps({"error": "proxy_failed", "message": str(e)}).encode(),
                {**cors_headers, "Content-Type": "application/json"}
            )
        return True

    # Metrics
    if internal_only and path.startswith('/metrics'):
        try:
            # Add session store stats to metrics
            session_stats = GLOBAL_SESSION_STORE.stats()
            
            # Add session stats to metrics dict
            metrics_with_sessions = {
                **metrics,
                'sessions_active_current': session_stats['active'],
                'sessions_expired_pending': session_stats['expired'],
                'sessions_total': session_stats['total'],
                'sessions_max_limit': session_stats['max_sessions'],
                'sessions_idle_ttl_seconds': session_stats['idle_ttl'],
            }
            
            body = "\n".join(f"{k} {v}" for k, v in metrics_with_sessions.items()) + "\n"
        except Exception:
            body = ""
        flow.response = http.Response.make(200, body.encode('utf-8'), {"Content-Type": "text/plain; charset=utf-8"})
        return True

    # Liveness endpoint
    if internal_only and path == '/liveness':
        flow.response = http.Response.make(200, b'{"status": "ok"}', {"Content-Type": "application/json; charset=utf-8"})
        return True

    # Readiness endpoint
    if internal_only and path == '/readiness':
        # Optionally, add readiness checks here (e.g., config loaded, features started)
        ready = True
        # Example: ready = features_started and get_config() is not None
        flow.response = http.Response.make(200, b'{"ready": true}', {"Content-Type": "application/json; charset=utf-8"})
        return True

    # Comprehensive health check endpoint
    if internal_only and path == '/health':
        import time
        
        # Debug: Log health check start
        try:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"\n[HEALTH CHECK] Endpoint called at {time.time()}\n")
        except Exception:
            pass
        
        health_status = {
            "status": "healthy",
            "timestamp": int(time.time() * 1000),
            "components": {}
        }
        
        # 1. Check proxy core (always healthy if we can respond)
        try:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[HEALTH CHECK] Component 1/5: Proxy core - always healthy\n")
        except Exception:
            pass
        health_status["components"]["proxy"] = {
            "status": "healthy",
            "message": "Proxy is responding"
        }
        
        # 2. Check auth service (SSO identity service)
        auth_healthy = False
        auth_message = ""
        try:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[HEALTH CHECK] Component 2/5: Checking auth service at https://identity.zerotrusted.ai/health\n")
        except Exception:
            pass
        try:
            auth_response = requests.get(
                'https://identity.zerotrusted.ai/health',
                timeout=3,
                proxies={"http": None, "https": None}
            )
            auth_healthy = auth_response.status_code == 200
            auth_message = "Auth service reachable" if auth_healthy else f"Auth service returned {auth_response.status_code}"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Auth service: {auth_message} (status={auth_response.status_code})\n")
            except Exception:
                pass
        except requests.exceptions.Timeout:
            auth_message = "Auth service timeout (3s)"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Auth service: TIMEOUT\n")
            except Exception:
                pass
        except Exception as e:
            auth_message = f"Auth service error: {str(e)[:100]}"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Auth service: ERROR - {str(e)}\n")
            except Exception:
                pass
        
        health_status["components"]["auth"] = {
            "status": "healthy" if auth_healthy else "degraded",
            "message": auth_message
        }
        
        # 3. Check PII/Guardrails service
        cfg = get_config() or {}
        features_url = cfg.get('features_url') or os.getenv('ZT_FEATURES_URL') or 'http://0.0.0.0:8000'
        try:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[HEALTH CHECK] Component 3/5: Checking PII service at {features_url}/docs\n")
        except Exception:
            pass
        pii_healthy = False
        pii_message = ""
        try:
            pii_response = requests.get(
                f"{features_url.rstrip('/')}/docs",
                timeout=2,
                proxies={"http": None, "https": None}
            )
            pii_healthy = pii_response.status_code == 200
            pii_message = "PII service reachable" if pii_healthy else f"PII service returned {pii_response.status_code}"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] PII service: {pii_message} (status={pii_response.status_code})\n")
            except Exception:
                pass
        except requests.exceptions.Timeout:
            pii_message = "PII service timeout (2s)"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] PII service: TIMEOUT\n")
            except Exception:
                pass
        except Exception as e:
            pii_message = f"PII service unavailable: {str(e)[:100]}"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] PII service: ERROR - {str(e)}\n")
            except Exception:
                pass
        
        health_status["components"]["pii_service"] = {
            "status": "healthy" if pii_healthy else "unhealthy",
            "message": pii_message,
            "url": features_url
        }
        
        # 4. Check blocklist/features API
        api_healthy = False
        api_message = ""
        if api_key and api_key != "MISSING":
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Component 4/5: Checking blocklist API (API key present)\n")
            except Exception:
                pass
            try:
                api_response = requests.get(
                    'https://dev-settings.zerotrusted.ai/api/v3/shadow-ai',
                    headers={'X-Custom-Token': api_key},
                    timeout=5
                )
                api_healthy = api_response.status_code == 200
                api_message = "Blocklist API reachable" if api_healthy else f"Blocklist API returned {api_response.status_code}"
                try:
                    with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[HEALTH CHECK] Blocklist API: {api_message} (status={api_response.status_code})\n")
                except Exception:
                    pass
            except requests.exceptions.Timeout:
                api_message = "Blocklist API timeout (5s)"
                try:
                    with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[HEALTH CHECK] Blocklist API: TIMEOUT\n")
                except Exception:
                    pass
            except Exception as e:
                api_message = f"Blocklist API error: {str(e)[:100]}"
                try:
                    with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[HEALTH CHECK] Blocklist API: ERROR - {str(e)}\n")
                except Exception:
                    pass
        else:
            api_message = "No API key configured (optional)"
            api_healthy = None  # Not applicable
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Component 4/5: Blocklist API - No API key (optional)\n")
            except Exception:
                pass
        
        health_status["components"]["blocklist_api"] = {
            "status": "healthy" if api_healthy else ("degraded" if api_healthy is None else "unhealthy"),
            "message": api_message
        }
        
        # 5. Check session store
        try:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[HEALTH CHECK] Component 5/5: Checking session store\n")
        except Exception:
            pass
        try:
            session_stats = GLOBAL_SESSION_STORE.stats()
            session_healthy = True
            session_message = f"Active sessions: {session_stats['active']}/{session_stats['max_sessions']}"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Session store: {session_message}\n")
            except Exception:
                pass
        except Exception as e:
            session_healthy = False
            session_message = f"Session store error: {str(e)[:100]}"
            try:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[HEALTH CHECK] Session store: ERROR - {str(e)}\n")
            except Exception:
                pass
        
        health_status["components"]["sessions"] = {
            "status": "healthy" if session_healthy else "unhealthy",
            "message": session_message
        }
        
        # 6. Overall status determination
        critical_components = ["proxy", "pii_service"]
        degraded_components = []
        unhealthy_components = []
        
        for component, status_info in health_status["components"].items():
            if status_info["status"] == "unhealthy":
                unhealthy_components.append(component)
            elif status_info["status"] == "degraded":
                degraded_components.append(component)
        
        # Determine overall status
        if any(c in unhealthy_components for c in critical_components):
            health_status["status"] = "unhealthy"
            health_status["message"] = f"Critical component(s) unhealthy: {', '.join([c for c in critical_components if c in unhealthy_components])}"
        elif unhealthy_components:
            health_status["status"] = "degraded"
            health_status["message"] = f"Non-critical component(s) unhealthy: {', '.join(unhealthy_components)}"
        elif degraded_components:
            health_status["status"] = "degraded"
            health_status["message"] = f"Component(s) degraded: {', '.join(degraded_components)}"
        else:
            health_status["status"] = "healthy"
            health_status["message"] = "All systems operational"
        
        # Return appropriate HTTP status code based on health
        status_code = 200 if health_status["status"] == "healthy" else (503 if health_status["status"] == "unhealthy" else 200)
        
        # Debug: Log final health status
        try:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[HEALTH CHECK] Final status: {health_status['status']} (HTTP {status_code})\n")
                lf.write(f"[HEALTH CHECK] Components summary: {len(health_status['components'])} checked\n")
                lf.write(f"[HEALTH CHECK] Unhealthy: {unhealthy_components}\n")
                lf.write(f"[HEALTH CHECK] Degraded: {degraded_components}\n")
                lf.write(f"[HEALTH CHECK] Returning response...\n\n")
        except Exception:
            pass
        
        flow.response = http.Response.make(
            status_code,
            json.dumps(health_status, indent=2).encode('utf-8'),
            {**cors_headers, "Content-Type": "application/json; charset=utf-8"}
        )
        return True

    # Mock login (temporary SSO stand-in)
    if internal_only and path.startswith('/mock-login'):
        # Always (re)create a session for mock user
        user_id = 'femi@zerotrusted.ai'
        sid = GLOBAL_SESSION_STORE.create_session(user_id)
        cookie_hdr = f"zt_sess={sid}; Path=/; HttpOnly"

        flow.response = http.Response.make(302, b"", {"Set-Cookie": cookie_hdr, "Location": "/zt-ui#auth"})
        return True

    # Ignore status endpoint
    # Note: This endpoint must work via proxied domain (e.g., https://chatgpt.com/ignore-status)
    # so we don't check internal_only
    if path.startswith('/ignore-status'):
        cfg_view = get_config() or {}
        sess = session_manager.get_session_for_internal_endpoint(headers, cfg_view)
        disable_auth = session_manager._is_auth_disabled(cfg_view)
        
        if sess:
            data = {
                "authenticated": True,
                "user_id": sess.user_id,
                "ignore_remaining": sess.ignore_remaining,
                "ignore_limit": sess.ignore_limit,
            }
            if disable_auth:
                data["auth_disabled"] = True
        else:
            data = {"authenticated": False}
        flow.response = http.Response.make(200, json.dumps(data).encode(), {**cors_headers, "Content-Type": "application/json"})
        return True

    # Ignore start (initialize if needed; returns remaining)
    # Note: This endpoint must work via proxied domain (e.g., https://chatgpt.com/ignore-start)
    # so we don't check internal_only
    if path.startswith('/ignore-start'):
        if method == 'OPTIONS':
            # Add cache-control to prevent browser caching CORS preflight failures
            flow.response = http.Response.make(200, b"", {**cors_headers, "Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"})
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        
        # Use SessionManager to retrieve session (handles anonymous sessions)
        cfg_view = get_config() or {}
        disable_auth = cfg_view.get('disable_auth', False)
        sess = session_manager.get_session_for_internal_endpoint(headers, cfg_view)
        
        # Debug logging
        try:
            x_zt_session = headers.get('X-ZT-Session') or headers.get('x-zt-session') or 'none'
            cookie = headers.get('Cookie') or headers.get('cookie') or 'none'
            has_zt_sess = 'zt_sess=' in cookie
            with open(session_manager.log_file, 'a', encoding='utf-8') as lf:
                lf.write(f"[IGNORE-START DEBUG] sess={sess is not None} x-zt-session={x_zt_session[:20] if x_zt_session != 'none' else 'none'} has_zt_sess={has_zt_sess} disable_auth={disable_auth}\n")
                if sess:
                    lf.write(f"[IGNORE-START DEBUG] session_id={sess.session_id} user={sess.user_id} ignore_remaining={sess.ignore_remaining}\n")
        except Exception:
            pass
        
        # If auth is disabled and no session found, create anonymous session with fallback identifier
        if not sess and disable_auth:
            # Use client IP as fallback identifier for anonymous users
            client_ip = flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else "unknown"
            fallback_user_id = f"anonymous_{client_ip}"
            
            try:
                with open(session_manager.log_file, 'a', encoding='utf-8') as lf:
                    lf.write(f"[IGNORE-START] Creating anonymous session for {fallback_user_id}\n")
            except Exception:
                pass
            
            # Create or get anonymous session for this IP
            sess = GLOBAL_SESSION_STORE.get_or_create_anonymous_session(fallback_user_id)
        
        if not sess:
            # Only return error if auth is enabled and no session found
            error_detail = {
                "error": "not_authenticated",
                "message": "No session found. Either log in via /mock-login, or enable disable_auth in config for anonymous access.",
                "has_x_zt_session": bool(headers.get('X-ZT-Session') or headers.get('x-zt-session')),
                "has_cookie": 'zt_sess=' in (headers.get('Cookie') or ''),
                "disable_auth": disable_auth
            }
            flow.response = http.Response.make(401, json.dumps(error_detail).encode(), {**cors_headers, "Content-Type": "application/json"})
            return True
        
        # Add an ignore token when user clicks "Proceed Anyway"
        # This grants the user one bypass for their next request
        added = GLOBAL_SESSION_STORE.add_ignore(sess.session_id, count=1)
        if not added:
            # Session expired
            flow.response = http.Response.make(403, json.dumps({"error": "session_expired", "ignore_remaining": 0}).encode(), {**cors_headers, "Content-Type": "application/json"})
            return True
        
        # Return updated count after addition
        # Need to refresh session to get updated count
        sess = GLOBAL_SESSION_STORE.get_session(sess.session_id, touch=False)
        remaining = sess.ignore_remaining if sess else 0
        flow.response = http.Response.make(200, json.dumps({"ignore_remaining": remaining, "added": True}).encode(), {**cors_headers, "Content-Type": "application/json"})
        return True

    # Session status check endpoint: GET /session-status with X-ZT-Session-Id header
    if internal_only and path.startswith('/session-status'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'GET':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
            return True
        
        session_id = headers.get('X-ZT-Session-Id') or headers.get('x-zt-session-id')
        if session_id:
            sess = GLOBAL_SESSION_STORE.get_session(session_id, touch=False)
            if sess:
                response_data = {
                    "valid": True,
                    "user": sess.user_id,
                    "session_id": session_id
                }
                flow.response = http.Response.make(200, json.dumps(response_data).encode(), {**cors_headers, "Content-Type": "application/json"})
                return True
        
        # Session not found or invalid
        response_data = {"valid": False, "session_id": session_id or None}
        flow.response = http.Response.make(200, json.dumps(response_data).encode(), {**cors_headers, "Content-Type": "application/json"})
        return True

    # SSO establish endpoint: accepts POST { "email": "...", "tid": "...", "auth_token": "..." } and creates a session
    if internal_only and path.startswith('/sso-establish'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        try:
            raw = flow.request.get_text(strict=False) or '{}'
            data = json.loads(raw)
            email = (data.get('email') or '').strip()
            tid = (data.get('tid') or '').strip()
            auth_token = (data.get('auth_token') or data.get('jwt') or '').strip()  # Accept both field names
            
            # Log SSO establish attempt with full details
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"\n{'='*80}\n")
                lf.write(f"[SSO ESTABLISH] New SSO authentication request\n")
                lf.write(f"[SSO ESTABLISH] Email: {email}\n")
                lf.write(f"[SSO ESTABLISH] Tenant ID: {tid}\n")
                lf.write(f"[SSO ESTABLISH] Auth token in request: {'YES ✓' if auth_token else 'NO ✗'}\n")
                if auth_token:
                    token_preview = auth_token[:20] + '...' if len(auth_token) > 20 else auth_token
                    lf.write(f"[SSO ESTABLISH] Token preview: {token_preview}\n")
                    lf.write(f"[SSO ESTABLISH] Token length: {len(auth_token)} chars\n")
                lf.write(f"[SSO ESTABLISH] Request payload keys: {list(data.keys())}\n")
            
            if not email:
                flow.response = http.Response.make(400, json.dumps({"error":"missing_email"}).encode(), {**cors_headers, "Content-Type":"application/json"})
                return True
            
            # Create session with JWT token (if provided)
            sid = GLOBAL_SESSION_STORE.create_session(email)
            
            # Store JWT token if provided
            if auth_token:
                GLOBAL_SESSION_STORE.set_session_auth_token(sid, auth_token)
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[SSO ESTABLISH] ✓ Session created with JWT token\n")
                    lf.write(f"[SSO ESTABLISH] Session ID: {sid}\n")
                    lf.write(f"[SSO ESTABLISH] User: {email}\n")
                    lf.write(f"[SSO ESTABLISH] Auth method: JWT (user settings will be fetched)\n")
                    lf.write(f"{'='*80}\n\n")
            else:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[SSO ESTABLISH] ⚠ Session created WITHOUT JWT token\n")
                    lf.write(f"[SSO ESTABLISH] Session ID: {sid}\n")
                    lf.write(f"[SSO ESTABLISH] User: {email}\n")
                    lf.write(f"[SSO ESTABLISH] Auth method: API_KEY_FALLBACK\n")
                    lf.write(f"[SSO ESTABLISH] ⚠ User settings cannot be fetched (no JWT)\n")
                    lf.write(f"[SSO ESTABLISH] 💡 Browser extension should send 'auth_token' or 'jwt' field\n")
                    lf.write(f"{'='*80}\n\n")
            
            cookie_hdr = f"zt_sess={sid}; Path=/; HttpOnly"
            response_data = {
                "ok": True, 
                "user": email, 
                "tenant": tid, 
                "session_id": sid,
                "auth_method": "jwt" if auth_token else "api_key"
            }
            flow.response = http.Response.make(200, json.dumps(response_data).encode(), {**cors_headers, "Content-Type":"application/json", "Set-Cookie": cookie_hdr})
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[SSO ESTABLISH ERROR] {str(e)}\n")
                lf.write(f"[SSO ESTABLISH ERROR TRACEBACK]\n{error_detail}\n")
            flow.response = http.Response.make(500, json.dumps({"error":"sso_failed","message":str(e),"traceback":error_detail}).encode(), {**cors_headers, "Content-Type":"application/json"})
        return True

    # Update session JWT token endpoint: POST { "session_id": "...", "auth_token": "..." }
    if internal_only and path.startswith('/sso-update-token'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        try:
            raw = flow.request.get_text(strict=False) or '{}'
            data = json.loads(raw)
            session_id = (data.get('session_id') or '').strip()
            auth_token = (data.get('auth_token') or data.get('jwt') or '').strip()
            
            if not session_id:
                flow.response = http.Response.make(400, json.dumps({"error":"missing_session_id"}).encode(), {**cors_headers, "Content-Type":"application/json"})
                return True
            
            if not auth_token:
                flow.response = http.Response.make(400, json.dumps({"error":"missing_auth_token"}).encode(), {**cors_headers, "Content-Type":"application/json"})
                return True
            
            # Update session with JWT token
            success = GLOBAL_SESSION_STORE.set_session_auth_token(session_id, auth_token)
            
            if success:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[SSO TOKEN UPDATE] session={session_id} auth_method=JWT\n")
                flow.response = http.Response.make(200, json.dumps({"ok": True, "message": "JWT token updated"}).encode(), {**cors_headers, "Content-Type":"application/json"})
            else:
                flow.response = http.Response.make(404, json.dumps({"error":"session_not_found","message":"Session expired or does not exist"}).encode(), {**cors_headers, "Content-Type":"application/json"})
        except Exception as e:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[SSO TOKEN UPDATE ERROR] {str(e)}\n")
            flow.response = http.Response.make(500, json.dumps({"error":"update_failed","message":str(e)}).encode(), {**cors_headers, "Content-Type":"application/json"})
        return True

    # Disconnect endpoint: clears session on server side
    if internal_only and path.startswith('/disconnect'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        try:
            # Extract session ID from X-ZT-Session header or zt_sess cookie
            session_id = None
            
            # Check header first
            for k, v in flow.request.headers.items():
                if k.lower() == 'x-zt-session':
                    session_id = v
                    break
            
            # Fallback to cookie
            if not session_id:
                cookie_header = flow.request.headers.get('cookie', '')
                for cookie in cookie_header.split(';'):
                    if 'zt_sess=' in cookie:
                        session_id = cookie.split('zt_sess=')[1].split(';')[0].strip()
                        break
            
            if session_id:
                # Remove session from store
                GLOBAL_SESSION_STORE.remove_session(session_id)
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[DISCONNECT] session={session_id} cleared\n")
                
                # Clear cookie
                clear_cookie = "zt_sess=; Path=/; HttpOnly; Max-Age=0"
                flow.response = http.Response.make(200, json.dumps({"ok": True, "message": "Session cleared"}).encode(), {**cors_headers, "Content-Type":"application/json", "Set-Cookie": clear_cookie})
            else:
                # No session to clear
                flow.response = http.Response.make(200, json.dumps({"ok": True, "message": "No active session"}).encode(), {**cors_headers, "Content-Type":"application/json"})
        except Exception as e:
            with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[DISCONNECT ERROR] {str(e)}\n")
            flow.response = http.Response.make(500, json.dumps({"error":"disconnect_failed","message":str(e)}).encode(), {**cors_headers, "Content-Type":"application/json"})
        return True

    # Logs tail
    if internal_only and path.startswith('/logs'):
        try:
            from urllib.parse import parse_qs, urlsplit as _urlsplit
            qs = parse_qs(_urlsplit(url).query or '')
            n = int((qs.get('n') or ['300'])[0])
            n = max(1, min(5000, n))
        except Exception:
            n = 300
        try:
            if os.path.exists(INTERCEPTED_LOG_FILE):
                with open(INTERCEPTED_LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-n:]
                txt = "".join(lines)
            else:
                txt = "(no log file yet)"
        except Exception as e:
            txt = f"Log read error: {e}"
        flow.response = http.Response.make(200, txt.encode('utf-8', errors='ignore'), {"Content-Type": "text/plain; charset=utf-8"})
        return True
    
    # Clear PII cache endpoint
    if internal_only and path.startswith('/clear-pii-cache'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'POST':
            try:
                from tools.runtime_helpers import clear_pii_cache
                clear_pii_cache()
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[CACHE] PII cache cleared\n")
                flow.response = http.Response.make(200, json.dumps({"ok": True, "message": "PII cache cleared"}).encode(), {**cors_headers, "Content-Type":"application/json"})
            except Exception as e:
                with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[CACHE] Clear error: {str(e)}\n")
                flow.response = http.Response.make(500, json.dumps({"error":"clear_failed","message":str(e)}).encode(), {**cors_headers, "Content-Type":"application/json"})
        else:
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
        return True

    # Config
    # Auth status endpoint - check if current session is authenticated
    if internal_only and path.startswith('/auth-status'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'GET':
            # Look up session from headers/cookies
            headers_dict = {k: v for k, v in flow.request.headers.items()}
            user_session = session_manager._lookup_authenticated_session(headers_dict)
            is_authenticated = session_manager.is_session_authenticated(user_session)
            
            response_data = {
                "authenticated": is_authenticated,
                "email": user_session.user_id if (user_session and is_authenticated) else None,
                "session_id": user_session.session_id[:10] + "..." if (user_session and user_session.session_id) else None
            }
            
            flow.response = http.Response.make(
                200, 
                json.dumps(response_data).encode(), 
                {**cors_headers, "Content-Type": "application/json"}
            )
            return True
    
    if internal_only and path.startswith('/config'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'GET':
            cfg_view = get_config()
            # Prefer file mtime for last_updated if available
            try:
                import datetime, os as _os
                ts = _os.path.getmtime(CONFIG_FILE_PATH) if _os.path.exists(CONFIG_FILE_PATH) else None
                last_upd = datetime.datetime.utcfromtimestamp(ts).isoformat()+"Z" if ts else CONFIG_LAST_UPDATED
            except Exception:
                last_upd = CONFIG_LAST_UPDATED
            
            # Check if Redis cache is available
            from tools.config_cache import get_config_cache
            config_cache = get_config_cache(file_path=CONFIG_FILE_PATH)
            cache_status = "redis" if config_cache.is_redis_available() else "file"
            
            # Get edition from environment
            edition = os.environ.get('ZT_EDITION', 'standalone').lower()
            
            resp = {
                "status": "ok",
                "config": cfg_view,
                "last_updated": last_upd,
                "config_path": CONFIG_FILE_PATH,
                "cache_backend": cache_status,
                "edition": edition
            }
            flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
            return True
        if method == 'POST':
            body_text = flow.request.get_text() or '{}'
            try:
                data = json.loads(body_text)
            except Exception as e:
                flow.response = http.Response.make(400, f"Invalid JSON: {e}".encode(), {**cors_headers, "Content-Type": "text/plain; charset=utf-8"})
                return True
            # Merge-on-write: load existing then update
            try:
                # Import config cache
                from tools.config_cache import get_config_cache
                config_cache = get_config_cache(file_path=CONFIG_FILE_PATH)
                
                # Get existing config from Redis ONLY
                existing = config_cache.get() or {}
                
                # Update existing with new keys
                if isinstance(data, dict):
                    existing.update({k: v for k, v in data.items() if v is not None})
                
                # Save to Redis ONLY with longer TTL to ensure it persists
                saved = config_cache.set(existing, ttl=86400)  # 24 hour TTL
                
                if not saved:
                    error_msg = f"Failed to save config to Redis. Redis available: {config_cache.is_redis_available()}"
                    print(f"[CONFIG ERROR] {error_msg}", file=sys.stderr)
                    flow.response = http.Response.make(500, json.dumps({
                        "status": "error",
                        "message": error_msg,
                        "redis_available": config_cache.is_redis_available()
                    }).encode(), {**cors_headers, "Content-Type": "application/json"})
                    return True
                
                # Update OS environment variables if features_url is set
                try:
                    if 'features_url' in existing and existing['features_url']:
                        os.environ['ZT_FEATURES_URL'] = str(existing['features_url'])
                        print(f"[CONFIG] Updated ZT_FEATURES_URL env to: {existing['features_url']}", file=sys.stderr)
                    if 'proxy_api_key' in existing and existing['proxy_api_key']:
                        os.environ['ZT_PROXY_API_KEY'] = str(existing['proxy_api_key'])
                    if 'features_bearer' in existing and existing['features_bearer']:
                        os.environ['ZT_FEATURES_BEARER'] = str(existing['features_bearer'])
                except Exception as env_err:
                    print(f"[CONFIG] Warning: Could not update ENV vars: {env_err}", file=sys.stderr)
                
                from datetime import datetime, timezone
                new_ts = datetime.now(timezone.utc).isoformat()
                resp_obj = {
                    "status": "ok",
                    "saved": True,
                    "mode": existing.get('filter_mode'),
                    "enforcement_mode": existing.get('enforcement_mode'),
                    "include_request_body": existing.get('include_request_body'),
                    "disable_auth": existing.get('disable_auth'),
                    "scan_uploads": existing.get('scan_uploads'),
                    "strict_block_all_uploads": existing.get('strict_block_all_uploads'),
                    "use_remote_blocklist": existing.get('use_remote_blocklist'),
                    "proxy_api_key": existing.get('proxy_api_key'),
                    "features_url": existing.get('features_url'),
                    "features_pii_url": existing.get('features_pii_url'),
                    "features_bearer": existing.get('features_bearer'),
                    "last_updated": new_ts,
                }
                flow.response = http.Response.make(200, json.dumps(resp_obj).encode(), {**cors_headers, "Content-Type": "application/json"})
                try:
                    with open(INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"\n[CONFIG] {resp_obj}\n")
                except Exception:
                    pass
            except Exception as e:
                flow.response = http.Response.make(500, f"Write error: {e}".encode(), {**cors_headers, "Content-Type": "text/plain; charset=utf-8"})
            return True
        flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, POST, OPTIONS"})
        return True
    
    # Debug endpoint to check Redis connection and current config
    if internal_only and path == '/config/debug':
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        from tools.config_cache import get_config_cache
        config_cache = get_config_cache(file_path=CONFIG_FILE_PATH)
        
        # Get current config
        current_config = get_config()
        redis_config = config_cache.get()
        
        debug_info = {
            "redis_available": config_cache.is_redis_available(),
            "redis_url_set": bool(os.getenv('REDIS_URL')),
            "current_config": current_config,
            "redis_config": redis_config if redis_config else None,
            "config_file_path": CONFIG_FILE_PATH,
            "config_file_exists": os.path.exists(CONFIG_FILE_PATH)
        }
        
        flow.response = http.Response.make(200, json.dumps(debug_info, indent=2).encode(), {**cors_headers, "Content-Type": "application/json"})
        return True

    # Simple page to test Sensitive Keywords anonymization
    if internal_only and path == '/test-pii':
        page = (
            """
            <!doctype html>
            <html><head><meta charset='utf-8'/><title>PII Anonymize Test</title>
            <style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1220;color:#e6ecf3;margin:0;padding:20px}
            textarea,input,button{font:inherit} textarea{width:100%;height:140px;background:#0f172a;color:#e6ecf3;border:1px solid #23324e;border-radius:8px;padding:10px;box-sizing:border-box}
            .wrap{max-width:860px;margin:0 auto} .row{display:flex;gap:10px;align-items:center;margin-top:10px}
            button{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:8px 12px;cursor:pointer}
            pre{background:#0f172a;border:1px solid #23324e;border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap}
            a{color:#81b9ff}
            </style></head><body>
            <div class=wrap>
              <h2>Test Sensitive Keywords (Anonymize)</h2>
              <p>Enter text below and submit. This calls <code>get_anonymized_prompt</code> and shows the result.</p>
              <textarea id=prompt placeholder="Type here...">My name is John Doe and my email is john.doe@example.com</textarea>
              <div class=row>
                <button id=submit>Submit</button>
                <span id=status class=note></span>
              </div>
              <h3>Result</h3>
              <pre id=out>(none)</pre>
              <p><a href="/zt-ui#docs">Back to Console</a></p>
            </div>
            <script>
            const $=id=>document.getElementById(id);
            $('submit').addEventListener('click', async ()=>{
                const prompt = $('prompt').value || '';
                $('status').textContent = 'Running...';
                $('out').textContent = '';
                try{
                    const r = await fetch('/pii-anonymize', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt})});
                    const ct = r.headers.get('content-type')||'';
                    if(ct.includes('application/json')){
                        const j = await r.json();
                        $('out').textContent = JSON.stringify(j, null, 2);
                    } else {
                        $('out').textContent = await r.text();
                    }
                    $('status').textContent = r.ok ? 'Done' : ('HTTP '+r.status);
                }catch(e){ $('status').textContent='Error'; $('out').textContent=String(e); }
            });
            </script>
            </body></html>
            """
        )
        flow.response = http.Response.make(200, page.encode('utf-8'), {"Content-Type": "text/html; charset=utf-8"})
        return True

    # Backend endpoint to call zt-guardrails-lib anonymizer (HTTP service first, then library fallback)
    if internal_only and path.startswith('/pii-anonymize'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        try:
            body_text = flow.request.get_text() or '{}'
            data = {}
            try:
                data = json.loads(body_text)
            except Exception:
                pass
            prompt = (data.get('prompt') or '').strip()
            if not prompt:
                flow.response = http.Response.make(400, json.dumps({"error":"missing_prompt"}).encode(), {**cors_headers, "Content-Type": "application/json"})
                return True
            # Try local/remote HTTP service first (zt-guardrails-lib FastAPI; default 0.0.0.0:8000)
            try:
                base = os.getenv('ZT_FEATURES_URL') or 'http://0.0.0.0:8000'
                headers_http = {"accept": "application/json"}
                
                # Get auth bearer - fallback to proxy API key if bearer not set
                bearer = os.getenv('ZT_FEATURES_BEARER')
                if not bearer:
                    # Try to get from config
                    try:
                        cfg = get_config_fn() or {}
                        bearer = (str(cfg.get('features_bearer') or '').strip()) or None
                        if not bearer:
                            # Fallback to proxy_api_key from config or ZT_PROXY_API_KEY env
                            bearer = (str(cfg.get('proxy_api_key') or '').strip()) or os.getenv('ZT_PROXY_API_KEY') or None
                    except Exception:
                        # Last resort: try ZT_PROXY_API_KEY env directly
                        bearer = os.getenv('ZT_PROXY_API_KEY') or None
                
                if bearer:
                    headers_http["Authorization"] = f"Bearer {bearer}"
                # 1) Preferred: /detect-pii (JSON), supported by current zt-guardrails-lib
                try:
                    url_detect = base.rstrip('/') + "/detect-pii"
                    r = requests.post(url_detect, json={"prompt": prompt, "text": prompt}, headers={**headers_http, "Content-Type": "application/json"}, timeout=20)
                except Exception:
                    r = None
                if r is not None and r.ok:
                    text = r.text or "{}"
                    try:
                        j = json.loads(text)
                    except Exception:
                        j = {"raw": text}
                    flow.response = http.Response.make(200, json.dumps(j).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
                    return True
                # 2) Fallback: older multipart endpoint
                try:
                    svc_url = base.rstrip('/') + "/get-anonymized-prompts-with-models"
                    files = {
                        "pii_entities": (None, "email, email address, gmail, person, organization, phone number, address, passport number, credit card number, social security number, health insurance id number, itin, date time, us passport_number, date, time, crypto currency number, url, date of birth, mobile phone number, bank account number, medication, cpf, driver's license number, tax identification number, medical condition, identity card number, national id number, ip address, iban, credit card expiration date, username, health insurance number, registration number, student id number, insurance number, flight number, landline phone number, blood type, cvv, reservation number, digital signature, social media handle, license plate number, cnpj, postal code, serial number, vehicle registration number, credit card brand, fax number, visa number, insurance company, identity document number, transaction number, national health insurance number, cvc, birth certificate number, train ticket number, passport expiration date, social_security_number, medical license"),
                        "prompt": (None, prompt),
                        "anonymize_keywords": (None, ""),
                        "keyword_safeguard": (None, "test, deteyryrysad asd"),
                        "uploaded_file": (None, ""),
                        "do_not_anonymize_keywords": (None, ""),
                    }
                    r2 = requests.post(svc_url, files=files, headers=headers_http, timeout=20)
                    if r2.ok:
                        text = r2.text or "{}"
                        try:
                            j = json.loads(text)
                        except Exception:
                            j = {"raw": text}
                        flow.response = http.Response.make(200, json.dumps(j).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
                        return True
                except Exception:
                    pass
            except Exception:
                # Fall through to library import fallback
                pass

            # Library fallback if HTTP service not available
            try:
                import asyncio as _asyncio
                _imp_err_last = None
                _mod_path = 'zt_guardrails_lib.tools.pii_detection.detect_pii'
                try:
                    _m = __import__(_mod_path, fromlist=['get_anonymized_prompt'])
                    _zt_get = getattr(_m, 'get_anonymized_prompt')
                except Exception as _e:
                    _imp_err_last = _e
                    _zt_get = None
                if not _zt_get:
                    raise ModuleNotFoundError(str(_imp_err_last) if _imp_err_last else 'guardrails lib module not found')
                try:
                    result_obj = _asyncio.run(_zt_get(prompt=prompt))
                except RuntimeError:
                    # If an event loop is running, create a new one
                    loop = _asyncio.new_event_loop()
                    try:
                        result_obj = loop.run_until_complete(_zt_get(prompt=prompt))
                    finally:
                        try:
                            loop.close()
                        except Exception:
                            pass
                if hasattr(result_obj, 'model_dump'):
                    result = result_obj.model_dump()
                elif hasattr(result_obj, 'dict'):
                    result = result_obj.dict()
                elif isinstance(result_obj, dict):
                    result = result_obj
                else:
                    try:
                        result = json.loads(json.dumps(result_obj, default=lambda o: getattr(o, '__dict__', str(o))))
                    except Exception:
                        result = {"success": False, "error_message": "Unsupported result type"}
                flow.response = http.Response.make(200, json.dumps(result).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
            except ModuleNotFoundError:
                flow.response = http.Response.make(500, json.dumps({"error":"missing_dependency","message":"PII service not reachable (set ZT_FEATURES_URL and optionally ZT_FEATURES_BEARER or start zt-guardrails-lib) and zt-guardrails-lib not importable. Install with: pip install zt-guardrails-lib"}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
            except Exception as e:
                flow.response = http.Response.make(500, json.dumps({"error":"anonymize_failed","message":str(e)}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
        except Exception as e:
            flow.response = http.Response.make(500, json.dumps({"error":"bad_request","message":str(e)}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
        return True

    # Test endpoint for detect_pii_remote (remote API)
    if internal_only and path.startswith('/test-pii-remote'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        try:
            body_text = flow.request.get_text() or '{}'
            data = json.loads(body_text)
            text = data.get('text') or data.get('prompt') or ''
            threshold = int(data.get('threshold', 3))
            categories = data.get('categories') or ['PII', 'PHI', 'PCI']
            
            if not text:
                flow.response = http.Response.make(
                    400,
                    json.dumps({"error": "missing_text", "message": "Text parameter required"}).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
                return True
            
            # Call detect_pii_remote
            from services.pii_fast import detect_pii_remote
            result = detect_pii_remote(text, threshold=threshold, categories=categories)
            
            flow.response = http.Response.make(
                200,
                json.dumps(result).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
        except Exception as e:
            flow.response = http.Response.make(
                500,
                json.dumps({"error": "test_failed", "message": str(e)}).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
        return True

    # Test endpoint for detect_pii_fast (local features service)
    if internal_only and path.startswith('/test-pii-fast'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        try:
            body_text = flow.request.get_text() or '{}'
            data = json.loads(body_text)
            text = data.get('text') or data.get('prompt') or ''
            threshold = int(data.get('threshold', 3))
            categories = data.get('categories') or ['PII', 'PHI', 'PCI']
            
            if not text:
                flow.response = http.Response.make(
                    400,
                    json.dumps({"error": "missing_text", "message": "Text parameter required"}).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
                return True
            
            # Call detect_pii_fast
            from services.pii_fast import detect_pii_fast
            result = detect_pii_fast(text, threshold=threshold, categories=categories)
            
            flow.response = http.Response.make(
                200,
                json.dumps(result).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
        except Exception as e:
            flow.response = http.Response.make(
                500,
                json.dumps({"error": "test_failed", "message": str(e)}).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
        return True

    # Features health
    if internal_only and path.startswith('/features-health'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        try:
            ok = False
            try:
                base = os.getenv('ZT_FEATURES_URL') or 'http://0.0.0.0:8000'
                # Prefer /docs (FastAPI), otherwise try base
                url_docs = base.rstrip('/') + '/docs'
                try:
                    r = requests.get(url_docs, timeout=2)
                    ok = (r.status_code == 200)
                except Exception:
                    r = requests.get(base, timeout=2)
                    ok = (200 <= r.status_code < 500)
            except Exception:
                ok = False
            resp = {"running": bool(ok), "attempted_autostart": bool(features_started)}
            flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
        except Exception as e:
            flow.response = http.Response.make(500, f"{e}".encode('utf-8'), {**cors_headers, "Content-Type": "text/plain; charset=utf-8"})
        return True

    # Manual privacy start (new endpoint)
    if internal_only and path.startswith('/privacy-start'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        try:
            ok = _launch_privacy_service(detached=True)
            flow.response = http.Response.make(200 if ok else 500, json.dumps({"started": bool(ok)}).encode(), {**cors_headers, "Content-Type": "application/json"})
        except Exception as e:
            flow.response = http.Response.make(500, json.dumps({"error": "start_failed", "message": str(e)}).encode(), {**cors_headers, "Content-Type": "application/json"})
        return True

    # Start features (legacy name kept for backward compatibility)
    if internal_only and path.startswith('/start-features'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        try:
            ok = _launch_privacy_service(detached=True)
            set_features_started(True)
            flow.response = http.Response.make(200 if ok else 500, json.dumps({"started": bool(ok)}).encode(), {**cors_headers, "Content-Type": "application/json"})
        except Exception as e:
            flow.response = http.Response.make(500, f"Start error: {e}".encode('utf-8'), {**cors_headers, "Content-Type": "text/plain; charset=utf-8"})
        return True

    # Blocklist status/refresh
    if internal_only and path.startswith('/blocklist'):
        from time import time as __t
        from urllib.parse import parse_qs, urlsplit
        
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
            
        if method == 'GET':
            # Check for ?force=true query param
            try:
                qs = parse_qs(urlsplit(url).query or '')
                force = (qs.get('force') or ['false'])[0].lower() in ('true', '1', 'yes')
            except Exception:
                force = False
            
            # Without force=true: return status info only (for UI status display)
            if not force:
                cfg_view = get_config()
                _urb = cfg_view.get('use_remote_blocklist')
                enabled = True if _urb is None else (str(_urb).lower() in ("1","true","yes","on") or (_urb is True))
                token_present = bool(api_key and api_key != "MISSING")
                
                # Get cache info
                try:
                    info = get_blocklist_cache_info() or {}
                    ts = float(info.get('ts') or 0.0)
                    count = int(info.get('count') or 0)
                    age = None
                    if ts:
                        try:
                            age = max(0, int(__t() - ts))
                        except Exception:
                            age = None
                except Exception:
                    age = None
                    count = 0
                
                resp = {
                    "status": "ok",
                    "enabled": enabled,
                    "token_present": token_present,
                    "count": count,
                    "age_seconds": age,
                    "ttl_seconds": BLOCKLIST_TTL_SEC
                }
                flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
                return True
            
            # With force=true: return full data (requires API key)
            if not (api_key and api_key != "MISSING"):
                flow.response = http.Response.make(
                    400,
                    json.dumps({"error": "missing_api_key", "message": "API key required for blocklist data fetch"}).encode(),
                    {**cors_headers, "Content-Type": "application/json"}
                )
                return True
            try:
                # API key only - no JWT needed for blocklist
                # Check what the service returns (might contain error info)
                from services.get_blocklist_service import get_block_features
                raw_result = get_block_features(api_key=api_key)
                
                # Check if there was an error
                if isinstance(raw_result, dict) and raw_result.get("error"):
                    resp = {
                        "refreshed": force,
                        "remote": True,
                        "error": raw_result.get("error"),
                        "message": raw_result.get("message"),
                        "status": raw_result.get("status"),
                        "black_count": 0,
                        "white_count": 0,
                        "black": [],
                        "white": [],
                    }
                    flow.response = http.Response.make(
                        raw_result.get("status", 500),
                        json.dumps(resp).encode(),
                        {**cors_headers, "Content-Type": "application/json"}
                    )
                    return True
                
                # No error - get cached data (force refresh if requested)
                bl_hosts = get_blocklist(api_key, force=force)
                wl_hosts = get_whitelist(api_key, force=force)
                
                # Get cache info
                try:
                    info = get_blocklist_cache_info() or {}
                    ts = float(info.get('ts') or 0.0)
                    count = int(info.get('count') or 0)
                    age = None
                    if ts:
                        try:
                            age = max(0, int(__t() - ts))
                        except Exception:
                            age = None
                except Exception:
                    age = None
                    count = 0
                
                resp = {
                    "status": "ok",
                    "refreshed": force,
                    "remote": True,
                    "black_count": len(bl_hosts or []),
                    "white_count": len(wl_hosts or []),
                    "black": bl_hosts or [],
                    "white": wl_hosts or [],
                    "age_seconds": age,
                    "ttl_seconds": BLOCKLIST_TTL_SEC,
                }
                
                if force:
                    try:
                        with open(INTERCEPTED_LOG_FILE,'a',encoding='utf-8') as lf:
                            lf.write(f"\n[BLOCKLIST REFRESH] black={resp['black_count']} white={resp['white_count']}\n")
                    except Exception:
                        pass
                
                flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
                return True
            except Exception as e:
                flow.response = http.Response.make(500, json.dumps({"error":"fetch_failed","message":str(e)}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
                return True
        
        if method == 'POST':
            # POST for backward compatibility - same as GET with force=true
            if not (api_key and api_key != "MISSING"):
                flow.response = http.Response.make(400, json.dumps({"error":"missing_api_key","message":"Set ZT_PROXY_API_KEY to refresh from server."}).encode(), {**cors_headers, "Content-Type": "application/json"})
                return True
            try:
                # API key only - no JWT needed for blocklist
                # Check what the service returns (might contain error info)
                from services.get_blocklist_service import get_block_features
                raw_result = get_block_features(api_key=api_key)
                
                # Check if there was an error
                if isinstance(raw_result, dict) and raw_result.get("error"):
                    resp = {
                        "refreshed": False,
                        "remote": True,
                        "error": raw_result.get("error"),
                        "message": raw_result.get("message"),
                        "status": raw_result.get("status"),
                        "black_count": 0,
                        "white_count": 0,
                    }
                    flow.response = http.Response.make(
                        raw_result.get("status", 500),
                        json.dumps(resp).encode(),
                        {**cors_headers, "Content-Type": "application/json"}
                    )
                    return True
                
                # No error - get cached data
                bl_hosts = get_blocklist(api_key, force=True)
                wl_hosts = get_whitelist(api_key, force=True)
                
                resp = {
                    "refreshed": True,
                    "remote": True,
                    "black_count": len(bl_hosts or []),
                    "white_count": len(wl_hosts or []),
                    "black_sample": (bl_hosts or [])[:5],  # First 5 for debugging
                    "white_sample": (wl_hosts or [])[:5],  # First 5 for debugging
                    "ttl_seconds": BLOCKLIST_TTL_SEC,
                }
                try:
                    with open(INTERCEPTED_LOG_FILE,'a',encoding='utf-8') as lf:
                        lf.write(f"\n[BLOCKLIST REFRESH] black={resp['black_count']} white={resp['white_count']}\n")
                except Exception:
                    pass
                flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
            except Exception as e:
                flow.response = http.Response.make(500, json.dumps({"error":"refresh_failed","message":str(e)}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
            return True
        flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, POST, OPTIONS"})
        return True

    # Features debug (black/white lists and cache info)
    if internal_only and path.startswith('/features'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'GET':
            try:
                info = get_features_cache_info() or {}
                ts = float(info.get('ts') or 0.0)
                black = info.get('black') or []
                white = info.get('white') or []
                from time import time as __t
                age = None
                if ts:
                    try:
                        age = max(0, int(__t() - ts))
                    except Exception:
                        age = None
                resp = {
                    "status": "ok",
                    "black": black,
                    "white": white,
                    "black_count": len(black),
                    "white_count": len(white),
                    "age_seconds": age,
                    "ttl_seconds": BLOCKLIST_TTL_SEC,
                }
                flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
            except Exception as e:
                flow.response = http.Response.make(500, json.dumps({"error":"features_failed","message":str(e)}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
            return True
        flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
        return True

    # Refresh features (forces remote fetch of black/white)
    if internal_only and path.startswith('/refresh-features'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        if not (api_key and api_key != "MISSING"):
            flow.response = http.Response.make(400, json.dumps({"error":"missing_api_key","message":"Set ZT_PROXY_API_KEY to refresh from server."}).encode(), {**cors_headers, "Content-Type": "application/json"})
            return True
        try:
            # API key only - no JWT needed for blocklist
            bl_hosts = get_blocklist(api_key, force=True)
            wl_hosts = get_whitelist(api_key, force=True)
            resp = {
                "refreshed": True,
                "remote": True,
                "black_count": len(bl_hosts or []),
                "white_count": len(wl_hosts or []),
                "ttl_seconds": BLOCKLIST_TTL_SEC,
            }
            flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
        except Exception as e:
            flow.response = http.Response.make(500, json.dumps({"error":"refresh_failed","message":str(e)}).encode('utf-8'), {**cors_headers, "Content-Type": "application/json"})
        return True

    # Safeguard Keywords endpoint (fetch organizational policy keywords)
    if internal_only and path.startswith('/safeguard-keywords'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'GET':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
            return True
        
        # Get session for JWT authentication
        cfg_view = get_config() or {}
        sess = session_manager.get_session_for_internal_endpoint(headers, cfg_view)
        
        # Get authentication headers (JWT preferred)
        from tools.auth_helper import get_auth_headers
        auth_hdrs = get_auth_headers(session=sess, api_key=api_key)
        
        if not auth_hdrs:
            flow.response = http.Response.make(
                401,
                json.dumps({"error": "missing_auth", "message": "Authentication required"}).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
            return True
        
        try:
            from services.safeguard_service import get_safeguard_keywords
            result = get_safeguard_keywords(auth_hdrs)
            
            if result.get("error"):
                flow.response = http.Response.make(
                    result.get("status", 500),
                    json.dumps(result).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
            else:
                flow.response = http.Response.make(
                    200,
                    json.dumps({
                        "keywords": result.get("keywords", []),
                        "count": len(result.get("keywords", [])),
                        "enabled": cfg_view.get("safeguard_enabled", False)
                    }).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
        except Exception as e:
            flow.response = http.Response.make(
                500,
                json.dumps({"error": "safeguard_fetch_failed", "message": str(e)}).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
        return True

    # Anonymize Keywords endpoint (fetch keywords for anonymization - feature not yet implemented)
    if internal_only and path.startswith('/anonymize-keywords'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'GET':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
            return True
        
        # Get session for JWT authentication
        cfg_view = get_config() or {}
        sess = session_manager.get_session_for_internal_endpoint(headers, cfg_view)
        
        # Get authentication headers (JWT preferred)
        from tools.auth_helper import get_auth_headers
        auth_hdrs = get_auth_headers(session=sess, api_key=api_key)
        
        if not auth_hdrs:
            flow.response = http.Response.make(
                401,
                json.dumps({"error": "missing_auth", "message": "Authentication required"}).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
            return True
        
        try:
            from services.anonymize_service import get_anonymize_keywords
            result = get_anonymize_keywords(auth_hdrs)
            
            if result.get("error"):
                flow.response = http.Response.make(
                    result.get("status", 500),
                    json.dumps(result).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
            else:
                flow.response = http.Response.make(
                    200,
                    json.dumps({
                        "keywords": result.get("keywords", []),
                        "count": len(result.get("keywords", [])),
                        "note": "Feature not yet implemented - API functional"
                    }).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
        except Exception as e:
            flow.response = http.Response.make(
                500,
                json.dumps({"error": "anonymize_fetch_failed", "message": str(e)}).encode('utf-8'),
                {**cors_headers, "Content-Type": "application/json"}
            )
        return True

    # Routing domains for PAC (server-managed only; no hardcoded domains)
    if internal_only and path.startswith('/routing'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'GET':
            # STANDALONE MODE: Always return baseline domains (no API calls)
            if IS_STANDALONE:
                print("[/routing] Standalone mode - returning baseline domains without API call", flush=True)
                baseline = {
                    *(os.getenv('ZT_BASELINE_DOMAINS', '').split(',') if os.getenv('ZT_BASELINE_DOMAINS') else [
                        'openai.com','api.openai.com','chatgpt.com','chat.openai.com','platform.openai.com',
                        'anthropic.com','api.anthropic.com','claude.ai',
                        'gemini.google.com','bard.google.com','aistudio.google.com','makersuite.google.com',
                        'copilot.microsoft.com','bing.com',
                        'mistral.ai','api.mistral.ai','chat.mistral.ai',
                        'cohere.ai','api.cohere.ai','dashboard.cohere.com',
                        'perplexity.ai','labs.perplexity.ai','www.perplexity.ai',
                        'huggingface.co','hf.space',
                        'groq.com','api.groq.com','console.groq.com',
                        'openrouter.ai','api.openrouter.ai',
                        'replicate.com','api.replicate.com',
                        'together.ai','api.together.xyz',
                        'character.ai','beta.character.ai',
                        'poe.com',
                        'stability.ai','api.stability.ai','platform.stability.ai',
                        'midjourney.com','www.midjourney.com',
                    ])
                }
                out = sorted(baseline)
                resp = {"status": "ok", "domains": out, "baseline": True, "remote": False}
                flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
                return True
            
            # ENTERPRISE MODE: Fetch from API first; use baseline only as fallback when API returns empty
            try:
                cfg_view = get_config()
                use_bl = str(cfg_view.get('use_remote_blocklist')).lower() in ("1","true","yes","on") or (cfg_view.get('use_remote_blocklist') is True)
            except Exception:
                use_bl = False
            
            # Extract JWT from X-ZT-Auth or Authorization header
            x_zt_auth_token = None
            bearer_token = None
            try:
                # Check X-ZT-Auth first (preferred for extension requests)
                xzt_header = flow.request.headers.get('X-ZT-Auth', '')
                if xzt_header.startswith('Bearer '):
                    x_zt_auth_token = xzt_header[7:].strip()
                    print(f"[/routing] Extracted JWT from X-ZT-Auth: {x_zt_auth_token[:20]}..." if x_zt_auth_token else "[/routing] No X-ZT-Auth token")
                else:
                    # Fallback to Authorization header
                    auth_header = flow.request.headers.get('Authorization', '')
                    if auth_header.startswith('Bearer '):
                        bearer_token = auth_header[7:].strip()
                        print(f"[/routing] Extracted JWT from Authorization: {bearer_token[:20]}..." if bearer_token else "[/routing] No Authorization token")
            except Exception as e:
                print(f"[/routing] JWT extraction failed: {e}")
            
            # Try to fetch from remote API first
            bl_hosts = []
            wl_hosts = []
            used_remote = False
            if (x_zt_auth_token or bearer_token or (api_key and api_key != "MISSING")) and (use_bl or True):
                try:
                    # Pass both x_zt_auth_token (from X-ZT-Auth) and bearer_token (from Authorization)
                    bl_hosts = get_blocklist(api_key, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token) or []
                    wl_hosts = get_whitelist(api_key, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token) or []
                    used_remote = True
                except Exception:
                    pass
            
            # If API call succeeded, use ONLY API data (even if empty)
            if used_remote:
                domains = set()
                for h in bl_hosts:
                    if isinstance(h, str) and h:
                        domains.add(h.lower())
                # Apply whitelist removal
                for w in wl_hosts:
                    if isinstance(w, str) and w:
                        domains.discard(w.lower())
                out = sorted(domains)
                resp = {"status": "ok", "domains": out, "baseline": False, "remote": True}
            else:
                # Fallback to baseline only when API call failed or not configured
                baseline = {
                    # OpenAI
                    *(os.getenv('ZT_BASELINE_DOMAINS', '').split(',') if os.getenv('ZT_BASELINE_DOMAINS') else [
                        'openai.com','api.openai.com','chatgpt.com','chat.openai.com','platform.openai.com',
                        'anthropic.com','api.anthropic.com','claude.ai',
                        'gemini.google.com','bard.google.com','aistudio.google.com','makersuite.google.com',
                        'copilot.microsoft.com','bing.com',
                        'mistral.ai','api.mistral.ai','chat.mistral.ai',
                        'cohere.ai','api.cohere.ai','dashboard.cohere.com',
                        'perplexity.ai','labs.perplexity.ai','www.perplexity.ai',
                        'huggingface.co','hf.space',
                        'groq.com','api.groq.com','console.groq.com',
                        'openrouter.ai','api.openrouter.ai',
                        'replicate.com','api.replicate.com',
                        'together.ai','api.together.xyz',
                        'character.ai','beta.character.ai',
                        'poe.com',
                        'stability.ai','api.stability.ai','platform.stability.ai',
                        'midjourney.com','www.midjourney.com',
                    ])
                }
                # Allow env override append
                try:
                    extra_env = os.getenv('ZT_BASELINE_DOMAINS')
                    if extra_env:
                        for d in re.split(r'[;,\s]', extra_env):
                            if d and d.strip():
                                baseline.add(d.strip().lower())
                except Exception:
                    pass
                domains = set(baseline)
                out = sorted(domains)
                resp = {"status": "ok", "domains": out, "baseline": True, "remote": False}
            flow.response = http.Response.make(200, json.dumps(resp).encode(), {**cors_headers, "Content-Type": "application/json"})
            return True
        flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
        return True

    # Dynamic PAC endpoint
    if internal_only and path.startswith('/pac'):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'GET':
            # STANDALONE MODE: Always return baseline domains (no API calls)
            if IS_STANDALONE:
                print("[/pac] Standalone mode - returning baseline domains without API call", flush=True)
                baseline = {
                    'openai.com','api.openai.com','chatgpt.com','chat.openai.com','platform.openai.com',
                    'anthropic.com','api.anthropic.com','claude.ai',
                    'gemini.google.com','bard.google.com','aistudio.google.com','makersuite.google.com',
                    'copilot.microsoft.com','bing.com',
                    'mistral.ai','api.mistral.ai','chat.mistral.ai',
                    'cohere.ai','api.cohere.ai','dashboard.cohere.com',
                    'perplexity.ai','labs.perplexity.ai','www.perplexity.ai',
                    'huggingface.co','hf.space',
                    'groq.com','api.groq.com','console.groq.com',
                    'openrouter.ai','api.openrouter.ai',
                    'replicate.com','api.replicate.com',
                    'together.ai','api.together.xyz',
                    'character.ai','beta.character.ai',
                    'poe.com',
                    'stability.ai','api.stability.ai','platform.stability.ai',
                    'midjourney.com','www.midjourney.com',
                }
                domains = set(baseline)
                dlist = sorted(domains)
                
                # Auto-detect proxy address from request
                proxy_host = '127.0.0.1'
                proxy_port = '8080'  # Default standalone port
                host_header = flow.request.headers.get('Host', '')
                if host_header and ':' in host_header:
                    _, proxy_port = host_header.rsplit(':', 1)
                
                proxy_addr = f"{proxy_host}:{proxy_port}"
                
                pac_lines = [
                    "function FindProxyForURL(url, host){",
                    " host = host.toLowerCase();",
                    " // Always use DIRECT for localhost and proxy itself to avoid recursion",
                    " if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host.startsWith('localhost:') || host.startsWith('127.0.0.1:') || host.startsWith('0.0.0.0:')) {",
                    "   console.log('[ZTProxy PAC] ✗ DIRECT: localhost/proxy endpoint');",
                    "   return 'DIRECT';",
                    " }",
                    f" var domains = {json.dumps(dlist)};",
                    " console.log('[ZTProxy PAC] Checking:', host, '(total domains:', domains.length + ')');",
                    " for (var i=0;i<domains.length;i++){ var d=domains[i]; if (host === d || host.endsWith('.'+d)) {",
                    "   console.log('[ZTProxy PAC] ✓ PROXY:', host, 'matches', d);",
                    f"   return 'PROXY {proxy_addr}';",
                    " }",
                    " }",
                    " console.log('[ZTProxy PAC] ✗ DIRECT:', host, '(not in domain list)');",
                    " return 'DIRECT';",
                    "}"
                ]
                pac_content = "\n".join(pac_lines)
                flow.response = http.Response.make(200, pac_content.encode('utf-8'), {**cors_headers, "Content-Type": "application/x-ns-proxy-autoconfig"})
                return True
            
            # ENTERPRISE MODE: Fetch from API first; use baseline only as fallback when API returns empty
            try:
                cfg_view = get_config()
                use_bl = str(cfg_view.get('use_remote_blocklist')).lower() in ("1","true","yes","on") or (cfg_view.get('use_remote_blocklist') is True)
            except Exception:
                use_bl = False
            
            # Check if this is a cache-busted request (query param 't' or 'force' present)
            force_refresh = False
            try:
                query_params = flow.request.query or {}
                force_refresh = 't' in query_params or 'force' in query_params
            except Exception:
                pass
            
            # Extract JWT from X-ZT-Auth or Authorization header
            x_zt_auth_token = None
            bearer_token = None
            try:
                # Check X-ZT-Auth first (preferred for extension requests)
                xzt_header = flow.request.headers.get('X-ZT-Auth', '')
                if xzt_header.startswith('Bearer '):
                    x_zt_auth_token = xzt_header[7:].strip()
                else:
                    # Fallback to Authorization header
                    auth_header = flow.request.headers.get('Authorization', '')
                    if auth_header.startswith('Bearer '):
                        bearer_token = auth_header[7:].strip()
            except Exception:
                pass
            
            # Try to fetch from remote API first
            bl_hosts = []
            wl_hosts = []
            used_remote = False
            if (x_zt_auth_token or bearer_token or (api_key and api_key != 'MISSING')) and (use_bl or True):
                try:
                    # Pass both x_zt_auth_token (from X-ZT-Auth) and bearer_token (from Authorization)
                    # Force refresh when cache-busting query param detected
                    bl_hosts = get_blocklist(api_key, force=force_refresh, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token) or []
                    wl_hosts = get_whitelist(api_key, force=force_refresh, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token) or []
                    used_remote = True
                except Exception:
                    pass
            
            # If API call succeeded, use ONLY API data (even if empty)
            if used_remote:
                domains = set()
                for h in bl_hosts:
                    if isinstance(h, str) and h:
                        domains.add(h.lower())
                # Apply whitelist removal
                for w in wl_hosts:
                    if isinstance(w, str) and w:
                        domains.discard(w.lower())
            else:
                # Fallback to baseline only when API returns nothing
                baseline = {
                    # OpenAI
                    'openai.com','api.openai.com','chatgpt.com','chat.openai.com','platform.openai.com',
                    # Anthropic
                    'anthropic.com','api.anthropic.com','claude.ai',
                    # Google
                    'gemini.google.com','bard.google.com','aistudio.google.com','makersuite.google.com',
                    # Microsoft
                    'copilot.microsoft.com','bing.com',
                    # Mistral
                    'mistral.ai','api.mistral.ai','chat.mistral.ai',
                    # Cohere
                    'cohere.ai','api.cohere.ai','dashboard.cohere.com',
                    # Perplexity
                    'perplexity.ai','labs.perplexity.ai','www.perplexity.ai',
                    # HuggingFace
                    'huggingface.co','hf.space',
                    # Groq
                    'groq.com','api.groq.com','console.groq.com',
                    # OpenRouter
                    'openrouter.ai','api.openrouter.ai',
                    # Replicate
                    'replicate.com','api.replicate.com',
                    # Together AI
                    'together.ai','api.together.xyz',
                    # Character AI
                    'character.ai','beta.character.ai',
                    # Poe
                    'poe.com',
                    # Stability AI
                    'stability.ai','api.stability.ai','platform.stability.ai',
                    # Midjourney
                    'midjourney.com','www.midjourney.com',
                }
                try:
                    extra_env = os.getenv('ZT_BASELINE_DOMAINS')
                    if extra_env:
                        for d in re.split(r'[;,\s]', extra_env):
                            if d and d.strip():
                                baseline.add(d.strip().lower())
                except Exception:
                    pass
                domains = set(baseline)
            dlist = sorted(domains)
            
            # Get proxy address from environment or auto-detect from request
            proxy_host = os.getenv('ZT_PROXY_HOST')
            proxy_port = os.getenv('ZT_PROXY_PORT')
            
            # If not set, try to auto-detect from the request Host header
            if not proxy_host:
                host_header = flow.request.headers.get('Host', '')
                if host_header:
                    # Parse host:port from Host header
                    if ':' in host_header:
                        proxy_host, proxy_port = host_header.rsplit(':', 1)
                    else:
                        proxy_host = host_header
                        # Infer port from scheme (443 for HTTPS, 80 for HTTP)
                        proxy_port = '443' if flow.request.scheme == 'https' else '80'
                else:
                    # Fallback to localhost
                    proxy_host = '127.0.0.1'
                    proxy_port = '8081'
            
            # Ensure port is set
            if not proxy_port:
                proxy_port = '443' if proxy_host != '127.0.0.1' and proxy_host != 'localhost' else '8081'
            
            proxy_addr = f"{proxy_host}:{proxy_port}"
            
            pac_lines = [
                "function FindProxyForURL(url, host){",
                " host = host.toLowerCase();",
                " // Always use DIRECT for localhost and proxy itself to avoid recursion",
                " if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host.startsWith('localhost:') || host.startsWith('127.0.0.1:') || host.startsWith('0.0.0.0:')) {",
                "   console.log('[ZTProxy PAC] ✗ DIRECT: localhost/proxy endpoint');",
                "   return 'DIRECT';",
                " }",
                f" var domains = {json.dumps(dlist)};",
                " console.log('[ZTProxy PAC] Checking:', host, '(total domains:', domains.length + ')');",
                " for (var i=0;i<domains.length;i++){ var d=domains[i]; if (host === d || host.endsWith('.'+d)) {",
                "   console.log('[ZTProxy PAC] ✓ PROXY:', host, 'matches', d);",
                f"   return 'PROXY {proxy_addr}';",
                " }}",
                " console.log('[ZTProxy PAC] ✗ DIRECT:', host);",
                " return 'DIRECT';",
                "}"
            ]
            pac_body = "\n".join(pac_lines)
            flow.response = http.Response.make(200, pac_body.encode(), {**cors_headers, "Content-Type": "application/x-ns-proxy-autoconfig"})
            return True
        flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "GET, OPTIONS"})
        return True

    # Whitelist request (server-side using stored API key)
    # Whitelist/Blacklist request endpoints
    # Note: This handles both whitelist and blacklist requests based on endpoint path
    if internal_only and (path.startswith('/whitelist-request') or path.startswith('/blacklist-request')):
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method != 'POST':
            flow.response = http.Response.make(405, b"Method Not Allowed", {**cors_headers, "Allow": "POST, OPTIONS"})
            return True
        
        # Determine if this is whitelist or blacklist request
        is_whitelist = path.startswith('/whitelist-request')
        request_type = "whitelist" if is_whitelist else "blacklist"
        
        try:
            body_text = flow.request.get_text() or '{}'
            try:
                payload = json.loads(body_text)
            except Exception:
                payload = {}
                
            host_name = (payload.get('hostName') or payload.get('host') or '').strip()
            if not host_name:
                flow.response = http.Response.make(
                    400,
                    b"hostName is required",
                    {**cors_headers, "Content-Type": "text/plain; charset=utf-8"}
                )
                return True
            
            # Get session for JWT authentication
            cfg_view = get_config() or {}
            sess = session_manager.get_session_for_internal_endpoint(headers, cfg_view)
            
            # Get authentication headers (JWT preferred, API key fallback)
            from tools.auth_helper import get_auth_headers
            auth_hdrs = get_auth_headers(session=sess, api_key=api_key)
            
            if not auth_hdrs:
                flow.response = http.Response.make(
                    401,
                    json.dumps({
                        "error": "missing_auth",
                        "message": "Authentication required (JWT or API key)"
                    }).encode('utf-8'),
                    {**cors_headers, "Content-Type": "application/json"}
                )
                return True
            
            # Use new v3 API endpoints
            if is_whitelist:
                upstream_url = "https://dev-settings.zerotrusted.ai/api/v3/shadow-ai/request-whitelist"
            else:
                upstream_url = "https://dev-settings.zerotrusted.ai/api/v3/shadow-ai/request-blacklist"
            
            # Build payload matching new API schema (capital H, capital N)
            upstream_payload = {"HostName": host_name}
            
            # Merge auth headers with Content-Type
            headers_u = {**auth_hdrs, "Content-Type": "application/json"}
            
            try:
                r = requests.post(upstream_url, headers=headers_u, json=upstream_payload, timeout=12)
                ct = r.headers.get('Content-Type', 'application/json; charset=utf-8')
                text = r.text or ""
                
                # Normalize outcomes for UI simplicity
                if r.status_code in (200, 201):
                    try:
                        j = json.loads(text)
                    except Exception:
                        j = {"raw": text}
                    norm = {
                        "accepted": True,
                        "status": "Created",
                        "type": request_type,
                        "host": host_name,
                        "upstream": j
                    }
                    flow.response = http.Response.make(
                        200,
                        json.dumps(norm).encode('utf-8'),
                        {**cors_headers, "Content-Type": "application/json"}
                    )
                elif r.status_code == 409:
                    try:
                        j = json.loads(text)
                    except Exception:
                        j = {"message": text}
                    msg = (j.get('message') or '').lower()
                    existing = j.get('existingId') or j.get('existing_id')
                    norm = {
                        "accepted": True,
                        "duplicate": True,
                        "type": request_type,
                        "host": host_name
                    }
                    if existing:
                        norm["existingId"] = existing
                    if msg:
                        norm["message"] = j.get('message')
                    flow.response = http.Response.make(
                        200,
                        json.dumps(norm).encode('utf-8'),
                        {**cors_headers, "Content-Type": "application/json"}
                    )
                else:
                    flow.response = http.Response.make(
                        r.status_code,
                        text.encode('utf-8', errors='ignore'),
                        {**cors_headers, "Content-Type": ct}
                    )
            except Exception as e:
                flow.response = http.Response.make(
                    502,
                    f"Upstream error: {e}".encode('utf-8'),
                    {**cors_headers, "Content-Type": "text/plain; charset=utf-8"}
                )
        except Exception as e:
            flow.response = http.Response.make(500, f"Error: {e}".encode('utf-8'), {**cors_headers, "Content-Type": "text/plain; charset=utf-8"})
        return True

    return False
