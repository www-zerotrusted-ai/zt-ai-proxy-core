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


# UI HTML loader: externalized to interceptor/ui/ui.html
def _load_ui_html_from_file() -> str:
    try:
        base_dir = os.path.dirname(__file__)
        ui_path = os.path.join(base_dir, 'ui', 'ui.html')
        with open(ui_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"""
        <html><head><meta charset='utf-8'/><title>ZTProxy</title></head>
        <body style='font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0b1320;color:#e6ecf3;'>
          <div style='padding:16px'>
            <h3>ZT Proxy</h3>
            <p>Embedded UI missing. Error: {e}</p>
            <p>Try: /config, /metrics, /logs, /features</p>
          </div>
        </body></html>
        """


# Auth-required block page (simplified - no ignore tokens, just Connect button)
AUTH_BLOCK_PAGE_HTML = """
<!doctype html><html><head><meta charset=\"utf-8\"/><title>Authentication Required · ZeroTrusted.ai</title><style>
*{box-sizing:border-box}
html,body{height:100%;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#e2e8f0;display:flex;align-items:center;justify-content:center;padding:20px}
.panel{max-width:600px;width:100%;background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px 32px;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 0 1px rgba(148,163,184,.1);position:relative;overflow:hidden}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,#3b82f6,#8b5cf6,#ec4899);opacity:.8}
.logo-container{text-align:center;margin-bottom:32px}
.logo{height:48px;margin-bottom:16px}
h1{margin:0 0 12px;font-size:28px;font-weight:700;color:#f1f5f9;text-align:center;letter-spacing:-0.5px}
.subtitle{text-align:center;font-size:15px;color:#94a3b8;margin-bottom:32px;line-height:1.6}
.warn{background:linear-gradient(135deg,#1e3a8a 0%,#1e40af 100%);border:1px solid #3b82f6;padding:20px;border-radius:12px;margin-bottom:28px;position:relative;box-shadow:0 4px 12px rgba(59,130,246,.15)}
.warn::before{content:'🔐';position:absolute;top:20px;left:20px;font-size:24px;opacity:.8}
.warn-content{padding-left:40px}
.warn-title{font-size:16px;font-weight:600;color:#ffffff;margin-bottom:8px}
.warn-text{font-size:14px;color:#bfdbfe;line-height:1.6}
.actions{display:flex;gap:12px;justify-content:center}
button{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:#fff;border:0;border-radius:10px;padding:14px 32px;cursor:pointer;font-size:16px;font-weight:600;transition:all .2s ease;box-shadow:0 4px 14px rgba(59,130,246,.4);position:relative;overflow:hidden}
button:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(59,130,246,.5)}
button:active{transform:translateY(0)}
button:disabled{opacity:.6;cursor:not-allowed;transform:none}
button::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.2),transparent);transition:left .5s}
button:hover::before{left:100%}
.status{text-align:center;margin-top:20px;font-size:14px;color:#64748b;min-height:20px}
.success{color:#22c55e;font-weight:500}
.error{color:#ef4444;font-weight:500}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.panel{animation:fadeIn .4s ease-out}
</style></head><body><div class=\"panel\"><div class=\"logo-container\">
<img src=\"https://identity.zerotrusted.ai/img/logo-with-tagline-white.png\" alt=\"ZeroTrusted.ai\" class=\"logo\">
<h1>Authentication Required</h1>
<p class=\"subtitle\">{{REASON}}</p>
</div>
<div class=\"warn\">
<div class=\"warn-content\">
<div class=\"warn-title\">Connect to Continue</div>
<div class=\"warn-text\">Click the button below to authenticate via SSO and gain secure access to AI services monitored by ZeroTrusted.ai.</div>
</div>
</div>
<div class=\"actions\">
<button id=\"zt-connect-btn\">Connect via Extension</button>
</div>
<div id=\"zt-status\" class=\"status\"></div>
</div>
<script>
(function(){
    const connectBtn = document.getElementById('zt-connect-btn');
    const statusEl = document.getElementById('zt-status');
    
    connectBtn.onclick = () => {
        connectBtn.disabled = true;
        connectBtn.textContent = 'Connecting...';
        statusEl.textContent = 'Opening SSO login window...';
        statusEl.className = 'status';
        
        // Try to send message to extension
        try {
            if (window.chrome && chrome.runtime) {
                chrome.runtime.sendMessage({ action: 'ztStartSso' }, (response) => {
                    if (chrome.runtime.lastError) {
                        statusEl.textContent = 'Extension not found. Please install and enable the ZTProxy extension.';
                        statusEl.className = 'status error';
                        connectBtn.disabled = false;
                        connectBtn.textContent = 'Connect via Extension';
                    } else if (response && response.ok) {
                        connectBtn.textContent = '✓ Connected';
                        statusEl.textContent = 'Successfully authenticated! Refreshing page...';
                        statusEl.className = 'status success';
                        // Store suppression timestamp in sessionStorage to suppress toasts after reload
                        try {
                            sessionStorage.setItem('zt_auth_completed', Date.now().toString());
                        } catch(e) {}
                        // Refresh the page after 2 seconds
                        setTimeout(() => {
                            window.location.reload();
                        }, 2000);
                    } else {
                        statusEl.textContent = 'Connection failed. Please try again.';
                        statusEl.className = 'status error';
                        connectBtn.disabled = false;
                        connectBtn.textContent = 'Connect via Extension';
                    }
                });
            } else {
                statusEl.textContent = 'Extension API not available. Please ensure the extension is installed.';
                statusEl.className = 'status error';
                connectBtn.disabled = false;
                connectBtn.textContent = 'Connect via Extension';
            }
        } catch(e) {
            statusEl.textContent = 'Failed to connect to extension: ' + e.message;
            statusEl.className = 'status error';
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect via Extension';
        }
    };
})();
</script>
</body>
</html>
"""

BLOCK_PAGE_HTML = """
<!doctype html><html><head><meta charset=\"utf-8\"/><title>Request Blocked · ZeroTrusted.ai</title><style>
html,body{height:100%}body{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#e6ecf3;display:flex;align-items:center;justify-content:center}
.panel{max-width:760px;width:94%;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:24px 22px;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 0 1px rgba(148,163,184,.1)}
h1{margin:0 0 10px;font-size:21px;color:#fff}p{margin:6px 0 0;line-height:1.55}a{color:#81b9ff}
.actions{margin-top:16px;display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}
button{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:9px 14px;cursor:pointer;font-size:14px}button:hover{background:#2b6ff1}
.note{font-size:12px;opacity:.8;margin-top:10px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.warn{background:#1e293b;border:1px solid #324563;padding:10px 12px;border-radius:8px;margin-top:14px;font-size:13.5px;line-height:1.5}
code{background:#1e293b;padding:2px 4px;border-radius:4px;font-size:12px}
 .logo-inline{height:32px;display:inline-block}
 .pii-list{margin:10px 0 4px 0;padding:0;list-style:none;font-size:13px;line-height:1.4}
 .pii-list li{background:#1e293b;border:1px solid #31435c;margin:4px 0;padding:6px 8px;border-radius:6px;word-break:break-all}
 .pii-mask{color:#ffb454;font-weight:600}
 .spinner{width:42px;height:42px;border:5px solid #22344f;border-top-color:#2563eb;border-radius:50%;animation:spin 1s linear infinite;margin:18px auto 6px auto;display:none}
 .mitigations{margin-top:8px;font-size:11.5px;letter-spacing:.5px;text-align:center;color:#9cb3d8;min-height:28px;display:none}
 @keyframes spin{to{transform:rotate(360deg)}}
</style></head><body><div class=\"panel\"><div class=\"brand\">
<svg class=\"logo-inline\" viewBox=\"0 0 140 36\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"0\" y=\"0\" width=\"140\" height=\"36\" rx=\"6\" fill=\"#1e2a44\"/><text x=\"12\" y=\"23\" font-family=\"Segoe UI,Arial,sans-serif\" font-size=\"15\" fill=\"#ffffff\">ZeroTrusted</text><circle cx=\"118\" cy=\"18\" r=\"7\" fill=\"#2563eb\"/></svg>
<h1>Request blocked by ZeroTrusted.ai</h1></div><p id=\"zt-reason\">{{REASON}}</p>
<div class=spinner id=\"zt-spinner\"></div>
<div class=mitigations id=\"zt-rotating-terms\"></div>
<div id=\"zt-auth-block\" class=\"warn\" style=\"display:none\">You are not connected. Use the <b>Connect</b> button (SSO) in the extension to authenticate and gain access.</div>
<div id=\"zt-ignore-info\" class=\"warn\" style=\"display:none\"></div><div class=\"actions\"><button id=\"zt-connect-btn\" style=\"display:none\">Connect</button><button id=\"zt-ignore-btn\" style=\"display:none\">Ignore Once (re-entry required)</button><button id=\"zt-retry-btn\" style=\"display:none\">Retry Request</button></div><div id=\"zt-status\" class=\"note\"></div></div>
<script>
        (function(){
            const $ = id => document.getElementById(id);
            const connectBtn = $('zt-connect-btn');
            const ignoreBtn = $('zt-ignore-btn');
            const retryBtn = $('zt-retry-btn');
            const authBlock = $('zt-auth-block');
            const ignoreInfo = $('zt-ignore-info');
            const statusEl = $('zt-status');
            const rotatingEl = $('zt-rotating-terms');
            const spinnerEl = $('zt-spinner');
            // Absolute proxy base injected server-side (not the blocked site origin)
            const PROXY_BASE = '{{PROXY_BASE}}';
            const TERMS = [
                'PII Scrubbing','Sensitive Data Shield','Privacy Enforcement','Compliance Guard','RegEx + ML Detection','Shadow AI Containment','Data Loss Prevention','Secrets Filtering','Policy Enforcement','Anonymization Layer','Real-time Inspection','Usage Governance'
            ];
            let termIdx = 0;
            function rotateTerms(){
                if(!rotatingEl) return; rotatingEl.textContent = TERMS[termIdx % TERMS.length]; termIdx++; setTimeout(rotateTerms, 1400);
            }
            function maybeActivateSpinner(){
                try {
                    const reasonTxt = (document.getElementById('zt-reason')?.textContent||'').toUpperCase();
                    if(reasonTxt.includes('PII') || reasonTxt.includes('SENSITIVE')){
                        if(spinnerEl) spinnerEl.style.display='block';
                        if(rotatingEl) { rotatingEl.style.display='block'; rotateTerms(); }
                    }
                } catch(_){}
            }
            maybeActivateSpinner();
            function setStatus(m){ try{ statusEl.textContent = m || ''; }catch(_){} }
            async function fetchJSON(url, opts){
                try{ const r = await fetch(url, Object.assign({credentials:'include'}, opts||{})); if(!r.ok) return null; return await r.json(); }catch(e){ return null; }
            }
            async function refresh(){
                const data = await fetchJSON(PROXY_BASE + '/ignore-status');
                if(!data){
                    // Assume unauthenticated if call fails (show connect so user can attempt SSO)
                    authBlock.style.display = 'block';
                    connectBtn.style.display = 'inline-block';
                    return;
                }
                if(data.authenticated){
                    authBlock.style.display = 'none';
                    ignoreBtn.style.display = 'inline-block';
                    retryBtn.style.display = 'inline-block';
                    connectBtn.style.display = 'none';
                    ignoreInfo.style.display = 'block';
                    ignoreInfo.innerHTML = 'Signed in as <b>'+ (data.user_id||'user') +'</b>.';
                    // Always allow "Proceed Anyway" - clicking adds a token
                    ignoreBtn.disabled = false;
                    ignoreBtn.textContent = 'Ignore Once (re-entry required)';
                } else {
                    authBlock.style.display = 'block';
                    connectBtn.style.display = 'inline-block';
                    ignoreBtn.style.display = 'none';
                    retryBtn.style.display = 'none';
                    ignoreInfo.style.display = 'none';
                }
            }
            connectBtn.onclick = () => { try { window.parent.postMessage({ type: 'ZT_SSO_CONNECT' }, '*'); } catch(_) {} setStatus('Opening SSO flow via extension...'); };
            ignoreBtn.onclick = async () => { 
                setStatus('Processing bypass request...'); 
                try { 
                    const r = await fetch(PROXY_BASE + '/ignore-start', { method:'POST', credentials:'include' }); 
                    if(r && r.ok){ 
                        setStatus('✅ Bypass granted. Redirecting back...'); 
                        // Auto-redirect back after successful ignore
                        setTimeout(() => {
                            try { history.back(); } catch(_) { location.reload(); }
                        }, 800);
                    } else { 
                        setStatus('❌ Failed to grant bypass (not authenticated).'); 
                        await refresh();
                    } 
                } catch(e){ 
                    setStatus('❌ Network error while processing bypass.'); 
                    await refresh();
                } 
            };
            retryBtn.onclick = () => { try { history.back(); } catch(_) { location.reload(); } };
            refresh();
        })();
    </script>
</body>
</html>
"""


class Interceptor:
    # Class-level flag to ensure HTTP/2 config is only applied once across all instances
    _http2_configured_global = False
    
    def __init__(self) -> None:
        self.store = default_store
        self.CONFIG_FILE_PATH = self.store.get_config_path()
        self.INTERCEPTED_LOG_FILE = self.store.get_log_path()
        self.UI_HTML = _load_ui_html_from_file()
        self.CONFIG_LAST_UPDATED = None
        self.features_started = False
        self._suppress_h2_errors = True  # Suppress noisy HTTP/2 protocol errors
        
        # Log edition mode
        print(f"[ZTPROXY] Edition: {EDITION.upper()} (IS_STANDALONE={IS_STANDALONE}, IS_ENTERPRISE={IS_ENTERPRISE})", flush=True)
        try:
            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"\n{'='*80}\n")
                lf.write(f"[ZTPROXY STARTUP] Edition: {EDITION.upper()}\n")
                lf.write(f"[ZTPROXY STARTUP] Mode: {'STANDALONE (local, no API calls)' if IS_STANDALONE else 'ENTERPRISE (API-driven)'}\n")
                lf.write(f"{'='*80}\n\n")
        except Exception:
            pass
        
        # Clear all caches on startup to prevent stale data issues
        self._clear_all_caches_on_startup()
        
        # Initialize session manager for centralized session handling
        self.session_manager = SessionManager(GLOBAL_SESSION_STORE, self.INTERCEPTED_LOG_FILE)
        
        # Rotate log on startup if needed (keep last 1000 lines)
        try:
            rotated = self.store.rotate_log_if_needed(self.INTERCEPTED_LOG_FILE, max_size_mb=5.0, keep_lines=1000)
            if rotated:
                self._debug("[LOG ROTATION] Startup rotation completed")
        except Exception as e:
            self._debug(f"[LOG ROTATION] Startup rotation failed: {e}")
        
        self.metrics = {
            'requests_total': 0,
            'blocked_total': 0,
            'allowed_total': 0,
            'errors_total': 0,
            'pii_detected_total': 0,
            'pii_threshold_met_not_blocked_total': 0,
            'post_chat_total': 0,
            'blocklist_matched_total': 0,
            'shadow_detected_total': 0,
            'forward_events_total': 0,
            'safeguard_detected_total': 0,
            'safeguard_blocked_total': 0,
            # Session / ignore model metrics
            'sessions_active': 0,              # snapshot updated per request
            'ignore_tokens_consumed_total': 0, # cumulative count of ignores used
            'ignore_tokens_remaining_sum': 0,  # snapshot sum across active sessions
            # File upload scanning metrics
            'file_uploads_scanned_total': 0,
            'file_uploads_pii_hits_total': 0,
            'file_uploads_blocked_total': 0,
            'file_uploads_sanitized_block_total': 0,
                'file_attachments_sanitized_block_total': 0,
            # Circuit breaker metrics
            'circuit_breaker_triggered_total': 0,      # Budget exceeded before PII call
            'circuit_breaker_late_trigger_total': 0,   # Budget exceeded after PII completed
            # PII optimization metrics (latency reduction)
            'pii_cache_hits_total': 0,                 # PII result served from cache
            'pii_short_text_bypass_total': 0,          # PII skipped for text < 50 chars
            'pii_whitelist_bypass_total': 0,           # PII skipped for common safe patterns
            'pii_service_calls_total': 0,              # Actual calls to PII service
        }
        # Start background refresh loop for features/blocklist (ENTERPRISE ONLY)
        if IS_ENTERPRISE:
            api_key = os.getenv('ZT_PROXY_API_KEY')
            if api_key:
                # Start synchronous refresher in its own daemon thread
                threading.Thread(target=features_refresh_loop, args=(api_key, self._debug), daemon=True).start()
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[ENTERPRISE] Started background features/blocklist refresh loop\n")
                except Exception:
                    pass
            else:
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[ENTERPRISE] No ZT_PROXY_API_KEY found, skipping refresh loop\n")
                except Exception:
                    pass
        else:
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[STANDALONE] Skipping features/blocklist refresh loop\n")
            except Exception:
                pass

    def _clear_all_caches_on_startup(self):
        """
        Clear all caches on proxy startup to prevent stale data issues.
        Clears both Redis caches (with zt:proxy:* pattern) and in-memory caches.
        Does NOT clear session caches (zt:session:*) as they have different lifecycle.
        """
        print("\n" + "="*80)
        print("[STARTUP CACHE CLEAR] Starting cache clearing on proxy initialization...")
        print("="*80)
        
        try:
            # STANDALONE: Skip Redis cache clear (no Redis, in-memory only)
            if IS_STANDALONE:
                print(f"[STARTUP CACHE CLEAR] ⚠ Standalone mode - skipping Redis cache clear (in-memory only)")
            else:
                # 1. Clear Redis caches with zt:proxy:* pattern (excludes zt:session:*)
                config_cache = get_config_cache()
                if config_cache.is_redis_available():
                    deleted_count = config_cache.clear_all_proxy_caches()
                    if deleted_count >= 0:
                        print(f"[STARTUP CACHE CLEAR] ✓ Redis proxy caches cleared ({deleted_count} keys)")
                    else:
                        print(f"[STARTUP CACHE CLEAR] ⚠ Redis cache clear failed")
                else:
                    print(f"[STARTUP CACHE CLEAR] ⚠ Redis not available - skipping Redis cache clear")
            
            # 2. Clear in-memory caches (blocklist, features, safeguard, anonymize, PII)
            clear_all_in_memory_caches()
            
            # 3. Clear user settings cache
            clear_user_settings_cache()
            
            print("="*80)
            print("[STARTUP CACHE CLEAR] ✓ All cache clearing completed successfully")
            print("="*80 + "\n")
            
        except Exception as e:
            print(f"[STARTUP CACHE CLEAR] ✗ EXCEPTION during cache clearing: {type(e).__name__}: {e}")
            import traceback
            print(f"[STARTUP CACHE CLEAR] Traceback:\n{traceback.format_exc()}")
            print("="*80 + "\n")

    # --- helper accessors for internal_api wiring ---
    def _get_config(self):
        return load_config()

    def _get_blocklist(self, token: str, force: bool = False, bearer_token: str = None, x_zt_auth_token: str = None):
        return get_cached_blocklist(token, force=force, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token)

    def _get_whitelist(self, token: str, force: bool = False, bearer_token: str = None, x_zt_auth_token: str = None):
        return get_cached_whitelist(token, force=force, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token)

    def _get_features_cache_info(self):
        return get_features_cache_info()

    def _get_blocklist_cache_info(self):
        return get_blocklist_cache_info()

    def _set_features_started(self, v: bool):
        self.features_started = bool(v)

    def _debug(self, msg: str):
        try:
            ctx.log.info(msg)
        except Exception:
            try:
                print(msg)
            except Exception:
                pass

    def configure(self, updated):
        """Configure HTTP/2 settings to handle high concurrent stream loads."""
        # DISABLED: The configure() hook is causing timeouts
        # Use command-line options instead when starting mitmproxy:
        # mitmdump --set http2_ping_keepalive=120 --set http2_ping_timeout=30 -s interceptor/interceptor_addon.py
        pass

    def error(self, flow: http.HTTPFlow):
        """Suppress noisy HTTP/2 errors that don't affect functionality."""
        if self._suppress_h2_errors and flow.error:
            err_msg = str(flow.error.msg).lower()
            # Suppress common HTTP/2 noise that doesn't impact user experience
            if any(x in err_msg for x in [
                'connectionterminated',
                'failed ping',
                'max inbound streams',
                'protocol error',
                'client disconnect',
                'server disconnect',
                'stream reset',
                'error establishing server connection',
                'stream closed',
                'flow control',
            ]):
                return  # Suppressed - these are expected in HTTP/2 under load
        
        # Log other unexpected errors
        try:
            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(f"[PROXY ERROR] {flow.error}\n")
        except Exception:
            pass

    def response(self, flow: http.HTTPFlow) -> None:
        """Add headers to responses when ignore tokens are consumed and auth status."""
        try:
            # Skip header injection for analytics/telemetry domains to avoid HTTP/2 header issues
            # These domains are bypassed in request() method and shouldn't have custom headers
            req = flow.request
            host = (req.headers.get('Host') or req.pretty_host or '').split(':')[0].lower()
            analytics_bypass_domains = {
                'ab.chatgpt.com', 'o.openai.com', 'browser-intake-datadoghq.com',
                'cdn.segment.com', 'api.segment.io', 'statsig.com', 'sentry.io', 'amplitude.com'
            }
            is_analytics = any(host == d or host.endswith('.' + d) for d in analytics_bypass_domains)
            if is_analytics:
                return  # Skip all header injection for analytics domains
            
            # Check if we consumed an ignore token for this request
            if flow.metadata.get('zt_token_consumed'):
                if flow.response:
                    flow.response.headers['X-ZT-Token-Consumed'] = '1'
                    # Also include the new count after consumption (count - 1)
                    # Extension should use this to update its local storage
                    try:
                        old_count = int(req.headers.get('X-ZT-Ignore-Token') or '0')
                        new_count = max(0, old_count - 1)
                        flow.response.headers['X-ZT-Ignore-Remaining'] = str(new_count)
                    except Exception:
                        pass
            
            # Add X-ZT-Auth header to all responses to indicate auth status
            # This allows the extension to know if the user is authenticated without needing a block
            if flow.response:
                # Check if user is authenticated (stored in metadata by request() method)
                is_authenticated = flow.metadata.get('zt_authenticated', False)
                if is_authenticated:
                    flow.response.headers['X-ZT-Auth'] = '1'
                    # Also add ignore remaining count if available
                    ignore_remaining = flow.metadata.get('zt_ignore_remaining', 0)
                    if ignore_remaining > 0:
                        flow.response.headers['X-ZT-Ignore-Remaining'] = str(ignore_remaining)
                else:
                    flow.response.headers['X-ZT-Auth'] = '0'
        except Exception as e:
            # Don't fail the response if header injection fails
            pass

    # --- core ---
    def request(self, flow: http.HTTPFlow) -> None:
        try:
            # Common request fields
            req = flow.request
            method = req.method.upper()
            host_header = req.headers.get('Host') or req.pretty_host
            host = (host_header or '').split(':')[0]
            path = req.path or '/'
            url = req.url
            headers = dict(req.headers) if req.headers else {}

            # === LOG EVERY REQUEST (for debugging routing issues) ===
            print(f"[PROXY REQUEST] {method} {host}{path}", flush=True)

            # === EARLY INTERNAL REQUEST DETECTION (Skip all processing for internal API calls) ===
            # Check if this is an internal API call to localhost/0.0.0.0/127.0.0.1
            host_lower = host.lower()
            is_internal_host = host_lower in {'localhost', '127.0.0.1', '0.0.0.0'}
            
            if is_internal_host:
                # Skip all config loading, user settings, logging for internal API calls
                # Just handle the request and return immediately
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
                    ctx=ctx,
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
                    debug_log=self._debug,
                    features_started=self.features_started,
                    set_features_started=self._set_features_started,
                    BLOCKLIST_TTL_SEC=BLOCKLIST_TTL_SEC,
                    get_blocklist_cache_info=self._get_blocklist_cache_info,
                )
                if handled:
                    return  # Request was handled, skip all normal processing
            # === END EARLY INTERNAL REQUEST DETECTION ===

            # --- Extract Bearer token from Authorization header (if present) ---
            bearer_token = None
            auth_header = headers.get('Authorization') or headers.get('authorization')
            if auth_header and auth_header.lower().startswith('bearer '):
                bearer_token = auth_header[7:].strip()

            # --- Extract JWT from X-ZT-Auth header (if present) ---
            x_zt_auth_token = None
            xzt_header = headers.get('X-ZT-Auth') or headers.get('x-zt-auth')
            if xzt_header and xzt_header.lower().startswith('bearer '):
                x_zt_auth_token = xzt_header[7:].strip()

            # --- Fetch per-user settings from zt-settings API using JWT token ---
            # ENTERPRISE ONLY: Fetch from API. Standalone uses fixed defaults.
            user_settings = None
            safeguard_keywords_from_api = []
            
            if IS_ENTERPRISE:
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"\n{'='*80}\n")
                        lf.write(f"[JWT TOKEN RESOLUTION] Starting user settings fetch\n")
                        lf.write(f"[JWT TOKEN RESOLUTION] X-ZT-Auth header present: {bool(x_zt_auth_token)}\n")
                        if x_zt_auth_token:
                            token_preview = x_zt_auth_token[:20] + '...' if len(x_zt_auth_token) > 20 else x_zt_auth_token
                            lf.write(f"[JWT TOKEN RESOLUTION] X-ZT-Auth token preview: {token_preview}\n")
                except Exception:
                    pass
                
                # Priority: X-ZT-Auth header > Session auth_token
                jwt_token = x_zt_auth_token
                
                # If no X-ZT-Auth header, try to get JWT from session
                if not jwt_token:
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[JWT TOKEN RESOLUTION] No X-ZT-Auth header, checking session manager\n")
                    except Exception:
                        pass
                    # Get session from session manager
                    try:
                        sess, _ = self.session_manager.get_session_for_request(headers, {}, client_ip=None)
                        if sess:
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[JWT TOKEN RESOLUTION] Session found: {sess.session_id[:16]}...\n")
                                    lf.write(f"[JWT TOKEN RESOLUTION] Session user: {sess.user_id}\n")
                                    lf.write(f"[JWT TOKEN RESOLUTION] Session has auth_token: {bool(sess.auth_token)}\n")
                                    if sess.auth_token:
                                        token_preview = sess.auth_token[:20] + '...' if len(sess.auth_token) > 20 else sess.auth_token
                                        lf.write(f"[JWT TOKEN RESOLUTION] auth_token preview: {token_preview}\n")
                            except Exception:
                                pass
                            
                            if sess.auth_token:
                                jwt_token = sess.auth_token
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[JWT TOKEN RESOLUTION] ✓ Using JWT from session.auth_token\n")
                                except Exception:
                                    pass
                            else:
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[JWT TOKEN RESOLUTION] ✗ session.auth_token is None/empty\n")
                                        lf.write(f"[JWT TOKEN RESOLUTION] ✗ Cannot fetch user settings without JWT token\n")
                                        lf.write(f"[JWT TOKEN RESOLUTION] ℹ Session was authenticated but missing JWT\n")
                                        lf.write(f"[JWT TOKEN RESOLUTION] ℹ Check browser extension → /sso-establish flow\n")
                                except Exception:
                                    pass
                        else:
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[JWT TOKEN RESOLUTION] ✗ No session found in session manager\n")
                            except Exception:
                                pass
                    except Exception as e:
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[JWT TOKEN RESOLUTION] Session lookup error: {e}\n")
                        except Exception:
                            pass
                
                # Call user settings API if we have a JWT token
                if jwt_token:
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[JWT TOKEN RESOLUTION] Calling get_user_settings()\n")
                            lf.write(f"{'='*80}\n\n")
                    except Exception:
                        pass
                    user_settings = get_user_settings(jwt_token)
                    if user_settings:
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"\n{'='*80}\n")
                                lf.write(f"[USER SETTINGS APPLIED] ✓ Retrieved settings from API\n")
                                lf.write(f"[USER SETTINGS APPLIED] Full response: {user_settings}\n")
                                
                                # Log individual settings being applied
                                if isinstance(user_settings, dict):
                                    lf.write(f"[USER SETTINGS APPLIED] Settings breakdown ({len(user_settings)} keys):\n")
                                    for key, value in user_settings.items():
                                        lf.write(f"  - {key}: {value}\n")
                                
                                lf.write(f"[USER SETTINGS APPLIED] These settings will now override config defaults\n")
                                lf.write(f"{'='*80}\n\n")
                        except Exception as e:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[USER SETTINGS APPLIED] Error logging settings: {e}\n")
                    else:
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"\n{'='*80}\n")
                                lf.write(f"[USER SETTINGS APPLIED] ✗ No settings retrieved from API (returned None)\n")
                                lf.write(f"[USER SETTINGS APPLIED] Will use config defaults only\n")
                                lf.write(f"{'='*80}\n\n")
                        except Exception:
                            pass
                    
                    # --- Fetch safeguard keywords from dedicated API ---
                    # Safeguard keywords come from a separate endpoint and are cached
                    try:
                        from tools.runtime_helpers import get_cached_safeguard_keywords
                        auth_headers = {'Authorization': f'Bearer {jwt_token}'}
                        safeguard_keywords_from_api = get_cached_safeguard_keywords(auth_headers, force=False)
                        
                        if safeguard_keywords_from_api:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[SAFEGUARD KEYWORDS] Fetched {len(safeguard_keywords_from_api)} keywords from API: {safeguard_keywords_from_api[:10]}\n")
                        else:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[SAFEGUARD KEYWORDS] No keywords returned from API\n")
                    except Exception as e:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[SAFEGUARD KEYWORDS] Error fetching: {e}\n")
                else:
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"\n{'='*80}\n")
                            lf.write(f"[JWT TOKEN RESOLUTION] ✗ ✗ ✗ NO JWT TOKEN AVAILABLE ✗ ✗ ✗\n")
                            lf.write(f"[JWT TOKEN RESOLUTION] Checked sources:\n")
                            lf.write(f"  1. X-ZT-Auth header: {'Present' if x_zt_auth_token else 'Missing'}\n")
                            
                            # Try to get session info for diagnosis
                            try:
                                sess, _ = self.session_manager.get_session_for_request(headers, {}, client_ip=None)
                                if sess:
                                    lf.write(f"  2. Session auth_token: {'Present' if sess.auth_token else 'Missing (THIS IS THE PROBLEM!)'}\n")
                                    lf.write(f"     Session ID: {sess.session_id[:16]}...\n")
                                    lf.write(f"     Session user: {sess.user_id or 'anonymous'}\n")
                                    if sess.user_id and not sess.auth_token:
                                        lf.write(f"\n[JWT TOKEN RESOLUTION] 🚨 ROOT CAUSE IDENTIFIED:\n")
                                        lf.write(f"  - User is authenticated (user={sess.user_id})\n")
                                        lf.write(f"  - But session.auth_token is None/empty\n")
                                        lf.write(f"  - Browser extension must send JWT via /sso-establish\n")
                                        lf.write(f"  - Check: Does extension call /sso-establish with auth_token field?\n")
                                else:
                                    lf.write(f"  2. Session: Not found\n")
                            except Exception as e:
                                lf.write(f"  2. Session: Error checking ({e})\n")
                            
                            lf.write(f"\n[JWT TOKEN RESOLUTION] ✗ Cannot fetch user settings without JWT\n")
                            lf.write(f"[JWT TOKEN RESOLUTION] Will use config defaults only\n")
                            lf.write(f"{'='*80}\n\n")
                    except Exception:
                        pass
            else:
                # STANDALONE MODE: Use fixed defaults, no API calls
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[STANDALONE MODE] Using fixed defaults, skipping API fetches\n")
                except Exception:
                    pass

            # =========================================================================
            # ANALYTICS BYPASS: Fastest possible path for telemetry/analytics domains
            # =========================================================================
            # Check BEFORE any session store access, logging, or config loading
            # to minimize latency impact on legitimate traffic
            analytics_bypass_domains = {
                'ab.chatgpt.com',  # ChatGPT analytics
                'o.openai.com',    # OpenAI telemetry
                'browser-intake-datadoghq.com',  # Datadog
                'cdn.segment.com', # Segment
                'api.segment.io',  # Segment API
                'statsig.com',     # Statsig
                'sentry.io',       # Sentry
                'amplitude.com',   # Amplitude
            }
            
            # Check if this is an analytics domain (exact match or subdomain)
            is_analytics = False
            for analytics_domain in analytics_bypass_domains:
                if host.lower() == analytics_domain or host.lower().endswith('.' + analytics_domain):
                    is_analytics = True
                    break
            
            if is_analytics:
                # Allow immediately - no logging, no metrics, no session store access
                return

            # === DETAILED REQUEST LOGGING (START) ===
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"\n{'='*80}\n")
                    lf.write(f"[REQUEST START] {method} {url}\n")
                    lf.write(f"[REQUEST] Host: {host} | Path: {path}\n")
                    lf.write(f"[REQUEST] Scheme: {req.scheme} | Port: {req.port}\n")
                    
                    # Log key headers
                    important_headers = ['User-Agent', 'Content-Type', 'Authorization', 'Cookie', 'Origin', 'Referer']
                    for hdr in important_headers:
                        val = headers.get(hdr) or headers.get(hdr.lower())
                        if val:
                            # Mask sensitive data
                            if hdr in ['Authorization', 'Cookie']:
                                masked = val[:20] + '...' if len(val) > 20 else val
                                lf.write(f"[REQUEST] {hdr}: {masked}\n")
                            else:
                                lf.write(f"[REQUEST] {hdr}: {val}\n")
                    
                    # Log body size
                    try:
                        body = req.get_text()
                        body_size = len(body) if body else 0
                        lf.write(f"[REQUEST] Body size: {body_size} bytes\n")
                        if body_size > 0 and body_size < 500:
                            lf.write(f"[REQUEST] Body preview: {body[:200]}...\n")
                    except Exception as body_err:
                        lf.write(f"[REQUEST] Body read error: {body_err}\n")
                    
                    lf.write(f"{'='*80}\n")
            except Exception as log_err:
                # Don't fail the request if logging fails
                print(f"[WARNING] Request logging error: {log_err}", file=__import__('sys').stderr)
            # === DETAILED REQUEST LOGGING (END) ===

            # CORS headers for internal endpoints (only needed for K8s service detection now)
            origin_hdr = headers.get('Origin') or headers.get('origin')
            allow_origin = origin_hdr if origin_hdr else '*'
            cors_headers = {
                "Access-Control-Allow-Origin": allow_origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
                "Vary": "Origin",
            }

            # Load config for non-internal requests
            cfg = self._get_config()

            # --- Merge user_settings into cfg if present ---
            if user_settings:
                # Merge/override config values with user-specific settings
                for k, v in user_settings.items():
                    if v is not None:
                        # Special handling for safeguard_keywords if it comes as a comma-separated string
                        if k in ('safeguard_keywords', 'safeguardKeywords') and isinstance(v, str):
                            # Parse comma-separated string into list
                            cfg['safeguard_keywords'] = [kw.strip() for kw in v.split(',') if kw.strip()]
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[USER SETTINGS] Parsed safeguard_keywords from string: {cfg['safeguard_keywords']}\n")
                            except Exception:
                                pass
                        else:
                            cfg[k] = v
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[USER SETTINGS] Applied overrides: {list(user_settings.keys())}\n")
                except Exception:
                    pass
            
            # --- Merge safeguard keywords from dedicated API ---
            # Only fetch from API if not already present in user_settings
            if not cfg.get('safeguard_keywords') and safeguard_keywords_from_api:
                cfg['safeguard_keywords'] = safeguard_keywords_from_api
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[SAFEGUARD KEYWORDS] Merged {len(safeguard_keywords_from_api)} keywords from API into config\n")
                except Exception:
                    pass
            elif cfg.get('safeguard_keywords') and safeguard_keywords_from_api:
                # User settings already had keywords, log that we're using them instead of API
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[SAFEGUARD KEYWORDS] Using keywords from user_settings ({len(cfg['safeguard_keywords'])} keywords), ignoring API fetch\n")
                except Exception:
                    pass
            
            # Check for K8s service internal requests (localhost already handled early)
            # Treat in-cluster service FQDNs for the proxy itself as internal so
            # requests routed by the Application Gateway to the service IP (or
            # service FQDN) are handled by the internal API/UI rather than
            # being forwarded and causing a hairpin loop.
            svc_internal = False
            try:
                lh = (host or '').lower()
                # Treat K8s internal service FQDNs AND public proxy domains as internal
                # This includes:
                # - zt-ai-proxy*.svc.cluster.local (K8s service)
                # - dev-ai-proxy.zerotrusted.ai, ai-proxy.zerotrusted.ai (public proxy domains)
                if (lh.endswith('.svc.cluster.local') and lh.startswith('zt-ai-proxy')) or \
                   (lh.endswith('-ai-proxy.zerotrusted.ai')) or \
                   (lh == 'ai-proxy.zerotrusted.ai'):
                    svc_internal = True
            except Exception:
                svc_internal = False

            if svc_internal:
                # Handle K8s internal service requests
                handled = handle_internal_request(
                    flow,
                    internal_only=True,
                    path=path,
                    url=url,
                    method=method,
                    headers=headers,
                    cors_headers=cors_headers,
                    ctx=ctx,
                    metrics=self.metrics,
                    INTERCEPTED_LOG_FILE=self.INTERCEPTED_LOG_FILE,
                    CONFIG_FILE_PATH=self.CONFIG_FILE_PATH,
                    UI_HTML=self.UI_HTML,
                    CONFIG_LAST_UPDATED=self.CONFIG_LAST_UPDATED,
                    api_key=(str(cfg.get('proxy_api_key') or '').strip()) or (os.getenv('ZT_PROXY_API_KEY') or "MISSING"),
                    get_config=self._get_config,
                    session_manager=self.session_manager,
                    get_blocklist=self._get_blocklist,
                    get_whitelist=self._get_whitelist,
                    get_features_cache_info=self._get_features_cache_info,
                    debug_log=self._debug,
                    features_started=self.features_started,
                    set_features_started=self._set_features_started,
                    BLOCKLIST_TTL_SEC=BLOCKLIST_TTL_SEC,
                    get_blocklist_cache_info=self._get_blocklist_cache_info,
                )
                if handled:
                    return

            # Update session snapshot metrics early (internal endpoints already returned)
            # NOTE: Removed session iteration - ignore tokens now browser-based
            try:
                sess_stats = GLOBAL_SESSION_STORE.stats()
                self.metrics['sessions_active'] = int(sess_stats.get('active') or 0)
            except Exception:
                pass

            # Bypass for ZeroTrusted service hosts and preflight
            if method == 'OPTIONS':
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[BYPASS] OPTIONS request: {url}\n")
                except Exception:
                    pass
                return
            if any(domain_matches(host, d) for d in get_bypass_hosts()):
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[BYPASS] Bypass host matched: {host}\n")
                except Exception:
                    pass
                return

            self.metrics['requests_total'] += 1
            
            # Log config and mode at start of filtering
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[FILTER START] Mode: {filter_mode} | Enforcement: {enforcement_mode}\n")
                    lf.write(f"[FILTER] Debug: {debug_enabled} | Auth disabled: {cfg.get('disable_auth')}\n")
                    lf.write(f"[FILTER] Remote blocklist: {use_remote_blocklist} | API key present: {bool(api_key and api_key != 'MISSING')}\n")
            except Exception:
                pass
            
            # Rotate log every 1000 requests if needed
            if self.metrics['requests_total'] % 1000 == 0:
                try:
                    rotated = self.store.rotate_log_if_needed(self.INTERCEPTED_LOG_FILE, max_size_mb=5.0, keep_lines=1000)
                    if rotated:
                        self._debug(f"[LOG ROTATION] Periodic rotation at {self.metrics['requests_total']} requests")
                except Exception as e:
                    self._debug(f"[LOG ROTATION] Periodic rotation failed: {e}")

            # Enforcement config - strictly honor what's in config
            filter_mode = str(cfg.get('filter_mode') or 'post-chat-pii').lower()
            enforcement_mode = str(cfg.get('enforcement_mode') or 'block').lower()
            
            # Log enforcement mode at the START of each request for debugging
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[ENFORCEMENT START] mode={enforcement_mode} filter={filter_mode} method={method} host={host} path={path}\n")
            except Exception:
                pass
            
            # Default to using remote blocklist when unset; honor explicit false
            _urb = cfg.get('use_remote_blocklist')
            use_remote_blocklist = True if _urb is None else bool(str(_urb).lower() in ("1","true","yes","on") or (_urb is True))
            include_body = cfg.get('include_request_body') in (True, 'true', 'True', '1')
            debug_enabled = bool(cfg.get('debug') or str(os.getenv('ZT_DEBUG') or '').lower() in ("1","true","yes","on"))

            BLOCKING_DISABLED = str(os.getenv('ZT_DISABLE_BLOCKING') or '').lower() in ("1","true","yes","on")
            # Prefer runtime-configured API key (proxy_api_key), fallback to env
            api_key = (str(cfg.get('proxy_api_key') or '').strip()) or (os.getenv('ZT_PROXY_API_KEY') or "MISSING")

            # Extract client IP for anonymous session tracking
            client_ip = flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else "unknown"

            # =========================================================================
            # CONVERSATION API PII CHECK (Standalone/Enterprise - block if PII detected)
            # =========================================================================
            # Check conversation endpoints (exclude /prepare and /init which are setup calls)
            if method == 'POST' and '/conversation' in path:
                # Skip /prepare and /init endpoints (they don't contain actual chat messages)
                if not any(x in path.lower() for x in ['/prepare', '/init', '/implicit_message_feedback']):
                    try:
                        # Extract request body
                        body_text = req.get_text()
                        
                        # Extract chat text using provider-specific extraction
                        if host_is_openai(host) or is_openai_chat_path(path):
                            chat_text = extract_openai_chat_text(body_text or '')
                        else:
                            chat_text = extract_chat_text(body_text or '')
                        
                        print(f"[CONVERSATION CHECK] Checking for PII in message (length={len(chat_text)})", flush=True)
                        
                        if chat_text:
                            # Use local PII detection
                            from interceptor.services import pii_fast
                            pii_result = pii_fast._detect_pii_local(chat_text, threshold=1)
                            
                            if pii_result and pii_result.get('detected'):
                                total_pii = pii_result.get('total', 0)
                                print(f"[CONVERSATION BLOCKED] PII detected (count={total_pii})", flush=True)
                                
                                # Log to file
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"\n[CONVERSATION BLOCKED] PII detected in POST {host}{path}\n")
                                        lf.write(f"[CONVERSATION BLOCKED] PII count: {total_pii}\n")
                                        lf.write(f"[CONVERSATION BLOCKED] Details: {pii_result}\n")
                                        lf.write(f"{'='*80}\n\n")
                                except Exception:
                                    pass
                                
                                # Generate block page with enterprise signup for standalone
                                pii_items_text = f"{total_pii} item{'s' if total_pii != 1 else ''}"
                                
                                # Create standalone-specific block page
                                standalone_html = f"""
<!doctype html><html><head><meta charset="utf-8"/><title>PII Detected · ZeroTrusted.ai</title><style>
html,body{{height:100%}}body{{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:#e6ecf3;display:flex;align-items:center;justify-content:center}}
.panel{{max-width:560px;width:94%;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 0 1px rgba(148,163,184,.1)}}
h1{{margin:0 0 16px;font-size:22px;color:#fff;font-weight:600}}
p{{margin:0 0 14px;line-height:1.6;color:#cbd5e1}}
.highlight{{color:#fbbf24;font-weight:500}}
.actions{{margin-top:24px;display:flex;gap:10px;flex-wrap:wrap}}
button{{border:0;border-radius:8px;padding:11px 18px;cursor:pointer;font-size:14.5px;font-weight:500;transition:all .2s}}
.primary{{background:#2563eb;color:#fff;flex:1}}
.primary:hover{{background:#1d4ed8}}
.secondary{{background:#334155;color:#e2e8f0;flex:1}}
.secondary:hover{{background:#475569}}
.enterprise{{background:#1e293b;border:1px solid #475569;padding:16px;border-radius:8px;margin-top:18px}}
.enterprise h3{{margin:0 0 8px;font-size:15px;color:#fbbf24}}
.enterprise p{{margin:0;font-size:13px;line-height:1.5;color:#94a3b8}}
.logo{{height:28px;margin-bottom:16px}}
</style></head><body>
<div class="panel">
<svg class="logo" viewBox="0 0 140 36" xmlns="http://www.w3.org/2000/svg">
<rect x="0" y="0" width="140" height="36" rx="6" fill="#1e2a44"/>
<text x="12" y="23" font-family="Segoe UI,Arial,sans-serif" font-size="15" fill="#ffffff">ZeroTrusted</text>
<circle cx="118" cy="18" r="7" fill="#2563eb"/>
</svg>
<h1>🛡️ Sensitive Information Detected</h1>
<p>Your message was blocked because it contains <span class="highlight">{pii_items_text} of potentially sensitive information</span> such as names, email addresses, phone numbers, or financial data.</p>
<p>ZeroTrusted protects you from accidentally sharing personal information with AI services.</p>
<div class="enterprise">
<h3>⚡ Upgrade to Enterprise</h3>
<p>Get advanced features including custom policies, detailed audit logs, team management, API integration, and priority support.</p>
</div>
<div class="actions">
<button class="primary" onclick="window.open('https://zerotrusted.ai/enterprise', '_blank')">Sign Up for Enterprise</button>
<button class="secondary" onclick="window.close()">Dismiss</button>
</div>
</div>
</body></html>
"""
                                
                                flow.response = http.Response.make(
                                    403,
                                    standalone_html.encode('utf-8'),
                                    {
                                        "Content-Type": "text/html; charset=utf-8",
                                        "X-ZT-Blocked": "1",
                                        "X-ZT-Mode": "post-chat",
                                        "X-ZT-Reason": "pii-detected",
                                        "X-ZT-PII-Count": str(total_pii),
                                    }
                                )
                                return
                            else:
                                print(f"[CONVERSATION ALLOWED] No PII detected, allowing request", flush=True)
                        else:
                            print(f"[CONVERSATION ALLOWED] No chat text extracted, allowing request", flush=True)
                            
                    except Exception as e:
                        print(f"[CONVERSATION CHECK ERROR] {e}", flush=True)
                        # On error, allow the request (fail open)
            # =========================================================================

            # =========================================================================
            # BLOCKLIST EARLY CHECK: Always check blocklist FIRST (before filter_mode)
            # =========================================================================
            # Blocklist must be respected regardless of filter_mode to ensure proper blocking
            if use_remote_blocklist and api_key and api_key != "MISSING":
                try:
                    bl_hosts = self._get_blocklist(api_key, force=False, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token)
                    wl_hosts = self._get_whitelist(api_key, force=False, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token)
                    
                    # Check whitelist first (always allow)
                    is_white = any(domain_matches(host, w) for w in (wl_hosts or []))
                    if is_white:
                        self.metrics['allowed_total'] += 1
                        if debug_enabled:
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[WHITELIST MATCH] Host whitelisted: {method} {host}{path}\n")
                            except Exception:
                                pass
                        return
                    
                    # Check blacklist - if matched, determine enforcement based on cached enforcement_type
                    is_blacklisted = any(domain_matches(host, b) for b in (bl_hosts or []))
                    if is_blacklisted:
                        # Get enforcement type from cached /shadow-ai API response
                        enforcement_type = None
                        try:
                            enforcement_type = get_cached_enforcement_type()
                        except Exception:
                            pass
                        
                        # If enforcement_type is "all_requests", block ALL requests immediately
                        # If enforcement_type is "post_chat_pii" or None, continue to filter_mode logic
                        if enforcement_type == 'all_requests':
                            self.metrics['blocklist_matched_total'] += 1
                            self.metrics['blocked_total'] += 1
                            
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[BLOCKLIST ALL_REQUESTS BLOCK] host={host} path={path} enforcement_type={enforcement_type}\n")
                            except Exception:
                                pass
                            
                            action_taken_str = "🚫 Request Blocked by ZeroTrusted.ai: Host matches blocklist (all requests blocked)."
                            try:
                                reason_header = action_taken_str.encode('ascii', 'ignore').decode('ascii')
                            except Exception:
                                reason_header = "Request Blocked by ZeroTrusted.ai"
                            
                            resp_headers = {
                                **cors_headers,
                                "Content-Type": "text/html; charset=utf-8",
                                "X-ZT-Blocked": "1",
                                "X-ZT-Reason": reason_header,
                                "X-ZT-Mode": "blocklist",
                                "X-ZT-Enforcement-Type": "all_requests",
                                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                "Pragma": "no-cache",
                                "Expires": "0",
                            }
                            
                            html = BLOCK_PAGE_HTML.replace("{{REASON}}", action_taken_str).replace("{{PROXY_BASE}}", proxy_base)
                            flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                            
                            # Send audit log
                            send_block_audit_log(
                                host=host,
                                path=path,
                                url=url,
                                method=method,
                                headers=headers,
                                block_reason="Blocklist match (all_requests enforcement)",
                                block_type="blocklist-all-requests",
                                config_loader=self._get_config,
                                session=user_session
                            )
                            return
                        else:
                            # enforcement_type is "post_chat_pii" or unknown - continue to filter logic
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[BLOCKLIST POST_CHAT_PII] host={host} enforcement_type={enforcement_type} - continuing to filter logic\n")
                            except Exception:
                                pass
                except Exception as bl_err:
                    # If blocklist check fails, continue with normal processing (fail open)
                    if debug_enabled:
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[BLOCKLIST CHECK ERROR] {bl_err}, continuing\n")
                        except Exception:
                            pass

            # =========================================================================
            # POST-CHAT-PII EARLY BYPASS: Skip auth + processing for non-targeted paths
            # =========================================================================
            # In post-chat-pii mode, ONLY these paths need authentication/inspection:
            # 1. POST /backend-api/f/conversation (chat endpoint with PII) - EXCLUDING /prepare and /init
            # 2. files.oaiusercontent.com uploads (file sanitization)
            # Everything else bypasses immediately (no auth check, no headers, no processing)
            # NOTE: Blacklist check above takes precedence - if host is blacklisted with all_requests, already blocked
            if filter_mode == 'post-chat-pii':
                is_conversation_endpoint = (
                    method == 'POST' and 
                    path.startswith('/backend-api/f/conversation') and
                    not any(exclude in path.lower() for exclude in ['/prepare', '/init'])
                )
                is_file_upload = ('files.oaiusercontent.com' in host.lower() or 'oaiusercontent' in host.lower())
                
                # Fast passthrough for everything except targeted endpoints
                if not is_conversation_endpoint and not is_file_upload:
                    self.metrics['allowed_total'] += 1
                    if debug_enabled:
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[POST-CHAT-PII EARLY BYPASS] {method} {host}{path}\n")
                        except Exception:
                            pass
                    return  # Complete bypass - no auth, no processing, no headers

            # =========================================================================
            # AUTHENTICATION GATE: Always require authentication for logging attribution
            # =========================================================================
            # STANDALONE MODE: Skip authentication gate completely
            if IS_STANDALONE:
                print(f"[STANDALONE] Skipping auth gate for {method} {host}{path}", flush=True)
                disable_auth = True
                is_authenticated = True
                user_session = None
                flow.metadata['zt_authenticated'] = True
                # Continue to normal filtering logic below
            else:
                # ENTERPRISE MODE: Enforce authentication
                # Simplified authentication flow:
                # 1. Always try to find authenticated session (check X-ZT-Session header, cookies)
                # 2. If NO authenticated session found → block and require login
                # 3. This ensures all audit logs have proper username attribution
                #
                # Note: This means first-time users MUST authenticate before using the proxy.
                # No anonymous access allowed - ensures complete audit trail from day one.
                
                # Debug: Log incoming headers for session debugging
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        x_zt_session = headers.get('X-ZT-Session') or headers.get('x-zt-session')
                        has_cookie = 'zt_sess=' in (headers.get('Cookie') or headers.get('cookie') or '')
                        lf.write(f"[AUTH DEBUG] {method} {host}{path}\n")
                        lf.write(f"[AUTH DEBUG] X-ZT-Session header: {'present' if x_zt_session else 'MISSING'}\n")
                        if x_zt_session:
                            lf.write(f"[AUTH DEBUG] X-ZT-Session value: {x_zt_session[:20]}...\n")
                        lf.write(f"[AUTH DEBUG] zt_sess cookie: {'present' if has_cookie else 'missing'}\n")
                except Exception:
                    pass
                
                # Try to find authenticated session (ignore disable_auth config)
                user_session = self.session_manager._lookup_authenticated_session(headers)
                is_authenticated = self.session_manager.is_session_authenticated(user_session)
                
                # Store auth status in flow metadata for response() method to add headers
                flow.metadata['zt_authenticated'] = is_authenticated
                if user_session and is_authenticated:
                    flow.metadata['zt_ignore_remaining'] = user_session.ignore_remaining
                
                # Set disable_auth based on authentication status (for compatibility with rest of code)
                disable_auth = False  # Always enforce authentication
                
                # Log authentication state
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        session_info = f"{user_session.session_id[:10]}..." if user_session and user_session.session_id else "None"
                        user_info = user_session.user_id if user_session else "None"
                        lf.write(f"[AUTH CHECK] authenticated={is_authenticated} | session={session_info} | user={user_info} | host={host}\n")
                except Exception:
                    pass
                
                # If not authenticated, ALWAYS block and require authentication
                # Authentication is required regardless of filter_mode or endpoint
                if not is_authenticated:
                    # Block and require authentication
                    self.metrics['blocked_total'] += 1
                    
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[AUTH REQUIRED] Blocking unauthenticated request: {method} {host}{path}\n")
                    except Exception:
                        pass
                    
                    # Determine enforcement type from cached /shadow-ai API response
                    # If enforcement_type is "post_chat_pii", use toast-only (no full page block)
                    # If enforcement_type is "all_requests", use full AUTH_BLOCK_PAGE_HTML
                    enforcement_type = None
                    try:
                        enforcement_type = get_cached_enforcement_type()
                        if not enforcement_type:
                            # Fallback to filter_mode config
                            enforcement_type = 'post_chat_pii' if filter_mode == 'post-chat-pii' else 'all_requests'
                    except Exception:
                        enforcement_type = 'all_requests'  # Safe default
                    
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[AUTH ENFORCEMENT] enforcement_type={enforcement_type} filter_mode={filter_mode}\n")
                    except Exception:
                        pass
                    
                    reason = "You must authenticate to access AI services monitored by ZeroTrusted.ai."
                    try:
                        reason_header = reason.encode('ascii', 'ignore').decode('ascii')
                    except Exception:
                        reason_header = "Authentication Required"
                    
                    resp_headers = {
                        **cors_headers,
                        "X-ZT-Blocked": "1",
                        "X-ZT-Reason": reason_header,
                        "X-ZT-Mode": "auth-required",
                        "X-ZT-Auth": "0",  # Indicates auth-required block
                        # Cache-busting headers
                        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                        "Pragma": "no-cache",
                        "Expires": "0",
                    }
                    
                    # Decide whether to show full page or just rely on toast
                    if enforcement_type == 'post_chat_pii':
                        # Toast-only mode: Return minimal response, extension will show toast with Connect button
                        resp_headers["Content-Type"] = "text/plain; charset=utf-8"
                        flow.response = http.Response.make(403, b"Authentication required", resp_headers)
                    else:
                        # Full page block mode (all_requests): Show AUTH_BLOCK_PAGE_HTML
                        try:
                            proxy_base = (
                                os.getenv('ZT_PROXY_URL') or
                                cfg.get('proxy_base_url') or 
                                os.getenv('ZT_PROXY_BASE_URL') or 
                                'https://ai-proxy.zerotrusted.ai'
                            )
                        except Exception:
                            proxy_base = "https://ai-proxy.zerotrusted.ai"
                        
                        resp_headers["Content-Type"] = "text/html; charset=utf-8"
                        html = AUTH_BLOCK_PAGE_HTML.replace("{{REASON}}", reason).replace("{{PROXY_BASE}}", proxy_base)
                        flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                    
                    # Send audit log with user info if session exists (even if not authenticated)
                    # Note: user_session may exist but not be authenticated (e.g., anonymous or expired)
                    send_block_audit_log(
                        host=host,
                        path=path,
                        url=url,
                        method=method,
                        headers=headers,
                        block_reason="Authentication required - no valid session",
                        block_type="auth-required",
                        config_loader=self._get_config,
                        session=user_session  # Pass session so username can be extracted
                    )
                    return
            
            # User is authenticated (or standalone mode) - proceed with normal filtering

            # =========================================================================
            # BROWSER-BASED IGNORE TOKEN CHECK
            # =========================================================================
            # Check for X-ZT-Ignore-Token header from Chrome extension
            # If present and > 0, this request should bypass all checks
            # STANDALONE MODE: Ignore this header to always enforce PII detection during testing
            ignore_token_header = headers.get('X-ZT-Ignore-Token') or headers.get('x-zt-ignore-token')
            has_ignore_token = False
            if ignore_token_header and not IS_STANDALONE:  # Only respect ignore tokens in enterprise mode
                try:
                    token_count = int(ignore_token_header)
                    if token_count > 0:
                        has_ignore_token = True
                        # Log token consumption
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[IGNORE TOKEN] Bypassing checks (browser token count: {token_count})\n")
                        except Exception:
                            pass
                        
                        self.metrics['allowed_total'] += 1
                        self.metrics['ignore_tokens_consumed_total'] = self.metrics.get('ignore_tokens_consumed_total', 0) + 1
                        
                        # Allow the request to proceed, but intercept response to add consumption header
                        # We'll add this in the response() hook
                        flow.metadata['zt_token_consumed'] = True
                        return
                except (ValueError, TypeError):
                    pass  # Invalid header value, ignore
            elif ignore_token_header and IS_STANDALONE:
                # Log that we're ignoring the token in standalone mode
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[STANDALONE] Ignoring X-ZT-Ignore-Token header (count: {ignore_token_header}) - always enforce PII detection\n")
                except Exception:
                    pass

            # =========================================================================
            # OPTIMIZED BYPASS: Non-blocklisted hosts (after blacklist check above)
            # =========================================================================
            # At this point, if using remote blocklist:
            # - Whitelisted hosts have already been allowed
            # - Blacklisted hosts with all_requests enforcement have already been blocked
            # - For remaining hosts (not in blocklist or post_chat_pii enforcement), allow non-targeted paths
            
            # For non-blacklisted hosts in post-chat-pii mode, skip non-targeted endpoints
            # POST-CHAT-PII mode: only inspect conversation endpoints and file uploads

            # Compute proxy base for internal API calls in block page
            # IMPORTANT: Internal endpoints like /ignore-start, /ignore-status must go to the proxy itself,
            # NOT to the original request host (e.g., chatgpt.com)
            try:
                # Use configured proxy address, env var, or default
                # For production: set ZT_PROXY_URL=https://zt-proxy.zerotrusted.ai
                proxy_base = (
                    os.getenv('ZT_PROXY_URL') or
                    cfg.get('proxy_base_url') or 
                    os.getenv('ZT_PROXY_BASE_URL') or 
                    'https://ai-proxy.zerotrusted.ai'  # Changed from 0.0.0.0 (unreachable from browser)
                )
            except Exception:
                proxy_base = "https://ai-proxy.zerotrusted.ai"

            # Remote blocklist check for POST-CHAT-PII enforcement mode
            # (Note: all_requests enforcement already handled above at early blocklist check)
            # This section only handles the legacy/fallback case for non-API-driven enforcement
            if filter_mode != 'post-chat-pii' and use_remote_blocklist and api_key and api_key != "MISSING":
                bl_hosts = self._get_blocklist(api_key, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token)
                wl_hosts = self._get_whitelist(api_key, bearer_token=bearer_token, x_zt_auth_token=x_zt_auth_token)
                is_black = any(domain_matches(host, b) for b in (bl_hosts or []))
                is_white = any(domain_matches(host, w) for w in (wl_hosts or []))
                if is_black and not is_white:
                    self.metrics['blocklist_matched_total'] += 1
                    if BLOCKING_DISABLED or enforcement_mode == 'observe':
                        bl_block = False
                    elif enforcement_mode == 'block':
                        bl_block = True
                    else:
                        bl_block = (method == 'POST')
                    action_taken_str = (
                        "🚫 Request Blocked by ZeroTrusted.ai: Host matches remote blocklist."
                        if bl_block else "✅ Allowed (host on remote blocklist, policy permits)"
                    )
                    # Log
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"\n[REMOTE BLOCKLIST MATCH] host={host} path={path} block={bl_block} mode={filter_mode} enf={enforcement_mode}\n")
                    except Exception:
                        pass
                    if bl_block:
                        self.metrics['blocked_total'] += 1
                        try:
                            reason_header = action_taken_str.encode('ascii', 'ignore').decode('ascii')
                        except Exception:
                            reason_header = "Request Blocked by ZeroTrusted.ai"
                        resp_headers = {
                            **cors_headers,
                            "Content-Type": "text/html; charset=utf-8",
                            "X-ZT-Blocked": "1",
                            "X-ZT-Reason": reason_header,
                            "X-ZT-Mode": "blocklist",
                            # Cache-busting headers to prevent browser from caching old proxy_base
                            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                            "Pragma": "no-cache",
                            "Expires": "0",
                        }
                        # Hide OpenAI inline error if present by injecting a style
                        extra_hide = """
<style>div.text-token-text-error{display:none!important}</style>
"""
                        disable_auth = bool(cfg.get('disable_auth')) or str(os.getenv('ZT_DISABLE_AUTH') or '').lower() in ("1","true","yes","on")
                        html = BLOCK_PAGE_HTML.replace("{{REASON}}", action_taken_str + extra_hide).replace("{{PROXY_BASE}}", proxy_base)
                        if disable_auth:
                            # Remove connect button section crudely if present
                            html = html.replace('id=\\"zt-connect-btn\\" style=\\"display:none\\"', 'id=\"zt-connect-btn\" style=\"display:none\" hidden')
                            html = html.replace('You are not connected.', 'Authentication disabled for testing.')
                        flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                        
                        # Send audit log for blocklist block
                        send_block_audit_log(
                            host=host,
                            path=path,
                            url=url,
                            method=method,
                            headers=headers,
                            block_reason="Remote blocklist match",
                            block_type="blocklist",
                            config_loader=self._get_config,
                            session=user_session
                        )
                        return
                    else:
                        self.metrics['allowed_total'] += 1
                        return  # allow immediately

            # --- File Upload Scanning (files.oaiusercontent.com) ---
            try:
                scan_uploads = cfg.get('scan_uploads')
                if scan_uploads in (None, 'true', 'True', '1', True):
                    scan_uploads = True
                else:
                    scan_uploads = False
                strict_block_all_uploads = cfg.get('strict_block_all_uploads') in (True, '1', 'true', 'True')
            except Exception:
                scan_uploads = True
                strict_block_all_uploads = False

            is_file_upload = (host.endswith('files.oaiusercontent.com') and method in ('PUT','POST'))
            if is_file_upload and scan_uploads:
                from time import perf_counter as _pfc
                _scan_start = _pfc()
                self.metrics['file_uploads_scanned_total'] += 1
                # Enforce sanitized filename prefix if configured
                try:
                    require_sanitized_uploads = cfg.get('require_sanitized_uploads')
                    if require_sanitized_uploads in (None, 'true', 'True', '1'):
                        require_sanitized_uploads = True
                    elif str(os.getenv('ZT_REQUIRE_SANITIZED_UPLOADS') or '').lower() in ("1","true","yes","on"):
                        require_sanitized_uploads = True
                    else:
                        require_sanitized_uploads = False
                except Exception:
                    require_sanitized_uploads = True
                unsanitized_blocked = False
                original_filename = ''
                if require_sanitized_uploads:
                    try:
                        # Try to parse filename from headers (Content-Disposition) or query params
                        cd = flow.request.headers.get('Content-Disposition') or flow.request.headers.get('content-disposition') or ''
                        fname = ''
                        if 'filename=' in cd:
                            # crude parsing
                            part = cd.split('filename=',1)[1]
                            if part.startswith('"'):
                                part = part.split('"',2)[1] if '"' in part[1:] else part.strip('"')
                            else:
                                part = part.split(';',1)[0]
                            fname = part.strip()
                        if not fname:
                            # Fallback: attempt to extract from path (last segment)
                            path_part = path or ''
                            if '/' in path_part:
                                maybe = path_part.rsplit('/',1)[-1]
                                if maybe and '.' in maybe:
                                    fname = maybe
                        original_filename = fname
                        if fname and not fname.startswith('[SANITIZED]'):
                            # Block immediately
                            action_taken_str = '🚫 Request Blocked by ZeroTrusted.ai: Unsanitized file upload (missing [SANITIZED] prefix).<br><br><a href="https://dev.zerotrusted.ai/file-sanitization" target="_blank" rel="noopener" style="color:#81b9ff;text-decoration:underline">Click here to sanitize your files.</a>'
                            html = BLOCK_PAGE_HTML.replace("{{REASON}}", action_taken_str).replace("{{PROXY_BASE}}", proxy_base)
                            try:
                                reason_header = action_taken_str.encode('ascii','ignore').decode('ascii')
                            except Exception:
                                reason_header = "Request Blocked by ZeroTrusted.ai"
                            resp_headers = {
                                "Content-Type": "text/html; charset=utf-8",
                                "X-ZT-Blocked": "1",
                                "X-ZT-Reason": reason_header,
                                "X-ZT-Mode": "file-upload-sanitization",
                                # Cache-busting headers
                                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                "Pragma": "no-cache",
                                "Expires": "0",
                            }
                            if fname:
                                resp_headers['X-ZT-Filename'] = fname[:120]
                            flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                            self.metrics['file_uploads_blocked_total'] += 1
                            self.metrics['file_uploads_sanitized_block_total'] += 1
                            self.metrics['blocked_total'] += 1
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[FILE UPLOAD SANITIZE BLOCK] host={host} filename={fname} path={path}\n")
                            except Exception:
                                pass
                            
                            # Send audit log
                            send_block_audit_log(
                                host=host,
                                path=path,
                                url=url,
                                method=method,
                                headers=headers,
                                block_reason=f"Unsanitized file upload: {fname}",
                                block_type="file-upload-sanitization",
                                config_loader=self._get_config,
                                session=user_session
                            )
                            return
                    except Exception:
                        pass
                body_bytes = b''
                try:
                    body_bytes = bytes(flow.request.content or b'')
                except Exception:
                    body_bytes = b''
                size = len(body_bytes)
                MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5MB cap
                truncated = False
                if size > MAX_SCAN_BYTES:
                    body_sample = body_bytes[:MAX_SCAN_BYTES]
                    truncated = True
                else:
                    body_sample = body_bytes

                # Decide text extraction heuristic
                text_for_scan = ''
                if body_sample:
                    # Attempt utf-8 decode first; fallback latin1 then ignore
                    try:
                        text_for_scan = body_sample.decode('utf-8')
                    except Exception:
                        try:
                            text_for_scan = body_sample.decode('latin-1')
                        except Exception:
                            text_for_scan = ''
                # For binary (likely) reduce to empty to avoid false positives
                if text_for_scan and not any(ch.isalpha() for ch in text_for_scan[:200]):
                    # treat as binary (skip)
                    text_for_scan = ''

                # If strict block all uploads is set, block immediately regardless
                if strict_block_all_uploads:
                    action_taken_str = "🚫 Request Blocked by ZeroTrusted.ai: File uploads disabled by policy."  # reason
                    html = BLOCK_PAGE_HTML.replace("{{REASON}}", action_taken_str).replace("{{PROXY_BASE}}", proxy_base)
                    try:
                        reason_header = action_taken_str.encode('ascii', 'ignore').decode('ascii')
                    except Exception:
                        reason_header = "Request Blocked by ZeroTrusted.ai"
                    resp_headers = {
                        "Content-Type": "text/html; charset=utf-8",
                        "X-ZT-Blocked": "1",
                        "X-ZT-Reason": reason_header,
                        "X-ZT-Mode": "file-upload-policy",
                        # Cache-busting headers
                        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                        "Pragma": "no-cache",
                        "Expires": "0",
                    }
                    flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                    self.metrics['file_uploads_blocked_total'] += 1
                    self.metrics['blocked_total'] += 1
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[FILE UPLOAD BLOCK] host={host} size={size} strict_policy=True\n")
                    except Exception:
                        pass
                    
                    # Send audit log
                    send_block_audit_log(
                        host=host,
                        path=path,
                        url=url,
                        method=method,
                        headers=headers,
                        block_reason="File uploads disabled by policy",
                        block_type="file-upload-policy",
                        config_loader=self._get_config,
                        session=user_session
                    )
                    return

                # If we have text, run PII gate (reuse existing categories/threshold defaults)
                if text_for_scan:
                    try:
                        # Basic threshold & categories; reuse environment or defaults similar to chat gate
                        pii_threshold = int(cfg.get('pii_threshold') or 1)
                        cats = cfg.get('pii_categories') or ['person','email','phone','address','credit_card','ssn','passport','bank_account']
                        
                        # Log PII scan attempt
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[PII SCAN] Upload file scan | threshold={pii_threshold} | text_len={len(text_for_scan)}\n")
                        except Exception:
                            pass
                        
                        result = run_pii_gate(text_for_scan[:5000], threshold=pii_threshold, categories=cats)  # type: ignore[arg-type]
                        entities = (result.get('entities') or []) if isinstance(result, dict) else []
                        hit = bool(entities)
                        
                        # Log PII scan result
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[PII RESULT] Upload | hit={hit} | entities_count={len(entities)}\n")
                                if entities:
                                    for ent in entities[:3]:
                                        ent_type = ent.get('type') if isinstance(ent, dict) else 'unknown'
                                        lf.write(f"[PII ENTITY] {ent_type}\n")
                        except Exception:
                            pass
                        
                        if hit:
                            self.metrics['file_uploads_pii_hits_total'] += 1
                            # Determine block decision
                            if not BLOCKING_DISABLED and enforcement_mode in ('block','auto'):
                                action_taken_str = "🚫 Request Blocked by ZeroTrusted.ai: File upload PII detected."
                                html = BLOCK_PAGE_HTML.replace("{{REASON}}", action_taken_str).replace("{{PROXY_BASE}}", proxy_base)
                                short_entities = []
                                try:
                                    for e in entities[:5]:
                                        if isinstance(e, dict):
                                            typ = e.get('type') or e.get('entity_type') or 'pii'
                                            val = e.get('value') or e.get('text') or ''
                                            if val and len(val) > 40:
                                                val = val[:37] + '...'
                                            short_entities.append(f"{typ}:{val}")
                                except Exception:
                                    pass
                                ent_header = ",".join(short_entities)
                                # Build masked list HTML (censored values with asterisks)
                                masked_items_html = ''
                                try:
                                    if entities:
                                        masked_lis = []
                                        for e in entities[:6]:
                                            if not isinstance(e, dict):
                                                continue
                                            typ = e.get('type') or e.get('entity_type') or 'pii'
                                            val = e.get('value') or e.get('text') or ''
                                            sval = str(val)
                                            # Mask strategy: keep first 2 and last 2 visible for longer strings, emails keep domain
                                            masked = sval
                                            if '@' in sval:
                                                parts = sval.split('@',1)
                                                left = parts[0]
                                                if len(left) > 2:
                                                    left_mask = left[:2] + '*' * max(0,len(left)-2)
                                                else:
                                                    left_mask = '*' * len(left)
                                                masked = left_mask + '@' + parts[1]
                                            elif len(sval) > 6:
                                                masked = sval[:2] + '*' * (len(sval)-4) + sval[-2:]
                                            else:
                                                masked = '*' * len(sval)
                                            if len(masked) > 80:
                                                masked = masked[:77] + '...'
                                            masked_lis.append(f"<li><b>{typ}</b>: <span class='pii-mask'>{masked}</span></li>")
                                        if masked_lis:
                                            masked_items_html = "<ul class='pii-list'>" + ''.join(masked_lis) + "</ul>"
                                except Exception:
                                    masked_items_html = ''
                                try:
                                    reason_header = action_taken_str.encode('ascii', 'ignore').decode('ascii')
                                except Exception:
                                    reason_header = "Request Blocked by ZeroTrusted.ai"
                                scan_ms = int((_pfc() - _scan_start) * 1000)
                                resp_headers = {
                                    "Content-Type": "text/html; charset=utf-8",
                                    "X-ZT-Blocked": "1",
                                    "X-ZT-Reason": reason_header,
                                    "X-ZT-Mode": "file-upload-pii",
                                    # Cache-busting headers
                                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                    "Pragma": "no-cache",
                                    "Expires": "0",
                                }
                                resp_headers['X-ZT-Scan-Time'] = str(scan_ms)
                                if ent_header:
                                    resp_headers['X-ZT-PII-Entities'] = ent_header
                                flow.response = http.Response.make(403, html.replace('</h1>Request blocked by ZeroTrusted.ai</h1>', '</h1>Request blocked by ZeroTrusted.ai</h1>'+masked_items_html).encode('utf-8'), resp_headers)
                                self.metrics['file_uploads_blocked_total'] += 1
                                self.metrics['blocked_total'] += 1
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[FILE UPLOAD BLOCK] host={host} size={size} pii_entities={ent_header} truncated={truncated}\n")
                                except Exception:
                                    pass
                                
                                # Send audit log with PII entities
                                send_block_audit_log(
                                    host=host,
                                    path=path,
                                    url=url,
                                    method=method,
                                    headers=headers,
                                    block_reason=f"PII detected in file upload",
                                    block_type="file-upload-pii",
                                    body_text=text_for_scan,
                                    pii_entities=entities,
                                    config_loader=self._get_config,
                                    session=user_session
                                )
                                return
                    except Exception as e:
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[FILE UPLOAD SCAN ERROR] host={host} err={e}\n")
                        except Exception:
                            pass
                # If not blocked, allow
                try:
                    scan_ms_allow = int((_pfc() - _scan_start) * 1000)
                except Exception:
                    scan_ms_allow = None
                self.metrics['allowed_total'] += 1
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[FILE UPLOAD ALLOW] host={host} size={size} text={'yes' if bool(text_for_scan) else 'no'} truncated={truncated} scan_ms={scan_ms_allow}\n")
                except Exception:
                    pass
                return

            # post-only mode (not applicable in post-chat-pii mode)
            if filter_mode == 'post-only' and method == 'POST':
                if not BLOCKING_DISABLED and enforcement_mode in ('block','auto'):
                    blocked, _ = handle_post_only_block(
                        flow,
                        reason="post-only",
                        html_template=BLOCK_PAGE_HTML,
                        proxy_base=proxy_base,
                        headers=headers,
                    )
                    if blocked:
                        self.metrics['blocked_total'] += 1
                        try:
                            if flow.response and flow.response.headers is not None:
                                flow.response.headers["X-ZT-Mode"] = "post-only"
                        except Exception:
                            pass
                        return

            # Check if path is excluded from chat processing (e.g., /prepare)
            if method == 'POST' and '/prepare' in path.lower():
                if debug_enabled:
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[CHAT PATH EXCLUDED] path={path} reason=prepare_endpoint\n")
                    except Exception:
                        pass
                # Passthrough - no PII/safeguard checks for /prepare
                return

            # DEBUG: Log all POST requests to chat-like paths
            if method == 'POST':
                is_chat = is_chat_path(path)
                ignore_remaining = user_session.ignore_remaining if user_session else 0
                session_id = user_session.session_id if user_session else 'none'
                try:
                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                        lf.write(f"[POST DEBUG] path={path} is_chat={is_chat} filter_mode={filter_mode} session={session_id} ignore_remaining={ignore_remaining}\n")
                except Exception:
                    pass

            if filter_mode == 'post-chat-pii' and method == 'POST' and is_chat_path(path):
                # Session already retrieved earlier for JWT authentication
                sess = user_session
                
                # Circuit Breaker: Start request timer for guaranteed max latency
                import time
                circuit_breaker_enabled = cfg.get('circuit_breaker_enabled')
                if circuit_breaker_enabled is None:
                    circuit_breaker_enabled = os.getenv('ZT_CIRCUIT_BREAKER_ENABLED', 'true').lower() == 'true'
                
                request_start_time = None
                max_latency_ms = None
                timeout_action = 'passthrough'
                async_audit_enabled = False
                
                if circuit_breaker_enabled:
                    request_start_time = time.time()
                    # Get max latency budget (default 6000ms = 6 seconds)
                    max_latency_ms = cfg.get('max_latency_ms')
                    if max_latency_ms is None:
                        max_latency_ms = int(os.getenv('ZT_MAX_LATENCY_MS', '6000'))
                    # Get timeout action (passthrough | block | log-only)
                    timeout_action_cfg = cfg.get('timeout_action')
                    if timeout_action_cfg:
                        timeout_action = str(timeout_action_cfg).lower()
                    else:
                        timeout_action = os.getenv('ZT_TIMEOUT_ACTION', 'passthrough').lower()
                    # Get async audit setting
                    async_audit_cfg = cfg.get('async_audit')
                    if async_audit_cfg is not None:
                        async_audit_enabled = bool(async_audit_cfg)
                    else:
                        async_audit_enabled = os.getenv('ZT_ASYNC_AUDIT', 'true').lower() == 'true'
                
                # Note: We do NOT auto-bypass based on ignore_remaining here.
                # The "Proceed Anyway" flow works by:
                # 1. User gets blocked by PII detection
                # 2. User clicks "Proceed Anyway" → calls /ignore-start which increments ignore counter
                # 3. User re-submits → Request allowed in the re-submit logic below
                # This ensures we always check PII first, then allow bypass only after explicit user action.
                
                # --- Attachment filename sanitization (metadata attachments[].name) ---
                try:
                    # Respect same config flag as raw file uploads
                    require_sanitized_uploads = cfg.get('require_sanitized_uploads')
                    if require_sanitized_uploads in (None, 'true', 'True', '1', True):
                        require_sanitized_uploads = True
                    else:
                        require_sanitized_uploads = False
                except Exception:
                    require_sanitized_uploads = True
                if require_sanitized_uploads and not BLOCKING_DISABLED:
                    try:
                        body_text = ''
                        try:
                            body_text = flow.request.get_text() or ''
                        except Exception:
                            body_text = ''
                        if body_text and body_text.strip().startswith('{') and 'attachments' in body_text:
                            import json as _json
                            parsed = None
                            try:
                                parsed = _json.loads(body_text)
                            except Exception:
                                parsed = None
                            if isinstance(parsed, dict):
                                msgs = parsed.get('messages')
                                if isinstance(msgs, list) and msgs:
                                    first = msgs[0] if isinstance(msgs[0], dict) else None
                                    meta = first.get('metadata') if isinstance(first, dict) else None
                                    atts = meta.get('attachments') if isinstance(meta, dict) else None
                                    unsanitized = []
                                    if isinstance(atts, list):
                                        for att in atts[:8]:
                                            if not isinstance(att, dict):
                                                continue
                                            nm = att.get('name') or att.get('filename') or ''
                                            if nm and not str(nm).startswith('[SANITIZED]'):
                                                unsanitized.append(str(nm)[:80])
                                    if unsanitized:
                                        reason = "🚫 Request Blocked by ZeroTrusted.ai: Unsanitized attached file(s)."
                                        try:
                                            reason_header = reason.encode('ascii','ignore').decode('ascii')
                                        except Exception:
                                            reason_header = 'Request Blocked by ZeroTrusted.ai'
                                        resp_headers = {
                                            'Content-Type': 'text/html; charset=utf-8',
                                            'X-ZT-Blocked': '1',
                                            'X-ZT-Reason': reason_header,
                                            'X-ZT-Mode': 'post-chat',
                                            'X-ZT-Mode-Detail': 'attachment-sanitization',
                                            # Cache-busting headers
                                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                                            'Pragma': 'no-cache',
                                            'Expires': '0',
                                        }
                                        try:
                                            resp_headers['X-ZT-Filenames'] = ';'.join(unsanitized)[:240]
                                        except Exception:
                                            pass
                                        html = BLOCK_PAGE_HTML.replace('{{REASON}}', reason + '<br><div style="margin-top:6px;font-size:12.5px">' + '<br>'.join(unsanitized[:6]) + '</div>').replace('{{PROXY_BASE}}', proxy_base)
                                        flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                                        try:
                                            self.metrics['file_attachments_sanitized_block_total'] += 1
                                            self.metrics['blocked_total'] += 1
                                        except Exception:
                                            pass
                                        try:
                                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                                lf.write(f"[ATTACHMENT SANITIZE BLOCK] host={host} path={path} names={unsanitized}\n")
                                        except Exception:
                                            pass
                                        
                                        # Send audit log
                                        send_block_audit_log(
                                            host=host,
                                            path=path,
                                            url=url,
                                            method=method,
                                            headers=headers,
                                            block_reason=f"Unsanitized attachments: {', '.join(unsanitized[:3])}",
                                            block_type="attachment-sanitization",
                                            body_text=body_text,
                                            config_loader=self._get_config,
                                            session=user_session
                                        )
                                        return
                    except Exception:
                        pass
                # Removed early bypass for /prepare endpoint; passthrough is now default for non-targeted paths in post-chat-pii mode
                self.metrics['post_chat_total'] += 1
                body_text = req.get_text() if include_body else req.get_text()  # still need text to check PII
                
                # Timing: Start text extraction
                import time
                extract_start = time.time()
                
                # Prefer provider-specific extraction for OpenAI/ChatGPT
                if host_is_openai(host) or is_openai_chat_path(path):
                    chat_text = extract_openai_chat_text(body_text or '')
                else:
                    chat_text = extract_chat_text(body_text or '')
                
                extract_time = time.time() - extract_start
                
                if debug_enabled:
                    try:
                        self._debug(f"[PII TRACE] extracted_text_len={len(chat_text)} extract_time={extract_time:.3f}s")
                    except Exception:
                        pass
                # Attachments: if metadata has attachments, include their text in PII gate too
                attach_text, attach_count = ('', 0)
                try:
                    attach_text, attach_count = extract_attachments_text(body_text or '')
                    if debug_enabled and attach_count:
                        self._debug(f"[PII TRACE] attachments found={attach_count} text_len={len(attach_text or '')}")
                except Exception as e:
                    if debug_enabled:
                        self._debug(f"[PII TRACE] attachments parse error: {e}")
                # Determine threshold and categories
                thr = None
                try:
                    if cfg.get('pii_threshold') not in (None, ''):
                        thr = int(cfg.get('pii_threshold'))
                except Exception:
                    thr = None
                if thr is None:
                    try:
                        thr = int(os.getenv('ZT_PII_THRESHOLD') or 3)
                    except Exception:
                        thr = 3
                cats = []
                try:
                    if cfg.get('pii_categories'):
                        cats = list(cfg.get('pii_categories'))
                    elif os.getenv('ZT_PII_CATEGORIES'):
                        cats = [c.strip() for c in re.split(r"[;,]", os.getenv('ZT_PII_CATEGORIES')) if c.strip()]
                except Exception:
                    cats = []
                if not cats:
                    cats = ['PII','PHI','PCI']
                if debug_enabled:
                    try:
                        self._debug(f"[PII TRACE] threshold={thr} categories={cats}")
                    except Exception:
                        pass

                if chat_text or attach_count:
                    # Circuit Breaker: Check if budget exceeded before PII call
                    if circuit_breaker_enabled and request_start_time and max_latency_ms:
                        elapsed_ms = (time.time() - request_start_time) * 1000
                        remaining_budget_ms = max_latency_ms - elapsed_ms
                        
                        if remaining_budget_ms <= 50:  # Less than 50ms remaining
                            # Budget exceeded - force action based on config
                            self.metrics['circuit_breaker_triggered_total'] = self.metrics.get('circuit_breaker_triggered_total', 0) + 1
                            
                            # Log to file using existing mechanism
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[CIRCUIT_BREAKER] elapsed={elapsed_ms:.0f}ms budget={max_latency_ms}ms action={timeout_action} host={host} path={path}\n")
                            except Exception:
                                pass
                            
                            if timeout_action == 'block':
                                # Block request on timeout
                                action_taken_str = "🚫 Request Blocked: Circuit breaker timeout exceeded."
                                html = BLOCK_PAGE_HTML.replace("{{REASON}}", action_taken_str).replace("{{PROXY_BASE}}", proxy_base)
                                flow.response = http.Response.make(403, html.encode('utf-8'), {
                                    "Content-Type": "text/html; charset=utf-8",
                                    "X-ZT-Blocked": "1",
                                    "X-ZT-Reason": "circuit-breaker-timeout",
                                    "X-ZT-Mode": "post-chat",
                                    "X-ZT-Mode-Detail": "timeout-block"
                                })
                                send_block_audit_log(
                                    host=host,
                                    path=path,
                                    url=url,
                                    method=method,
                                    headers=headers,
                                    block_reason="Circuit breaker timeout exceeded",
                                    block_type="circuit-breaker-timeout",
                                    config_loader=self._get_config,
                                    session=user_session
                                )
                                return
                            elif timeout_action == 'passthrough':
                                # Force passthrough - let request continue
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[CIRCUIT_BREAKER] PASSTHROUGH forced host={host} path={path}\n")
                                except Exception:
                                    pass
                                # Don't run PII check, just allow through
                                return
                            # else: log-only - continue with PII check (will likely timeout but logged)
                    
                    # Allow one-time bypass of PII gate if header present and admin enabled
                    # Legacy bypass header/cookie removed (session-based ignore now)
                    allow_proceed = False  # retained for header signaling only; not used for bypass
                    # Combine chat text and attachment text for detection
                    combined = chat_text or ''
                    if attach_text:
                        combined = (combined + "\n\n" + attach_text) if combined else attach_text
                    # Log gate entry to file (always) for observability
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[PII GATE ENTER] host={host} path={path} chars={len(combined)} thr={thr} cats={','.join(cats)} attach={attach_count}\n")
                            # Log sample of text being scanned (first 200 chars)
                            if combined:
                                sample = combined[:200].replace('\n', ' ')
                                lf.write(f"[PII TEXT SAMPLE] {sample}...\n")
                    except Exception:
                        pass
                    
                    # Timing: Start PII service call
                    pii_start = time.time()
                    res = run_pii_gate(combined, threshold=thr, categories=cats)
                    pii_time = time.time() - pii_start
                    
                    # Track optimization metrics
                    try:
                        if res.get('_cached'):
                            self.metrics['pii_cache_hits_total'] += 1
                        elif res.get('_short_text_bypass'):
                            self.metrics['pii_short_text_bypass_total'] += 1
                        elif res.get('_whitelist_bypass'):
                            self.metrics['pii_whitelist_bypass_total'] += 1
                        else:
                            self.metrics['pii_service_calls_total'] += 1
                    except Exception:
                        pass
                    
                    # Circuit Breaker: Check if total time exceeded budget
                    budget_exceeded_after_pii = False
                    if circuit_breaker_enabled and request_start_time and max_latency_ms:
                        total_elapsed_ms = (time.time() - request_start_time) * 1000
                        if total_elapsed_ms > max_latency_ms:
                            budget_exceeded_after_pii = True
                            self.metrics['circuit_breaker_late_trigger_total'] = self.metrics.get('circuit_breaker_late_trigger_total', 0) + 1
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[CIRCUIT_BREAKER] LATE_TRIGGER elapsed={total_elapsed_ms:.0f}ms budget={max_latency_ms}ms (PII completed but budget exceeded)\n")
                            except Exception:
                                pass
                    
                    # Log timing metrics with optimization flags
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            cached = res.get('_cached', False)
                            short_bypass = res.get('_short_text_bypass', False)
                            whitelist_bypass = res.get('_whitelist_bypass', False)
                            cb_status = "BUDGET_OK" if not budget_exceeded_after_pii else "BUDGET_EXCEEDED"
                            
                            # Add optimization flags to log
                            opt_flags = []
                            if cached:
                                opt_flags.append('CACHE_HIT')
                            if short_bypass:
                                opt_flags.append('SHORT_TEXT_BYPASS')
                            if whitelist_bypass:
                                opt_flags.append('WHITELIST_BYPASS')
                            opt_str = ','.join(opt_flags) if opt_flags else 'SERVICE_CALL'
                            
                            lf.write(f"[PII TIMING] extract={extract_time:.3f}s service={pii_time:.3f}s total={(extract_time + pii_time):.3f}s optimizations=[{opt_str}] circuit_breaker={cb_status}\n")
                    except Exception:
                        pass
                    
                    # Robust extraction of meets/total in case service shape varies
                    meets = bool(res.get('meets_threshold'))
                    total = int(res.get('total') or 0)
                    if not total:
                        # Fallback: derive total from counts or list lengths
                        try:
                            counts_obj = res.get('counts') or {}
                            if isinstance(counts_obj, dict):
                                csum = sum(int(v or 0) for v in counts_obj.values())
                                if csum > total:
                                    total = csum
                        except Exception:
                            pass
                    if meets and total == 0:
                        # Some detectors may flag meets_threshold but omit total; infer from items/entities
                        try:
                            inferred = 0
                            for key in ('items','entities','pii_entities','details'):
                                val = res.get(key)
                                if isinstance(val, list):
                                    inferred = max(inferred, len(val))
                            if inferred:
                                total = inferred
                        except Exception:
                            pass
                    if debug_enabled:
                        try:
                            counts = res.get('counts') or {}
                            self._debug(f"[PII TRACE] detect total={total} meets_threshold={meets} counts={counts}")
                        except Exception:
                            pass
                    # Always log result to file
                    try:
                        counts_log = res.get('counts') or {}
                        items_log = res.get('items') or []
                        sample_items = []
                        if isinstance(items_log, list):
                            for it in items_log[:3]:
                                try:
                                    if isinstance(it, dict):
                                        sample_items.append(f"{it.get('category','PII')}:{str(it.get('value',''))[:20]}")
                                except Exception:
                                    continue
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[PII GATE RESULT] host={host} path={path} meets={meets} total={total} counts={counts_log} samples={'|'.join(sample_items)}\n")
                    except Exception:
                        pass
                    
                    # =========================================
                    # SAFEGUARD KEYWORD GATE
                    # =========================================
                    safeguard_start = time.time()
                    safeguard_blocked = False
                    safeguard_matches = []
                    
                    try:
                        # Get safeguard keywords from user settings (merged into cfg)
                        safeguard_keywords = cfg.get('safeguard_keywords', [])
                        
                        # DEBUG: Log cfg state to diagnose missing keywords
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[SAFEGUARD DEBUG] cfg keys: {list(cfg.keys())}\n")
                                lf.write(f"[SAFEGUARD DEBUG] safeguard_keywords from cfg: {safeguard_keywords}\n")
                                lf.write(f"[SAFEGUARD DEBUG] user_settings available: {user_settings is not None if 'user_settings' in locals() else False}\n")
                                if 'user_settings' in locals() and user_settings:
                                    lf.write(f"[SAFEGUARD DEBUG] user_settings keys: {list(user_settings.keys())}\n")
                                    lf.write(f"[SAFEGUARD DEBUG] user_settings safeguard_keywords: {user_settings.get('safeguard_keywords', 'NOT FOUND')}\n")
                        except Exception as dbg_err:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[SAFEGUARD DEBUG ERROR] {dbg_err}\n")
                        
                        if safeguard_keywords:
                            # Run safeguard gate (case-insensitive by default)
                            from tools.request_filters import run_safeguard_gate
                            safeguard_result = run_safeguard_gate(combined, keywords=safeguard_keywords, case_sensitive=False)
                            
                            safeguard_blocked = safeguard_result.get('blocked', False)
                            safeguard_matches = safeguard_result.get('matches', [])
                            
                            # Log result
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                matches_str = ','.join(safeguard_matches[:5]) if safeguard_matches else '(none)'
                                lf.write(f"[SAFEGUARD GATE] host={host} path={path} blocked={safeguard_blocked} matches={len(safeguard_matches)} keywords={matches_str}\n")
                            
                            if safeguard_blocked:
                                self.metrics['safeguard_detected_total'] += 1
                        else:
                            # Log when no keywords configured
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[SAFEGUARD GATE] host={host} path={path} skipped - no keywords configured in user settings\n")
                    except Exception as sg_err:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[SAFEGUARD ERROR] {sg_err}\n")
                    
                    safeguard_time = time.time() - safeguard_start
                    
                    # Decide if request should be blocked (PII OR safeguard)
                    decision_start = time.time()
                    should_block = (meets or safeguard_blocked)
                    
                    if meets:
                        self.metrics['pii_detected_total'] += 1
                    
                    if should_block:
                        # NOTE: Old session-based ignore token logic removed
                        # Ignore tokens are now handled by browser-side X-ZT-Ignore-Token header
                        # Check happens early in request() method before any PII processing
                        
                        # Log the enforcement decision
                        try:
                            with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                lf.write(f"[ENFORCEMENT DECISION] BLOCKING_DISABLED={BLOCKING_DISABLED} enforcement_mode={enforcement_mode} should_block={should_block}\n")
                                lf.write(f"[BLOCK CHECK] safeguard_blocked={safeguard_blocked} meets_threshold={meets}\n")
                        except Exception:
                            pass
                        
                        if not BLOCKING_DISABLED and enforcement_mode in ('block','auto'):
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[BLOCK PATH ENTER] Entering block creation logic... safeguard={safeguard_blocked}\n")
                            except Exception:
                                pass
                            # Determine which gate triggered the block
                            block_type = "safeguard" if safeguard_blocked else "pii"
                            
                            if safeguard_blocked:
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[SAFEGUARD BLOCK PATH] Building safeguard block page with {len(safeguard_matches)} keywords\n")
                                except Exception:
                                    pass
                                self.metrics['safeguard_blocked_total'] += 1
                                # Build safeguard block page with detected keywords
                                reason_summary = f"🚫 Request Blocked by ZeroTrusted.ai: Policy violation detected ({len(safeguard_matches)} keyword(s))"
                                
                                # Build HTML with detected keywords (show actual keywords, not masked)
                                def _esc(s: str) -> str:
                                    try:
                                        return (s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                                    except Exception:
                                        return s
                                
                                keywords_html = ''
                                if safeguard_matches:
                                    try:
                                        show = safeguard_matches[:10]
                                        lis = []
                                        for kw in show:
                                            try:
                                                escaped_kw = _esc(str(kw))
                                                # Find context around keyword in the text
                                                context = ""
                                                try:
                                                    kw_lower = kw.lower()
                                                    text_lower = combined.lower()
                                                    idx = text_lower.find(kw_lower)
                                                    if idx >= 0:
                                                        # Get 50 chars before and after
                                                        start = max(0, idx - 50)
                                                        end = min(len(combined), idx + len(kw) + 50)
                                                        snippet = combined[start:end]
                                                        # Add ellipsis if truncated
                                                        if start > 0:
                                                            snippet = '...' + snippet
                                                        if end < len(combined):
                                                            snippet = snippet + '...'
                                                        context = f"<div style='margin-top:4px;opacity:0.7;font-size:11px'>{_esc(snippet)}</div>"
                                                except Exception:
                                                    pass
                                                
                                                lis.append(f"<li><code style='background:#fee;padding:2px 6px;border-radius:3px'>{escaped_kw}</code>{context}</li>")
                                            except Exception:
                                                continue
                                        
                                        keywords_html = (
                                            "<div style='margin-top:8px'>"
                                            + "<div style='font-weight:600;margin-bottom:4px'>Detected Keywords:</div>"
                                            + f"<ul style='margin:6px 0 0 16px;padding:0;list-style:none'>{''.join(lis)}</ul>"
                                            + "</div>"
                                        )
                                    except Exception:
                                        keywords_html = ""
                                
                                html_reason = reason_summary + "<br>" + keywords_html + "\n<style>div.text-token-text-error{{display:none!important}}</style>"
                                
                                # Build compact reason for toast header with keywords
                                try:
                                    compact_keywords = ', '.join(safeguard_matches[:3])
                                    if len(safeguard_matches) > 3:
                                        compact_keywords += f' (+{len(safeguard_matches) - 3} more)'
                                    reason_header = f"{reason_summary} [{compact_keywords}]"
                                    reason_header = reason_header.encode('ascii', 'ignore').decode('ascii')
                                except Exception:
                                    reason_header = (reason_summary).encode('ascii', 'ignore').decode('ascii')
                                resp_headers = {
                                    **cors_headers,
                                    "Content-Type": "text/html; charset=utf-8",
                                    "X-ZT-Blocked": "1",
                                    "X-ZT-Reason": reason_header,
                                    "X-ZT-Mode": "post-chat",
                                    "X-ZT-Mode-Detail": "safeguard",
                                    "X-ZT-Toast": "1",
                                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                    "Pragma": "no-cache",
                                    "Expires": "0",
                                }
                                # Add session/auth headers
                                # Since auth gate always requires authentication, sess should always exist here
                                try:
                                    is_auth = sess and self.session_manager.is_session_authenticated(sess)
                                    if is_auth:
                                        resp_headers['X-ZT-Auth'] = '1'
                                        resp_headers['X-ZT-Ignore-Remaining'] = str(sess.ignore_remaining)
                                    else:
                                        # This shouldn't happen since auth gate blocks unauthenticated users
                                        resp_headers['X-ZT-Auth'] = '0'
                                        resp_headers['X-ZT-Ignore-Remaining'] = '0'
                                    # Debug log
                                    try:
                                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                            lf.write(f"[X-ZT-AUTH HEADER] Setting X-ZT-Auth={resp_headers.get('X-ZT-Auth')} sess_exists={sess is not None} is_authenticated={is_auth}\n")
                                    except Exception:
                                        pass
                                except Exception as e:
                                    try:
                                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                            lf.write(f"[X-ZT-AUTH ERROR] {e}\n")
                                    except Exception:
                                        pass
                                resp_headers["X-ZT-Allow-Proceed"] = "1"
                                html = BLOCK_PAGE_HTML.replace("{{REASON}}", html_reason).replace("{{PROXY_BASE}}", proxy_base)
                                flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                                self.metrics['blocked_total'] += 1
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[SAFEGUARD BLOCK COMPLETE] Response created, returning\n")
                                except Exception:
                                    pass
                                return
                            
                            # Legacy bypass path removed; no bypass diagnostic needed
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK PATH START] Building PII block page for {total} findings\n")
                            except Exception:
                                pass
                            # Summary reason (used for headers)
                            reason_summary = f"🚫 Request Blocked by ZeroTrusted.ai: PII threshold met ({total} findings)"
                            # Build HTML details with sample detected PII
                            try:
                                items = res.get('items') or []
                            except Exception:
                                items = []
                            # Escape helper
                            def _esc(s: str) -> str:
                                try:
                                    return (s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                                except Exception:
                                    return s
                            details_html = ""
                            if items:
                                try:
                                    show = items[:5]
                                    lis = []
                                    for it in show:
                                        try:
                                            cat = _esc(str(it.get('category') or 'PII'))
                                            val = _esc(str(it.get('value') or '')[:120])
                                            lis.append(f"<li><b>{cat}</b>: <code>{val}</code></li>")
                                        except Exception:
                                            continue
                                    details_html = (
                                        "<div style='margin-top:8px'>"
                                        + "<div style='font-weight:600;margin-bottom:4px'>Detected:</div>"
                                        + f"<ul style='margin:6px 0 0 16px;padding:0'>{''.join(lis)}</ul>"
                                        + (f"<div style='margin-top:6px;opacity:.85'>Attachments scanned: {attach_count}</div>" if attach_count else "")
                                        + "</div>"
                                    )
                                except Exception:
                                    details_html = ""
                            # Build compact header reason with truncated samples for toast visibility
                            try:
                                compact_samples = []
                                try:
                                    for it in (items or [])[:3]:
                                        try:
                                            cat = str(it.get('category') or 'PII')
                                            val = str(it.get('value') or '')
                                            # basic masking/truncation per value type
                                            v = val.strip()
                                            if len(v) > 40:
                                                v = v[:37] + '…'
                                            # mask emails partially
                                            if '@' in v:
                                                parts = v.split('@',1)
                                                if parts[0]:
                                                    local = parts[0]
                                                    if len(local) > 3:
                                                        local = local[:3] + '…'
                                                    v = local + '@' + parts[1]
                                            # shorten long digits
                                            if sum(ch.isdigit() for ch in v) >= 6 and len(v) > 10:
                                                v = v[:6] + '…'
                                            compact_samples.append(f"{cat}:{v}")
                                        except Exception:
                                            continue
                                except Exception:
                                    pass
                                samples_str = ''
                                if compact_samples:
                                    joined = '; '.join(compact_samples)
                                    if len(joined) > 120:
                                        joined = joined[:117] + '…'
                                    samples_str = ' [' + joined + ']'
                                reason_header = (reason_summary).encode('ascii', 'ignore').decode('ascii')
                            except Exception:
                                reason_header = "Request Blocked by ZeroTrusted.ai"
                            resp_headers = {
                                **cors_headers,
                                "Content-Type": "text/html; charset=utf-8",
                                "X-ZT-Blocked": "1",
                                "X-ZT-Reason": reason_header,
                                # Use backward-compatible mode so older extensions show toast
                                "X-ZT-Mode": "post-chat",
                                # Provide additional detail for newer UIs/extensions
                                "X-ZT-Mode-Detail": "post-chat-pii",
                                "X-ZT-PII": "1",
                                "X-ZT-Toast": "1",  # explicit signal for toast
                                # Cache-busting headers to prevent browser from caching old proxy_base
                                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                "Pragma": "no-cache",
                                "Expires": "0",
                            }
                            # Pre-populate auth/session headers so extension can immediately render Proceed UI
                            # Since auth gate always requires authentication, sess should always exist here
                            try:
                                is_auth = sess and self.session_manager.is_session_authenticated(sess)
                                if is_auth:
                                    resp_headers['X-ZT-Auth'] = '1'
                                    resp_headers['X-ZT-Ignore-Remaining'] = str(sess.ignore_remaining)
                                else:
                                    # This shouldn't happen since auth gate blocks unauthenticated users
                                    resp_headers['X-ZT-Auth'] = '0'
                                    resp_headers['X-ZT-Ignore-Remaining'] = '0'
                                # Debug log
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[X-ZT-AUTH HEADER] Setting X-ZT-Auth={resp_headers.get('X-ZT-Auth')} sess_exists={sess is not None} is_authenticated={is_auth}\n")
                                except Exception:
                                    pass
                            except Exception as e:
                                try:
                                    with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                        lf.write(f"[X-ZT-AUTH ERROR] {e}\n")
                                except Exception:
                                    pass
                            # Signal to extension whether Proceed is permitted by admin config
                            # Allow-Proceed header maintained for backward UI compatibility (always '1' when session model present)
                            resp_headers["X-ZT-Allow-Proceed"] = "1"
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK PATH 1] Starting to build masked items...\n")
                            except Exception:
                                pass
                            # Build masked list with improved formatting
                            def _mask_value(label: str, raw: str) -> str:
                                try:
                                    s = raw.strip()
                                    # Credit card style (>=12 digits)
                                    digits_only = ''.join(ch for ch in s if ch.isdigit())
                                    if '@' in s:
                                        user, dom = s.split('@',1)
                                        if len(user) > 2:
                                            user = user[:2] + '*' * (len(user)-2)
                                            v = user + '@' + dom
                                        else:
                                            user = '*' * len(user)
                                            v = user + '@' + dom
                                    if len(digits_only) >= 12:
                                        first4 = digits_only[:4]
                                        # produce groups after first 5th digit masked pattern
                                        return f"{first4} {digits_only[4:5]}xxx xxxx xxxx"[:64]
                                    if len(s) > 10:
                                        return s[:5] + ''.join('*' if c.isalnum() else c for c in s[5:])[:60]
                                    if len(s) > 4:
                                        return s[0] + '*' * (len(s)-2) + s[-1]
                                    return '*' * len(s)
                                except Exception:
                                    return '***'
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK PATH 2] Building masked items HTML...\n")
                            except Exception:
                                pass
                            masked_items_html = ''
                            try:
                                det_items = res.get('items') or []
                                if det_items:
                                    lines = []
                                    for it in det_items[:6]:
                                        if not isinstance(it, dict):
                                            continue
                                        catv = str(it.get('category') or 'PII')
                                        valv = str(it.get('value') or '')
                                        masked = _mask_value(catv, valv)
                                        lines.append(f"<div><b>{catv}:</b> <code class='pii-mask'>{masked}</code></div>")
                                    if lines:
                                        masked_items_html = ("<div style='margin-top:10px;font-size:12.5px'><div style='font-weight:600;margin-bottom:4px'>Sensitive Keywords Detected:</div>" + ''.join(lines) + "</div>")
                            except Exception:
                                masked_items_html = ''
                            # Prepare masked keywords list (compact) for header and potential UI usage
                            masked_keywords = []
                            try:
                                # Reuse det_items collected above; limit to 8 for header size
                                for it in (res.get('items') or [])[:8]:
                                    if not isinstance(it, dict):
                                        continue
                                    catv = str(it.get('category') or 'PII')
                                    valv = str(it.get('value') or '')
                                    # derive masked value using same helper
                                    mv = _mask_value(catv, valv)
                                    # collapse spaces
                                    mv = re.sub(r"\s+", " ", mv)[:40]
                                    masked_keywords.append(f"{catv}:{mv}")
                            except Exception:
                                masked_keywords = []
                            masked_kw_header = ''
                            if masked_keywords:
                                masked_kw_header = ",".join(masked_keywords)
                                if len(masked_kw_header) > 240:  # hard cap
                                    masked_kw_header = masked_kw_header[:237] + '…'
                            html_reason = reason_summary + "<br>" + masked_items_html + details_html + "\n<style>div.text-token-text-error{display:none!important}</style>"
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK PATH 3] html_reason built, length={len(html_reason)}\n")
                            except Exception:
                                pass
                            # Log before creating block page
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[CREATING BLOCK PAGE] PII block - total={total} threshold={thr}\n")
                            except Exception:
                                pass
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK PATH 4] About to create response object...\n")
                            except Exception:
                                pass
                            html = BLOCK_PAGE_HTML.replace("{{REASON}}", html_reason).replace("{{PROXY_BASE}}", proxy_base)
                            flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[BLOCK PAGE CREATED] Response set with 403 status, headers count={len(resp_headers)}\n")
                            except Exception:
                                pass
                            try:
                                if masked_kw_header:
                                    flow.response.headers['X-ZT-PII-Masked'] = masked_kw_header
                            except Exception:
                                pass
                            self.metrics['blocked_total'] += 1
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK PATH 5] Metrics updated, about to return...\n")
                            except Exception:
                                pass
                            if debug_enabled:
                                try:
                                    self._debug("[PII TRACE] action=block reason=threshold_met")
                                except Exception:
                                    pass
                            # Log to remote audit platform (failure case: blocked)
                            try:
                                api_key = cfg.get('proxy_api_key') or os.getenv('ZT_PROXY_API_KEY') or ''
                                pii_entities = res.get('items') or []
                                anonymized_prompt = None
                                try:
                                    # Build anonymized prompt if possible
                                    body_obj = json.loads(body_text) if body_text else {}
                                    anonymized_prompt = body_obj
                                except Exception:
                                    anonymized_prompt = {"text": chat_text[:500] if chat_text else ""}
                                run_async_in_thread(send_log_to_api(
                                    api_key=api_key,
                                    host=f"https://{host}{path}",
                                    path=path,
                                    url=f"https://{host}{path}",
                                    method=method,
                                    headers=dict(req.headers),
                                    pii_entities=pii_entities,
                                    anonymized_prompt=anonymized_prompt,
                                    body=body_obj if 'body_obj' in locals() else None,
                                    metrics={'status': 403, 'total_pii': total, 'blocked': True},
                                    action_taken={'action': 'blocked', 'reason': 'pii_threshold_met', 'threshold': thr, 'total': total},
                                    session=sess
                                ))
                            except Exception as log_err:
                                if debug_enabled:
                                    self._debug(f"[LOG FORWARD ERROR] {log_err}")
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII BLOCK COMPLETE] Returning with 403 response\n")
                            except Exception:
                                pass
                            return
                        else:
                            # Not blocking despite threshold; add trace and optional header for diagnostics
                            if debug_enabled:
                                try:
                                    self._debug(f"[PII TRACE] threshold met but not blocked (enforcement={enforcement_mode} disabled_blocking={BLOCKING_DISABLED})")
                                except Exception:
                                    pass
                            try:
                                self.metrics['pii_threshold_met_not_blocked_total'] += 1
                            except Exception:
                                pass
                            try:
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"[PII THRESHOLD NOT BLOCKED] host={host} path={path} enf={enforcement_mode} disabled_blocking={BLOCKING_DISABLED} total={total}\n")
                            except Exception:
                                pass
                            try:
                                # Only set header if we haven't already produced a response (i.e., allow path)
                                flow.request.headers["X-ZT-Why-Not-Blocked"] = f"enf={enforcement_mode} disabled={BLOCKING_DISABLED}"  # request header for downstream logging
                            except Exception:
                                pass
                    elif debug_enabled:
                        try:
                            self._debug("[PII TRACE] threshold not met -> allow")
                        except Exception:
                            pass
                    
                    # Final timing breakdown (before async audit to avoid including thread spawn overhead)
                    decision_time = time.time() - decision_start
                    total_request_time = time.time() - request_start_time if request_start_time else 0
                    try:
                        with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                            lf.write(f"[REQUEST TIMING BREAKDOWN] host={host} path={path} extract={extract_time:.3f}s pii_service={pii_time:.3f}s safeguard={safeguard_time:.3f}s decision={decision_time:.3f}s total={total_request_time:.3f}s\n")
                    except Exception:
                        pass
                    
                    # Log to remote audit platform (success case: allowed) - Fire and forget after response
                    # Do this AFTER timing log and move all prep work into the async thread
                    try:
                        api_key = cfg.get('proxy_api_key') or os.getenv('ZT_PROXY_API_KEY') or ''
                        if api_key:  # Only if audit is configured
                            # Capture minimal context for async processing
                            audit_context = {
                                'api_key': api_key,
                                'host': host,
                                'path': path,
                                'method': method,
                                'headers': dict(req.headers),
                                'body_text': body_text,
                                'chat_text': chat_text[:500] if chat_text else "",
                                'pii_items': res.get('items', []) if 'res' in locals() else [],
                                'total_detected': total if 'total' in locals() else 0,
                                'threshold': thr if 'thr' in locals() else 3,
                                'session': sess,
                            }
                            
                            # Spawn thread WITHOUT doing heavy work first
                            def async_audit():
                                try:
                                    # Heavy work (JSON parsing) happens in thread
                                    body_obj = None
                                    anonymized_prompt = None
                                    try:
                                        body_obj = json.loads(audit_context['body_text']) if audit_context['body_text'] else {}
                                        anonymized_prompt = body_obj
                                    except Exception:
                                        anonymized_prompt = {"text": audit_context['chat_text']}
                                    
                                    import asyncio
                                    asyncio.run(send_log_to_api(
                                        api_key=audit_context['api_key'],
                                        host=f"https://{audit_context['host']}{audit_context['path']}",
                                        path=audit_context['path'],
                                        url=f"https://{audit_context['host']}{audit_context['path']}",
                                        method=audit_context['method'],
                                        headers=audit_context['headers'],
                                        pii_entities=audit_context['pii_items'],
                                        anonymized_prompt=anonymized_prompt,
                                        body=body_obj,
                                        metrics={'status': 200, 'total_pii': audit_context['total_detected'], 'blocked': False},
                                        action_taken={'action': 'allowed', 'reason': 'pii_threshold_not_met', 'threshold': audit_context['threshold'], 'total': audit_context['total_detected']},
                                        session=audit_context['session']
                                    ))
                                except Exception as e:
                                    pass  # Silent failure for audit
                            
                            threading.Thread(target=async_audit, daemon=True).start()
                    except Exception:
                        pass  # Don't block request on audit error
                elif debug_enabled:
                    try:
                        self._debug("[PII TRACE] no chat text extracted -> allow")
                    except Exception:
                        pass
                return
                

            # (Removed redundant second post-chat-pii block)
            
            # post-chat mode (block all chat POSTs per enforcement)
            if filter_mode == 'post-chat' and method == 'POST' and is_chat_path(path):
                # In observe: allow; in block: block; in auto: block (since POST)
                should_block = False
                if not BLOCKING_DISABLED:
                    if enforcement_mode == 'block':
                        should_block = True
                    elif enforcement_mode == 'auto':
                        should_block = True
                if should_block:
                    reason = "🚫 Request Blocked by ZeroTrusted.ai: Chat POSTs blocked by policy (post-chat)."
                    try:
                        reason_header = reason.encode('ascii', 'ignore').decode('ascii')
                    except Exception:
                        reason_header = "Request Blocked by ZeroTrusted.ai"
                    resp_headers = {
                        **cors_headers,
                        "Content-Type": "text/html; charset=utf-8",
                        "X-ZT-Blocked": "1",
                        "X-ZT-Reason": reason_header,
                        "X-ZT-Mode": "post-chat",
                        # Cache-busting headers
                        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                        "Pragma": "no-cache",
                        "Expires": "0",
                    }
                    html = BLOCK_PAGE_HTML.replace("{{REASON}}", reason + "\n<style>div.text-token-text-error{display:none!important}</style>").replace("{{PROXY_BASE}}", proxy_base)
                    flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                    self.metrics['blocked_total'] += 1
                    
                    # Send audit log
                    send_block_audit_log(
                        host=host,
                        path=path,
                        url=url,
                        method=method,
                        headers=headers,
                        block_reason="Chat POST blocked by policy",
                        block_type="post-chat-policy",
                        body_text=req.get_text() if 'req' in locals() else None,
                        config_loader=self._get_config,
                        session=user_session
                    )
                    return

            # Shadow AI detection: in 'all' mode, check every request
            if filter_mode == 'all':
                # Parse body best-effort
                text_body = None
                parsed_body = {}
                try:
                    text_body = req.get_text()
                    if text_body:
                        try:
                            parsed_body = json.loads(text_body)
                        except Exception:
                            parsed_body = {}
                except Exception:
                    text_body = None
                    parsed_body = {}

                try:
                    detected = bool(
                        is_shadow_ai_request(
                            host=host,
                            path=path,
                            headers=headers,
                            body=text_body or '',
                            parsed_body=parsed_body,
                        )
                    )
                except Exception as e:
                    detected = False
                    if debug_enabled:
                        self._debug(f"[SHADOW TRACE] detector error: {e}")
                if debug_enabled:
                    self._debug(f"[SHADOW TRACE] detected={detected} method={method} path={path}")
                if detected:
                    self.metrics['shadow_detected_total'] += 1
                    action_block = False
                    if not BLOCKING_DISABLED:
                        if enforcement_mode == 'block':
                            action_block = True
                        elif enforcement_mode == 'auto':
                            # Safer default: block only POSTs in auto
                            action_block = (method == 'POST')
                        else:
                            action_block = False
                    if action_block:
                        reason = "🚫 Request Blocked by ZeroTrusted.ai: Shadow AI usage is not allowed."
                        try:
                            reason_header = reason.encode('ascii', 'ignore').decode('ascii')
                        except Exception:
                            reason_header = "Request Blocked by ZeroTrusted.ai"
                        resp_headers = {
                            **cors_headers,
                            "Content-Type": "text/html; charset=utf-8",
                            "X-ZT-Blocked": "1",
                            "X-ZT-Reason": reason_header,
                            "X-ZT-Mode": "shadow",
                            # Cache-busting headers
                            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                            "Pragma": "no-cache",
                            "Expires": "0",
                        }
                        html = BLOCK_PAGE_HTML.replace("{{REASON}}", reason).replace("{{PROXY_BASE}}", proxy_base)
                        flow.response = http.Response.make(403, html.encode('utf-8'), resp_headers)
                        self.metrics['blocked_total'] += 1
                        if debug_enabled:
                            self._debug("[SHADOW TRACE] action=block")
                        
                        # Send audit log
                        send_block_audit_log(
                            host=host,
                            path=path,
                            url=url,
                            method=method,
                            headers=headers,
                            block_reason="Shadow AI usage detected",
                            block_type="shadow-ai",
                            body_text=text_body if 'text_body' in locals() else None,
                            config_loader=self._get_config,
                            session=user_session
                        )
                        return
                    else:
                        self.metrics['allowed_total'] += 1
                        if debug_enabled:
                            self._debug("[SHADOW TRACE] action=allow (observe or disabled)")
                        return

            # Fallthrough: allow
            self.metrics['allowed_total'] += 1
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[ALLOWED] {method} {host}{path} | Mode: {filter_mode}\n")
                    lf.write(f"{'='*80}\n\n")
            except Exception:
                pass

        except Exception as e:
            self.metrics['errors_total'] += 1
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[ERROR] Request handling failed: {e}\n")
                    lf.write(f"{'='*80}\n\n")
            except Exception:
                pass
            try:
                self._debug(f"[ERROR] request handling failed: {e}")
            except Exception:
                pass

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Intercept WebSocket messages for PII detection (ChatGPT uses WebSocket for chat)"""
        try:
            message = flow.websocket.messages[-1]  # Get the most recent message
            from_client = message.from_client
            content = message.content
            
            # Only check client->server messages (outgoing chat messages)
            if not from_client:
                return
                
            # Log that we're seeing WebSocket traffic
            print(f"[WEBSOCKET] from_client={from_client} content_length={len(content) if content else 0}", flush=True)
            
            # Try to parse as text/JSON
            try:
                if isinstance(content, bytes):
                    text_content = content.decode('utf-8', errors='ignore')
                else:
                    text_content = str(content)
                    
                # Log first 200 chars of content for debugging
                preview = (text_content[:200] + '...') if len(text_content) > 200 else text_content
                print(f"[WEBSOCKET CONTENT] {preview}", flush=True)
                
                # Try to parse as JSON
                try:
                    import json as json_lib
                    data = json_lib.loads(text_content)
                    print(f"[WEBSOCKET JSON] type={type(data).__name__}", flush=True)
                    
                    # Check if this looks like a chat message
                    message_text = None
                    
                    # Handle JSON objects
                    if isinstance(data, dict):
                        for key in ['message', 'text', 'content', 'body', 'prompt', 'input', 'parts']:
                            if key in data:
                                val = data.get(key)
                                if isinstance(val, str):
                                    message_text = val
                                    break
                                elif isinstance(val, list) and val and isinstance(val[0], str):
                                    message_text = ' '.join(val)
                                    break
                    
                    # Handle JSON arrays (check each item)
                    elif isinstance(data, list):
                        print(f"[WEBSOCKET JSON] array items={len(data)}", flush=True)
                        for item in data:
                            if isinstance(item, dict):
                                # Check top-level fields
                                for key in ['message', 'text', 'content', 'body', 'prompt', 'input', 'parts']:
                                    if key in item:
                                        val = item.get(key)
                                        if isinstance(val, str):
                                            message_text = val
                                            break
                                        elif isinstance(val, list) and val and isinstance(val[0], str):
                                            message_text = ' '.join(val)
                                            break
                                
                                # Check nested objects (command, data, payload)
                                if not message_text:
                                    for nested_key in ['command', 'data', 'payload']:
                                        if nested_key in item and isinstance(item[nested_key], dict):
                                            nested = item[nested_key]
                                            for key in ['message', 'text', 'content', 'body', 'prompt', 'input', 'parts']:
                                                if key in nested:
                                                    val = nested.get(key)
                                                    if isinstance(val, str):
                                                        message_text = val
                                                        break
                                                    elif isinstance(val, list) and val and isinstance(val[0], str):
                                                        message_text = ' '.join(val)
                                                        break
                                            if message_text:
                                                break
                            if message_text:
                                break
                    
                    if message_text and len(message_text) > 10:  # Only process substantial messages
                        print(f"[WEBSOCKET CHAT MESSAGE DETECTED] length={len(message_text)}", flush=True)
                        
                        # Apply PII detection
                        try:
                            from interceptor.services import pii_fast
                            pii_result = pii_fast._detect_pii_local(message_text)
                            
                            if pii_result and pii_result.get('detected'):
                                total_pii = pii_result.get('total', 0)
                                print(f"[WEBSOCKET PII DETECTED] count={total_pii}", flush=True)
                                
                                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                                    lf.write(f"\n[WEBSOCKET BLOCKED] PII detected (count={total_pii})\n")
                                    lf.write(f"[WEBSOCKET BLOCKED] Message: {message_text[:200]}\n")
                                    lf.write(f"[WEBSOCKET BLOCKED] Details: {pii_result}\n")
                                    lf.write(f"{'='*80}\n\n")
                                
                                # Block WebSocket by killing the flow
                                print(f"[WEBSOCKET BLOCKED] Killing WebSocket due to PII", flush=True)
                                flow.kill()
                            else:
                                print(f"[WEBSOCKET] No PII in message", flush=True)
                                
                        except Exception as pii_err:
                            print(f"[WEBSOCKET] PII check error: {pii_err}", flush=True)
                            
                except json_lib.JSONDecodeError:
                    print("[WEBSOCKET] Not valid JSON", flush=True)
                    
            except Exception as e:
                print(f"[WEBSOCKET ERROR] Failed to parse content: {e}", flush=True)
                
        except Exception as e:
            print(f"[WEBSOCKET HANDLER ERROR] {e}", flush=True)
            try:
                with open(self.INTERCEPTED_LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"[ERROR] WebSocket handling failed: {e}\n")
            except Exception:
                pass


addons = [Interceptor()]
