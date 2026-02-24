from mitmproxy import http
import json
import os

def handle_internal_request(flow, *, path, method, headers, cors_headers, get_config, metrics=None, **kwargs):
    if path == '/zt-ui':
        # Serve the standalone UI HTML
        ui_path = os.path.join(os.path.dirname(__file__), 'ui', 'ui.html')
        try:
            with open(ui_path, 'r', encoding='utf-8') as f:
                html = f.read()
            flow.response = http.Response.make(200, html.encode('utf-8'), {"Content-Type": "text/html; charset=utf-8"})
        except Exception as e:
            flow.response = http.Response.make(500, f"Error loading UI: {e}".encode('utf-8'), {"Content-Type": "text/plain; charset=utf-8"})
        return True
    # Minimal internal API endpoints for standalone
    if path == '/liveness':
        flow.response = http.Response.make(200, b'{"status": "ok"}', {"Content-Type": "application/json; charset=utf-8"})
        return True
    if path == '/metrics':
        body = "proxy_requests_total 0\nproxy_blocks_total 0\n"
        flow.response = http.Response.make(200, body.encode('utf-8'), {"Content-Type": "text/plain; charset=utf-8"})
        return True
    if path.startswith('/config'):
        if method == 'GET':
            cfg = get_config() if get_config else {}
            resp = {"status": "ok", "config": cfg, "edition": os.environ.get('ZT_EDITION', 'standalone')}
            flow.response = http.Response.make(200, json.dumps(resp).encode(), {"Content-Type": "application/json"})
            return True
        if method == 'POST':
            flow.response = http.Response.make(200, b'{"status": "ok"}', {"Content-Type": "application/json"})
            return True
    if path == '/auth-status':
        flow.response = http.Response.make(200, b'{"authenticated": false}', {"Content-Type": "application/json"})
        return True
    if path == '/features-status':
        flow.response = http.Response.make(200, b'{"features": "none", "status": "ok"}', {"Content-Type": "application/json"})
        return True
    if path == '/routing':
        # Hardcoded blacklist for open source
        blacklist = [
            "openai.com",
            "chat.openai.com",
            "api.openai.com",
            "bard.google.com",
            "gemini.google.com",
            "claude.ai",
            "copilot.microsoft.com",
            "bing.com",
            "chatgpt.com"
        ]
        flow.response = http.Response.make(
            200,
            json.dumps({"domains": blacklist}).encode(),
            {"Content-Type": "application/json"}
        )
        return True
    if path == '/pac':
        # Dynamic PAC endpoint consistent with enterprise logic
        cors_headers = cors_headers or {"Content-Type": "application/x-ns-proxy-autoconfig"}
        method = method.upper()
        if method == 'OPTIONS':
            flow.response = http.Response.make(200, b"", cors_headers)
            return True
        if method == 'GET':
            # STANDALONE MODE: Always return baseline domains (no API calls)
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
    return False

def get_bypass_hosts():
    return set()

def has_internal_token(headers):
    return 'X-Custom-Token' in headers or 'x-custom-token' in headers
