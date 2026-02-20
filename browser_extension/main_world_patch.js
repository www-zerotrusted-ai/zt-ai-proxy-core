// Runs in the page's MAIN world to observe fetch/XHR and dispatch events when a ZT block is detected.
(() => {
  try { if (window.__ZT_MAIN_PATCH__) return; window.__ZT_MAIN_PATCH__ = true; } catch(_) {}
  try { console.info('[ZTProxy] main_world_patch installed v2 (debug)'); } catch(_) {}

  // Minimal state for duplicate suppression
  let LAST_DISPATCH_AT = 0;

  const DEBUG = true; // temporary diagnostic flag (remove or gate later)
  function dispatchBlocked(reason, url, extra){
    try {
      const now = Date.now();
      if (now - LAST_DISPATCH_AT < 500) return; // debounce rapid duplicates
      LAST_DISPATCH_AT = now;
      const detail = { reason: reason || 'Blocked by ZeroTrusted.ai', url: url || location.href };
      if (extra && typeof extra === 'object') {
        try { Object.assign(detail, extra); } catch(_) {}
      }
      try { if (DEBUG) console.info('[ZTProxy][main_world_patch] dispatchBlocked', detail); } catch(_) {}
      const ev = new CustomEvent('ztproxy-blocked', { detail });
      window.dispatchEvent(ev);
    } catch(_) {}
  }

  // Patch fetch
  try {
    const _fetch = window.fetch;
    if (typeof _fetch === 'function') {
      window.fetch = async function(input, init){
        // Pre-dispatch a loading event ONLY for post-chat-pii mode (PII scan phase)
        let dispatchedLoading = false;
        let urlStr = '';
        try {
          const method = (init && init.method ? String(init.method) : 'GET').toUpperCase();
          urlStr = (typeof input === 'string') ? input : (input && input.url) || '';
          if (method === 'POST' && /(chat|conversation|messages|completions|generate|openai|anthropic|api|\/v1\/)/i.test(urlStr)) {
            // Show loader for POST chat requests (proxy handles filtering)
            // Note: Can't dynamically check proxy config from main world context
            let showLoader = true;
            
            if (showLoader) {
              // Heuristic: only show if body hints at chat payload (messages/prompt) or content-type json
              let bodySample = '';
              if (init && typeof init.body === 'string' && init.body.length < 4000) bodySample = init.body;
              const headersObj = init && init.headers ? new Headers(init.headers) : null;
              const ct = headersObj ? (headersObj.get('content-type') || headersObj.get('Content-Type') || '') : '';
              if (/json/i.test(ct) || /"messages"|"prompt"|"inputs"|"input"/i.test(bodySample)) {
                dispatchedLoading = true;
                try {
                  const detail = { url: urlStr, mode: 'post-chat-pii', reason: 'Scanning for sensitive data…', ts: Date.now() };
                  try { (window.__ZT_PENDING__ = window.__ZT_PENDING__ || {})[urlStr] = detail; } catch(_) {}
                  const ev = new CustomEvent('ztproxy-loading', { detail });
                  window.dispatchEvent(ev);
                  if (DEBUG) console.info('[ZTProxy][main_world_patch] Loading toast dispatched for', urlStr);
                } catch(_) {}
              }
            }
          }
        } catch(_) {}
        // Capture a shallow copy of init for potential replay
        let captured = null;
        try {
          const headersClone = (() => {
            if (!init || !init.headers) return null;
            const h = new Headers(init.headers);
            const out = {};
            h.forEach((v, k) => { out[k] = v; });
            return out;
          })();
          captured = {
            input: (typeof input === 'string') ? input : (input && input.url),
            init: init ? {
              method: init.method || 'GET',
              headers: headersClone || null,
              body: ('body' in init ? init.body : undefined),
              mode: init.mode,
              credentials: init.credentials,
              cache: init.cache,
              redirect: init.redirect,
              referrer: init.referrer,
              referrerPolicy: init.referrerPolicy,
              integrity: init.integrity,
              keepalive: init.keepalive,
              signal: undefined // avoid reusing aborted signals
            } : { method: 'GET', headers: null }
          };
        } catch(_) {}

        // (Bypass logic removed: session-based ignore handled server-side)
        const res = await _fetch.apply(this, arguments);
        try{
          if (res && res.status === 403) {
            const blocked = res.headers && res.headers.get && res.headers.get('X-ZT-Blocked');
            if (blocked === '1') {
              // Don't clear loading - transform it into block toast
              try { const u = (typeof input === 'string') ? input : (input && input.url); if (window.__ZT_PENDING__) delete window.__ZT_PENDING__[u]; } catch(_) {}
              const reason = (res.headers.get && res.headers.get('X-ZT-Reason')) || 'Blocked by ZeroTrusted.ai';
              const mode = (res.headers.get && res.headers.get('X-ZT-Mode')) || '';
              const silent = (res.headers.get && res.headers.get('X-ZT-Silent')) === '1';
              const allowProceed = (res.headers.get && res.headers.get('X-ZT-Allow-Proceed')) === '1';
              const auth = (res.headers.get && res.headers.get('X-ZT-Auth')) === '1';
              const ignoreRem = (res.headers.get && res.headers.get('X-ZT-Ignore-Remaining')) || null;
              const masked = (res.headers.get && res.headers.get('X-ZT-PII-Masked')) || '';
              const url = (typeof input === 'string') ? input : (input && input.url);
              dispatchBlocked(reason, url, { mode, silent, allowProceed, auth, masked, ignoreRemaining: ignoreRem });
            }
          } else {
            // Allowed path: clear loading if we previously showed it
            if (dispatchedLoading) {
              try { 
                window.dispatchEvent(new CustomEvent('ztproxy-clear-loading', { detail: { url: urlStr } }));
                if (DEBUG) console.info('[ZTProxy][main_world_patch] Request allowed, clearing loading toast for', urlStr);
              } catch(_) {}
            }
            try { const u = (typeof input === 'string') ? input : (input && input.url); if (window.__ZT_PENDING__) delete window.__ZT_PENDING__[u]; } catch(_) {}
          }
        } catch(_) {}
        return res;
      };
    }
  } catch(_) {}

  // Patch XHR
  try {
    const XHR = window.XMLHttpRequest;
    if (XHR && XHR.prototype) {
      const open = XHR.prototype.open; const send = XHR.prototype.send; const setRequestHeader = XHR.prototype.setRequestHeader;
      XHR.prototype.open = function(method, url){ this.__zt_url = url; this.__zt_method = method; this.__zt_headers = {}; return open.apply(this, arguments); };
      XHR.prototype.setRequestHeader = function(name, value){ try { if (this.__zt_headers) this.__zt_headers[name] = value; } catch(_){} return setRequestHeader.apply(this, arguments); };
  XHR.prototype.send = function(body){ this.__zt_body = body; 
  this.addEventListener('load', () => {
          try{
    if (this.status === 403) {
              const blocked = this.getResponseHeader && this.getResponseHeader('X-ZT-Blocked');
              if (blocked === '1') {
          const reason = (this.getResponseHeader && this.getResponseHeader('X-ZT-Reason')) || 'Blocked by ZeroTrusted.ai';
        const mode = (this.getResponseHeader && this.getResponseHeader('X-ZT-Mode')) || '';
        const silent = (this.getResponseHeader && this.getResponseHeader('X-ZT-Silent')) === '1';
  const allowProceed = (this.getResponseHeader && this.getResponseHeader('X-ZT-Allow-Proceed')) === '1';
  const auth = (this.getResponseHeader && this.getResponseHeader('X-ZT-Auth')) === '1';
  const ignoreRem = (this.getResponseHeader && this.getResponseHeader('X-ZT-Ignore-Remaining')) || null;
  const masked = (this.getResponseHeader && this.getResponseHeader('X-ZT-PII-Masked')) || '';
    dispatchBlocked(reason, this.__zt_url, { mode, silent, allowProceed, auth, masked, ignoreRemaining: ignoreRem });
              }
            }
            else {
  // Nothing additional to clear
            }
          } catch(_) {}
        });
        return send.apply(this, arguments);
      };
    }
  } catch(_) {}
  // End patch
})();
