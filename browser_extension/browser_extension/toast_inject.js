// Injected into all pages to surface a small toast when ZTProxy blocks async calls
(function(){
  // Only run in top window to avoid duplicate toasts from iframes
  try { if (window.top !== window) return; } catch(_) {}
  // If the full-page block container is present (page load block), do not install toast
  try {
    // Only treat as full block page if dedicated marker element exists AND body is mostly empty of app root
    const hasBlockMarker = document.getElementById('zt-req-allow-btn');
    if (hasBlockMarker) return; // preserve original behavior: don't load toast on full block page
  } catch(_) {}
  if (window.__ZT_TOAST_INSTALLED__) return; 
  window.__ZT_TOAST_INSTALLED__ = true;
  try { console.info('[ZTProxy] toast_inject loaded'); } catch(e) {}

  // Check if authentication was just completed (suppress toasts for 5 seconds after auth)
  // This prevents race condition toasts when page reloads after SSO before session headers propagate
  // Reduced from 10s to 5s to improve detection responsiveness
  let authSuppressUntil = 0;
  try {
    const authCompleted = sessionStorage.getItem('zt_auth_completed');
    if (authCompleted) {
      const authTime = parseInt(authCompleted, 10);
      const now = Date.now();
      const elapsed = now - authTime;
      if (elapsed < 5000) { // 5 seconds (reduced from 10)
        authSuppressUntil = authTime + 5000;
        console.info('[ZTProxy] Auth recently completed, suppressing toasts for', (5000 - elapsed)/1000, 'seconds');
      } else {
        // Clear old auth marker if > 5s elapsed
        sessionStorage.removeItem('zt_auth_completed');
      }
    }
  } catch(e) {}

  // Simple suppression to avoid repeated toasts for the same URL shortly after dismiss/proceed
  const SUPPRESS = { byKey: new Map(), untilAll: Math.max(0, authSuppressUntil) };
  function keyFromUrl(u){
    try { const x = new URL(u, location.href); return x.origin + x.pathname; } catch(_) { return String(u||''); }
  }
  function isSuppressed(u){
    const now = Date.now();
    if (now < SUPPRESS.untilAll) return true;
    const k = keyFromUrl(u);
    const t = SUPPRESS.byKey.get(k) || 0;
    return now < t;
  }
  function suppress(u, ms){
    const k = keyFromUrl(u);
    SUPPRESS.byKey.set(k, Date.now() + Math.max(0, ms||0));
  }
  function suppressAll(ms){ SUPPRESS.untilAll = Date.now() + Math.max(0, ms||0); }

  // Helper to get proxy base URL from extension
  async function getProxyBase() {
    try {
      return await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'ZT_GET_PROXY_BASE' }, (response) => {
          // Use injected config or env variable if available
          resolve(response?.base || window.ZT_PROXY_BASE_URL || 'https://dev-ai-proxy.zerotrusted.ai');
        });
      });
    } catch(_) {
      return window.ZT_PROXY_BASE_URL || 'https://dev-ai-proxy.zerotrusted.ai'; // fallback
    }
  }

  function ensureStyles(){
  if (document.getElementById('zt-toast-style')) return;
    const s = document.createElement('style');
    s.id = 'zt-toast-style';
      s.textContent = `
        .zt-toast{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;pointer-events:none}
        .zt-toast .card{pointer-events:auto;background:#1f2937;color:#fff;border-left:4px solid #d93025;padding:14px 17px;border-radius:8px;box-shadow:0 10px 24px rgba(0,0,0,.35);width:69%;max-width:540px;font:15.6px system-ui,Segoe UI,Roboto,Arial;line-height:1.6}
        .zt-toast .card b{color:#ffd1ce}
        .zt-toast .card .row{display:flex;align-items:center;gap:10px}
        .zt-toast .card button{background:#374151;color:#fff;border:0;border-radius:4px;padding:6px 10px;cursor:pointer;font-size:15.6px}
  .zt-toast .card button:hover{background:#4b5563}
  .zt-spinner{width:18px;height:18px;border:3px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;animation:ztspin 1s linear infinite}
  @keyframes ztspin{to{transform:rotate(360deg)}}
  .zt-health-banner{position:fixed;top:0;left:0;right:0;z-index:2147483646;padding:12px 20px;font:14px system-ui,Segoe UI,Roboto,Arial;color:#fff;box-shadow:0 2px 8px rgba(0,0,0,.25);pointer-events:auto;animation:ztSlideDown 0.3s ease-out}
  .zt-health-banner.critical{background:#DC2626;border-bottom:3px solid #991b1b}
  .zt-health-banner.warning{background:#F59E0B;border-bottom:3px solid #d97706;color:#000}
  .zt-health-banner.degraded{background:#FFA500;border-bottom:3px solid #ff8c00;color:#000}
  .zt-health-banner .banner-content{display:flex;align-items:center;justify-content:space-between;max-width:1200px;margin:0 auto}
  .zt-health-banner .banner-text{display:flex;align-items:center;gap:12px}
  .zt-health-banner .banner-icon{font-size:20px}
  .zt-health-banner button{background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.3);color:inherit;border-radius:4px;padding:6px 12px;cursor:pointer;font-size:13px;font-weight:600}
  .zt-health-banner button:hover{background:rgba(255,255,255,.3)}
  @keyframes ztSlideDown{from{transform:translateY(-100%)}to{transform:translateY(0)}}
      `;
  (document.head || document.documentElement).appendChild(s);
  }

  // Health banner management
  let currentHealthBanner = null;

  function showHealthBanner(type, message, persistent = false) {
    ensureStyles();
    
    // Remove existing banner
    if (currentHealthBanner) {
      try { currentHealthBanner.remove(); } catch(_) {}
      currentHealthBanner = null;
    }
    
    const banner = document.createElement('div');
    banner.className = `zt-health-banner ${type}`;
    banner.id = 'zt-health-banner';
    
    const icon = type === 'critical' ? '🔴' : (type === 'warning' || type === 'degraded' ? '⚠️' : 'ℹ️');
    
    banner.innerHTML = `
      <div class="banner-content">
        <div class="banner-text">
          <span class="banner-icon">${icon}</span>
          <strong>${message}</strong>
        </div>
        <button id="zt-banner-dismiss" title="Dismiss this notification">Dismiss</button>
      </div>
    `;
    
    document.documentElement.appendChild(banner);
    currentHealthBanner = banner;
    
    // Wire dismiss button
    const dismissBtn = banner.querySelector('#zt-banner-dismiss');
    if (dismissBtn) {
      dismissBtn.onclick = () => {
        try { banner.remove(); } catch(_) {}
        currentHealthBanner = null;
      };
    }
    
    // Auto-dismiss non-critical banners after 15 seconds
    if (!persistent && type !== 'critical') {
      setTimeout(() => {
        if (currentHealthBanner === banner) {
          try { banner.remove(); } catch(_) {}
          currentHealthBanner = null;
        }
      }, 15000);
    }
    
    return banner;
  }

  function hideHealthBanner() {
    if (currentHealthBanner) {
      try { currentHealthBanner.remove(); } catch(_) {}
      currentHealthBanner = null;
    }
  }

  function showToast(reason, url, opts){
  // Guard again in case this runs due to background message on a block page
  try { if ((document.title && /Request Blocked/i.test(document.title)) || document.getElementById('zt-req-allow-btn')) return; } catch(_) {}
  if (isSuppressed(url)) { try { console.info('[ZTProxy] toast suppressed for', url); } catch(_) {} return; }
    try { console.info('[ZTProxy] showing toast for blocked request:', { reason, url }); } catch(e) {}
    ensureStyles();
    // Hide provider inline error while toast is visible
    try {
      let hide = document.getElementById('zt-hide-provider-errors');
      if (!hide) {
        hide = document.createElement('style');
        hide.id = 'zt-hide-provider-errors';
        hide.textContent = `.text-token-text-error{display:none!important}`;
        (document.head || document.documentElement).appendChild(hide);
      }
    } catch(_) {}
    function removeProviderError(){
      try {
        const errs = document.querySelectorAll('.text-token-text-error');
        errs.forEach(el => { try { el.remove(); } catch(_) {} });
      } catch(_) {}
    }
    // Resolve per-world state to ensure this also works in injected main world
    const STATE = (window.__ZT_TOAST_STATE__ = window.__ZT_TOAST_STATE__ || { activeCard:null, root:null });
    let host = 'unknown';
    try{ host = new URL(url, location.href).host; }catch{}
    // Ensure root
    let root = STATE.root || document.getElementById('zt-toast-root');
    if(!root){
      root = document.createElement('div');
      root.id = 'zt-toast-root';
      root.className = 'zt-toast';
      document.documentElement.appendChild(root);
      STATE.root = root;
    }

    // If a toast is already visible, ignore new requests completely
    if (STATE.activeCard && STATE.activeCard.isConnected){ return; }

    // Create a new card (session-based ignore/login model)
    const card = document.createElement('div');
    card.className = 'card';
  const allowProceed = true; // session model always allows potential ignore/login path
  const isAuth = !!(opts && opts.auth);
    const ignoreRemaining = opts && opts.ignoreRemaining != null ? String(opts.ignoreRemaining) : null;
  const maskedList = opts && opts.masked ? String(opts.masked) : '';
    let maskedHtml = '';
    if (maskedList) {
      try {
        const parts = maskedList.split(',').slice(0,8);
        if (parts.length) {
          maskedHtml = '<div style="margin-top:8px;font-size:12.5px"><b>Sensitive Keywords Detected:</b><br>' + parts.map(p=>'<code style="margin-right:6px">'+p.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</code>').join(' ') + '</div>';
        }
      } catch(_) { maskedHtml=''; }
    }
  const showIgnore = allowProceed && isAuth; // Always show if authenticated (clicking adds a token)
  const showLogin = false; // Removed login from toast; SSO connect only via extension popup
    
    // Check if this is a file upload sanitization block
    const mode = opts && opts.mode ? String(opts.mode) : '';
    
    console.info('[ZTProxy] Creating toast card - opts.auth:', opts?.auth, 'isAuth:', isAuth, 'showIgnore:', showIgnore, 'showConnect:', !isAuth, 'mode:', mode);
    
    const isFileUploadBlock = mode === 'file-upload-sanitization' || (reason && reason.includes('Unsanitized file upload'));
    const sanitizeLink = isFileUploadBlock ? '<div style="margin-top:8px;font-size:13px"><a href="https://dev.zerotrusted.ai/file-sanitization" target="_blank" rel="noopener noreferrer" style="color:#4a9eff;text-decoration:underline">Click here to sanitize your files.</a></div>' : '';
    
    // Check if this is a PII detection block from standalone edition
    const isPIIBlock = reason && (reason.includes('pii') || reason.includes('PII') || reason.includes('sensitive'));
    
    if (isPIIBlock && !isAuth) {
      // Show standalone-specific PII detection UI with enterprise upgrade
      card.innerHTML = `<div class="row"><img src="https://dev-identity.zerotrusted.ai/img/logo-with-tagline-white.png" alt="ZT" style="height:22px"> <b>🛡️ Sensitive Information Detected</b></div>
        <div style="margin-top:8px;line-height:1.5;opacity:.95">Your message was blocked because it contains potentially sensitive information such as names, email addresses, phone numbers, or financial data.</div>
        <div style="margin-top:10px;padding:10px;background:rgba(234,179,8,.15);border-left:3px solid #eab308;border-radius:4px;font-size:13px">
          <b style="color:#fbbf24">⚡ Upgrade to Enterprise</b>
          <div style="margin-top:4px;opacity:.9">Get custom policies, audit logs, team management, and priority support.</div>
        </div>
        <div class="zt-host" style="margin-top:8px;font-size:13.2px;opacity:.8">${host}</div>
        <div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end">
          <button id="zt-toast-enterprise" style="background:#eab308;color:#000;font-weight:600">Sign Up for Enterprise</button>
          <button id="zt-toast-close">Dismiss</button>
        </div>`;
    } else {
      // Standard block UI (with Connect/Ignore buttons for enterprise)
      card.innerHTML = `<div class="row"><img src="https://dev-identity.zerotrusted.ai/img/logo-with-tagline-white.png" alt="ZT" style="height:22px"> <b>Request Blocked</b></div>
        <div class="zt-reason" style="margin-top:6px;opacity:.9">${reason || 'Blocked by ZeroTrusted.ai'}</div>${sanitizeLink}${maskedHtml}
        <div class="zt-host" style="margin-top:6px;font-size:13.2px;opacity:.8">${host}</div>
        <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end">
    ${showIgnore ? `<button id="zt-toast-ignore" title="Identical requests will be ignored during this session. Re-entry required after dismissing this alert.">Ignore</button>` : ''}
    ${!isAuth ? '<button id="zt-toast-connect" style="background:#dc2626">Connect</button>' : ''}
          <button id="zt-toast-close">Dismiss</button>
        </div>`;
    }
    root.appendChild(card);
    console.info('[ZTProxy] Toast card created and appended to DOM');

    // Wire buttons
    const ignoreBtn = card.querySelector('#zt-toast-ignore');
    if (ignoreBtn) ignoreBtn.onclick = async () => {
      // Notify background script to increment ignore token
      // Storage is now handled entirely in background service worker (chrome.storage.local)
      try {
        // First, get current count from background
        chrome.runtime.sendMessage({ type: 'GET_IGNORE_COUNT' }, async (response) => {
          const currentCount = (response && response.count) || 0;
          const newCount = currentCount + 1;
          
          console.log('[ZTProxy Toast] IGNORE button clicked - Adding ignore token. Count:', currentCount, '→', newCount);
          
          // Send update message
          chrome.runtime.sendMessage({
            type: 'UPDATE_IGNORE_TOKEN',
            count: newCount
          }, (updateResponse) => {
            if (chrome.runtime.lastError) {
              console.error('[ZTProxy Content] Failed to update token:', chrome.runtime.lastError.message);
            } else if (updateResponse && updateResponse.success) {
              console.log('[ZTProxy Content] Token updated successfully. New count:', newCount);
            } else {
              console.error('[ZTProxy Content] Token update failed:', updateResponse);
            }
          });
        });
      } catch (e) {
        console.error('[ZTProxy Content] Failed to increment ignore token:', e);
      }
      
      // Close toast immediately
      try { card.remove(); } catch(_) {}
      try { if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } catch(_) {}
      STATE.activeCard = null; STATE.root = null;
      try { removeProviderError(); } catch(_) {}
      
      // Brief suppression to avoid immediate re-pop if provider retries fast
      suppress(url, 2000);
    };

    const connectBtn = card.querySelector('#zt-toast-connect');
    if (connectBtn) connectBtn.onclick = () => {
      console.info('[ZTProxy] Connect button clicked, starting SSO');
      // Disable button and show loading state
      connectBtn.disabled = true;
      connectBtn.textContent = 'Connecting...';
      chrome.runtime.sendMessage({ action: 'ztStartSso' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('[ZTProxy] Failed to start SSO:', chrome.runtime.lastError.message);
          connectBtn.textContent = 'Failed';
          setTimeout(() => {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect';
          }, 2000);
        } else if (response && response.ok) {
          console.info('[ZTProxy] SSO initiated successfully');
          // Show success status
          connectBtn.style.background = '#16a34a';
          connectBtn.textContent = '✓ Connected';
          // Suppress all toasts for 10 seconds to avoid race condition after auth
          // (gives time for session header rule to propagate and first requests to complete)
          suppressAll(10000);
          console.info('[ZTProxy] Suppressing toasts for 10s after successful auth');
          // Close toast and refresh page after brief delay
          setTimeout(() => {
            try { card.remove(); } catch(_) {}
            try { if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } catch(_) {}
            STATE.activeCard = null; STATE.root = null;
            // Refresh the page
            window.location.reload();
          }, 2000);
        } else {
          console.error('[ZTProxy] SSO initiation failed:', response);
          connectBtn.textContent = 'Failed';
          setTimeout(() => {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect';
          }, 2000);
        }
      });
    };

    const enterpriseBtn = card.querySelector('#zt-toast-enterprise');
    if (enterpriseBtn) enterpriseBtn.onclick = () => {
      console.info('[ZTProxy] Enterprise signup button clicked');
      // Open enterprise signup page in new tab
      window.open('https://zerotrusted.ai/enterprise', '_blank');
      // Close the toast
      try { card.remove(); } catch(_) {}
      try { if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } catch(_) {}
      STATE.activeCard = null; STATE.root = null;
      try { removeProviderError(); } catch(_) {}
      // Brief suppression
      suppress(url, 2000);
    };

    const closeBtn = card.querySelector('#zt-toast-close');
    if (closeBtn) closeBtn.onclick = () => {
      console.log('[ZTProxy Toast] DISMISS button clicked - NO ignore token added, toast will close');
      try { card.remove(); } catch(_) {}
      try { if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } catch(_) {}
      STATE.activeCard = null; STATE.root = null;
      try { removeProviderError(); } catch(_) {}
      // Don't suppress on dismiss - allow future blocks to show toasts
      // suppress(url, 4000);  // REMOVED: User should see new block toasts after dismissing
    };

    STATE.activeCard = card;
  }

  // Lightweight loading toast (does not block subsequent block toast)
  function showLoading(reason, url){
    try { if (document.getElementById('zt-req-allow-btn')) return; } catch(_) {}
    // Avoid duplicate loading card
    if (document.getElementById('zt-loading-card')) return;
    ensureStyles();
    const STATE = (window.__ZT_TOAST_STATE__ = window.__ZT_TOAST_STATE__ || { activeCard:null, root:null });
    let root = STATE.root || document.getElementById('zt-toast-root');
    if(!root){
      root = document.createElement('div');
      root.id = 'zt-toast-root';
      root.className = 'zt-toast';
      document.documentElement.appendChild(root);
      STATE.root = root;
    }
    const card = document.createElement('div');
    card.className = 'card';
    card.id = 'zt-loading-card';
    card.innerHTML = `<div class=\"row\"><img src=\"https://dev-identity.zerotrusted.ai/img/logo-with-tagline-white.png\" alt=\"ZT\" style=\"height:22px\"> <b>Validating Request</b></div>
      <div style=\"margin-top:10px;display:flex;align-items:center;gap:10px\"><div class=\"zt-spinner\"></div><div style=\"opacity:.9\">${reason || 'Scanning for sensitive data…'}</div></div>
      <div style=\"margin-top:10px;font-size:12.5px;opacity:.65\">Auto-dismisses if allowed. You will see details if blocked.</div>`;
    root.appendChild(card);
    // Safety auto-timeout (avoid lingering if a network error occurs)
    setTimeout(()=>{ try { if(card.isConnected) { card.remove(); if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } } catch(_){} }, 15000);
  }

  function clearLoading(){
    try {
      const card = document.getElementById('zt-loading-card');
      if (card) {
        card.remove();
        const STATE = (window.__ZT_TOAST_STATE__ = window.__ZT_TOAST_STATE__ || { activeCard:null, root:null });
        if (STATE.root && !STATE.root.children.length) STATE.root.remove();
      }
    } catch(_) {}
  }

  // Listen for blocked events dispatched by the main world patch (no inline JS)
  try {
    window.addEventListener('ztproxy-blocked', (ev) => {
      try {
        const detail = (ev && ev.detail) || {}; 
        if (detail && detail.silent) return;
        
        // Check if a loading toast exists - if so, transform it instead of clearing
        const loadingCard = document.getElementById('zt-loading-card');
        if (loadingCard) {
          try {
            // Transform loading card into block card
            const allowProceed = (detail && (detail.allowProceed === true || detail.allowProceed === '1'));
            const isAuth = !!(detail && detail.auth);
            console.info('[ZTProxy] Transforming loading card - detail.auth:', detail?.auth, 'isAuth:', isAuth);
            const ignoreRemaining = detail && detail.ignoreRemaining != null ? String(detail.ignoreRemaining) : null;
            const maskedList = detail && detail.masked ? String(detail.masked) : '';
            let maskedHtml = '';
            if (maskedList) {
              try {
                const parts = maskedList.split(',').slice(0,8);
                if (parts.length) {
                  maskedHtml = '<div style="margin-top:8px;font-size:12.5px"><b>Sensitive Keywords Detected:</b><br>' + parts.map(p=>'<code style="margin-right:6px">'+p.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</code>').join(' ') + '</div>';
                }
              } catch(_) { maskedHtml=''; }
            }
            const showIgnore = allowProceed && isAuth; // Always show if authenticated (clicking adds a token)
            let host = 'unknown';
            try{ host = new URL(detail.url, location.href).host; }catch{}
            
            // Check if this is a file upload sanitization block
            const isFileUploadBlock = detail.mode === 'file-upload-sanitization' || (detail.reason && detail.reason.includes('Unsanitized file upload'));
            const reasonText = detail.reason || 'Blocked by ZeroTrusted.ai';
            const sanitizeLink = isFileUploadBlock ? '<div style="margin-top:8px;font-size:13px"><a href="https://dev.zerotrusted.ai/file-sanitization" target="_blank" rel="noopener noreferrer" style="color:#4a9eff;text-decoration:underline">Click here to sanitize your files.</a></div>' : '';
            
            loadingCard.innerHTML = `<div class="row"><img src="https://dev-identity.zerotrusted.ai/img/logo-with-tagline-white.png" alt="ZT" style="height:22px"> <b>Request Blocked</b></div>
              <div class="zt-reason" style="margin-top:6px;opacity:.9">${reasonText}</div>${sanitizeLink}${maskedHtml}
              <div class="zt-host" style="margin-top:6px;font-size:13.2px;opacity:.8">${host}</div>
              <div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end">
                ${showIgnore ? `<button id="zt-toast-ignore" title="Identical requests will be ignored during this session. Re-entry required after dismissing this alert.">Ignore</button>` : ''}
                ${!isAuth ? '<span style="flex:1;text-align:left;font-size:12px;opacity:.75">Open ZTProxy extension and click Connect to authenticate.</span>' : ''}
                <button id="zt-toast-close">Dismiss</button>
              </div>`;
            
            // Re-wire buttons
            const ignoreBtn = loadingCard.querySelector('#zt-toast-ignore');
            if (ignoreBtn) ignoreBtn.onclick = async () => {
              const proxyBase = await getProxyBase();
              try { 
                const response = await fetch(proxyBase + '/ignore-start', { method: 'POST', credentials: 'include' });
                if (response.ok) {
                  try {
                    const data = await response.json();
                    // Update ignore token count via background script
                    if (typeof data.ignore_remaining === 'number' && typeof chrome !== 'undefined' && chrome.runtime) {
                      try {
                        // Use the existing UPDATE_IGNORE_TOKEN message handler in background.js
                        chrome.runtime.sendMessage({ type: 'UPDATE_IGNORE_TOKEN', count: data.ignore_remaining }, (response) => {
                          if (chrome.runtime.lastError) {
                            console.warn('[ZTProxy Toast] Message error:', chrome.runtime.lastError);
                          } else {
                            console.log('[ZTProxy Toast] Token count updated:', data.ignore_remaining);
                          }
                        });
                      } catch(e) {
                        console.warn('[ZTProxy Toast] Could not send message:', e);
                      }
                    }
                  } catch(e) {
                    console.warn('[ZTProxy Toast] Could not parse response:', e);
                  }
                }
              } catch(e) {
                console.warn('[ZTProxy Toast] Could not call /ignore-start:', e);
              }
              try { loadingCard.remove(); } catch(_) {}
              const STATE = (window.__ZT_TOAST_STATE__ = window.__ZT_TOAST_STATE__ || { activeCard:null, root:null });
              try { if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } catch(_) {}
              STATE.activeCard = null; STATE.root = null;
              try { removeProviderError(); } catch(_) {}
              suppress(detail.url, 2000);
            };
            
            const closeBtn = loadingCard.querySelector('#zt-toast-close');
            if (closeBtn) closeBtn.onclick = () => {
              console.log('[ZTProxy Toast] DISMISS button clicked (loading card) - NO ignore token added, toast will close');
              try { loadingCard.remove(); } catch(_) {}
              const STATE = (window.__ZT_TOAST_STATE__ = window.__ZT_TOAST_STATE__ || { activeCard:null, root:null });
              try { if(STATE.root && !STATE.root.children.length) STATE.root.remove(); } catch(_) {}
              STATE.activeCard = null; STATE.root = null;
              try { removeProviderError(); } catch(_) {}
              // Don't suppress on dismiss - allow future blocks to show toasts
              // suppress(detail.url, 4000);  // REMOVED: User should see new block toasts after dismissing
            };
            
            // Update state to track this as active card
            const STATE = (window.__ZT_TOAST_STATE__ = window.__ZT_TOAST_STATE__ || { activeCard:null, root:null });
            STATE.activeCard = loadingCard;
            return; // Don't show new toast
          } catch(e) {
            console.warn('[ZTProxy] Failed to transform loading card', e);
          }
        }
        
        // Fallback: show normal toast if no loading card present
        const allowProceed = (detail && (detail.allowProceed === true || detail.allowProceed === '1'));
        showToast(detail.reason, detail.url, { allowProceed, masked: detail.masked, auth: detail.auth, ignoreRemaining: detail.ignoreRemaining });
      } catch(_) {}
    }, false);
  } catch(_) {}

  // Loading / clear events
  try { window.addEventListener('ztproxy-loading', (ev)=>{ try { const d = ev.detail || {}; showLoading(d.reason, d.url); } catch(_){} }, false); } catch(_){ }
  try { window.addEventListener('ztproxy-clear-loading', ()=>{ clearLoading(); }, false); } catch(_){ }
  // Late injection recovery: show most recent pending if present
  try {
    setTimeout(()=>{ try { const pending = window.__ZT_PENDING__ || {}; const ks = Object.keys(pending); if(ks.length){ let latest=ks[0]; for(const k of ks){ if((pending[k].ts||0) > (pending[latest].ts||0)) latest=k; } const d = pending[latest]; if(d && !document.getElementById('zt-loading-card')) showLoading(d.reason, d.url || latest); } } catch(_){} },50);
  } catch(_){ }

  // Also listen for background-detected blocked calls
  try {
    chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'ZT_BLOCKED') {
        try { 
          console.info('[ZTProxy] message from background', msg); 
          console.info('[ZTProxy] auth status:', msg.auth, 'mode:', msg.mode, 'silent:', msg.silent);
        } catch(_){ }
  if (msg.silent) {
    console.info('[ZTProxy] toast suppressed due to silent flag');
    return;
  }
  const allowProceed = (msg && (msg.allowProceed === true || msg.allowProceed === '1'));
  console.info('[ZTProxy] showing toast for blocked request, auth=', msg.auth);
  showToast(msg.reason, msg.url, { allowProceed, masked: msg.masked, auth: msg.auth, ignoreRemaining: msg.ignoreRemaining, mode: msg.mode });
      }
      // Health status messages from background
      if (msg && msg.type === 'ZT_HEALTH_CRITICAL') {
        try {
          const message = msg.message || 'ZTProxy is unavailable. Routing disabled as fail-safe.';
          showHealthBanner('critical', message, true);
        } catch(_) {}
      }
      if (msg && msg.type === 'ZT_HEALTH_DEGRADED') {
        try {
          const message = msg.message || 'ZTProxy is experiencing issues. Some features may be unavailable.';
          showHealthBanner('degraded', message, false);
        } catch(_) {}
      }
      if (msg && msg.type === 'ZT_HEALTH_WARNING') {
        try {
          const message = msg.message || 'ZTProxy service warning detected.';
          showHealthBanner('warning', message, false);
        } catch(_) {}
      }
      if (msg && msg.type === 'ZT_HEALTH_RECOVERED') {
        try {
          hideHealthBanner();
        } catch(_) {}
      }
      // Legacy failsafe message (kept for backward compatibility)
      if (msg && msg.type === 'ZT_HEALTH_DOWN') {
        try {
          showHealthBanner('critical', 'ZTProxy is unavailable. Routing has been disabled as a fail-safe. Try restarting ZTProxy.', true);
        } catch(_) {}
      }
      if (msg && msg.type === 'ZT_FAILSAFE_ACTIVE') {
        try {
          const message = msg.reason || 'ZTProxy connection lost. Fail-safe mode activated.';
          showHealthBanner('critical', message, true);
        } catch(_) {}
      }
    });
  } catch (e) { try { console.warn('[ZTProxy] onMessage addListener failed', e); } catch(_) {} }

  // Listen for postMessage events from block page or other scripts to initiate SSO connect
  try {
    window.addEventListener('message', (ev) => {
      try {
        if (!ev || !ev.data) return;
        if (ev.data.type === 'ZT_SSO_CONNECT') {
          // Relay to background to start SSO flow
          chrome.runtime.sendMessage({ action: 'ztStartSso' }, (resp) => {
            if (!resp || resp.ok !== true) {
              console.warn('[ZTProxy] SSO connect failed', resp && resp.error);
            } else {
              console.info('[ZTProxy] SSO connect initiated');
            }
          });
        }
      } catch(e) { /* ignore */ }
    }, false);
  } catch(_) {}
})();