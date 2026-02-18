// ZTProxy Background Service Worker

// Edition detection: Detect if proxy is standalone or enterprise
// Will be populated on startup by querying proxy's /config endpoint
let PROXY_EDITION = 'unknown'; // 'standalone' or 'enterprise'
let IS_STANDALONE = false;
let IS_ENTERPRISE = false;

// Browser detection and compatibility
const isEdge = navigator.userAgent.indexOf('Edg/') > -1;
const isChrome = !isEdge && navigator.userAgent.indexOf('Chrome/') > -1;
const browserName = isEdge ? 'Edge' : (isChrome ? 'Chrome' : 'Unknown');

console.log(`[ZTProxy] Running on ${browserName}`);
console.log(`[ZTProxy] User Agent: ${navigator.userAgent}`);
console.log(`[ZTProxy] Chrome Proxy API available: ${!!(chrome && chrome.proxy && chrome.proxy.settings)}`);

// Test proxy API immediately
if (chrome && chrome.proxy && chrome.proxy.settings) {
  chrome.proxy.settings.get({}, (config) => {
    console.log(`[ZTProxy] Initial proxy config:`, JSON.stringify(config, null, 2));
  });
} else {
  console.error(`[ZTProxy] ⚠️ Proxy API NOT available in ${browserName}!`);
}

let currentConfig = {
  host: 'localhost',
  port: '8081',
  filter: 'post-chat-pii',
  enforcement: 'block'
};

// Cached auth info (user, tenant) after SSO established
let ssoAuth = null;
let sessionId = null; // Store session ID for header injection
let ignoreTokenDecrementTimer = null; // Track auto-decrement timer

// Health monitor state
let health = {
  downSince: null,
  lastStatusOkAt: Date.now(),
  pacDisabled: false,
  notifying: false,
  failSafeActive: false,
  consecutiveErrors: 0,
  lastErrorTime: 0,
  recoveryAttempts: 0
};

// Routing domains cache (populated from /routing endpoint)
let routedDomains = new Set();

// Helper to create icon ImageData from canvas
function createIconImageData(size, bgColor, emoji) {
  const canvas = new OffscreenCanvas(size, size);
  const ctx = canvas.getContext('2d');
  
  // Draw rounded rectangle background
  ctx.fillStyle = bgColor;
  ctx.beginPath();
  const radius = 8;
  ctx.roundRect(0, 0, size, size, radius);
  ctx.fill();
  
  // Draw emoji/text
  ctx.fillStyle = 'white';
  ctx.font = `${size * 0.5}px Arial`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(emoji, size / 2, size / 2);
  
  return ctx.getImageData(0, 0, size, size);
}

// Update extension icon to reflect proxy status
function updateProxyIcon(state) {
  const iconConfigs = {
    active: { 
      title: 'ZTProxy Active',
      bg: '#10B981', 
      emoji: '✓'
    },
    failsafe: { 
      title: 'ZTProxy Fail-Safe Mode',
      bg: '#FFA500', 
      emoji: '⚠'
    },
    disconnected: { 
      title: 'ZTProxy Disconnected',
      bg: '#DC2626', 
      emoji: '✕'
    }
  };
  
  const config = iconConfigs[state] || iconConfigs.active;
  
  try {
    chrome.action.setTitle({ title: config.title });
    
    // Create icons at multiple sizes for different display contexts
    const imageData = {
      '16': createIconImageData(16, config.bg, config.emoji),
      '32': createIconImageData(32, config.bg, config.emoji),
      '48': createIconImageData(48, config.bg, config.emoji)
    };
    
    chrome.action.setIcon({ imageData });
  } catch (e) {
    console.warn('[ZTProxy] Failed to update icon:', e);
  }
}

// Fetch routing domains from proxy
async function fetchRoutingDomains() {
  const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
  try {
    // Build headers with Bearer token if available
    const headers = { 'Accept': 'application/json' };
    if (ssoAuth && ssoAuth.authToken) {
      headers['X-ZT-Auth'] = `Bearer ${ssoAuth.authToken}`;
    }
    
    const r = await fetch(base + '/routing', { 
      method: 'GET',
      headers: headers,
      cache: 'no-store',
      signal: AbortSignal.timeout(3000)
    });
    if (r.ok) {
      const data = await r.json();
      if (Array.isArray(data.domains)) {
        routedDomains = new Set(data.domains);
        console.log('[ZTProxy] Loaded', routedDomains.size, 'routed domains');
      }
    } else {
      console.warn('[ZTProxy] Failed to fetch routing domains - HTTP', r.status);
    }
  } catch (e) {
    // Only log if we're not already in fail-safe mode (reduces console noise)
    if (!health.failSafeActive) {
      console.warn('[ZTProxy] Cannot fetch routing domains - proxy may not be running:', e.message);
    }
  }
}

// Check if domain is in routed list
function isRoutedDomain(hostname) {
  if (!hostname) return false;
  // Exact match
  if (routedDomains.has(hostname)) return true;
  // Check parent domains (e.g., api.openai.com matches openai.com)
  const parts = hostname.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');
    if (routedDomains.has(parent)) return true;
  }
  return false;
}

// Enter fail-safe mode - disable PAC and update UI
async function enterFailSafeMode(reason = 'Proxy connection error') {
  if (health.failSafeActive) return; // Already in fail-safe
  
  console.warn(`[ZTProxy ${browserName}] Entering fail-safe mode:`, reason);
  health.failSafeActive = true;
  health.pacDisabled = true;
  
  // 1. Clear PAC configuration immediately
  try {
    await chrome.proxy.settings.clear({ scope: 'regular' });
    console.log(`[ZTProxy ${browserName}] PAC cleared - browsing in DIRECT mode`);
  } catch (e) {
    console.error(`[ZTProxy ${browserName}] Failed to clear PAC:`, e);
  }
  
  // 2. Update icon to grey warning state
  updateProxyIcon('failsafe');
  
  // 3. Update badge
  try {
    chrome.action.setBadgeText({ text: '⚠️' });
    chrome.action.setBadgeBackgroundColor({ color: '#FFA500' }); // Orange
  } catch (e) {
    console.warn('[ZTProxy] Failed to update badge:', e);
  }
  
  // 4. Store fail-safe state
  try {
    await chrome.storage.local.set({
      failSafeActive: true,
      failSafeReason: reason,
      failSafeTimestamp: Date.now()
    });
  } catch (e) {
    console.warn('[ZTProxy] Failed to save fail-safe state:', e);
  }
  
  // 5. Notify all tabs about fail-safe activation
  notifyAllTabs({ 
    type: 'ZT_FAILSAFE_ACTIVE', 
    reason: reason 
  });
  notifyAllTabs({ 
    type: 'ZT_HEALTH_CRITICAL',
    message: `ZTProxy disconnected: ${reason}`
  });
  
  // 6. Schedule recovery attempt every 30 seconds
  const retryIntervalMs = 30000; // 30 seconds
  console.log('[ZTProxy] Scheduling recovery attempt in', retryIntervalMs / 1000, 'seconds');
  setTimeout(attemptRecovery, retryIntervalMs);
}

// Attempt to recover from fail-safe mode
async function attemptRecovery() {
  console.log('[ZTProxy] Attempting proxy recovery (attempt', health.recoveryAttempts + 1, ')...');
  
  const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
  let isHealthy = false;
  let healthStatus = null;
  
  // Try new /liveness endpoint first
  try {
    const r = await fetch(base + '/liveness', {
      method: 'GET',
      cache: 'no-store',
      signal: AbortSignal.timeout(3000)
    });
    // Just check if we got a successful response
    isHealthy = r.ok;
  } catch (_) {
    // Fall back to simple metrics check
    try {
      const mr = await fetch(base + '/metrics', {
        method: 'GET',
        cache: 'no-store',
        signal: AbortSignal.timeout(3000)
      });
      isHealthy = mr && mr.ok;
    } catch (_) {
      isHealthy = false;
    }
  }
  
  if (isHealthy) {
    console.log('[ZTProxy] Proxy recovered - re-enabling PAC');
    health.failSafeActive = false;
    health.pacDisabled = false;
    health.downSince = null;
    health.consecutiveErrors = 0;
    health.recoveryAttempts = 0;
    health.lastStatusOkAt = Date.now();
    
    // Update icon based on health status
    const icon = healthStatus?.status === 'degraded' ? 'failsafe' : 'active';
    
    // Re-enable PAC
    try {
      await setupProxyFromStorage();
      updateProxyIcon(icon);
      
      if (healthStatus?.status === 'degraded') {
        chrome.action.setBadgeText({ text: '⚠' });
        chrome.action.setBadgeBackgroundColor({ color: '#FFA500' }); // Orange
      } else {
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#10B981' }); // Green
      }
      
      await chrome.storage.local.set({ failSafeActive: false });
      console.log('[ZTProxy] Recovery successful');
      
      // Notify tabs of recovery
      notifyAllTabs({ type: 'ZT_HEALTH_RECOVERED' });
      
      // Clear notifications
      notifiedComponents.forEach(componentId => {
        try {
          chrome.notifications.clear(componentId);
        } catch (_) {}
      });
      notifiedComponents.clear();
    } catch (e) {
      console.error('[ZTProxy] Failed to re-enable PAC:', e);
    }
  } else {
    console.log('[ZTProxy] Proxy still unhealthy - staying in fail-safe');
    health.recoveryAttempts++;
    
    // Schedule next recovery attempt every 30 seconds
    const retryIntervalMs = 30000; // 30 seconds
    console.log('[ZTProxy] Next recovery attempt in', retryIntervalMs / 1000, 'seconds');
    setTimeout(attemptRecovery, retryIntervalMs);
  }
}

// Enhanced health tracking with component-level details
let lastHealthStatus = null;
let notifiedComponents = new Set(); // Track which components we've already notified about

// Ping ZTProxy and manage fail-safe behavior with detailed health checks
async function checkProxyHealth() {
  const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
  const healthUrl = base + '/liveness';
  
  // NOTE: Background service worker fetch() may follow system proxy in some cases.
  // The PAC file explicitly excludes localhost to prevent proxy recursion.
  // If "Request destination unknown" errors occur, ensure PAC file is refreshed.
  
  try {
    // Use 3-second timeout for liveness check
    const r = await fetch(healthUrl, { 
      method: 'GET', 
      cache: 'no-store',
      signal: AbortSignal.timeout(3000)
    });
    
    // Just check if proxy is alive (r.ok)
    if (r.ok) {
      health.lastStatusOkAt = Date.now();
      health.downSince = null;
      health.consecutiveErrors = 0;
      
      // Proxy is alive - recover from fail-safe if needed
      if (health.failSafeActive) {
        attemptRecovery();
      } else {
        updateProxyIcon('active');
      }
      
      // Clear any previous notifications
      notifiedComponents.forEach(componentId => {
        try {
          chrome.notifications.clear(componentId);
        } catch (_) {}
      });
      notifiedComponents.clear();
      
      // Notify all tabs that proxy is healthy
      notifyAllTabs({ type: 'ZT_HEALTH_RECOVERED' });
      
      return true;
    }
  } catch (fetchError) {
    console.warn('[ZTProxy] Health check failed:', fetchError.message);
  }
  
  // Fallback to simple metrics check if /liveness endpoint unavailable
  try {
    const metricsUrl = base + '/metrics';
    const mr = await fetch(metricsUrl, { 
      method: 'GET', 
      cache: 'no-store',
      signal: AbortSignal.timeout(3000)
    });
    
    if (mr && mr.ok) {
      health.lastStatusOkAt = Date.now();
      health.downSince = null;
      health.consecutiveErrors = 0;
      
      if (health.failSafeActive) {
        attemptRecovery();
      }
      return true;
    }
  } catch (_) {}
  
  // Complete failure - increment error counter
  const now = Date.now();
  if (now - health.lastErrorTime < 30000) {
    health.consecutiveErrors++;
  } else {
    health.consecutiveErrors = 1;
  }
  health.lastErrorTime = now;
  
  // Trigger fail-safe after 2 consecutive health check failures
  // if (health.consecutiveErrors >= 2 && !health.failSafeActive) {
  //   await enterFailSafeMode('Proxy not responding');
    
  //   // Show critical notification
  //   showHealthNotification(
  //     'zt-proxy-critical',
  //     'ZTProxy Disconnected',
  //     'The ZTProxy service is not responding. Browsing will continue in DIRECT mode without protection until the service recovers.',
  //     'error'
  //   );
  // }
  
  return false;
}

// Notify user about degraded components
function notifyDegradedComponents(components) {
  if (!components) return;
  
  const degradedComponents = Object.entries(components)
    .filter(([_, info]) => info.status === 'degraded');
  
  degradedComponents.forEach(([component, info]) => {
    const notificationId = `zt-degraded-${component}`;
    
    // Only notify once per component until it recovers
    if (notifiedComponents.has(notificationId)) return;
    
    let title = 'ZTProxy Warning';
    let message = info.message || `${component} service degraded`;
    
    // Component-specific messages
    if (component === 'auth') {
      title = 'Authentication Service Degraded';
      message = 'SSO authentication may be slow. Existing sessions will continue to work.';
    } else if (component === 'blocklist_api') {
      title = 'Blocklist Service Degraded';
      message = 'Domain blocklist updates may be delayed. Current blocklist remains active.';
    }
    
    showHealthNotification(notificationId, title, message, 'warning');
    notifiedComponents.add(notificationId);
  });
}

// Notify user about unhealthy components
function notifyUnhealthyComponents(components) {
  if (!components) return;
  
  const unhealthyComponents = Object.entries(components)
    .filter(([_, info]) => info.status === 'unhealthy');
  
  unhealthyComponents.forEach(([component, info]) => {
    const notificationId = `zt-unhealthy-${component}`;
    
    // Only notify once per component until it recovers
    if (notifiedComponents.has(notificationId)) return;
    
    let title = 'ZTProxy Critical Error';
    let message = info.message || `${component} service unavailable`;
    
    // Component-specific messages
    if (component === 'pii_service') {
      title = 'PII Detection Service Down';
      message = 'PII detection is unavailable. Sensitive data protection is disabled until service recovers.';
    } else if (component === 'proxy') {
      title = 'ZTProxy Core Service Down';
      message = 'The proxy service has stopped. Browsing continues in DIRECT mode without protection.';
    }
    
    showHealthNotification(notificationId, title, message, 'error');
    notifiedComponents.add(notificationId);
  });
}

// Notify all active tabs about health status changes
function notifyAllTabs(message) {
  try {
    chrome.tabs.query({}, (tabs) => {
      (tabs || []).forEach(tab => {
        try {
          chrome.tabs.sendMessage(tab.id, message, () => {
            // Suppress "Receiving end does not exist" errors for tabs without content script
            if (chrome.runtime.lastError) {
              // Silent ignore
            }
          });
        } catch (_) {}
      });
    });
  } catch (_) {}
}

// Show health notification with appropriate icon and priority
function showHealthNotification(notificationId, title, message, type = 'info') {
  try {
    const iconUrl = type === 'error' 
      ? 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><circle cx="24" cy="24" r="20" fill="%23DC2626"/><text x="24" y="32" font-size="24" text-anchor="middle" fill="white">✕</text></svg>'
      : type === 'warning'
      ? 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><circle cx="24" cy="24" r="20" fill="%23FFA500"/><text x="24" y="32" font-size="24" text-anchor="middle" fill="white">⚠</text></svg>'
      : 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><circle cx="24" cy="24" r="20" fill="%2310B981"/><text x="24" y="32" font-size="24" text-anchor="middle" fill="white">ℹ</text></svg>';
    
    chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: iconUrl,
      title: title,
      message: message,
      priority: type === 'error' ? 2 : (type === 'warning' ? 1 : 0),
      requireInteraction: type === 'error', // Critical errors require user acknowledgment
      buttons: type === 'error' ? [{ title: 'View Status' }] : undefined
    }, () => {
      if (chrome.runtime.lastError) {
        console.warn('[ZTProxy] Notification failed:', chrome.runtime.lastError.message);
      }
    });
  } catch (e) {
    console.warn('[ZTProxy] Failed to show notification:', e);
  }
}

// Handle notification button clicks
try {
  chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (notificationId.startsWith('zt-')) {
      // Open proxy UI status page
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      chrome.tabs.create({ url: `${base}/zt-ui#status` });
      chrome.notifications.clear(notificationId);
    }
  });
  
  chrome.notifications.onClicked.addListener((notificationId) => {
    if (notificationId.startsWith('zt-')) {
      // Open proxy UI status page
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      chrome.tabs.create({ url: `${base}/zt-ui#status` });
      chrome.notifications.clear(notificationId);
    }
  });
} catch (_) {}

// (removed unused helpers)

function createUrlPacConfig(host = 'localhost', port = '8081', bustCache = false) {
  // Point Chrome/Edge at dynamic PAC endpoint so domain list updates automatically
  // Use HTTPS for port 443, HTTP otherwise
  const protocol = (port === '443' || port === 443) ? 'https' : 'http';
  const portSuffix = (port === '443' || port === 443) ? '' : ':' + port;
  // Add cache-busting timestamp when explicitly refreshing to force browser PAC reload
  const cacheBuster = bustCache ? `?t=${Date.now()}` : '';
  const pacUrl = `${protocol}://${host}${portSuffix}/pac${cacheBuster}`;
  console.log(`[ZTProxy ${browserName}] Creating PAC config with URL: ${pacUrl}`);
  return { mode: 'pac_script', pacScript: { url: pacUrl, mandatory: true } };
}

// Test if PAC file is accessible
async function testPacAccessibility(host = 'localhost', port = '8081') {
  const protocol = (port === '443' || port === 443) ? 'https' : 'http';
  const portSuffix = (port === '443' || port === 443) ? '' : ':' + port;
  const pacUrl = `${protocol}://${host}${portSuffix}/pac`;
  
  // Skip PAC test for localhost since Chrome can access it directly even if our fetch can't
  // (fetch might go through proxy causing recursion, but Chrome's PAC loader bypasses proxy)
  if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0') {
    console.log(`[ZTProxy ${browserName}] ℹ Skipping PAC accessibility test for ${host} (local proxy, Chrome will access directly)`);
    return true;
  }
  
  try {
    const response = await fetch(pacUrl, { 
      method: 'GET',
      cache: 'no-store',
      signal: AbortSignal.timeout(5000)
    });
    
    if (response.ok) {
      const pacContent = await response.text();
      console.log(`[ZTProxy ${browserName}] ✓ PAC file accessible, length: ${pacContent.length} bytes`);
      console.log(`[ZTProxy ${browserName}] PAC preview:`, pacContent.substring(0, 200));
      return true;
    } else {
      console.warn(`[ZTProxy ${browserName}] ⚠ PAC file returned status: ${response.status} (may still work if proxy is running)`);
      return false;
    }
  } catch (error) {
    console.warn(`[ZTProxy ${browserName}] ⚠ PAC file not accessible via fetch:`, error.message);
    console.warn(`[ZTProxy ${browserName}] This is expected if proxy isn't running yet, or if fetch is going through the proxy (recursion)`);
    console.warn(`[ZTProxy ${browserName}] Chrome's PAC loader may still work. Verify proxy is running: ${protocol}://${host}${portSuffix}/metrics`);
    // Return true for localhost/local IPs since Chrome bypasses proxy for PAC URL
    return (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0');
  }
}

// Helper function to build base URL with correct protocol
function getProxyBaseUrl(host = 'localhost', port = '8081') {
  const protocol = (port === '443' || port === 443) ? 'https' : 'http';
  const portSuffix = (port === '443' || port === 443) ? '' : ':' + port;
  return `${protocol}://${host}${portSuffix}`;
}

// Detect proxy edition (standalone vs enterprise)
async function detectProxyEdition() {
  try {
    const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
    const response = await fetch(`${base}/config`, {
      method: 'GET',
      signal: AbortSignal.timeout(3000)
    });
    
    if (response.ok) {
      const config = await response.json();
      const edition = config.edition || 'enterprise'; // Default to enterprise if not specified
      PROXY_EDITION = edition.toLowerCase();
      IS_STANDALONE = (PROXY_EDITION === 'standalone');
      IS_ENTERPRISE = (PROXY_EDITION === 'enterprise');
      
      console.log(`[ZTProxy] Detected proxy edition: ${PROXY_EDITION.toUpperCase()} (standalone=${IS_STANDALONE}, enterprise=${IS_ENTERPRISE})`);
      
      // Store edition in chrome.storage for popup access
      await chrome.storage.local.set({ ztProxyEdition: PROXY_EDITION });
      
      return PROXY_EDITION;
    } else {
      console.warn('[ZTProxy] Failed to detect edition from /config, defaulting to enterprise');
      PROXY_EDITION = 'enterprise';
      IS_ENTERPRISE = true;
      return 'enterprise';
    }
  } catch (error) {
    console.warn('[ZTProxy] Error detecting edition (proxy may be offline), defaulting to enterprise:', error.message);
    PROXY_EDITION = 'enterprise';
    IS_ENTERPRISE = true;
    return 'enterprise';
  }
}

// Restore authentication and session from storage
async function restoreAuthFromStorage() {
  try {
    const result = await chrome.storage.local.get(['ztAuth', 'ztSessionId']);
    
    console.log('[ZTProxy] 🔍 Storage check:', {
      hasAuth: !!result.ztAuth,
      hasSessionId: !!result.ztSessionId,
      authKeys: result.ztAuth ? Object.keys(result.ztAuth) : [],
      sessionIdLength: result.ztSessionId ? result.ztSessionId.length : 0
    });
    
    // Restore auth data
    if (result.ztAuth) {
      ssoAuth = result.ztAuth;
      console.log('[ZTProxy] ✓ Auth restored from storage', { 
        email: ssoAuth.email ? '***' : null,
        hasToken: !!ssoAuth.authToken,
        fullAuth: !!result.ztAuth
      });
    } else {
      console.warn('[ZTProxy] ✗ No auth found in storage - user needs to authenticate');
    }
    
    // Restore session ID
    if (result.ztSessionId) {
      sessionId = result.ztSessionId;
      console.log('[ZTProxy] ✓ Session ID restored:', sessionId.substring(0, 10) + '...');
      
      // Verify session is still valid in proxy
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      try {
        const authCheckResponse = await fetch(`${base}/auth-status`, { 
          method: 'GET',
          credentials: 'include',
          signal: AbortSignal.timeout(5000)
        });
        
        if (authCheckResponse.ok) {
          const authData = await authCheckResponse.json();
          if (authData.authenticated) {
            console.log('[ZTProxy] ✓ Session verified as active:', authData.email || 'unknown');
            // Update declarativeNetRequest rule to inject session header
            console.log('[ZTProxy] 📡 Calling updateSessionHeaderRule() to inject X-ZT-Session header...');
            await updateSessionHeaderRule();
            return; // Session is valid, we're done
          }
        }
        console.warn('[ZTProxy] ✗ Session expired in proxy - will re-establish');
      } catch (e) {
        console.warn('[ZTProxy] ⚠ Could not verify session (proxy offline?) - will attempt header injection anyway:', e);
        // Still inject headers in case proxy comes back online
        await updateSessionHeaderRule();
        return;
      }
    }
    
    // If we reach here: either no sessionId in storage, or session expired
    // Re-establish session if we have auth data
    if (ssoAuth && ssoAuth.email) {
      console.log('[ZTProxy] 🔄 Re-establishing session with stored auth...');
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      try {
        const response = await fetch(`${base}/sso-establish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: ssoAuth.email || ssoAuth.upn || ssoAuth.user || 'unknown',
            tid: ssoAuth.tid || ssoAuth.tenantId || '',
            auth_token: ssoAuth.authToken || ssoAuth.accessToken || ''
          }),
          credentials: 'include',
          signal: AbortSignal.timeout(5000)
        });
        
        if (response.ok) {
          const sessionData = await response.json();
          sessionId = sessionData.session_id;
          console.log('[ZTProxy] ✓ Session re-established successfully');
          
          // Update stored session ID
          await chrome.storage.local.set({ ztSessionId: sessionId });
          
          // Update declarativeNetRequest rule to inject header
          await updateSessionHeaderRule();
        } else {
          console.error('[ZTProxy] ✗ Failed to re-establish session:', response.status);
        }
      } catch (e) {
        console.error('[ZTProxy] ✗ Failed to re-establish session:', e);
      }
    } else if (!result.ztSessionId) {
      console.warn('[ZTProxy] ✗ No session ID in storage - header injection will NOT work!');
      console.warn('[ZTProxy] ✗ No auth data available for re-establishment - user must login');
    }
  } catch(e) {
    console.error('[ZTProxy] ❌ Failed to restore auth from storage:', e);
  }
}

// Check authentication status and ensure user is logged in
async function checkAndEnsureAuth() {
  // Skip auth checks in standalone mode
  if (IS_STANDALONE) {
    console.log('[ZTProxy] Standalone mode - skipping auth check');
    return;
  }
  
  try {
    const result = await chrome.storage.local.get(['ztAuth', 'ztSessionId']);
    
    // No JWT token stored - user needs to login manually via popup
    // Don't force login on startup - let user browse and connect when needed
    if (!result.ztAuth || !result.ztAuth.authToken) {
      console.log('ZTProxy: No authentication found - user can connect via extension popup');
      return;
    }
    
    // Have JWT, check if session is still valid with proxy
    if (result.ztSessionId) {
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      try {
        const resp = await fetch(`${base}/session-status`, {
          method: 'GET',
          headers: { 'X-ZT-Session-Id': result.ztSessionId },
          signal: AbortSignal.timeout(3000)
        });
        
        if (resp.ok) {
          const data = await resp.json();
          if (data.valid) {
            console.log('ZTProxy: Session is valid', { user: data.user ? '***' : null });
            return;
          }
        }
        
        console.log('ZTProxy: Session expired or invalid - re-establishing with stored JWT');
      } catch (e) {
        console.warn('ZTProxy: Could not check session status, will re-establish', e);
      }
      
      // Session invalid or check failed - re-establish using stored JWT
      try {
        const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
        const response = await fetch(`${base}/sso-establish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: result.ztAuth.email || 'unknown',
            tid: result.ztAuth.tid || '',
            auth_token: result.ztAuth.authToken
          }),
          credentials: 'include',
          signal: AbortSignal.timeout(5000)
        });
        
        if (response.ok) {
          const sessionData = await response.json();
          sessionId = sessionData.session_id;
          console.log('ZTProxy: Session re-established successfully');
          
          // Update stored session ID
          await chrome.storage.local.set({ ztSessionId: sessionId });
          
          // Update declarativeNetRequest rule to inject header
          await updateSessionHeaderRule();
        } else {
          console.error('ZTProxy: Failed to re-establish session', response.status);
        }
      } catch (e) {
        console.error('ZTProxy: Failed to re-establish session with stored JWT', e);
      }
    }
  } catch (e) {
    console.error('ZTProxy: Error in checkAndEnsureAuth', e);
  }
}

// Periodic session recovery - check every 5 minutes and auto-recover if needed
// This ensures auth persists indefinitely by re-establishing sessions before they expire
setInterval(async () => {
  try {
    const result = await chrome.storage.local.get(['ztAuth', 'ztSessionId']);
    if (result.ztAuth && result.ztAuth.authToken) {
      console.log('[ZTProxy] Periodic auth check - verifying session');
      await checkAndEnsureAuth();  // This will re-establish if needed
    }
  } catch (e) {
    console.error('[ZTProxy] Periodic auth check failed:', e);
  }
}, 5 * 60 * 1000);  // Every 5 minutes

// Set up proxy configuration on startup
chrome.runtime.onStartup.addListener(async () => {
  console.log("ZTProxy: Extension startup");
  
  // Detect proxy edition (standalone vs enterprise)
  await detectProxyEdition();
  
  // Restore auth and session from storage (no forced login)
  // Only attempt auth restoration in enterprise mode
  if (IS_ENTERPRISE) {
    await restoreAuthFromStorage();
  } else {
    console.log('[ZTProxy] Standalone mode - skipping auth restoration');
  }
  
  // Restore fail-safe state from storage if extension was in fail-safe before reload
  const stored = await chrome.storage.local.get(['failSafeActive']);
  if (stored.failSafeActive) {
    health.failSafeActive = true;
    updateProxyIcon('failsafe');
    console.log("ZTProxy: Restored fail-safe state from storage");
  } else {
    // Initialize with disconnected icon until health check completes
    updateProxyIcon('disconnected');
  }
  
  // Check proxy health before setting up PAC to avoid "no internet" if proxy is down
  checkProxyHealth().then(() => {
    // Only set up proxy if health check passed or will retry
    setTimeout(() => {
      if (!health.pacDisabled) {
        setupProxyFromStorage();
      } else {
        console.warn("ZTProxy: Proxy unavailable on startup, skipping PAC setup");
        updateProxyIcon('disconnected');
      }
    }, 100);
  });
  
  // Health check every 15 seconds for proactive monitoring
  try { 
    chrome.alarms.create('ztproxy-health', { 
      delayInMinutes: 0.25, // 15 seconds
      periodInMinutes: 0.25 
    }); 
  } catch(_) {}
});

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("ZTProxy: Extension installed/updated");
  
  // Detect proxy edition (standalone vs enterprise)
  await detectProxyEdition();
  
  // Restore auth and session from storage (no forced login)
  // Only attempt auth restoration in enterprise mode
  if (IS_ENTERPRISE) {
    await restoreAuthFromStorage();
  } else {
    console.log('[ZTProxy] Standalone mode - skipping auth restoration');
  }
  
  // Restore fail-safe state from storage if extension was in fail-safe before reload
  const stored = await chrome.storage.local.get(['failSafeActive']);
  if (stored.failSafeActive) {
    health.failSafeActive = true;
    updateProxyIcon('failsafe');
    console.log("ZTProxy: Restored fail-safe state from storage");
  } else {
    // Initialize with disconnected icon until health check completes
    updateProxyIcon('disconnected');
  }
  
  if (details.reason === 'install') {
    // Set default configuration on first install
    chrome.storage.sync.set({
      proxyHost: 'ai-proxy.zerotrusted.ai',
      proxyPort: '443',
      requestFilter: 'post-chat-pii',
      enforcementMode: 'block'
    });
  }
  
  // Check proxy health before setting up PAC
  checkProxyHealth().then(() => {
    setTimeout(() => {
      if (!health.pacDisabled) {
        setupProxyFromStorage();
      } else {
        console.warn("ZTProxy: Proxy unavailable on install, skipping PAC setup");
        updateProxyIcon('disconnected');
      }
    }, 100);
  });
  
  // Health check every 15 seconds for proactive monitoring
  try { 
    chrome.alarms.create('ztproxy-health', { 
      delayInMinutes: 0.25, // 15 seconds
      periodInMinutes: 0.25 
    }); 
  } catch(_) {}
});

// React to health alarms
try {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (!alarm || !alarm.name) return;
    if (alarm.name === 'ztproxy-health' || alarm.name === 'ztproxy-health-retry') {
      checkProxyHealth();
    }
  });
} catch(_) {}

// Monitor webRequest errors for proxy-related issues
try {
  if (chrome.webRequest && chrome.webRequest.onErrorOccurred) {
    chrome.webRequest.onErrorOccurred.addListener(
      (details) => {
        try {
          const proxyErrors = [
            'ERR_CERT_AUTHORITY_INVALID',
            'ERR_CERT_COMMON_NAME_INVALID',
            'ERR_CERT_DATE_INVALID',
            'ERR_CONNECTION_REFUSED',
            'ERR_TUNNEL_CONNECTION_FAILED',
            'ERR_CONNECTION_TIMED_OUT'
          ];
          
          // Check if this is a proxy-related error
          const isProxyError = proxyErrors.some(err => details.error.includes(err));
          
          if (isProxyError && details.url) {
            try {
              const url = new URL(details.url);
              const hostname = url.hostname;
              
              // Only trigger fail-safe for errors on routed domains
              if (isRoutedDomain(hostname)) {
                console.error('[ZTProxy WebRequest ERROR]', details.error, '| URL:', details.url);
                
                const now = Date.now();
                // Track consecutive errors within 30 seconds
                if (now - health.lastErrorTime < 30000) {
                  health.consecutiveErrors++;
                } else {
                  health.consecutiveErrors = 1;
                }
                health.lastErrorTime = now;
                
                // Trigger fail-safe after 3 consecutive errors on routed domains (recommended: Option B)
                if (health.consecutiveErrors >= 3 && !health.failSafeActive) {
                  enterFailSafeMode(`${details.error} on ${hostname}`);
                }
              }
            } catch (urlError) {
              // Invalid URL, skip
            }
          }
        } catch (e) {
          console.warn('[ZTProxy] Error in onErrorOccurred handler:', e);
        }
      },
      { urls: ["<all_urls>"] }
    );
  }
} catch (e) {
  console.warn('[ZTProxy] Could not attach onErrorOccurred listener:', e);
}

// ADDITIONAL: Listen for completed requests with 403 status to catch auth blocks
try {
  if (chrome.webRequest && chrome.webRequest.onCompleted) {
    chrome.webRequest.onCompleted.addListener(
      async (details) => {
        // Only handle 403 responses from AI domains
        if (details.statusCode === 403 && details.url) {
          try {
            const url = new URL(details.url);
            if (isRoutedDomain(url.hostname)) {
              console.log('[ZTProxy] 403 detected on AI domain (onCompleted):', details.url, 'tabId:', details.tabId);
              // Check if user has cached auth
              let hasAuth = false;
              try {
                const authCheck = await chrome.storage.local.get(['ztAuth']);
                hasAuth = !!(authCheck.ztAuth && authCheck.ztAuth.authToken);
              } catch(_) {}
              
              // Note: We can't read response headers here, but can notify about 403
              if (details.tabId >= 0) {
                const message = {
                  type: 'ZT_BLOCKED',
                  url: details.url,
                  reason: 'Authentication Required: Please connect using the extension',
                  mode: 'auth-required',
                  silent: false,
                  allowProceed: false,
                  masked: '',
                  auth: hasAuth, // Use cached auth status
                  ignoreRemaining: null
                };
                console.log('[ZTProxy] Sending ZT_BLOCKED message to tab', details.tabId, message);
                chrome.tabs.sendMessage(details.tabId, message, (response) => {
                  if (chrome.runtime.lastError) {
                    console.warn('[ZTProxy] Failed to send message to tab:', chrome.runtime.lastError.message);
                  } else {
                    console.log('[ZTProxy] Message sent successfully to tab', details.tabId);
                  }
                });
              } else {
                console.warn('[ZTProxy] No valid tabId for 403 response:', details.url);
              }
            }
          } catch (e) {
            // Invalid URL
          }
        }
      },
      { urls: ["<all_urls>"] }
    );
  }
} catch (e) {
  console.warn('[ZTProxy] Could not attach onCompleted listener:', e);
}

// Fallback: detect blocked calls via webRequest and notify content script
// Also handle ignore token consumption
try {
  if (chrome.webRequest && chrome.webRequest.onHeadersReceived) {
    chrome.webRequest.onHeadersReceived.addListener(
      async (details) => {
        try {
          // Debug: log conversation requests to verify listener is working
          if (details.url.includes('/conversation')) {
            console.log('[ZTProxy Background] onHeadersReceived fired for:', details.url.substring(0, 100));
          }
          
          // Check if proxy consumed an ignore token
          const tokenConsumedHeader = details.responseHeaders?.find(h => h.name.toLowerCase() === 'x-zt-token-consumed');
          
          // Debug: log all custom headers
          if (details.url.includes('/conversation')) {
            const customHeaders = details.responseHeaders?.filter(h => h.name.toLowerCase().startsWith('x-zt-')) || [];
            console.log('[ZTProxy Background] Custom headers:', customHeaders.map(h => `${h.name}=${h.value}`).join(', '));
          }
          
          if (tokenConsumedHeader && tokenConsumedHeader.value === '1') {
            console.log('[ZTProxy Background] Token consumed by proxy, URL:', details.url.substring(0, 100));
            
            // Check if proxy sent back the new count (preferred method)
            const ignoreRemainingHeader = details.responseHeaders?.find(h => h.name.toLowerCase() === 'x-zt-ignore-remaining');
            
            if (ignoreRemainingHeader) {
              // Use the count provided by proxy (already decremented)
              const newCount = parseInt(ignoreRemainingHeader.value || '0', 10);
              console.log('[ZTProxy Background] Using proxy-provided count:', newCount);
              try {
                await chrome.storage.local.set({ zt_ignore_token_count: newCount });
                await updateSessionHeaderRule();
                console.log('[ZTProxy Background] Updated to new count:', newCount);
              } catch (e) {
                console.warn('ZTProxy: Could not update token count:', e);
              }
            } else {
              // Fallback: manually decrement
              console.log('[ZTProxy Background] No proxy count, manually decrementing');
              try {
                const result = await chrome.storage.local.get(['zt_ignore_token_count']);
                const currentCount = parseInt(result.zt_ignore_token_count || '0', 10);
                if (currentCount > 0) {
                  const newCount = currentCount - 1;
                  await chrome.storage.local.set({ zt_ignore_token_count: newCount });
                  console.log('[ZTProxy Background] Token decremented. Remaining:', newCount);
                  
                  // Update the header rule with new count
                  await updateSessionHeaderRule();
                }
              } catch (e) {
                console.warn('ZTProxy: Could not decrement ignore token:', e);
              }
            }
          }
          
          // Handle blocked responses
          if (details.statusCode === 403 && details.responseHeaders) {
            const blocked = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-blocked');
            if (blocked && blocked.value === '1') {
              const reasonHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-reason');
              const reason = (reasonHeader && reasonHeader.value) || 'Blocked by ZeroTrusted.ai';
        const modeHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-mode');
        const silentHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-silent');
  const allowProceedHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-allow-proceed');
  const maskedHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-pii-masked');
  const authHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-auth');
  const ignoreRemHeader = details.responseHeaders.find(h => h.name.toLowerCase() === 'x-zt-ignore-remaining');
  const mode = (modeHeader && modeHeader.value) || '';
  const silent = (silentHeader && silentHeader.value) === '1';
  const allowProceed = (allowProceedHeader && allowProceedHeader.value) === '1';
  const masked = (maskedHeader && maskedHeader.value) || '';
  // Check cached auth from storage instead of trusting proxy header alone
  let auth = (authHeader && authHeader.value) === '1';
  try {
    const authCheck = await chrome.storage.local.get(['ztAuth']);
    if (authCheck.ztAuth && authCheck.ztAuth.authToken) {
      auth = true; // Override: user has cached auth, always consider authenticated
      console.log('[ZTProxy] Auth override: cached auth found, setting auth=true');
    } else {
      console.log('[ZTProxy] No cached auth found, using proxy header auth=' + auth);
    }
  } catch(e) {
    console.warn('[ZTProxy] Failed to check cached auth:', e);
  }
  const ignoreRemaining = ignoreRemHeader ? ignoreRemHeader.value : null;
        console.log('ZTProxy: detected blocked response', { url: details.url, tabId: details.tabId, reason, mode, silent, auth });
              if (details.tabId >= 0) {
                try {
                    chrome.tabs.sendMessage(details.tabId, {
                      type: 'ZT_BLOCKED',
                      url: details.url,
                      reason,
                      mode,
                      silent,
                      allowProceed,
                      masked,
                      auth,
                      ignoreRemaining
                    }, () => { if (chrome.runtime.lastError) { /* suppress missing receiver error */ } });
                } catch(_) {}
              } else {
                console.log('ZTProxy: blocked response without tabId (worker or service worker)');
                // Try to notify the active tab as a best-effort
                chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
                  if (tabs && tabs.length) {
          tabs.forEach(t => {
                      if (t && t.id >= 0) {
            try { chrome.tabs.sendMessage(t.id, { type: 'ZT_BLOCKED', url: details.url, reason, mode, silent }, () => { if (chrome.runtime.lastError) {} }); } catch(_) {}
                      }
                    });
                  } else if (chrome.notifications && chrome.notifications.create) {
          if (silent) return; // suppress noisy notifications
                    const title = 'Request Blocked by ZeroTrusted.ai';
                    const message = `${reason}\n${details.url}`;
                    chrome.notifications.create('', {
                      type: 'basic',
                      iconUrl: 'icon48.png',
                      title,
                      message
                    });
                  }
                });
              }
            }
          }
        } catch (e) {
          console.warn('ZTProxy webRequest parse error', e);
        }
      },
      { urls: ["<all_urls>"] },
      ["responseHeaders", "extraHeaders"]
    );
  }
} catch (e) {
  console.warn('ZTProxy could not attach webRequest listener', e);
}

// Inject X-ZT-Session and X-ZT-Ignore-Token headers on proxied requests using declarativeNetRequest
async function updateSessionHeaderRule() {
  console.log('[ZTProxy] 📡 updateSessionHeaderRule() called. sessionId:', sessionId ? sessionId.substring(0, 10) + '...' : 'NOT SET');
  
  if (!chrome.declarativeNetRequest) {
    console.warn('ZTProxy: declarativeNetRequest API not available');
    return;
  }

  try {
    // CRITICAL FIX: Read session ID from storage to ensure we have the latest value
    // The global sessionId variable may be stale or null after extension reload
    try {
      const result = await chrome.storage.local.get(['ztSessionId']);
      if (result.ztSessionId) {
        sessionId = result.ztSessionId;
        console.log('🔄 [ZTProxy] Synced session ID from storage:', sessionId.substring(0, 10) + '...');
      }
    } catch (e) {
      console.warn('ZTProxy: Could not read session ID from storage:', e);
    }
    
    // Remove existing rules
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const ruleIdsToRemove = existingRules.map(rule => rule.id);
    if (ruleIdsToRemove.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: ruleIdsToRemove
      });
    }

    // Get ignore token count from chrome.storage.local (not page localStorage)
    let ignoreCount = 0;
    try {
      const result = await chrome.storage.local.get(['zt_ignore_token_count']);
      ignoreCount = parseInt(result.zt_ignore_token_count || '0', 10);
      console.log('🔍 [ZTProxy Background] CRITICAL: Ignore token count from storage:', ignoreCount, '(Will be sent as X-ZT-Ignore-Token header)');
    } catch (e) {
      console.log('ZTProxy: Could not read ignore tokens from storage:', e);
    }

    // Create separate rules for session header vs ignore token header
    const rulesToAdd = [];
    
    // Rule 1: X-ZT-Session AND X-ZT-Auth headers on ALL AI domain requests (including navigation)
    // Use requestDomains to explicitly match AI services
    if (sessionId) {
      const requestHeaders = [{
        header: 'X-ZT-Session',
        operation: 'set',
        value: sessionId
      }];
      
      // Add X-ZT-Auth header with JWT token if available
      if (ssoAuth && ssoAuth.authToken) {
        requestHeaders.push({
          header: 'X-ZT-Auth',
          operation: 'set',
          value: `Bearer ${ssoAuth.authToken}`
        });
        console.log('🔐 [ZTProxy] Adding X-ZT-Auth header with JWT token for user settings');
      } else {
        console.warn('⚠️ [ZTProxy] No JWT token available - user settings will NOT be fetched');
      }
      
      rulesToAdd.push({
        id: 1,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          requestHeaders: requestHeaders
        },
          condition: {
            // Explicitly match AI service domains to ensure reliable header injection
            requestDomains: [
              'chatgpt.com',
              'openai.com',
              'api.openai.com',
              'claude.ai',
              'api.anthropic.com',
              'bard.google.com',
              'gemini.google.com',
              'ai.google.dev',
              'api.perplexity.ai',
              'perplexity.ai',
              'labs.perplexity.ai',
              'you.com',
              'api.you.com',
              'poe.com',
              'mistral.ai',
              'chat.mistral.ai',
              'console.anthropic.com',
              'beta.character.ai',
              'character.ai'
            ],
            resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'websocket', 'other']
          }
        });
        console.log('ZTProxy: Adding X-ZT-Session header rule for AI domains with session:', sessionId.substring(0, 10) + '...');
      }
      
      // Rule 2: X-ZT-Ignore-Token header ONLY on conversation endpoints
      if (ignoreCount > 0) {
        console.log('⚠️ [ZTProxy Background] ADDING IGNORE TOKEN RULE with count:', ignoreCount, '- This will BYPASS proxy checks!');
        const ignoreRule = {
          id: 2,
          priority: 2,
          action: {
            type: 'modifyHeaders',
            requestHeaders: [{
              header: 'X-ZT-Ignore-Token',
              operation: 'set',
              value: String(ignoreCount)
            }]
          },
          condition: {
            // Match conversation endpoints - including ChatGPT, OpenAI API, Claude, etc.
            // Matches: /conversation, /conversations, /backend-api/conversation, /backend-api/f/conversation, /v1/chat/completions
            regexFilter: '.*/(backend-api/(f/)?)?conversation(s)?.*|.*/v\\d+/(chat|completions).*',
            resourceTypes: ['xmlhttprequest']
          }
        };
        rulesToAdd.push(ignoreRule);
        console.log('✅ [ZTProxy Background] Ignore token rule ACTIVE - Next conversation request will bypass proxy checks');
        console.log('🔍 [DEBUG] Ignore rule being added:', JSON.stringify(ignoreRule, null, 2));
        
        // DISABLED: Auto-decrement timer removed
        // The proxy server handles consumption via X-ZT-Token-Consumed response header
        // The webRequest.onHeadersReceived listener (line ~906) handles decrementing
        // This gives the user unlimited time to retry the blocked request
        console.log('⏰ [ZTProxy Background] Token will be consumed by proxy on next conversation request (no auto-decrement)');
      } else {
        console.log('✅ [ZTProxy Background] No ignore token rule added - count is 0 (normal blocking will occur)');
      }

      // Add rules if we have any
      if (rulesToAdd.length > 0) {
        console.log('🔧 [DEBUG] About to add rules:', JSON.stringify(rulesToAdd, null, 2));
        await chrome.declarativeNetRequest.updateDynamicRules({
          addRules: rulesToAdd
        });
        console.log('ZTProxy: Header injection rules updated. Session:', !!sessionId, 'Auth token:', !!(ssoAuth && ssoAuth.authToken), 'Ignore tokens:', ignoreCount);
        
        // Verify rules were added with FULL details
        const updatedRules = await chrome.declarativeNetRequest.getDynamicRules();
        console.log('ZTProxy: Active rules after update:', updatedRules);
        console.log('🔍 [DEBUG] Full rule details:', JSON.stringify(updatedRules, null, 2));
        
        // Test regex pattern manually to verify it should match
        if (ignoreCount > 0) {
          const testUrls = [
            'https://chatgpt.com/backend-api/f/conversation',
            'https://chatgpt.com/backend-api/conversation',
            'https://api.openai.com/v1/chat/completions'
          ];
          const ignoreRule = rulesToAdd.find(r => r.id === 2);
          if (ignoreRule && ignoreRule.condition.regexFilter) {
            console.log('🧪 [DEBUG] Testing regex:', ignoreRule.condition.regexFilter);
            const testRegex = new RegExp(ignoreRule.condition.regexFilter);
            testUrls.forEach(url => {
              console.log(`  ${url} → ${testRegex.test(url) ? '✅ MATCHES' : '❌ NO MATCH'}`);
            });
          }
        }
      } else {
        console.log('ZTProxy: No sessionId or ignore tokens, skipping rule creation');
      }
  } catch (e) {
    console.warn('ZTProxy: Could not update session header rule', e);
  }
}

// Handle configuration updates from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateConfig') {
    currentConfig = message.config;
    // Allow passing an API key for notifications if available
    if (message.ztproxyConfig && typeof message.ztproxyConfig.features_bearer === 'string') {
      currentConfig.apiKey = message.ztproxyConfig.features_bearer;
    }
    
    // Send configuration to ZTProxy if available
    if (message.ztproxyConfig) {
      sendConfigToZTProxy(message.ztproxyConfig);
    }
    
    // Force cache bust when config changes (host/port/mode) to apply immediately
    setupProxyFromStorage(true);
  }
  
  // Handle ignore token updates from content script
  if (message && message.type === 'UPDATE_IGNORE_TOKEN') {
    console.log('[ZTProxy Background] ✅ Received UPDATE_IGNORE_TOKEN message with count:', message.count);
    // Store count in chrome.storage.local
    chrome.storage.local.set({ zt_ignore_token_count: message.count }, () => {
      if (chrome.runtime.lastError) {
        console.error('[ZTProxy Background] ❌ Failed to store ignore token count:', chrome.runtime.lastError);
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
        return;
      }
      console.log('[ZTProxy Background] ✅ Stored ignore token count:', message.count);
      
      // Verify it was actually stored
      chrome.storage.local.get(['zt_ignore_token_count'], (verifyResult) => {
        console.log('[ZTProxy Background] 🔍 Verification: storage now contains:', verifyResult.zt_ignore_token_count);
        
        // Update header injection rules
        updateSessionHeaderRule().then(() => {
          console.log('[ZTProxy Background] ✅ Updated header rules with ignore token');
          sendResponse({ success: true });
        }).catch(err => {
          console.error('[ZTProxy Background] ❌ Failed to update header rules:', err);
          sendResponse({ success: false, error: err.message });
        });
      });
    });
    return true; // Keep message channel open for async response
  }
  
  // Handle ignore token count requests
  if (message && message.type === 'GET_IGNORE_COUNT') {
    chrome.storage.local.get(['zt_ignore_token_count'], (result) => {
      const count = parseInt(result.zt_ignore_token_count || '0', 10);
      console.log('[ZTProxy Background] Current ignore token count:', count);
      sendResponse({ count: count });
    });
    return true; // Keep message channel open for async response
  }
  
  // DIAGNOSTIC: Check auth and session state
  if (message && message.type === 'DEBUG_AUTH_STATE') {
    chrome.storage.local.get(['ztAuth', 'ztSessionId'], (result) => {
      chrome.declarativeNetRequest.getDynamicRules().then(rules => {
        const state = {
          storage: {
            hasAuth: !!result.ztAuth,
            authEmail: result.ztAuth?.email || null,
            hasSessionId: !!result.ztSessionId,
            sessionIdPreview: result.ztSessionId ? result.ztSessionId.substring(0, 10) + '...' : null
          },
          memory: {
            hasSsoAuth: !!ssoAuth,
            ssoAuthEmail: ssoAuth?.email || null,
            hasSessionId: !!sessionId,
            sessionIdPreview: sessionId ? sessionId.substring(0, 10) + '...' : null
          },
          headerRules: {
            count: rules.length,
            rules: rules.map(r => ({
              id: r.id,
              priority: r.priority,
              headers: r.action.requestHeaders?.map(h => h.header) || [],
              domains: r.condition.requestDomains || []
            }))
          },
          config: currentConfig
        };
        console.log('[ZTProxy] 🔍 DIAGNOSTIC AUTH STATE:', JSON.stringify(state, null, 2));
        sendResponse(state);
      });
    });
    return true;
  }
  
  if (message && message.type === 'GET_HEALTH') {
    // Return current health state and edition info to popup
    chrome.storage.local.get(['ztProxyEdition'], (result) => {
      const edition = result.ztProxyEdition || PROXY_EDITION || 'enterprise';
      sendResponse({ 
        isHealthy: health.lastStatusOkAt && (Date.now() - health.lastStatusOkAt < 120000),
        pacDisabled: health.pacDisabled,
        downSince: health.downSince,
        edition: edition,
        isStandalone: edition === 'standalone',
        isEnterprise: edition === 'enterprise'
      });
    });
    return true;
  }
  
  // Add diagnostic command for Edge troubleshooting
  if (message && message.type === 'CHECK_PROXY_STATUS') {
    chrome.proxy.settings.get({incognito:false}, (config) => {
      console.log(`[ZTProxy ${browserName}] DIAGNOSTIC - Proxy status check:`, JSON.stringify(config, null, 2));
      sendResponse({ 
        config: config,
        browser: browserName,
        apiAvailable: !!(chrome && chrome.proxy && chrome.proxy.settings)
      });
    });
    return true;
  }
  
  if (message && message.type === 'RETRY_PROXY') {
    // Reset health state and retry setup
    health.downSince = null;
    health.pacDisabled = false;
    checkProxyHealth().then(() => {
      if (!health.pacDisabled) {
        setupProxyFromStorage();
      }
    });
    sendResponse({ ok: true });
    return true;
  }
  if (message && message.type === 'ZT_GET_PROXY_BASE') {
    try {
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      sendResponse({ base });
    } catch (_) { sendResponse({ base: '' }); }
    return true;
  }
  if (message && message.action === 'enableProxy') {
    // Re-run setup using server-managed routing (/routing)
    // Force cache bust to immediately apply new domains
    setupProxyFromStorage(true);
    sendResponse && sendResponse({ ok: true });
    return true;
  }
  if (message && message.action === 'ztAuthCode') {
    // Block in standalone mode
    if (IS_STANDALONE) {
      console.log('[ZTProxy] Standalone mode - ignoring auth code');
      sendResponse && sendResponse({ ok: false, error: 'Authentication not available in standalone mode' });
      return true;
    }
    
    // Received code from auth-complete.html; proceed with exchange
    performCodeExchange(message.code).then(()=>{
      sendResponse && sendResponse({ ok: true });
    }).catch(e=>{
      console.error('ZTProxy SSO exchange failed', e);
      sendResponse && sendResponse({ ok: false, error: String(e) });
    });
    return true;
  }
  if (message && message.action === 'ztStartSso') {
    startSsoLoginFlow().then(r=> sendResponse && sendResponse(r)).catch(e=>{
      sendResponse && sendResponse({ ok:false, error:String(e) });
    });
    return true;
  }
  if (message && message.action === 'ztGetAuth') {
    sendResponse && sendResponse({ auth: ssoAuth || null });
    return true;
  }
  if (message && message.action === 'ztClearAuth') {
    // Clear stale auth state (called when proxy session is expired)
    console.log('[ZTProxy Background] Clearing stale auth state');
    ssoAuth = null;
    sendResponse && sendResponse({ ok: true });
    return true;
  }
  if (message && message.action === 'ztUpdateSessionHeaders') {
    // Update header injection rules with current ignore token count from storage
    updateSessionHeaderRule().then(() => {
      console.log('[ZTProxy Background] Updated header rules after ignore token change');
      sendResponse && sendResponse({ ok: true });
    }).catch(err => {
      console.error('[ZTProxy Background] Failed to update header rules:', err);
      sendResponse && sendResponse({ ok: false, error: err.message });
    });
    return true; // Keep message channel open for async response
  }
  if (message && message.action === 'ztLogout') {
    // Block in standalone mode (nothing to logout from)
    if (IS_STANDALONE) {
      console.log('[ZTProxy] Standalone mode - ignoring logout request');
      sendResponse && sendResponse({ ok: true });
      return true;
    }
    
    performLogout().then(r=> sendResponse && sendResponse(r)).catch(e=>{
      sendResponse && sendResponse({ ok:false, error:String(e) });
    });
    return true;
  }
  if (message && message.action === 'ztLoginWithEmail') {
    // Block in standalone mode
    if (IS_STANDALONE) {
      console.log('[ZTProxy] Standalone mode - ignoring email login');
      sendResponse && sendResponse({ ok: false, error: 'Authentication not available in standalone mode' });
      return true;
    }
    
    performEmailLogin(message.email, message.password).then(r=> sendResponse && sendResponse(r)).catch(e=>{
      sendResponse && sendResponse({ ok:false, error:String(e) });
    });
    return true;
  }
});

function sendConfigToZTProxy(config) {
  // Try to send configuration to ZTProxy via HTTP/HTTPS (depending on remote vs local)
  const base = getProxyBaseUrl(currentConfig.host, currentConfig.port);
  const configUrl = `${base}/config`;
  
  fetch(configUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(config)
  })
  .then(response => {
    if (response.ok) {
      console.log('ZTProxy: Configuration sent successfully');
  } else {
      console.log('ZTProxy: Configuration endpoint not available (proxy not reachable or refused)');
    }
  })
  .catch(error => {
    console.log('ZTProxy: Configuration endpoint not available (proxy not reachable)');
  });
}

async function setupProxyFromStorage(bustCache = false) {
  chrome.storage.sync.get(['proxyHost', 'proxyPort', 'requestFilter', 'enforcementMode'], async (result) => {
    const host = result.proxyHost || 'localhost';
    const port = result.proxyPort || '8081';
    const filter = result.requestFilter || 'post-chat-pii';
    const enforcement = result.enforcementMode || 'block';
    
    currentConfig = { host, port, filter, enforcement };
    
    console.log(`[ZTProxy ${browserName}] Configuring proxy with ${host}:${port} (${filter}; ${enforcement})${bustCache ? ' [CACHE BUST]' : ''}`);
    
    // Layer 1: Preemptive health check BEFORE setting PAC (recommended approach)
    console.log(`[ZTProxy ${browserName}] Checking proxy health before enabling PAC...`);
    const isHealthy = await checkProxyHealth();
    
    if (!isHealthy && !health.failSafeActive) {
      console.warn(`[ZTProxy ${browserName}] Proxy unhealthy - not enabling PAC, staying in DIRECT mode`);
      updateProxyIcon('disconnected');
      chrome.action.setBadgeText({ text: '✕' });
      chrome.action.setBadgeBackgroundColor({ color: '#DC2626' }); // Red
      return;
    }
    
    // Proxy is healthy or we're recovering from fail-safe - proceed to set PAC
    console.log(`[ZTProxy ${browserName}] Proxy healthy - enabling PAC`);
    
    // Test PAC file accessibility (especially important for Edge)
    console.log(`[ZTProxy ${browserName}] Testing PAC file accessibility...`);
    const pacAccessible = await testPacAccessibility(host, port);
    
    if (!pacAccessible && host !== 'localhost' && host !== '127.0.0.1' && host !== '0.0.0.0') {
      console.warn(`[ZTProxy ${browserName}] ⚠ PAC file pre-check failed for remote host ${host}`);
      console.warn(`[ZTProxy ${browserName}] Continuing anyway - Chrome may still be able to access it`);
      // Continue anyway - Chrome's PAC loader might succeed even if our fetch failed
    }
    
    // Apply URL PAC directly (domains served by /pac)
    const proxyConfig = createUrlPacConfig(host, port, bustCache);
    const protocol = (port === '443' || port === 443) ? 'https' : 'http';
    const portSuffix = (port === '443' || port === 443) ? '' : ':' + port;
    console.log(`[ZTProxy ${browserName}] Applying dynamic PAC URL ${protocol}://${host}${portSuffix}/pac`);
    
    if (chrome.proxy && chrome.proxy.settings) {
      // Edge-specific: Try with additional error handling and verification
      try {
        console.log(`[ZTProxy ${browserName}] Attempting to set proxy...`, proxyConfig);
        
        await new Promise((resolve, reject) => {
          chrome.proxy.settings.set({ value: proxyConfig, scope: 'regular' }, () => {
            if (chrome.runtime.lastError) {
              console.error(`[ZTProxy ${browserName}] Setup ERROR:`, chrome.runtime.lastError);
              reject(chrome.runtime.lastError);
            } else {
              console.log(`[ZTProxy ${browserName}] PAC proxy set command completed for ${host}:${port}`);
              resolve();
            }
          });
        });
        
        // Wait a moment for Edge to apply the setting
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Verify the setting was applied (especially important for Edge)
        chrome.proxy.settings.get({incognito:false}, (config) => {
          console.log(`[ZTProxy ${browserName}] Verification - Current proxy settings:`, JSON.stringify(config, null, 2));
          
          if (config && config.value && config.value.mode === 'pac_script') {
            console.log(`[ZTProxy ${browserName}] ✓ PAC configuration verified successfully`);
            console.log(`[ZTProxy ${browserName}] PAC URL: ${config.value.pacScript?.url}`);
            console.log(`[ZTProxy ${browserName}] Level of control: ${config.levelOfControl}`);
            updateProxyIcon('active');
            chrome.action.setBadgeText({ text: '✓' });
            chrome.action.setBadgeBackgroundColor({ color: '#10B981' }); // Green
          } else {
            console.warn(`[ZTProxy ${browserName}] ⚠️ PAC NOT active after setting! Current mode:`, config?.value?.mode);
            console.warn(`[ZTProxy ${browserName}] Level of control:`, config?.levelOfControl);
            
            // In Edge, sometimes need to clear first then set
            if (isEdge) {
              console.log(`[ZTProxy ${browserName}] Edge detected - attempting clear and re-set...`);
              chrome.proxy.settings.clear({ scope: 'regular' }, () => {
                console.log(`[ZTProxy ${browserName}] Cleared proxy, waiting before re-apply...`);
                setTimeout(() => {
                  console.log(`[ZTProxy ${browserName}] Re-applying proxy configuration...`);
                  chrome.proxy.settings.set({ value: proxyConfig, scope: 'regular' }, () => {
                    if (!chrome.runtime.lastError) {
                      console.log(`[ZTProxy ${browserName}] Edge: PAC re-applied`);
                      
                      // Verify again
                      setTimeout(() => {
                        chrome.proxy.settings.get({incognito:false}, (finalConfig) => {
                          console.log(`[ZTProxy ${browserName}] Final verification:`, JSON.stringify(finalConfig, null, 2));
                          if (finalConfig && finalConfig.value && finalConfig.value.mode === 'pac_script') {
                            console.log(`[ZTProxy ${browserName}] ✓ Edge: PAC verified after retry`);
                            updateProxyIcon('active');
                            chrome.action.setBadgeText({ text: '✓' });
                            chrome.action.setBadgeBackgroundColor({ color: '#10B981' });
                          } else {
                            console.error(`[ZTProxy ${browserName}] ✗ Edge: PAC still not active after retry!`);
                            console.error(`[ZTProxy ${browserName}] This may indicate Edge policy restrictions or permissions issue`);
                          }
                        });
                      }, 1000);
                    } else {
                      console.error(`[ZTProxy ${browserName}] Edge re-set failed:`, chrome.runtime.lastError);
                    }
                  });
                }, 1000);
              });
            }
          }
        });
      } catch (error) {
        console.error(`[ZTProxy ${browserName}] Failed to set proxy:`, error);
        updateProxyIcon('disconnected');
      }
    } else {
      console.error(`[ZTProxy ${browserName}] ⚠️ Proxy API not available!`);
      console.error(`[ZTProxy ${browserName}] chrome.proxy exists:`, !!(chrome && chrome.proxy));
      console.error(`[ZTProxy ${browserName}] chrome.proxy.settings exists:`, !!(chrome && chrome.proxy && chrome.proxy.settings));
    }
    
    // Fetch routing domains for error detection
    await fetchRoutingDomains();
    
    // Optional: prime routing fetch for logging insight
    const routingUrl = getProxyBaseUrl(host, port) + '/routing';
    const routingHeaders = { 'Accept': 'application/json' };
    if (ssoAuth && ssoAuth.authToken) {
      routingHeaders['X-ZT-Auth'] = `Bearer ${ssoAuth.authToken}`;
    }
    fetch(routingUrl, { headers: routingHeaders })
      .then(r => r.ok ? r.json() : null)
      .then(j => { 
        if (j && j.domains) {
          console.log(`[ZTProxy ${browserName}] /routing domains count`, j.domains.length);
        }
      })
      .catch(e => {
        console.warn(`[ZTProxy ${browserName}] Failed to fetch routing:`, e);
      });
  });
}

async function startSsoLoginFlow(){
  // Disable SSO in standalone mode
  if (IS_STANDALONE) {
    console.log('[ZTProxy] Standalone mode - SSO authentication not available');
    return { ok: false, error: 'SSO authentication not available in standalone mode' };
  }
  
  const APP_BASE = 'https://dev-identity.zerotrusted.ai';
  const redirectUri = chrome.identity.getRedirectURL('auth-complete.html');
  const loginUrl = `${APP_BASE}/External/ExtenstionAzureLogin?returnUrl=${encodeURIComponent(redirectUri)}`;
  
  console.log('ZTProxy: Starting SSO login flow', { loginUrl, redirectUri });
  
  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow({ url: loginUrl, interactive: true }, (finalUrl) => {
      if (chrome.runtime.lastError) {
        const errorMsg = chrome.runtime.lastError.message || String(chrome.runtime.lastError);
        console.error('ZTProxy: Auth flow error:', errorMsg);
        console.error('ZTProxy: Error details:', JSON.stringify(chrome.runtime.lastError, null, 2));
        return reject(new Error(errorMsg));
      }
      if (!finalUrl) {
        console.error('ZTProxy: No finalUrl from auth flow');
        return reject(new Error('No finalUrl from auth flow'));
      }
      
      console.log('ZTProxy: Auth flow completed', { finalUrl: finalUrl.substring(0, 100) + '...' });
      
      // Parse both query params and hash params (server may use either)
      const url = new URL(finalUrl);
      const queryParams = new URLSearchParams(url.search.slice(1));
      const hashParams = new URLSearchParams(url.hash.slice(1));
      
      const getParam = (key) => queryParams.get(key) || hashParams.get(key);
      
      // Check for direct access_token (working sample pattern)
      const accessToken = getParam('access_token');
      if (accessToken) {
        console.log('ZTProxy: Found access_token directly in redirect');
        handleDirectToken(accessToken, finalUrl).then(() => resolve({ ok: true })).catch(reject);
        return;
      }
      
      // Fallback: Check for authorization code (OAuth2 code flow)
      const code = getParam('code');
      if (code) {
        console.log('ZTProxy: Found authorization code, exchanging...');
        performCodeExchange(code).then(() => resolve({ ok: true })).catch(reject);
        return;
      }
      
      // No token or code found
      console.error('ZTProxy: Missing both access_token and code in redirect');
      reject(new Error('Missing access_token or code in redirect URL'));
    });
  });
}

// Handle direct access_token return (implicit flow / simplified flow)
async function handleDirectToken(accessToken, finalUrl){
  console.log('ZTProxy: Processing direct access_token');
  
  // Parse URL for additional data
  const url = new URL(finalUrl);
  const queryParams = new URLSearchParams(url.search.slice(1));
  const hashParams = new URLSearchParams(url.hash.slice(1));
  const getParam = (key) => queryParams.get(key) || hashParams.get(key);
  
  // Try to decode JWT to extract user info
  let email = null;
  let tid = null;
  
  try {
    const parts = accessToken.split('.');
    if (parts.length >= 2) {
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      email = payload.email || payload.upn || payload.preferred_username || payload.unique_name || null;
      tid = payload.tid || payload.tenant_id || null;
      console.log('ZTProxy: Decoded JWT', { email: email ? '***' : null, tid: tid ? '***' : null });
    }
  } catch(e) {
    console.warn('ZTProxy: Could not decode JWT', e);
  }
  
  // Fallback: check URL params for email/user info
  if (!email) {
    email = getParam('email') || getParam('user') || getParam('upn') || getParam('UserPrincipalName') || '';
  }
  if (!tid) {
    tid = getParam('tid') || getParam('tenantId') || getParam('tenant_id') || '';
  }
  
  // Store auth data
  const authData = {
    accessToken,
    token: accessToken, // Alias for compatibility
    authToken: accessToken, // JWT token for proxy authentication
    email,
    tid,
    acquiredAt: Date.now()
  };
  
  ssoAuth = authData;
  
  try {
    await chrome.storage.local.set({ 
      ztAuth: authData,
      ztSessionId: null // Will be set after session establishment
    });
    console.log('ZTProxy: Auth data saved to storage');
  } catch(e) {
    console.warn('ZTProxy: Failed to save auth to storage', e);
  }
  
  // Establish local proxy session
  try {
    const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
    console.log('ZTProxy: Establishing session with proxy', { base, email: email ? '***' : null, hasAuthToken: !!accessToken });
    
    const response = await fetch(`${base}/sso-establish`, { 
      method: 'POST', 
      headers: { 'Content-Type': 'application/json' }, 
      body: JSON.stringify({ 
        email: email || 'unknown', 
        tid: tid || '',
        auth_token: accessToken || ''  // Send JWT token if available
      }),
      credentials: 'include'
    });
    
    if (response.ok) {
      const result = await response.json();
      sessionId = result.session_id;
      const authMethod = result.auth_method || 'unknown';
      console.log('ZTProxy: Session established', { 
        sessionId: sessionId ? '***' : null, 
        authMethod: authMethod 
      });
      
      // Save session ID to storage
      try {
        await chrome.storage.local.set({ ztSessionId: sessionId });
      } catch(e) {
        console.warn('ZTProxy: Failed to save session ID', e);
      }
      
      // Update declarativeNetRequest rule to inject header
      await updateSessionHeaderRule();
    } else {
      console.error('ZTProxy: Session establishment failed', response.status);
      // Try to get error details
      try {
        const errorData = await response.json();
        console.error('ZTProxy: Session error details', errorData);
      } catch(e) {
        // Ignore JSON parse errors
      }
    }
  } catch(e) {
    console.error('ZTProxy: Local session establish failed', e);
  }
}

async function performLogout() {
  console.log('ZTProxy: Performing logout...');
  
  // Call proxy disconnect endpoint
  try {
    const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
    const response = await fetch(`${base}/disconnect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(sessionId ? { 'X-ZT-Session': sessionId } : {})
      }
    });
    
    if (response.ok) {
      console.log('ZTProxy: Server session cleared');
    } else {
      console.warn('ZTProxy: Disconnect endpoint returned', response.status);
    }
  } catch (e) {
    console.warn('ZTProxy: Could not call disconnect endpoint', e);
  }
  
  // Clear local state
  ssoAuth = null;
  sessionId = null;
  
  // Clear chrome storage
  try {
    await chrome.storage.local.remove(['ztAuth', 'ztSessionId']);
    console.log('ZTProxy: Local storage cleared');
  } catch (e) {
    console.warn('ZTProxy: Failed to clear storage', e);
  }
  
  // Remove session header injection rule
  await updateSessionHeaderRule();
  
  return { ok: true };
}

// Email/Password login via ZTA identity API
async function performEmailLogin(email, password) {
  console.log('ZTProxy: Performing email/password login...');
  
  if (!email || !password) {
    throw new Error('Email and password are required');
  }
  
  try {
    // Call ZTA identity API
    const LOGIN_API = 'https://dev-identity.zerotrusted.ai/external/ztalogin';
    const response = await fetch(LOGIN_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: email,
        password: password
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('ZTProxy: Login API error:', response.status, errorText);
      throw new Error(`Login failed: ${response.status}`);
    }
    
    const result = await response.json();
    console.log('ZTProxy: Login API response:', { success: result.success, hasToken: !!(result.data?.access_token) });
    
    if (!result.success || !result.data?.access_token) {
      throw new Error(result.message || 'Login failed - no access token');
    }
    
    const accessToken = result.data.access_token;
    
    // Decode JWT to extract user info
    let userEmail = email; // Fallback to provided email
    let tid = null;
    
    try {
      const parts = accessToken.split('.');
      if (parts.length >= 2) {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        userEmail = payload.email || payload.upn || payload.preferred_username || payload.unique_name || email;
        tid = payload.tid || payload.tenant_id || null;
        console.log('ZTProxy: Decoded JWT', { email: userEmail ? '***' : null, tid: tid ? '***' : null });
      }
    } catch(e) {
      console.warn('ZTProxy: Could not decode JWT', e);
    }
    
    // Store auth data
    const authData = {
      accessToken,
      token: accessToken,
      authToken: accessToken,
      email: userEmail,
      tid,
      acquiredAt: Date.now()
    };
    
    ssoAuth = authData;
    
    try {
      await chrome.storage.local.set({ 
        ztAuth: authData,
        ztSessionId: null
      });
      console.log('ZTProxy: Auth data saved to storage');
    } catch(e) {
      console.warn('ZTProxy: Failed to save auth to storage', e);
    }
    
    // Establish local proxy session
    try {
      const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
      console.log('ZTProxy: Establishing session with proxy', { base, email: userEmail ? '***' : null, hasAuthToken: !!accessToken });
      
      const sessionResponse = await fetch(`${base}/sso-establish`, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ 
          email: userEmail, 
          tid: tid || '',
          auth_token: accessToken
        }),
        credentials: 'include'
      });
      
      if (sessionResponse.ok) {
        const sessionResult = await sessionResponse.json();
        sessionId = sessionResult.session_id;
        const authMethod = sessionResult.auth_method || 'unknown';
        console.log('ZTProxy: Session established', { 
          sessionId: sessionId ? '***' : null, 
          authMethod: authMethod 
        });
        
        // Save session ID to storage
        try {
          await chrome.storage.local.set({ ztSessionId: sessionId });
        } catch(e) {
          console.warn('ZTProxy: Failed to save session ID', e);
        }
        
        // Update declarativeNetRequest rule to inject header
        await updateSessionHeaderRule();
      } else {
        console.error('ZTProxy: Session establishment failed', sessionResponse.status);
        try {
          const errorData = await sessionResponse.json();
          console.error('ZTProxy: Session error details', errorData);
        } catch(e) {
          // Ignore JSON parse errors
        }
      }
    } catch(e) {
      console.error('ZTProxy: Local session establish failed', e);
    }
    
    return { ok: true };
    
  } catch (error) {
    console.error('ZTProxy: Email/password login failed:', error);
    throw error;
  }
}

async function performCodeExchange(code){
  const APP_BASE = 'https://dev-identity.zerotrusted.ai';
  const resp = await fetch(`${APP_BASE}/api/ext/exchange`, { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ code }) });
  if(!resp.ok) throw new Error(`exchange_failed_${resp.status}`);
  const data = await resp.json();
  ssoAuth = data;
  try { await chrome.storage.local.set({ ztAuth: data }); } catch(_) {}
  // Establish local proxy session
  try {
    const base = getProxyBaseUrl(currentConfig.host || 'localhost', currentConfig.port || '8081');
    // Map expected fields: assume data has email or user principal name
    const email = data.email || data.upn || data.user || data.UserPrincipalName || '';
    const tid = data.tid || data.tenantId || '';
    const authToken = data.authToken || data.accessToken || data.auth_token || '';
    if (email) {
      const response = await fetch(`${base}/sso-establish`, { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ email, tid, auth_token: authToken }), credentials: 'include' });
      if (response.ok) {
        const result = await response.json();
        sessionId = result.session_id; // Store session ID for header injection
        const authMethod = result.auth_method || 'unknown';
        console.log('ZTProxy: Session established', { sessionId: sessionId ? '***' : null, authMethod: authMethod, hasAuthToken: !!authToken });
        
        // Save session ID to storage
        try {
          await chrome.storage.local.set({ ztSessionId: sessionId });
        } catch(e) {
          console.warn('ZTProxy: Failed to save session ID', e);
        }
        
        // Update declarativeNetRequest rule to inject header
        await updateSessionHeaderRule();
      }
    }
  } catch(e) { console.warn('ZTProxy: local session establish failed', e); }
}

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
  console.log('ZTProxy: Extension icon clicked');
  // Check if we're on an AI domain
  // Best-effort check: defer to proxy UI /routing; here we simply indicate on any http(s) page
  const isHttp = tab.url && /^https?:\/\//i.test(tab.url);
  
  if (isHttp) {
    chrome.action.setBadgeText({
      text: "ON",
      tabId: tab.id
    });
    chrome.action.setBadgeBackgroundColor({
      color: "#00FF00",
      tabId: tab.id
    });
  }
});
