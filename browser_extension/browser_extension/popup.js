// Popup script for ZTProxy extension
document.addEventListener('DOMContentLoaded', function() {
  const statusElement = document.getElementById('statusText');
  const statusDiv = document.getElementById('proxyStatus');
  const statusIndicator = document.getElementById('statusIndicator');
  const failsafeWarning = document.getElementById('failsafeWarning');
  const retryProxyBtn = document.getElementById('retryProxy');
  const blocklistStatusEl = document.getElementById('blocklistStatus');
  const connectBtn = document.getElementById('connectSso');
  const disconnectBtn = document.getElementById('disconnectSso');
  const authStatusSpan = document.getElementById('authStatus');
  const enableBtn = document.getElementById('enableProxy');
  const disableBtn = document.getElementById('disableProxy');
  const saveConfigBtn = document.getElementById('saveConfig');
  const testBtn = document.getElementById('testConnection');
  const refreshBtn = document.getElementById('refreshRouting');
  const hostInput = document.getElementById('proxyHost');
  const portInput = document.getElementById('proxyPort');
  const requestFilterSelect = document.getElementById('requestFilter');
  const enforcementSelect = document.getElementById('enforcementMode');
  const currentConfigSpan = document.getElementById('currentConfig');

  // Collapsible sections functionality
  const collapsibles = document.querySelectorAll('.collapsible');
  collapsibles.forEach((collapsible) => {
    collapsible.addEventListener('click', function() {
      this.classList.toggle('active');
      const content = this.nextElementSibling;
      const chevron = this.querySelector('.chevron');
      
      if (content.classList.contains('active')) {
        content.classList.remove('active');
        if (chevron) chevron.classList.remove('open');
      } else {
        content.classList.add('active');
        if (chevron) chevron.classList.add('open');
      }
    });
  });

  // Email login toggle functionality
  const emailLoginToggleBtn = document.getElementById('emailLoginToggle');
  const emailLoginContentDiv = document.getElementById('emailLoginContent');
  console.log('Email login toggle button:', emailLoginToggleBtn);
  console.log('Email login content div:', emailLoginContentDiv);
  if (emailLoginToggleBtn && emailLoginContentDiv) {
    emailLoginToggleBtn.addEventListener('click', function(e) {
      console.log('Email login button clicked');
      e.preventDefault();
      e.stopPropagation();
      if (emailLoginContentDiv.classList.contains('active')) {
        emailLoginContentDiv.classList.remove('active');
        console.log('Collapsed email form');
      } else {
        emailLoginContentDiv.classList.add('active');
        console.log('Expanded email form');
      }
    });
  } else {
    console.error('Email login elements not found!');
  }

  // Filter mode descriptions
  const filterDescriptions = {
    'all': 'Routes all AI traffic through proxy',
    'post-only': 'Only POST requests (faster, less noise)',
    'post-chat': 'Only chat/conversation endpoints',
    'post-chat-pii': 'Chat endpoints with PII detection'
  };

  // Update filter description
  function updateFilterDescription() {
    const filterDesc = document.getElementById('filterDescription');
    if (filterDesc && requestFilterSelect) {
      filterDesc.textContent = filterDescriptions[requestFilterSelect.value] || '';
    }
  }

  // Listen for filter changes
  if (requestFilterSelect) {
    requestFilterSelect.addEventListener('change', updateFilterDescription);
    updateFilterDescription(); // Initial update
  }

  // Check if fail-safe is active (get health state from background)
  // Store edition info globally for use in popup
  let proxyEdition = 'enterprise'; // Default to enterprise
  let isStandaloneMode = false;
  
  chrome.runtime.sendMessage({ type: 'GET_HEALTH' }, (response) => {
    if (response) {
      // Store edition info
      if (response.edition) {
        proxyEdition = response.edition;
        isStandaloneMode = response.isStandalone || false;
        console.log(`[ZTProxy Popup] Proxy edition: ${proxyEdition}`);
      }
      
      // Handle failsafe warning
      if (response.pacDisabled) {
        failsafeWarning.style.display = 'block';
        statusDiv.classList.remove('active');
        statusDiv.classList.add('inactive');
      }
      
      // Hide auth section in standalone mode
      const authSection = document.getElementById('authSection');
      if (isStandaloneMode && authSection) {
        authSection.style.display = 'none';
        console.log('[ZTProxy Popup] Standalone mode - hiding auth section');
      }
    }
  });

  // Retry connection button
  if (retryProxyBtn) {
    retryProxyBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'RETRY_PROXY' }, () => {
        window.close(); // Close popup, user can reopen to see new status
      });
    });
  }

  // Load saved configuration
  chrome.storage.sync.get(['proxyHost', 'proxyPort', 'enforcementMode'], (result) => {
    console.log('ZTProxy Extension: Loaded config from storage:', result);
  const host = result.proxyHost || 'ai-proxy.zerotrusted.ai';
  const port = result.proxyPort || '443';
  const enforcement = result.enforcementMode || 'block';
    
    hostInput.value = host;
    portInput.value = port;
  enforcementSelect.value = enforcement;
  currentConfigSpan.textContent = `${host}:${port} (${enforcement})`;
    
    // Check if localhost and hide auth section accordingly
    toggleAuthSectionBasedOnHost(host);
  });

  // Function to check if host is localhost and toggle auth section
  function toggleAuthSectionBasedOnHost(host) {
    const authSection = document.getElementById('authSection');
    if (!authSection) return;
    
    const isLocalhost = host === 'localhost' || host === '127.0.0.1' || host.startsWith('localhost:') || host.startsWith('127.0.0.1:');
    
    if (isLocalhost) {
      authSection.style.display = 'none';
      console.log('[ZTProxy Popup] Localhost detected - hiding auth section');
    } else {
      authSection.style.display = 'block';
      console.log('[ZTProxy Popup] Remote host detected - showing auth section');
    }
  }

  // Listen for host input changes
  if (hostInput) {
    hostInput.addEventListener('input', function() {
      const host = this.value.trim();
      toggleAuthSectionBasedOnHost(host);
      // Auto-sync port based on host
      if (host === 'ai-proxy.zerotrusted.ai') {
        portInput.value = '443';
      } else if (host === 'localhost') {
        portInput.value = '8080';
      }
    });
    hostInput.addEventListener('change', function() {
      const host = this.value.trim();
      toggleAuthSectionBasedOnHost(host);
      // Auto-sync port based on host
      if (host === 'ai-proxy.zerotrusted.ai') {
        portInput.value = '443';
      } else if (host === 'localhost') {
        portInput.value = '8080';
      }
    });
  }

  // Check current proxy status
  chrome.proxy.settings.get({}, (config) => {
    if (config.value.mode === 'pac_script') {
      statusElement.innerHTML = 'Active - AI traffic routed <span style="color: #dc3545;">(restart browser if needed)</span>';
      statusDiv.className = 'status active';
      if (statusIndicator) {
        statusIndicator.className = 'status-indicator active';
      }
    } else {
      statusElement.textContent = 'Inactive - Direct';
      statusDiv.className = 'status inactive';
      if (statusIndicator) {
        statusIndicator.className = 'status-indicator inactive';
      }
    }
  });

  // Helper function to sanitize host input (remove protocol if present)
  function sanitizeHost(input) {
    let host = input.trim();
    // Remove http:// or https:// prefix if present
    host = host.replace(/^https?:\/\//, '');
    // Remove trailing slash if present
    host = host.replace(/\/$/, '');
    return host || 'localhost';
  }

  // Save configuration
  saveConfigBtn.addEventListener('click', () => {
    const host = sanitizeHost(hostInput.value);
    const port = portInput.value.trim() || '443';
  const enforcement = enforcementSelect.value || 'block';
    
    console.log('ZTProxy Extension: Saving config:', { host, port, enforcement });
    
    chrome.storage.sync.set({
      proxyHost: host,
      proxyPort: port,
      enforcementMode: enforcement
    }, () => {
      if (chrome.runtime.lastError) {
        console.error('ZTProxy Extension: Error saving config:', chrome.runtime.lastError);
        return;
      }
      console.log('ZTProxy Extension: Config saved successfully');
      
      currentConfigSpan.textContent = `${host}:${port} (${enforcement})`;
      statusElement.textContent = 'Configuration saved and applied';
      statusDiv.className = 'status active';
      
      // Create configuration for ZTProxy - always use post-chat-pii mode
      const config = {
        filter_mode: 'post-chat-pii',
        enforcement_mode: enforcement,
        proxy_host: host,
        proxy_port: port,
        include_request_body: true,
        timestamp: new Date().toISOString()
      };
      
      // Notify background script to update configuration and create config file
      chrome.runtime.sendMessage({
        action: 'updateConfig',
  config: { host, port, filter: 'post-chat-pii', enforcement },
        ztproxyConfig: config
      });
    });
  });

  // Test connection
  testBtn.addEventListener('click', () => {
    const host = sanitizeHost(hostInput.value);
    const port = portInput.value.trim() || '8081';
    
    // Use HTTPS for port 443, HTTP otherwise
    const protocol = (port === '443' || port === 443) ? 'https' : 'http';
    const testUrl = `${protocol}://${host}${port === '443' ? '' : ':' + port}`;
    
    statusElement.textContent = 'Testing connection...';
    
    fetch(testUrl)
      .then(() => {
        statusElement.textContent = `Connection successful to ${testUrl}`;
        statusDiv.className = 'status active';
      })
      .catch(() => {
        statusElement.textContent = `Cannot connect to ${testUrl}`;
        statusDiv.className = 'status inactive';
      });
  });

  // Enable proxy with current configuration
  enableBtn.addEventListener('click', () => {
    // Delegate to background to fetch server-managed routing (/routing) and apply PAC
    chrome.runtime.sendMessage({ action: 'enableProxy' }, (resp) => {
      chrome.storage.sync.get(['proxyHost', 'proxyPort'], (result) => {
        const host = result.proxyHost || 'localhost';
        const port = result.proxyPort || '8081';
        if (chrome.runtime.lastError || !resp || resp.ok !== true) {
          statusElement.textContent = 'Error enabling proxy' + (chrome.runtime.lastError ? (': ' + chrome.runtime.lastError.message) : '');
          statusDiv.className = 'status inactive';
        } else {
          statusElement.textContent = `Active - Managed domains -> ${host}:${port}`;
          statusDiv.className = 'status active';
          updateBlocklistStatus();
        }
      });
    });
  });

  // Refresh routing domains (re-fetch /routing and reapply PAC without toggling other settings)
  refreshBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'enableProxy' }, (resp) => {
      chrome.storage.sync.get(['proxyHost', 'proxyPort'], (result) => {
        const host = result.proxyHost || 'localhost';
        const port = result.proxyPort || '8081';
        if (chrome.runtime.lastError || !resp || resp.ok !== true) {
          statusElement.textContent = 'Error refreshing routing' + (chrome.runtime.lastError ? (': ' + chrome.runtime.lastError.message) : '');
          statusDiv.className = 'status inactive';
        } else {
          statusElement.textContent = `Routing refreshed - Managed domains → ${host}:${port}`;
          statusDiv.className = 'status active';
          updateBlocklistStatus();
        }
      });
    });
  });

  // Disable proxy
  disableBtn.addEventListener('click', () => {
    chrome.proxy.settings.set({
      value: { mode: "direct" },
      scope: 'regular'
    }, () => {
      statusElement.textContent = 'Inactive - Direct connections';
      statusDiv.className = 'status inactive';
    });
  });

  // Connect (SSO) button logic
  if (connectBtn) {
    connectBtn.addEventListener('click', () => {
      authStatusSpan.textContent = 'Connecting...';
      chrome.runtime.sendMessage({ action: 'ztStartSso' }, (resp) => {
        if (!resp || resp.ok !== true) {
          authStatusSpan.textContent = 'Failed';
          return;
        }
        // After success, query stored auth
        setTimeout(refreshAuthStatus, 500);
      });
    });
  }

  // Disconnect button logic
  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', () => {
      authStatusSpan.textContent = 'Disconnecting...';
      chrome.runtime.sendMessage({ action: 'ztLogout' }, (resp) => {
        if (!resp || resp.ok !== true) {
          authStatusSpan.textContent = 'Disconnect failed';
          return;
        }
        // After success, refresh status
        setTimeout(refreshAuthStatus, 500);
        
        // Close any open AI service tabs to force full reconnection
        chrome.tabs.query({}, (tabs) => {
          const aiDomains = ['chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com', 'gemini.google.com'];
          tabs.forEach(tab => {
            if (tab.url && aiDomains.some(domain => tab.url.includes(domain))) {
              chrome.tabs.reload(tab.id, { bypassCache: true });
            }
          });
        });
      });
    });
  }

  // Email/Password Login button logic
  const loginEmailInput = document.getElementById('loginEmail');
  const loginPasswordInput = document.getElementById('loginPassword');
  const loginWithEmailBtn = document.getElementById('loginWithEmail');
  const emailLoginStatusEl = document.getElementById('emailLoginStatus');
  
  if (loginWithEmailBtn && loginEmailInput && loginPasswordInput) {
    loginWithEmailBtn.addEventListener('click', () => {
      const email = loginEmailInput.value.trim();
      const password = loginPasswordInput.value.trim();
      
      if (!email || !password) {
        if (emailLoginStatusEl) {
          emailLoginStatusEl.textContent = 'Please enter both email and password';
          emailLoginStatusEl.style.color = '#dc3545';
        }
        return;
      }
      
      if (emailLoginStatusEl) {
        emailLoginStatusEl.textContent = 'Logging in...';
        emailLoginStatusEl.style.color = '#666';
      }
      
      chrome.runtime.sendMessage({ 
        action: 'ztLoginWithEmail', 
        email: email, 
        password: password 
      }, (resp) => {
        if (!resp || resp.ok !== true) {
          if (emailLoginStatusEl) {
            emailLoginStatusEl.textContent = resp?.error || 'Login failed';
            emailLoginStatusEl.style.color = '#dc3545';
          }
          return;
        }
        
        if (emailLoginStatusEl) {
          emailLoginStatusEl.textContent = 'Login successful!';
          emailLoginStatusEl.style.color = '#28a745';
        }
        
        // Clear password field
        loginPasswordInput.value = '';
        
        // After success, refresh auth status
        setTimeout(refreshAuthStatus, 500);
      });
    });
  }

  function refreshAuthStatus(){
    // Skip auth checks in standalone mode
    if (isStandaloneMode) {
      authStatusSpan.textContent = 'Standalone (no auth required)';
      if (connectBtn) connectBtn.style.display = 'none';
      if (disconnectBtn) disconnectBtn.style.display = 'none';
      const emailLoginToggle = document.getElementById('emailLoginToggle');
      const emailLoginContent = document.getElementById('emailLoginContent');
      if (emailLoginToggle) emailLoginToggle.style.display = 'none';
      if (emailLoginContent) emailLoginContent.style.display = 'none';
      console.log('[ZTProxy Popup] Standalone mode - skipping auth checks');
      return;
    }
    
    // Show loading state and hide all buttons
    if (authStatusSpan) {
      authStatusSpan.innerHTML = '<span class="loader"></span>Checking session...';
    }
    if (connectBtn) {
      connectBtn.style.display = 'none';
    }
    if (disconnectBtn) {
      disconnectBtn.style.display = 'none';
    }
    const emailLoginToggleBtn = document.getElementById('emailLoginToggle');
    if (emailLoginToggleBtn) {
      emailLoginToggleBtn.style.display = 'none';
    }
    
    // ALWAYS verify with proxy first to detect expired sessions
    // This prevents showing "authenticated" in extension while proxy has no valid session
    chrome.storage.sync.get(['proxyHost', 'proxyPort'], (cfg) => {
      const host = cfg.proxyHost || 'localhost';
      const port = cfg.proxyPort || '8081';
      const isLocalhost = ['localhost', '127.0.0.1', '0.0.0.0'].includes(host.toLowerCase());
      const protocol = isLocalhost ? 'http' : 'https';
      const portSuffix = (protocol === 'https' && port === '443') || (protocol === 'http' && port === '80') ? '' : ':' + port;
      const base = `${protocol}://${host}${portSuffix}`;
      
      // Get DOM elements for hiding/showing login sections
      const authSection = document.getElementById('authSection');
      const emailLoginToggle = document.getElementById('emailLoginToggle');
      const emailLoginContent = document.getElementById('emailLoginContent');
      
      console.log('[ZTProxy Popup] Checking auth status at:', base + '/auth-status');
      
      // Try to get session ID from storage to send as header (in case cookie isn't working)
      chrome.storage.local.get(['ztSessionId'], (storageResult) => {
        const sessionId = storageResult.ztSessionId;
        console.log('[ZTProxy Popup] Session ID from storage:', sessionId ? sessionId.substring(0, 10) + '...' : 'none');
        
        const headers = { 'Accept': 'application/json' };
        if (sessionId) {
          headers['X-ZT-Session'] = sessionId;
          console.log('[ZTProxy Popup] Adding X-ZT-Session header to auth check');
        }
        
        // Check proxy's /auth-status endpoint to see if there's a valid session
        fetch(base + '/auth-status', { credentials: 'include', headers: headers })
        .then(r => {
          console.log('[ZTProxy Popup] Auth status response:', r.status, r.ok);
          return r.ok ? r.json() : null;
        })
        .then(data => {
          console.log('[ZTProxy Popup] Auth data:', data);
          if (data && data.authenticated && data.email) {
            // Proxy has valid session - this is the source of truth
            authStatusSpan.textContent = data.email;
            if (connectBtn) {
              connectBtn.style.display = 'none';
            }
            if (disconnectBtn) {
              disconnectBtn.style.display = 'inline-block';
            }
            // Hide login sections when authenticated
            const emailLoginToggleBtn = document.getElementById('emailLoginToggle');
            if (emailLoginToggleBtn) {
              emailLoginToggleBtn.style.display = 'none';
            }
            if (emailLoginToggle) emailLoginToggle.style.display = 'none';
            if (emailLoginContent) emailLoginContent.style.display = 'none';
            console.log('[ZTProxy Popup] Proxy session valid:', data.email);
            
            // Sync with background if it doesn't have auth
            chrome.runtime.sendMessage({ action: 'ztGetAuth' }, (resp) => {
              if (!resp || !resp.auth) {
                console.log('[ZTProxy Popup] Background auth missing, but proxy session valid. User should reconnect to sync.');
              }
            });
          } else {
            // No valid session in proxy - clear any stale background state
            authStatusSpan.textContent = 'Not connected';
            if (connectBtn) {
              connectBtn.style.display = 'inline-block';
            }
            if (disconnectBtn) {
              disconnectBtn.style.display = 'none';
            }
            // Show login sections when not authenticated
            const emailLoginToggleBtn = document.getElementById('emailLoginToggle');
            if (emailLoginToggleBtn) {
              emailLoginToggleBtn.style.display = 'block';
            }
            if (emailLoginToggle) emailLoginToggle.style.display = 'block';
            console.log('[ZTProxy Popup] No valid proxy session. User must authenticate.');
            
            // Clear stale background auth if it exists
            chrome.runtime.sendMessage({ action: 'ztGetAuth' }, (resp) => {
              if (resp && resp.auth) {
                console.log('[ZTProxy Popup] Clearing stale background auth state');
                chrome.runtime.sendMessage({ action: 'ztClearAuth' });
              }
            });
          }
        })
        .catch(() => {
          // Proxy not reachable, fall back to background state
          console.log('[ZTProxy Popup] Proxy unreachable, checking background state');
          chrome.runtime.sendMessage({ action: 'ztGetAuth' }, (resp) => {
            if (resp && resp.auth) {
              const email = resp.auth.email || resp.auth.upn || resp.auth.user || 'Connected';
              authStatusSpan.textContent = email + ' (proxy offline)';
              if (connectBtn) {
                connectBtn.style.display = 'none';
              }
              if (disconnectBtn) {
                disconnectBtn.style.display = 'inline-block';
              }
              // Hide login sections if we have auth even if proxy offline
              const emailLoginToggleBtn = document.getElementById('emailLoginToggle');
              if (emailLoginToggleBtn) {
                emailLoginToggleBtn.style.display = 'none';
              }
              if (emailLoginToggle) emailLoginToggle.style.display = 'none';
              if (emailLoginContent) emailLoginContent.style.display = 'none';
            } else {
              authStatusSpan.textContent = 'Not connected';
              if (connectBtn) {
                connectBtn.style.display = 'inline-block';
              }
              if (disconnectBtn) {
                disconnectBtn.style.display = 'none';
              }
              // Show login sections when not authenticated
              const emailLoginToggleBtn = document.getElementById('emailLoginToggle');
              if (emailLoginToggleBtn) {
                emailLoginToggleBtn.style.display = 'block';
              }
              if (emailLoginToggle) emailLoginToggle.style.display = 'block';
            }
          });
        });
      }); // Close chrome.storage.local.get callback
    }); // Close chrome.storage.sync.get callback
  }

  refreshAuthStatus();


});

// Fetch remote features status + merged routing list and update UI element
function updateBlocklistStatus() {
  const blocklistStatusEl = document.getElementById('blocklistStatus');
  if (!blocklistStatusEl) return;
  chrome.storage.sync.get(['proxyHost','proxyPort'], (cfg) => {
    const host = cfg.proxyHost || 'localhost';
    const port = cfg.proxyPort || '8081';
    // Determine protocol: http for localhost/127.0.0.1/0.0.0.0, https for production
    const isLocalhost = ['localhost', '127.0.0.1', '0.0.0.0'].includes(host.toLowerCase());
    const protocol = isLocalhost ? 'http' : 'https';
    const portSuffix = (protocol === 'https' && port === '443') || (protocol === 'http' && port === '80') ? '' : ':' + port;
    const base = `${protocol}://${host}${portSuffix}`;
    blocklistStatusEl.textContent = 'Remote Blocklist: querying...';

    const featuresUrl = base + '/features-status';
    const routingUrl = base + '/routing';

    // Get auth token from storage to include in requests
    chrome.storage.local.get(['ztAuth'], (authResult) => {
      const headers = { 'Accept': 'application/json' };
      if (authResult.ztAuth && authResult.ztAuth.authToken) {
        headers['X-ZT-Auth'] = `Bearer ${authResult.ztAuth.authToken}`;
      }

      Promise.all([
        fetch(featuresUrl, { headers }).then(r => r.ok ? r.json() : null).catch(()=>null),
        fetch(routingUrl, { headers }).then(r => r.ok ? r.json() : null).catch(()=>null)
      ]).then(([features, routing]) => {
      let remoteStr = 'disabled';
      if (features && !features.error && typeof features.black_count === 'number') {
        const age = (typeof features.age_seconds === 'number') ? `${Math.round(features.age_seconds)}s` : 'n/a';
        remoteStr = `${features.black_count} black / ${features.white_count || 0} white (age ${age})`;
      } else if (features && features.error === 'missing_api_key') {
        remoteStr = 'no API key';
      } else if (features && features.error) {
        remoteStr = `error (${features.error})`;
      }
      const mergedCount = (routing && Array.isArray(routing.domains)) ? routing.domains.length : 0;
      const remoteEnabled = features && !features.error && typeof features.black_count === 'number';
      const mergedNote = routing ? (routing.remote ? 'baseline+remote' : 'baseline-only') : 'n/a';
      blocklistStatusEl.textContent = `Remote Blocklist: ${remoteStr} | Routed Domains: ${mergedCount} (${mergedNote})`;
      }).catch(() => {
        blocklistStatusEl.textContent = 'Remote Blocklist: error (fetch failed)';
      });
    });
  });
}

// Initial status update after popup load (small delay to allow proxy settings read)
setTimeout(updateBlocklistStatus, 250);
