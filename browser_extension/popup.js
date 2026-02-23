// Popup script for ZTProxy extension
// (Restored from browser_extension_previous)
document.addEventListener('DOMContentLoaded', function () {
  // Show install warning if just installed (simple heuristic: first popup open)
  const installWarning = document.getElementById('installWarning');
  const restartBrowserBtn = document.getElementById('restartBrowserBtn');
  if (installWarning && restartBrowserBtn) {
    chrome.storage.local.get(['ztInstallWarned'], (result) => {
      if (!result.ztInstallWarned) {
        installWarning.style.display = 'flex';
        chrome.storage.local.set({ ztInstallWarned: true });
      }
    });
    restartBrowserBtn.addEventListener('click', () => {
      alert('Please close and reopen your browser to complete the extension installation.\n\nAutomatic restart is not supported by Chrome.');
    });
  }

  // ── DOM refs ──────────────────────────────────────────────────
  const statusElement      = document.getElementById('statusText');
  const statusDiv          = document.getElementById('proxyStatus');
  const statusIndicator    = document.getElementById('statusIndicator');
  const failsafeWarning    = document.getElementById('failsafeWarning');
  const retryProxyBtn      = document.getElementById('retryProxy');
  const blocklistStatusEl  = document.getElementById('blocklistStatus');
  const connectBtn         = document.getElementById('connectSso');
  const disconnectBtn      = document.getElementById('disconnectSso');
  const authStatusSpan     = document.getElementById('authStatus');
  const authDivider        = document.getElementById('authDivider');
  const enableBtn          = document.getElementById('enableProxy');
  const disableBtn         = document.getElementById('disableProxy');
  const saveConfigBtn      = document.getElementById('saveConfig');
  const testBtn            = document.getElementById('testConnection');
  const refreshBtn         = document.getElementById('refreshRouting');
  const hostSelectWrap     = document.getElementById('hostSelectWrap');
  const hostSelect         = document.getElementById('proxyHostSelect');
  const hostText           = document.getElementById('proxyHostText');
  const portInput          = document.getElementById('proxyPort');
  const enforcementSelect  = document.getElementById('enforcementMode');
  const currentConfigSpan  = document.getElementById('currentConfig');
  const emailLoginToggle   = document.getElementById('emailLoginToggle');
  const emailLoginContent  = document.getElementById('emailLoginContent');
  const loginEmailInput    = document.getElementById('loginEmail');
  const loginPasswordInput = document.getElementById('loginPassword');
  const loginWithEmailBtn  = document.getElementById('loginWithEmail');
  const emailLoginStatusEl = document.getElementById('emailLoginStatus');
  const hostModeDropdown   = document.getElementById('hostModeDropdown');
  const hostModeText       = document.getElementById('hostModeText');

  let isStandaloneMode = false;

  // ── Helper: get active host value ────────────────────────────
  function getHostValue() {
    if (hostText.style.display !== 'none') {
      return hostText.value.trim();
    }
    return hostSelect.value;
  }

  function autoSetPort(host) {
    if (host === 'ai-proxy.zerotrusted.ai') {
      portInput.value = '443';
    } else if (host === 'localhost' || host === '127.0.0.1') {
      portInput.value = '8080';
    }
  }

  hostModeDropdown.addEventListener('click', function () {
    hostModeDropdown.classList.add('active');
    hostModeText.classList.remove('active');
    hostSelectWrap.style.display = '';
    hostText.style.display = 'none';
    autoSetPort(hostSelect.value);
    toggleAuthSectionBasedOnHost(hostSelect.value);
  });

  hostModeText.addEventListener('click', function () {
    hostModeText.classList.add('active');
    hostModeDropdown.classList.remove('active');
    hostSelectWrap.style.display = 'none';
    hostText.style.display = '';
    hostText.focus();
  });

  hostSelect.addEventListener('change', function () {
    autoSetPort(this.value);
    toggleAuthSectionBasedOnHost(this.value);
  });

  hostText.addEventListener('input', function () {
    autoSetPort(this.value.trim());
    toggleAuthSectionBasedOnHost(this.value.trim());
  });

  function toggleAuthSectionBasedOnHost(host) {
    const authSection = document.getElementById('authSection');
    if (!authSection) return;
    const isLocal = host === 'localhost' || host === '127.0.0.1'
      || host.startsWith('localhost:') || host.startsWith('127.0.0.1:');
    authSection.style.display = isLocal ? 'none' : '';
  }

  [
    { toggle: 'authToggle',   body: 'authBody',   chevron: 'authChevron'   },
    { toggle: 'configToggle', body: 'configBody', chevron: 'configChevron' },
    { toggle: 'toolsToggle',  body: 'toolsBody',  chevron: 'toolsChevron'  },
  ].forEach(({ toggle, body, chevron }) => {
    const btn = document.getElementById(toggle);
    const bd  = document.getElementById(body);
    const ch  = document.getElementById(chevron);
    if (!btn || !bd) return;
    btn.addEventListener('click', () => {
      const open = bd.classList.toggle('open');
      if (ch) ch.classList.toggle('open', open);
    });
  });

  if (emailLoginToggle && emailLoginContent) {
    emailLoginToggle.addEventListener('click', function () {
      emailLoginContent.classList.add('open');
      emailLoginToggle.style.display = 'none';
    });
  }

  const closeEmailFormBtn = document.getElementById('closeEmailForm');
  if (closeEmailFormBtn) {
    closeEmailFormBtn.addEventListener('click', function () {
      if (emailLoginContent) emailLoginContent.classList.remove('open');
      if (emailLoginToggle)  emailLoginToggle.style.display = 'block';
      if (emailLoginStatusEl) emailLoginStatusEl.textContent = '';
    });
  }

  chrome.runtime.sendMessage({ type: 'GET_HEALTH' }, (response) => {
    if (!response) return;
    if (response.edition) {
      isStandaloneMode = response.isStandalone || false;
    }
    if (response.pacDisabled) {
      failsafeWarning.classList.add('visible');
      statusDiv.className = 'status-bar warning';
    }
    if (isStandaloneMode) {
      const authSection = document.getElementById('authSection');
      if (authSection) authSection.style.display = 'none';
    }
  });

  if (retryProxyBtn) {
    retryProxyBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'RETRY_PROXY' }, () => window.close());
    });
  }

  chrome.storage.sync.get(['proxyHost', 'proxyPort', 'enforcementMode', 'proxyHostMode'], (result) => {
    const host        = result.proxyHost       || 'ai-proxy.zerotrusted.ai';
    const port        = result.proxyPort       || '443';
    const enforcement = result.enforcementMode || 'block';
    const hostMode    = result.proxyHostMode   || 'dropdown';

    portInput.value         = port;
    enforcementSelect.value = enforcement;
    currentConfigSpan.textContent = `${host}:${port} (${enforcement})`;

    if (hostMode === 'text') {
      hostModeText.click();
      hostText.value = host;
    } else {
      const option = hostSelect.querySelector(`option[value="${host}"]`);
      if (option) {
        hostSelect.value = host;
      } else {
        hostModeText.click();
        hostText.value = host;
      }
    }

    toggleAuthSectionBasedOnHost(host);
  });

  chrome.proxy.settings.get({}, (config) => {
    if (config.value.mode === 'pac_script') {
      statusElement.textContent = 'Active — AI traffic is being routed through proxy';
      statusDiv.className = 'status-bar active';
      if (statusIndicator) statusIndicator.classList.add('active');
    } else {
      statusElement.textContent = 'Inactive — Using direct connections';
      statusDiv.className = 'status-bar inactive';
      if (statusIndicator) statusIndicator.classList.remove('active');
    }
  });

  function sanitizeHost(input) {
    return (input || '').trim()
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '') || 'localhost';
  }

  saveConfigBtn.addEventListener('click', () => {
    const host        = sanitizeHost(getHostValue());
    const port        = portInput.value.trim() || '443';
    const enforcement = enforcementSelect.value || 'block';
    const hostMode    = (hostText.style.display !== 'none') ? 'text' : 'dropdown';

    chrome.storage.sync.set({ proxyHost: host, proxyPort: port, enforcementMode: enforcement, proxyHostMode: hostMode }, () => {
      if (chrome.runtime.lastError) return;

      currentConfigSpan.textContent = `${host}:${port} (${enforcement})`;
      statusElement.textContent = 'Configuration saved successfully ✓';
      statusDiv.className = 'status-bar active';

      const ztproxyConfig = {
        filter_mode: 'post-chat-pii',
        enforcement_mode: enforcement,
        proxy_host: host,
        proxy_port: port,
        include_request_body: true,
        timestamp: new Date().toISOString()
      };

      chrome.runtime.sendMessage({
        action: 'updateConfig',
        config: { host, port, filter: 'post-chat-pii', enforcement },
        ztproxyConfig
      });
    });
  });

  testBtn.addEventListener('click', () => {
    const host     = sanitizeHost(getHostValue());
    const port     = portInput.value.trim() || '8081';
    const protocol = (port === '443') ? 'https' : 'http';
    const testUrl  = `${protocol}://${host}${port === '443' ? '' : ':' + port}`;

    statusElement.textContent = 'Testing connection…';

    fetch(testUrl)
      .then(() => {
        statusElement.textContent = `Connection successful → ${testUrl}`;
        statusDiv.className = 'status-bar active';
      })
      .catch(() => {
        statusElement.textContent = `Unable to connect to ${testUrl}`;
        statusDiv.className = 'status-bar inactive';
      });
  });

  enableBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'enableProxy' }, (resp) => {
      chrome.storage.sync.get(['proxyHost', 'proxyPort'], (result) => {
        const host = result.proxyHost || 'localhost';
        const port = result.proxyPort || '8081';
        if (chrome.runtime.lastError || !resp || resp.ok !== true) {
          statusElement.textContent = 'Error enabling proxy' + (chrome.runtime.lastError ? ': ' + chrome.runtime.lastError.message : '');
          statusDiv.className = 'status-bar inactive';
          if (statusIndicator) statusIndicator.classList.remove('active');
        } else {
          statusElement.textContent = `Active — Managed domains → ${host}:${port}`;
          statusDiv.className = 'status-bar active';
          if (statusIndicator) statusIndicator.classList.add('active');
          updateBlocklistStatus();
        }
      });
    });
  });

  refreshBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'enableProxy' }, (resp) => {
      chrome.storage.sync.get(['proxyHost', 'proxyPort'], (result) => {
        const host = result.proxyHost || 'localhost';
        const port = result.proxyPort || '8081';
        if (chrome.runtime.lastError || !resp || resp.ok !== true) {
          statusElement.textContent = 'Error refreshing routing';
          statusDiv.className = 'status-bar inactive';
        } else {
          statusElement.textContent = `Routing refreshed → ${host}:${port}`;
          statusDiv.className = 'status-bar active';
          updateBlocklistStatus();
        }
      });
    });
  });

  disableBtn.addEventListener('click', () => {
    chrome.proxy.settings.set({ value: { mode: 'direct' }, scope: 'regular' }, () => {
      statusElement.textContent = 'Inactive — Using direct connections';
      statusDiv.className = 'status-bar inactive';
      if (statusIndicator) statusIndicator.classList.remove('active');
    });
  });

  if (connectBtn) {
    connectBtn.addEventListener('click', () => {
      authStatusSpan.innerHTML = '<span class="loader"></span>&nbsp;Connecting via Microsoft…';
      chrome.runtime.sendMessage({ action: 'ztStartSso' }, (resp) => {
        if (!resp || resp.ok !== true) {
          authStatusSpan.textContent = 'SSO connection failed';
          return;
        }
        setTimeout(refreshAuthStatus, 500);
      });
    });
  }

  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', () => {
      authStatusSpan.innerHTML = '<span class="loader"></span>&nbsp;Disconnecting…';
      chrome.runtime.sendMessage({ action: 'ztLogout' }, (resp) => {
        if (!resp || resp.ok !== true) {
          authStatusSpan.textContent = 'Disconnect failed';
          return;
        }
        setTimeout(refreshAuthStatus, 500);
        chrome.tabs.query({}, (tabs) => {
          const aiDomains = ['chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com', 'gemini.google.com'];
          tabs.forEach(tab => {
            if (tab.url && aiDomains.some(d => tab.url.includes(d))) {
              chrome.tabs.reload(tab.id, { bypassCache: true });
            }
          });
        });
      });
    });
  }

  if (loginWithEmailBtn) {
    loginWithEmailBtn.addEventListener('click', () => {
      const email    = (loginEmailInput.value || '').trim();
      const password = (loginPasswordInput.value || '').trim();

      if (!email || !password) {
        emailLoginStatusEl.textContent = '⚠ Please enter both email and password.';
        emailLoginStatusEl.style.color = '#dc2626';
        return;
      }

      emailLoginStatusEl.innerHTML = '<span class="loader"></span>&nbsp;Signing in…';
      emailLoginStatusEl.style.color = '#94a3b8';

      chrome.runtime.sendMessage({ action: 'ztLoginWithEmail', email, password }, (resp) => {
        if (!resp || resp.ok !== true) {
          emailLoginStatusEl.textContent = '✗ ' + (resp?.error || 'Login failed. Please try again.');
          emailLoginStatusEl.style.color = '#dc2626';
          return;
        }
        emailLoginStatusEl.textContent = '✓ Signed in successfully!';
        emailLoginStatusEl.style.color = '#16a34a';
        loginPasswordInput.value = '';
        setTimeout(refreshAuthStatus, 500);
      });
    });
  }

  function refreshAuthStatus() {
    if (isStandaloneMode) {
      authStatusSpan.textContent = 'Standalone — no authentication required';
      if (connectBtn)       connectBtn.style.display       = 'none';
      if (disconnectBtn)    disconnectBtn.style.display    = 'none';
      if (emailLoginToggle) emailLoginToggle.style.display = 'none';
      if (authDivider)      authDivider.style.display      = 'none';
      return;
    }

    authStatusSpan.innerHTML = '<span class="loader"></span>&nbsp;Checking session…';
    if (connectBtn)       connectBtn.style.display       = 'none';
    if (disconnectBtn)    disconnectBtn.style.display    = 'none';
    if (emailLoginToggle) emailLoginToggle.style.display = 'none';
    if (authDivider)      authDivider.style.display      = 'none';

    chrome.storage.sync.get(['proxyHost', 'proxyPort'], (cfg) => {
      const host      = cfg.proxyHost || 'localhost';
      const port      = cfg.proxyPort || '8081';
      const isLocal   = ['localhost', '127.0.0.1', '0.0.0.0'].includes(host.toLowerCase());
      const protocol  = isLocal ? 'http' : 'https';
      const portSuffix = (protocol === 'https' && port === '443') || (protocol === 'http' && port === '80') ? '' : ':' + port;
      const base      = `${protocol}://${host}${portSuffix}`;

      chrome.storage.local.get(['ztSessionId'], (storageResult) => {
        const sessionId = storageResult.ztSessionId;
        const headers   = { 'Accept': 'application/json' };
        if (sessionId) headers['X-ZT-Session'] = sessionId;

        fetch(base + '/auth-status', { credentials: 'include', headers })
          .then(r => r.ok ? r.json() : null)
          .then(data => {
            if (data && data.authenticated && data.email) {
              setAuthenticatedUI(data.email);
            } else {
              setUnauthenticatedUI();
              chrome.runtime.sendMessage({ action: 'ztGetAuth' }, (resp) => {
                if (resp && resp.auth) chrome.runtime.sendMessage({ action: 'ztClearAuth' });
              });
            }
          })
          .catch(() => {
            chrome.runtime.sendMessage({ action: 'ztGetAuth' }, (resp) => {
              if (resp && resp.auth) {
                const email = resp.auth.email || resp.auth.upn || resp.auth.user || 'Connected';
                setAuthenticatedUI(email + ' (proxy offline)');
              } else {
                setUnauthenticatedUI();
              }
            });
          });
      });
    });
  }

  function setAuthenticatedUI(email) {
    authStatusSpan.innerHTML =
      `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#16a34a;margin-right:5px;flex-shrink:0;box-shadow:0 0 0 2px #bbf7d0;"></span>${email}`;
    if (connectBtn)        connectBtn.style.display        = 'none';
    if (disconnectBtn)     disconnectBtn.style.display     = 'inline-flex';
    if (emailLoginToggle)  emailLoginToggle.style.display  = 'none';
    if (emailLoginContent) emailLoginContent.classList.remove('open');
    if (authDivider)       authDivider.style.display       = 'none';
  }

  function setUnauthenticatedUI() {
    authStatusSpan.innerHTML = '<span style="color:#94a3b8;">Not signed in</span>';
    if (connectBtn)        connectBtn.style.display        = 'block';
    if (disconnectBtn)     disconnectBtn.style.display     = 'none';
    if (emailLoginToggle)  emailLoginToggle.style.display  = 'block';
    if (emailLoginContent) emailLoginContent.classList.remove('open');
    if (authDivider)       authDivider.style.display       = 'flex';
  }

  refreshAuthStatus();

});

function updateBlocklistStatus() {
  const el = document.getElementById('blocklistStatus');
  if (!el) return;

  chrome.storage.sync.get(['proxyHost', 'proxyPort'], (cfg) => {
    const host      = cfg.proxyHost || 'localhost';
    const port      = cfg.proxyPort || '8081';
    const isLocal   = ['localhost', '127.0.0.1', '0.0.0.0'].includes(host.toLowerCase());
    const protocol  = isLocal ? 'http' : 'https';
    const portSuffix = (protocol === 'https' && port === '443') || (protocol === 'http' && port === '80') ? '' : ':' + port;
    const base      = `${protocol}://${host}${portSuffix}`;

    el.textContent = 'Blocklist: querying…';

    chrome.storage.local.get(['ztAuth'], (authResult) => {
      const headers = { 'Accept': 'application/json' };
      if (authResult.ztAuth?.authToken) {
        headers['X-ZT-Auth'] = `Bearer ${authResult.ztAuth.authToken}`;
      }

      Promise.all([
        fetch(base + '/features-status', { headers }).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch(base + '/routing',         { headers }).then(r => r.ok ? r.json() : null).catch(() => null)
      ]).then(([features, routing]) => {
        let remoteStr = 'disabled';
        if (features && typeof features.black_count === 'number') {
          const age = typeof features.age_seconds === 'number'
            ? `${Math.round(features.age_seconds)}s` : 'n/a';
          remoteStr = `${features.black_count} blocked / ${features.white_count || 0} allowed (${age})`;
        } else if (features?.error === 'missing_api_key') {
          remoteStr = 'no API key configured';
        } else if (features?.error) {
          remoteStr = `error: ${features.error}`;
        }

        const mergedCount = routing?.domains?.length || 0;
        const mergedNote  = routing ? (routing.remote ? 'baseline + remote' : 'baseline only') : 'n/a';
        el.textContent = `Blocklist: ${remoteStr}  ·  Routed domains: ${mergedCount} (${mergedNote})`;
      }).catch(() => {
        el.textContent = 'Blocklist: unable to fetch status';
      });
    });
  });
}

setTimeout(updateBlocklistStatus, 250);
