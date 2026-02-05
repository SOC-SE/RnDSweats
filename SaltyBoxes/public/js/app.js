/**
 * Salt-GUI Frontend Application
 *
 * Vanilla JavaScript - No frameworks, no build step
 *
 * @author Samuel Brucker
 * @version 1.0.0
 */

(function() {
  'use strict';

  // ============================================================
  // Configuration
  // ============================================================

  const API_BASE = window.location.origin;
  const HEALTH_CHECK_INTERVAL = 30000;
  const DEVICE_REFRESH_INTERVAL = 60000;

  // ============================================================
  // Application State
  // ============================================================

  const state = {
    authenticated: false,
    user: null,
    devices: [],
    selectedDevices: new Set(),
    scripts: [],
    selectedScript: null,
    currentView: 'devices'
  };

  // ============================================================
  // Theme Management
  // ============================================================

  function initTheme() {
    // Check for saved preference, default to light
    const savedTheme = localStorage.getItem('salt-gui-theme') || 'light';
    applyTheme(savedTheme);
  }

  function applyTheme(theme) {
    if (theme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    updateThemeButton(theme);
  }

  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('salt-gui-theme', newTheme);
    applyTheme(newTheme);
  }

  function updateThemeButton(theme) {
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) {
      btn.textContent = theme === 'dark' ? 'Light' : 'Dark';
      btn.title = theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme';
    }
  }

  // Initialize theme immediately before page renders
  initTheme();

  // ============================================================
  // API Helper
  // ============================================================

  async function api(endpoint, options = {}) {
    const { signal, ...restOptions } = options;
    const url = API_BASE + endpoint;
    const defaultOptions = {
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...restOptions.headers
      }
    };

    try {
      const fetchOptions = { ...defaultOptions, ...restOptions };
      if (signal) fetchOptions.signal = signal;
      const response = await fetch(url, fetchOptions);
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      return data;
    } catch (error) {
      if (error.name === 'AbortError') {
        throw error;
      }
      if (error.name === 'TypeError') {
        throw new Error('Network error - server may be unreachable');
      }
      throw error;
    }
  }

  // ============================================================
  // Toast Notifications
  // ============================================================

  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 5000);
  }

  // ============================================================
  // Modal Helper
  // ============================================================

  function showConfirmModal(title, message, onConfirm) {
    console.log('showConfirmModal called:', { title, message });
    const modal = document.getElementById('confirm-modal');
    console.log('Modal element:', modal);
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = message;

    const confirmBtn = document.getElementById('modal-confirm');
    const cancelBtn = document.getElementById('modal-cancel');

    modal.classList.remove('hidden');

    const cleanup = () => {
      modal.classList.add('hidden');
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
    };

    confirmBtn.onclick = () => {
      cleanup();
      onConfirm();
    };

    cancelBtn.onclick = cleanup;
  }

  // ============================================================
  // Utility Functions
  // ============================================================

  function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleString();
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  // ============================================================
  // Authentication
  // ============================================================

  async function checkAuth() {
    try {
      const result = await api('/api/auth/status');
      state.authenticated = result.authenticated;
      state.user = result.user;
      return result.authenticated;
    } catch (error) {
      state.authenticated = false;
      state.user = null;
      return false;
    }
  }

  async function checkSetupRequired() {
    try {
      const result = await api('/api/auth/setup-required');
      return result.required;
    } catch (error) {
      return false;
    }
  }

  function showLoginScreen(setupRequired = false) {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('app-screen').classList.add('hidden');

    const loginForm = document.getElementById('login-form');
    const setupForm = document.getElementById('setup-form');

    if (setupRequired) {
      loginForm.classList.add('hidden');
      setupForm.classList.remove('hidden');
    } else {
      loginForm.classList.remove('hidden');
      setupForm.classList.add('hidden');
    }
  }

  function showAppScreen() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app-screen').classList.remove('hidden');

    if (state.user) {
      document.getElementById('current-user').textContent = state.user.username;
    }

    loadDevices();
    checkSaltConnection();
  }

  async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');

    try {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      errorEl.classList.add('hidden');
      await checkAuth();
      showAppScreen();
      showToast('Login successful', 'success');
    } catch (error) {
      errorEl.textContent = error.message;
      errorEl.classList.remove('hidden');
    }
  }

  async function handleSetup(e) {
    e.preventDefault();
    const username = document.getElementById('setup-username').value;
    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;
    const errorEl = document.getElementById('setup-error');

    if (password !== confirm) {
      errorEl.textContent = 'Passwords do not match';
      errorEl.classList.remove('hidden');
      return;
    }

    try {
      await api('/api/auth/setup', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      errorEl.classList.add('hidden');
      showToast('Admin user created', 'success');

      // Now login
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      await checkAuth();
      showAppScreen();
    } catch (error) {
      errorEl.textContent = error.message;
      errorEl.classList.remove('hidden');
    }
  }

  async function handleLogout() {
    try {
      await api('/api/auth/logout', { method: 'POST' });
      state.authenticated = false;
      state.user = null;
      showLoginScreen();
      showToast('Logged out', 'success');
    } catch (error) {
      showToast('Logout failed: ' + error.message, 'error');
    }
  }

  // ============================================================
  // Connection Status
  // ============================================================

  async function checkSaltConnection() {
    const statusEl = document.getElementById('connection-status');
    const bannerEl = document.getElementById('salt-disconnect-banner');

    try {
      const health = await api('/api/health');

      if (health.salt.status === 'connected') {
        statusEl.textContent = 'Connected';
        statusEl.className = 'status-badge status-connected';
        if (bannerEl) bannerEl.classList.add('hidden');
      } else {
        statusEl.textContent = 'Disconnected';
        statusEl.className = 'status-badge status-disconnected';
        if (bannerEl) bannerEl.classList.remove('hidden');
      }
    } catch (error) {
      statusEl.textContent = 'Error';
      statusEl.className = 'status-badge status-disconnected';
      if (bannerEl) bannerEl.classList.remove('hidden');
    }
  }

  // ============================================================
  // Navigation
  // ============================================================

  function switchView(viewName) {
    state.currentView = viewName;

    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewName);
    });

    // Show/hide views
    document.querySelectorAll('.view').forEach(view => {
      view.classList.toggle('active', view.id === `view-${viewName}`);
      view.classList.toggle('hidden', view.id !== `view-${viewName}`);
    });

    // Load view-specific data
    switch (viewName) {
      case 'devices':
        loadDevices();
        break;
      case 'scripts':
        loadScripts();
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('script');
        toggleInlineSelectorVisibility('script', 'script-target-type', 'selected');
        break;
      case 'states':
        loadStates();
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('state');
        toggleInlineSelectorVisibility('state', 'state-target-type', 'selected');
        break;
      case 'playbooks':
        loadPlaybooks();
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('playbook');
        toggleInlineSelectorVisibility('playbook', 'playbook-target-type', 'selected');
        break;
      case 'commands':
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('cmd');
        toggleInlineSelectorVisibility('cmd', 'cmd-target-type', 'selected');
        break;
      case 'audit':
        loadAuditLog();
        break;
      case 'settings':
        loadSettings();
        break;
      case 'services':
        populateSingleDeviceSelects();
        break;
      case 'processes':
        populateSingleDeviceSelects();
        break;
      case 'network':
        populateSingleDeviceSelects();
        break;
      case 'files':
        populateSingleDeviceSelects();
        break;
      case 'logs':
        populateSingleDeviceSelects();
        break;
      case 'suspicious':
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('susp');
        toggleInlineSelectorVisibility('susp', 'susp-target-type', 'selected');
        break;
      case 'reports':
        populateSecurityTargetSelect();
        break;
      case 'monitoring':
        loadMonitoringView();
        break;
      case 'passwords':
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('pwd');
        toggleInlineSelectorVisibility('pwd', 'pwd-target-type', 'selected');
        break;
      case 'emergency':
        populateSingleDeviceSelects();
        renderInlineDeviceSelector('emergency');
        toggleInlineSelectorVisibility('emergency', 'emergency-target-type', 'selected');
        break;
      case 'keys':
        loadKeys();
        break;
      case 'forensics':
        populateSingleDeviceSelects();
        populateForensicsTargetSelects();
        loadForensicsJobs();
        renderForensicsDeviceChecklist();
        break;
    }
  }

  // ============================================================
  // Devices
  // ============================================================

  async function loadDevices(forceRefresh = false) {
    const listEl = document.getElementById('device-list');
    listEl.innerHTML = '<div class="loading">Loading devices...</div>';

    try {
      const url = forceRefresh ? '/api/devices?refresh=true' : '/api/devices';
      const result = await api(url);
      state.devices = result.devices || [];

      renderDeviceList();
      updateDeviceCounts();
      // Initialize all inline device selectors with the new device list
      initializeAllInlineSelectors();
      // Populate all single device dropdowns
      populateSingleDeviceSelects();
    } catch (error) {
      listEl.innerHTML = `<div class="no-devices">Failed to load devices: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderDeviceList() {
    const listEl = document.getElementById('device-list');
    const filter = document.getElementById('device-filter').value.toLowerCase();

    const filteredDevices = state.devices.filter(d =>
      d.id.toLowerCase().includes(filter) ||
      d.os.toLowerCase().includes(filter) ||
      d.ip.toLowerCase().includes(filter)
    );

    if (filteredDevices.length === 0) {
      listEl.innerHTML = '<div class="no-devices">No devices found</div>';
      return;
    }

    listEl.innerHTML = filteredDevices.map(device => `
      <div class="device-item ${state.selectedDevices.has(device.id) ? 'selected' : ''}" data-id="${escapeHtml(device.id)}">
        <input type="checkbox" class="device-checkbox" ${state.selectedDevices.has(device.id) ? 'checked' : ''}>
        <span class="device-name">${escapeHtml(device.id)}</span>
        <span class="device-os">${escapeHtml(device.os)}</span>
        <span class="device-ip">${escapeHtml(device.ip)}</span>
        <span class="device-status ${device.status}">${device.status}</span>
      </div>
    `).join('');

    // Add click handlers
    listEl.querySelectorAll('.device-item').forEach(item => {
      item.addEventListener('click', (e) => {
        if (e.target.classList.contains('device-checkbox')) return;
        toggleDeviceSelection(item.dataset.id);
      });

      item.querySelector('.device-checkbox').addEventListener('change', (e) => {
        toggleDeviceSelection(item.dataset.id);
      });
    });
  }

  function toggleDeviceSelection(deviceId) {
    if (state.selectedDevices.has(deviceId)) {
      state.selectedDevices.delete(deviceId);
    } else {
      state.selectedDevices.add(deviceId);
    }
    renderDeviceList();
    updateDeviceCounts();
    // Update shell selector visibility for user creation
    updateShellSelectorVisibility();
  }

  function selectAllDevices() {
    state.devices.forEach(d => state.selectedDevices.add(d.id));
    renderDeviceList();
    updateDeviceCounts();
    updateShellSelectorVisibility();
  }

  function selectLinuxDevices() {
    state.devices.forEach(d => {
      if (d.kernel === 'Linux') {
        state.selectedDevices.add(d.id);
      }
    });
    renderDeviceList();
    updateDeviceCounts();
    updateShellSelectorVisibility();
  }

  function selectWindowsDevices() {
    state.devices.forEach(d => {
      if (d.kernel === 'Windows') {
        state.selectedDevices.add(d.id);
      }
    });
    renderDeviceList();
    updateDeviceCounts();
    updateShellSelectorVisibility();
  }

  function clearDeviceSelection() {
    state.selectedDevices.clear();
    renderDeviceList();
    updateDeviceCounts();
    updateShellSelectorVisibility();
  }

  function updateDeviceCounts() {
    document.getElementById('device-count').textContent = `${state.devices.length} devices`;
    document.getElementById('selected-count').textContent = `${state.selectedDevices.size} selected`;

    // Update all inline device selector counts
    updateAllInlineSelectors();
  }

  // ============================================================
  // Inline Device Selector Component
  // ============================================================

  // List of all inline device selectors (prefix => {listId, countId, visible based on target type})
  const inlineSelectors = [
    { prefix: 'cmd', targetTypeId: 'cmd-target-type', showOnValue: 'selected' },
    { prefix: 'script', targetTypeId: 'script-target-type', showOnValue: 'selected' },
    { prefix: 'state', targetTypeId: 'state-target-type', showOnValue: 'selected' },
    { prefix: 'playbook', targetTypeId: 'playbook-target-type', showOnValue: 'selected' },
    { prefix: 'susp', targetTypeId: 'susp-target-type', showOnValue: 'selected' },
    { prefix: 'emergency', targetTypeId: 'emergency-target-type', showOnValue: 'selected' },
    { prefix: 'pwd', targetTypeId: 'pwd-target-type', showOnValue: 'selected' }
  ];

  function renderInlineDeviceSelector(prefix) {
    const listEl = document.getElementById(`${prefix}-device-list`);
    const countEl = document.getElementById(`${prefix}-selected-count`);

    if (!listEl) return;

    if (state.devices.length === 0) {
      listEl.innerHTML = '<div class="loading">No devices available</div>';
      if (countEl) countEl.textContent = '0';
      return;
    }

    let html = '';
    state.devices.forEach(device => {
      const isSelected = state.selectedDevices.has(device.id);
      const isOffline = device.status !== 'online';
      html += `
        <label class="device-selector-item ${isOffline ? 'offline' : ''}">
          <input type="checkbox" value="${escapeHtml(device.id)}" ${isSelected ? 'checked' : ''} data-prefix="${prefix}">
          <div class="device-info">
            <span class="device-name">${escapeHtml(device.id)}</span>
            <span class="device-os">${escapeHtml(device.os || 'unknown')}</span>
            <span class="device-ip">${escapeHtml(device.ip || '')}</span>
          </div>
        </label>
      `;
    });

    listEl.innerHTML = html;

    // Add change listeners to checkboxes - sync with global state
    listEl.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', () => {
        if (cb.checked) {
          state.selectedDevices.add(cb.value);
        } else {
          state.selectedDevices.delete(cb.value);
        }
        // Update all selectors to stay in sync
        updateAllInlineSelectors();
        // Also update main device list if visible
        if (state.currentView === 'devices') {
          renderDeviceList();
        }
        // Update shell selector visibility for user creation
        updateShellSelectorVisibility();
      });
    });

    if (countEl) countEl.textContent = state.selectedDevices.size;
  }

  function updateAllInlineSelectors() {
    inlineSelectors.forEach(selector => {
      const listEl = document.getElementById(`${selector.prefix}-device-list`);
      const countEl = document.getElementById(`${selector.prefix}-selected-count`);

      if (listEl) {
        // Update checkboxes to match global state
        listEl.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          cb.checked = state.selectedDevices.has(cb.value);
        });
      }

      if (countEl) {
        countEl.textContent = state.selectedDevices.size;
      }
    });
  }

  function inlineSelectorSelectAll(prefix) {
    state.devices.forEach(d => state.selectedDevices.add(d.id));
    updateAllInlineSelectors();
    if (state.currentView === 'devices') renderDeviceList();
    updateDeviceCounts();
  }

  function inlineSelectorSelectLinux(prefix) {
    state.devices.forEach(d => {
      if (d.kernel === 'Linux') {
        state.selectedDevices.add(d.id);
      }
    });
    updateAllInlineSelectors();
    if (state.currentView === 'devices') renderDeviceList();
    updateDeviceCounts();
  }

  function inlineSelectorSelectWindows(prefix) {
    state.devices.forEach(d => {
      if (d.kernel === 'Windows') {
        state.selectedDevices.add(d.id);
      }
    });
    updateAllInlineSelectors();
    if (state.currentView === 'devices') renderDeviceList();
    updateDeviceCounts();
  }

  function inlineSelectorSelectNone(prefix) {
    state.selectedDevices.clear();
    updateAllInlineSelectors();
    if (state.currentView === 'devices') renderDeviceList();
    updateDeviceCounts();
  }

  function toggleInlineSelectorVisibility(prefix, targetTypeId, showOnValue) {
    const selectorEl = document.getElementById(`${prefix}-device-selector`);
    const targetTypeEl = document.getElementById(targetTypeId);

    if (selectorEl && targetTypeEl) {
      const shouldShow = targetTypeEl.value === showOnValue;
      selectorEl.classList.toggle('hidden', !shouldShow);
    }
  }

  function initializeAllInlineSelectors() {
    // Render all inline selectors
    inlineSelectors.forEach(selector => {
      renderInlineDeviceSelector(selector.prefix);
      toggleInlineSelectorVisibility(selector.prefix, selector.targetTypeId, selector.showOnValue);
    });
  }

  // ============================================================
  // Commands
  // ============================================================

  function getCommandTargets() {
    const targetType = document.getElementById('cmd-target-type').value;

    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        throw new Error('No devices selected');
      }
      return Array.from(state.selectedDevices);
    } else if (targetType === 'single') {
      const target = document.getElementById('cmd-single-target').value;
      if (!target) {
        throw new Error('Select a device');
      }
      return [target];
    } else if (targetType === 'all') {
      return '*';
    } else {
      const custom = document.getElementById('cmd-custom-target').value.trim();
      if (!custom) {
        throw new Error('Custom target pattern is required');
      }
      return custom;
    }
  }

  // ============================================================
  // Command History (localStorage)
  // ============================================================

  const CMD_HISTORY_KEY = 'salt-gui-cmd-history';
  const CMD_HISTORY_MAX = 50;
  let cmdHistoryIndex = -1;
  let cmdHistoryTemp = '';

  function getCmdHistory() {
    try {
      return JSON.parse(localStorage.getItem(CMD_HISTORY_KEY)) || [];
    } catch { return []; }
  }

  function addCmdHistory(command, shell) {
    const history = getCmdHistory();
    history.unshift({ command, shell, timestamp: Date.now() });
    if (history.length > CMD_HISTORY_MAX) history.length = CMD_HISTORY_MAX;
    localStorage.setItem(CMD_HISTORY_KEY, JSON.stringify(history));
    cmdHistoryIndex = -1;
  }

  function navigateCmdHistory(direction) {
    const input = document.getElementById('cmd-input');
    const history = getCmdHistory();
    if (history.length === 0) return;

    if (direction === 'up') {
      if (cmdHistoryIndex === -1) cmdHistoryTemp = input.value;
      if (cmdHistoryIndex < history.length - 1) {
        cmdHistoryIndex++;
        input.value = history[cmdHistoryIndex].command;
      }
    } else {
      if (cmdHistoryIndex > 0) {
        cmdHistoryIndex--;
        input.value = history[cmdHistoryIndex].command;
      } else if (cmdHistoryIndex === 0) {
        cmdHistoryIndex = -1;
        input.value = cmdHistoryTemp;
      }
    }
  }

  // ============================================================
  // Command Execution State (cancel, timer)
  // ============================================================

  let activeCommandAbort = null;
  let activeCommandTimer = null;
  let activeEventSource = null;

  function setCommandRunning(running) {
    const btn = document.getElementById('cmd-execute-btn');
    if (running) {
      btn.textContent = 'Cancel';
      btn.classList.remove('btn-primary');
      btn.classList.add('btn-danger');
    } else {
      btn.textContent = 'Execute';
      btn.classList.remove('btn-danger');
      btn.classList.add('btn-primary');
      if (activeCommandTimer) { clearInterval(activeCommandTimer); activeCommandTimer = null; }
      activeCommandAbort = null;
    }
  }

  function startElapsedTimer(outputEl) {
    const startTime = Date.now();
    outputEl.textContent = 'Executing... (0s)';
    activeCommandTimer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      outputEl.textContent = `Executing... (${elapsed}s)`;
    }, 1000);
  }

  async function executeCommand() {
    // If already running, cancel
    if (activeCommandAbort) {
      activeCommandAbort.abort();
      if (activeEventSource) { activeEventSource.close(); activeEventSource = null; }
      setCommandRunning(false);
      document.getElementById('cmd-output').textContent += '\n[Cancelled]';
      return;
    }

    const command = document.getElementById('cmd-input').value.trim();
    const outputEl = document.getElementById('cmd-output');
    const shell = document.getElementById('cmd-shell').value;
    const timeout = document.getElementById('cmd-timeout').value;

    if (!command) {
      showToast('Please enter a command', 'warning');
      return;
    }

    let targets;
    try {
      targets = getCommandTargets();
    } catch (error) {
      showToast(error.message, 'warning');
      return;
    }

    // Save to history
    addCmdHistory(command, shell);

    const abortController = new AbortController();
    activeCommandAbort = abortController;
    setCommandRunning(true);
    startElapsedTimer(outputEl);

    // Try SSE streaming first, fall back to synchronous
    try {
      const asyncResult = await api('/api/commands/run-async', {
        method: 'POST',
        signal: abortController.signal,
        body: JSON.stringify({
          targets,
          command,
          shell: shell === 'auto' ? undefined : shell,
          timeout: parseInt(timeout)
        })
      });

      if (asyncResult.jid) {
        // Stream results via SSE
        await streamCommandResults(asyncResult.jid, outputEl, abortController);
        setCommandRunning(false);
        return;
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        setCommandRunning(false);
        return;
      }
      // SSE/async failed, fall back to synchronous
    }

    // Synchronous fallback
    try {
      const result = await api('/api/commands/run', {
        method: 'POST',
        signal: abortController.signal,
        body: JSON.stringify({
          targets,
          command,
          shell: shell === 'auto' ? undefined : shell,
          timeout: parseInt(timeout)
        })
      });

      if (activeCommandTimer) clearInterval(activeCommandTimer);

      let output = '';
      for (const [minion, data] of Object.entries(result.results)) {
        output += `-- ${minion} -----------------------------------------------\n`;
        if (data.error) {
          output += `ERROR: ${data.output}\n`;
        } else {
          output += `${data.output}\n`;
        }
        output += '\n';
      }

      output += `\n[${result.summary.success}/${result.summary.total} succeeded in ${result.execution_time_ms}ms]`;
      outputEl.textContent = output;

      showToast(`Command executed on ${result.summary.total} devices`, 'success');
    } catch (error) {
      if (error.name === 'AbortError') {
        // Already handled
      } else {
        if (activeCommandTimer) clearInterval(activeCommandTimer);
        outputEl.textContent = `Error: ${error.message}`;
        showToast('Command execution failed', 'error');
      }
    }
    setCommandRunning(false);
  }

  function streamCommandResults(jid, outputEl, abortController) {
    return new Promise((resolve, reject) => {
      const url = `${API_BASE}/api/commands/stream/${jid}`;
      const es = new EventSource(url, { withCredentials: true });
      activeEventSource = es;
      let output = '';
      let minionCount = 0;

      es.addEventListener('result', (e) => {
        const data = JSON.parse(e.data);
        minionCount++;
        output += `-- ${data.minion} -----------------------------------------------\n`;
        output += `${data.output}\n\n`;
        if (activeCommandTimer) clearInterval(activeCommandTimer);
        outputEl.textContent = output + `[${minionCount} minion(s) reported]`;
      });

      es.addEventListener('status', (e) => {
        const data = JSON.parse(e.data);
        if (data.status === 'complete' || data.status === 'timeout') {
          if (activeCommandTimer) clearInterval(activeCommandTimer);
          outputEl.textContent = output + `\n[${minionCount} minion(s) completed]`;
          es.close();
          activeEventSource = null;
          showToast(`Command completed on ${minionCount} devices`, 'success');
          resolve();
        }
      });

      es.addEventListener('error', (e) => {
        es.close();
        activeEventSource = null;
        reject(new Error('SSE stream error'));
      });

      es.onerror = () => {
        es.close();
        activeEventSource = null;
        // Don't reject - fall back handled by caller
        resolve();
      };

      // Handle abort
      abortController.signal.addEventListener('abort', () => {
        es.close();
        activeEventSource = null;
        resolve();
      });
    });
  }

  // ============================================================
  // Scripts
  // ============================================================

  async function loadScripts() {
    const treeEl = document.getElementById('scripts-tree');
    treeEl.innerHTML = '<div class="loading">Loading scripts...</div>';

    try {
      const result = await api('/api/scripts/tree');
      renderScriptTree(result.tree);
    } catch (error) {
      treeEl.innerHTML = `<div class="loading">Failed to load scripts: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderScriptTree(tree, filter = 'all') {
    const treeEl = document.getElementById('scripts-tree');

    function renderNode(node, path = '') {
      if (node.type === 'directory') {
        const fullPath = path ? `${path}/${node.name}` : node.name;

        // Skip if filtering by OS
        if (filter !== 'all' && node.name !== filter && path === 'scripts') {
          return '';
        }

        const children = node.children.map(child => renderNode(child, fullPath)).join('');
        if (!children && node.children.length === 0) return '';

        return `
          <div class="script-folder expanded">
            <div class="script-folder-name">${escapeHtml(node.name)}</div>
            <div class="script-folder-contents">${children}</div>
          </div>
        `;
      } else {
        const fullPath = `${path}/${node.name}`.replace(/^scripts\//, '');
        return `
          <div class="script-file" data-path="${escapeHtml(fullPath)}">${escapeHtml(node.name)}</div>
        `;
      }
    }

    const html = tree.children.map(child => renderNode(child, 'scripts')).join('');
    treeEl.innerHTML = html || '<div class="loading">No scripts found</div>';

    // Add event listeners
    treeEl.querySelectorAll('.script-folder-name').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        el.parentElement.classList.toggle('expanded');
      });
    });

    treeEl.querySelectorAll('.script-file').forEach(el => {
      el.addEventListener('click', () => {
        loadScriptContent(el.dataset.path);
        treeEl.querySelectorAll('.script-file').forEach(f => f.classList.remove('selected'));
        el.classList.add('selected');
      });
    });
  }

  async function loadScriptContent(scriptPath) {
    const infoEl = document.getElementById('script-info');
    const contentEl = document.getElementById('script-content');
    const executeBtn = document.getElementById('script-execute-btn');

    state.selectedScript = scriptPath;

    try {
      const result = await api(`/api/scripts/content/${encodeURIComponent(scriptPath)}`);
      const script = result.script;

      infoEl.innerHTML = `
        <div class="script-info-grid">
          <div class="script-info-item">
            <span class="script-info-label">Name</span>
            <span class="script-info-value">${escapeHtml(script.name)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">OS</span>
            <span class="script-info-value">${escapeHtml(script.os)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Shell</span>
            <span class="script-info-value">${escapeHtml(script.shell)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Size</span>
            <span class="script-info-value">${formatBytes(script.size)}</span>
          </div>
        </div>
      `;

      contentEl.textContent = script.content;
      executeBtn.disabled = false;
    } catch (error) {
      infoEl.innerHTML = `<p class="placeholder-text">Failed to load script: ${escapeHtml(error.message)}</p>`;
      contentEl.textContent = '';
      executeBtn.disabled = true;
    }
  }

  async function executeScript() {
    if (!state.selectedScript) {
      showToast('Please select a script', 'warning');
      return;
    }

    const outputEl = document.getElementById('script-output');
    const argsEl = document.getElementById('script-args');
    const targetType = document.getElementById('script-target-type').value;

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'single') {
      const target = document.getElementById('script-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('script-custom-target').value.trim();
      if (!targets) {
        showToast('Custom target pattern is required', 'warning');
        return;
      }
    }

    const args = argsEl.value.trim().split(/\s+/).filter(a => a);

    const executeBtn = document.getElementById('script-execute-btn');
    executeBtn.disabled = true;
    executeBtn.textContent = 'Executing...';

    const startTime = Date.now();
    outputEl.textContent = 'Executing... (0s)';
    const timer = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      outputEl.textContent = `Executing... (${elapsed}s)`;
    }, 1000);

    try {
      const result = await api('/api/scripts/run', {
        method: 'POST',
        body: JSON.stringify({
          targets,
          script: state.selectedScript,
          args
        })
      });

      clearInterval(timer);

      let output = '';
      for (const [minion, data] of Object.entries(result.results)) {
        output += `-- ${minion} -----------------------------------------------\n`;
        if (data.error) {
          output += `ERROR: ${data.output}\n`;
        } else {
          output += `${data.output}\n`;
        }
        output += '\n';
      }

      output += `\n[${result.summary.success}/${result.summary.total} succeeded in ${result.execution_time_ms}ms]`;
      outputEl.textContent = output;

      showToast(`Script executed on ${result.summary.total} devices`, 'success');
    } catch (error) {
      clearInterval(timer);
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Script execution failed', 'error');
    } finally {
      executeBtn.disabled = false;
      executeBtn.textContent = 'Execute Script';
    }
  }

  // ============================================================
  // States
  // ============================================================

  let selectedState = null;

  async function loadStates() {
    const treeEl = document.getElementById('states-tree');
    treeEl.innerHTML = '<div class="loading">Loading states...</div>';

    try {
      const result = await api('/api/states/local');
      renderStatesTree(result.states);
    } catch (error) {
      treeEl.innerHTML = `<div class="loading">Failed to load states: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderStatesTree(states, filter = 'all') {
    const treeEl = document.getElementById('states-tree');

    function renderNode(node, path = '') {
      if (node.type === 'directory') {
        const fullPath = path ? `${path}/${node.name}` : node.name;

        // Skip if filtering by OS
        if (filter !== 'all' && (node.name === 'linux' || node.name === 'windows') && node.name !== filter) {
          return '';
        }

        const children = (node.children || []).map(child => renderNode(child, fullPath)).join('');
        if (!children && (!node.children || node.children.length === 0)) return '';

        return `
          <div class="script-folder expanded">
            <div class="script-folder-name">${escapeHtml(node.name)}</div>
            <div class="script-folder-contents">${children}</div>
          </div>
        `;
      } else {
        return `
          <div class="script-file" data-path="${escapeHtml(node.path)}">${escapeHtml(node.name)}</div>
        `;
      }
    }

    const html = states.map(node => renderNode(node, '')).join('');
    treeEl.innerHTML = html || '<div class="loading">No states found. Add .sls files to the states/ directory.</div>';

    // Add event listeners
    treeEl.querySelectorAll('.script-folder-name').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        el.parentElement.classList.toggle('expanded');
      });
    });

    treeEl.querySelectorAll('.script-file').forEach(el => {
      el.addEventListener('click', () => {
        loadStateContent(el.dataset.path);
        treeEl.querySelectorAll('.script-file').forEach(f => f.classList.remove('selected'));
        el.classList.add('selected');
      });
    });
  }

  async function loadStateContent(statePath) {
    const infoEl = document.getElementById('state-info');
    const contentEl = document.getElementById('state-content');
    const applyBtn = document.getElementById('state-apply-btn');

    selectedState = statePath;

    try {
      const result = await api(`/api/states/local/${encodeURIComponent(statePath)}`);
      const state = result.state;

      infoEl.innerHTML = `
        <div class="script-info-grid">
          <div class="script-info-item">
            <span class="script-info-label">Name</span>
            <span class="script-info-value">${escapeHtml(state.name)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Path</span>
            <span class="script-info-value">${escapeHtml(state.path)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Size</span>
            <span class="script-info-value">${formatBytes(state.size)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Modified</span>
            <span class="script-info-value">${formatDate(state.modified)}</span>
          </div>
        </div>
      `;

      contentEl.textContent = state.content;
      applyBtn.disabled = false;
    } catch (error) {
      infoEl.innerHTML = `<p class="placeholder-text">Failed to load state: ${escapeHtml(error.message)}</p>`;
      contentEl.textContent = '';
      applyBtn.disabled = true;
    }
  }

  async function applyState() {
    if (!selectedState) {
      showToast('Please select a state', 'warning');
      return;
    }

    const outputEl = document.getElementById('state-output');
    const targetType = document.getElementById('state-target-type').value;
    const testMode = document.getElementById('state-test-mode').checked;

    let targets;
    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'single') {
      const target = document.getElementById('state-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('state-custom-target').value.trim();
      if (!targets) {
        showToast('Custom target pattern is required', 'warning');
        return;
      }
    }

    outputEl.textContent = `Applying state ${selectedState}${testMode ? ' (test mode)' : ''}...`;

    try {
      // Convert local path to state name (remove .sls extension)
      const stateName = selectedState.replace(/\.sls$/, '').replace(/\//g, '.');

      const result = await api('/api/states/apply', {
        method: 'POST',
        body: JSON.stringify({
          targets,
          state: stateName,
          test: testMode
        })
      });

      let output = `State: ${result.state}${result.test ? ' (TEST MODE)' : ''}\n`;
      output += `Total: ${result.summary.total}, Success: ${result.summary.success}, Failed: ${result.summary.failed}, Changed: ${result.summary.changed}\n`;
      output += `Time: ${result.execution_time_ms}ms\n\n`;

      for (const [minion, data] of Object.entries(result.results || {})) {
        output += `-- ${minion} --\n`;
        if (data.error) {
          output += `ERROR: ${data.message}\n`;
        } else {
          output += `Success: ${data.success}, Changed: ${data.changed}\n`;
          if (data.states) {
            data.states.forEach(s => {
              const status = s.result === true ? 'OK' : s.result === false ? 'FAILED' : 'CHANGED';
              output += `  [${status}] ${s.name || s.id}\n`;
              if (s.comment) output += `         ${s.comment}\n`;
            });
          }
        }
        output += '\n';
      }

      outputEl.textContent = output;
      showToast(`State applied to ${result.summary.total} devices`, result.summary.failed > 0 ? 'warning' : 'success');
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('State application failed', 'error');
    }
  }

  // ============================================================
  // Playbooks
  // ============================================================

  let selectedPlaybook = null;

  async function loadPlaybooks() {
    const treeEl = document.getElementById('playbooks-tree');
    treeEl.innerHTML = '<div class="loading">Loading playbooks...</div>';

    try {
      const result = await api('/api/playbooks/tree');
      renderPlaybooksTree(result.tree);
    } catch (error) {
      treeEl.innerHTML = `<div class="loading">Failed to load playbooks: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderPlaybooksTree(tree, filter = 'all') {
    const treeEl = document.getElementById('playbooks-tree');

    function renderNode(node, path = '') {
      if (node.type === 'directory') {
        const fullPath = path ? `${path}/${node.name}` : node.name;

        // Skip if filtering by OS at top level
        if (filter !== 'all' && !path && (node.name === 'linux' || node.name === 'windows') && node.name !== filter) {
          return '';
        }

        const children = (node.children || []).map(child => renderNode(child, fullPath)).join('');
        if (!children && (!node.children || node.children.length === 0)) return '';

        return `
          <div class="script-folder expanded">
            <div class="script-folder-name">${escapeHtml(node.name)}</div>
            <div class="script-folder-contents">${children}</div>
          </div>
        `;
      } else {
        const fullPath = path ? `${path}/${node.name}` : node.name;
        return `
          <div class="script-file" data-path="${escapeHtml(node.path)}">${escapeHtml(node.name)}</div>
        `;
      }
    }

    const children = tree.children || [];
    const html = children.map(node => renderNode(node, '')).join('');
    treeEl.innerHTML = html || '<div class="loading">No playbooks found. Add .yaml files to the playbooks/ directory.</div>';

    // Add event listeners
    treeEl.querySelectorAll('.script-folder-name').forEach(el => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        el.parentElement.classList.toggle('expanded');
      });
    });

    treeEl.querySelectorAll('.script-file').forEach(el => {
      el.addEventListener('click', () => {
        loadPlaybookContent(el.dataset.path);
        treeEl.querySelectorAll('.script-file').forEach(f => f.classList.remove('selected'));
        el.classList.add('selected');
      });
    });
  }

  async function loadPlaybookContent(playbookPath) {
    const infoEl = document.getElementById('playbook-info');
    const stepsEl = document.getElementById('playbook-steps');
    const runBtn = document.getElementById('playbook-run-btn');

    selectedPlaybook = playbookPath;

    try {
      const result = await api(`/api/playbooks/content/${encodeURIComponent(playbookPath)}`);
      const playbook = result.playbook;

      infoEl.innerHTML = `
        <div class="script-info-grid">
          <div class="script-info-item">
            <span class="script-info-label">Name</span>
            <span class="script-info-value">${escapeHtml(playbook.name)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">OS</span>
            <span class="script-info-value">${escapeHtml(playbook.os)}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Steps</span>
            <span class="script-info-value">${playbook.steps.length}</span>
          </div>
          <div class="script-info-item">
            <span class="script-info-label">Description</span>
            <span class="script-info-value">${escapeHtml(playbook.description || 'No description')}</span>
          </div>
        </div>
      `;

      // Render steps
      let stepsHtml = '<div class="playbook-steps-list">';
      playbook.steps.forEach((step, i) => {
        stepsHtml += `
          <div class="playbook-step">
            <div class="playbook-step-number">${i + 1}</div>
            <div class="playbook-step-content">
              <div class="playbook-step-name">${escapeHtml(step.name || 'Unnamed step')}</div>
              <div class="playbook-step-type">${escapeHtml(step.type)} ${step.type === 'command' ? ': ' + escapeHtml(step.command || '').substring(0, 50) : step.type === 'script' ? ': ' + escapeHtml(step.script || '') : step.type === 'state' ? ': ' + escapeHtml(step.state || '') : ''}</div>
              <div class="playbook-step-target">Target: ${escapeHtml(step.target || 'default (*)')}</div>
            </div>
          </div>
        `;
      });
      stepsHtml += '</div>';

      stepsEl.innerHTML = stepsHtml;
      runBtn.disabled = false;
    } catch (error) {
      infoEl.innerHTML = `<p class="placeholder-text">Failed to load playbook: ${escapeHtml(error.message)}</p>`;
      stepsEl.innerHTML = '<p class="placeholder-text">Select a playbook to view steps</p>';
      runBtn.disabled = true;
    }
  }

  async function runPlaybook() {
    if (!selectedPlaybook) {
      showToast('Please select a playbook', 'warning');
      return;
    }

    const outputEl = document.getElementById('playbook-output');
    const targetType = document.getElementById('playbook-target-type').value;

    let targets = null; // null = use playbook defaults

    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'single') {
      const target = document.getElementById('playbook-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    } else if (targetType === 'all') {
      targets = '*';
    } else if (targetType === 'custom') {
      targets = document.getElementById('playbook-custom-target').value.trim();
      if (!targets) {
        showToast('Custom target pattern is required', 'warning');
        return;
      }
    }
    // targetType === 'default' leaves targets as null

    outputEl.textContent = `Running playbook ${selectedPlaybook}...`;

    try {
      const body = { playbook: selectedPlaybook };
      if (targets !== null) {
        body.targets = targets;
      }

      const result = await api('/api/playbooks/run', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      let output = `Playbook: ${result.playbook}\n`;
      output += `Total Steps: ${result.summary.total}, Success: ${result.summary.success}, Failed: ${result.summary.failed}\n`;
      output += `Time: ${result.execution_time_ms}ms\n\n`;

      result.results.forEach(step => {
        output += `=== Step ${step.step}: ${step.name} ===\n`;
        output += `Type: ${step.type}\n`;
        output += `Status: ${step.success ? 'SUCCESS' : 'FAILED'}\n`;
        output += `Duration: ${step.duration_ms}ms\n`;

        if (step.output) {
          if (typeof step.output === 'string') {
            output += `Output: ${step.output}\n`;
          } else {
            for (const [minion, data] of Object.entries(step.output)) {
              output += `-- ${minion} --\n`;
              if (typeof data === 'string') {
                output += `${data}\n`;
              } else {
                output += `${JSON.stringify(data, null, 2)}\n`;
              }
            }
          }
        }
        output += '\n';
      });

      outputEl.textContent = output;
      showToast(`Playbook completed: ${result.summary.success}/${result.summary.total} steps succeeded`, result.summary.failed > 0 ? 'warning' : 'success');
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Playbook execution failed', 'error');
    }
  }

  // ============================================================
  // Audit Log
  // ============================================================

  async function loadAuditLog() {
    const listEl = document.getElementById('audit-list');
    const actionFilter = document.getElementById('audit-action-filter').value;
    const userFilter = document.getElementById('audit-user-filter').value;
    const limit = document.getElementById('audit-limit').value;

    listEl.innerHTML = '<div class="loading">Loading audit log...</div>';

    try {
      let url = `/api/audit?limit=${limit}`;
      if (actionFilter) url += `&action=${encodeURIComponent(actionFilter)}`;
      if (userFilter) url += `&user=${encodeURIComponent(userFilter)}`;

      const result = await api(url);

      if (result.entries.length === 0) {
        listEl.innerHTML = '<div class="loading">No audit entries found</div>';
        return;
      }

      listEl.innerHTML = result.entries.map(entry => `
        <div class="audit-item">
          <div class="audit-header">
            <span class="audit-timestamp">${formatDate(entry.timestamp)}</span>
            <span class="audit-action">${escapeHtml(entry.action)}</span>
            <span class="audit-user">${escapeHtml(entry.user || 'system')}</span>
          </div>
          ${entry.details ? `<div class="audit-details">${escapeHtml(JSON.stringify(entry.details, null, 2))}</div>` : ''}
        </div>
      `).join('');

      // Load filter options
      loadAuditFilters();
    } catch (error) {
      listEl.innerHTML = `<div class="loading">Failed to load audit log: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadAuditFilters() {
    try {
      const [actions, users] = await Promise.all([
        api('/api/audit/actions'),
        api('/api/audit/users')
      ]);

      const actionSelect = document.getElementById('audit-action-filter');
      const userSelect = document.getElementById('audit-user-filter');

      // Preserve current values
      const currentAction = actionSelect.value;
      const currentUser = userSelect.value;

      actionSelect.innerHTML = '<option value="">All Actions</option>' +
        actions.actions.map(a => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join('');

      userSelect.innerHTML = '<option value="">All Users</option>' +
        users.users.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('');

      actionSelect.value = currentAction;
      userSelect.value = currentUser;
    } catch (error) {
      // Ignore filter loading errors
    }
  }

  // ============================================================
  // Settings
  // ============================================================

  async function loadSettings() {
    try {
      const result = await api('/api/settings');
      const settings = result.settings;

      if (settings.salt.api) {
        document.getElementById('salt-url').value = settings.salt.api.url || '';
        document.getElementById('salt-username').value = settings.salt.api.username || '';
        document.getElementById('salt-eauth').value = settings.salt.api.eauth || 'pam';
      }

      // Load system status
      loadSystemStatus();
    } catch (error) {
      showToast('Failed to load settings: ' + error.message, 'error');
    }
  }

  async function loadSystemStatus() {
    const statusEl = document.getElementById('system-status');

    try {
      const result = await api('/api/settings/status');
      const status = result.status;

      statusEl.innerHTML = `
        <div class="status-grid">
          <div class="status-item">
            <span class="status-label">Uptime</span>
            <span class="status-value">${Math.floor(status.server.uptime / 60)} min</span>
          </div>
          <div class="status-item">
            <span class="status-label">Node.js</span>
            <span class="status-value">${escapeHtml(status.server.nodeVersion)}</span>
          </div>
          <div class="status-item">
            <span class="status-label">Salt API</span>
            <span class="status-value ${status.salt.connected ? 'text-success' : 'text-error'}">
              ${status.salt.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div class="status-item">
            <span class="status-label">Minions</span>
            <span class="status-value">
              ${status.salt.minions ? `${status.salt.minions.online} online / ${status.salt.minions.offline} offline` : 'N/A'}
            </span>
          </div>
        </div>
      `;
    } catch (error) {
      statusEl.innerHTML = `<div class="loading">Failed to load status</div>`;
    }
  }

  async function testSaltConnection() {
    const resultEl = document.getElementById('salt-test-result');
    resultEl.className = 'test-result';
    resultEl.classList.remove('hidden');
    resultEl.textContent = 'Testing connection...';

    const url = document.getElementById('salt-url').value;
    const username = document.getElementById('salt-username').value;
    const password = document.getElementById('salt-password').value;
    const eauth = document.getElementById('salt-eauth').value;

    try {
      const result = await api('/api/settings/salt/test', {
        method: 'POST',
        body: JSON.stringify({ url, username, password, eauth })
      });

      if (result.connected) {
        resultEl.className = 'test-result success';
        resultEl.textContent = `Connected! Response time: ${result.details.responseTime}ms`;
      } else {
        resultEl.className = 'test-result error';
        resultEl.textContent = result.message || 'Connection failed';
      }
    } catch (error) {
      resultEl.className = 'test-result error';
      resultEl.textContent = error.message;
    }
  }

  async function saveSaltSettings(e) {
    e.preventDefault();

    const url = document.getElementById('salt-url').value;
    const username = document.getElementById('salt-username').value;
    const password = document.getElementById('salt-password').value;
    const eauth = document.getElementById('salt-eauth').value;

    try {
      await api('/api/settings/salt', {
        method: 'POST',
        body: JSON.stringify({ url, username, password, eauth })
      });

      showToast('Settings saved', 'success');
      checkSaltConnection();
    } catch (error) {
      showToast('Failed to save settings: ' + error.message, 'error');
    }
  }

  async function changePassword(e) {
    e.preventDefault();
    const resultEl = document.getElementById('password-result');

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-new-password').value;

    if (newPassword !== confirmPassword) {
      resultEl.className = 'test-result error';
      resultEl.classList.remove('hidden');
      resultEl.textContent = 'New passwords do not match';
      return;
    }

    try {
      await api('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword })
      });

      resultEl.className = 'test-result success';
      resultEl.classList.remove('hidden');
      resultEl.textContent = 'Password changed successfully';

      // Clear form
      document.getElementById('change-password-form').reset();
    } catch (error) {
      resultEl.className = 'test-result error';
      resultEl.classList.remove('hidden');
      resultEl.textContent = error.message;
    }
  }

  // ============================================================
  // Emergency Actions
  // ============================================================

  function initiateLockdown() {
    const targetType = document.getElementById('emergency-target-type').value;
    let targets;

    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'single') {
      const target = document.getElementById('emergency-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('emergency-custom-target').value.trim();
      if (!targets) {
        showToast('Custom target pattern is required', 'warning');
        return;
      }
    }

    const targetDesc = Array.isArray(targets) ? targets.join(', ') : targets;

    showConfirmModal(
      'Confirm Lockdown',
      `This will lock down the following targets: ${targetDesc}\n\nAll non-essential services will be stopped and firewall rules will be applied. Only Salt connectivity will be preserved. Are you sure?`,
      async () => {
        showToast('Lockdown initiated...', 'warning');

        try {
          const result = await api('/api/emergency/lockdown', {
            method: 'POST',
            body: JSON.stringify({
              targets,
              confirm: 'LOCKDOWN'
            })
          });

          let message = `Lockdown complete: ${result.summary.success}/${result.summary.total} succeeded`;
          if (result.summary.failed > 0) {
            showToast(message, 'warning');
          } else {
            showToast(message, 'success');
          }
        } catch (error) {
          showToast('Lockdown failed: ' + error.message, 'error');
        }
      }
    );
  }

  // ============================================================
  // Key Management
  // ============================================================

  async function loadKeys() {
    try {
      const result = await api('/api/devices/keys/all');
      renderKeys(result.keys, result.counts);
    } catch (error) {
      showToast('Failed to load keys: ' + error.message, 'error');
    }
  }

  function renderKeys(keys, counts) {
    // Update counts
    document.getElementById('pending-count').textContent = counts.pending;
    document.getElementById('accepted-count').textContent = counts.accepted;
    document.getElementById('rejected-count').textContent = counts.rejected;
    document.getElementById('denied-count').textContent = counts.denied;

    // Render pending keys
    const pendingList = document.getElementById('pending-keys-list');
    if (keys.pending.length === 0) {
      pendingList.innerHTML = '<div class="keys-empty">No pending keys</div>';
    } else {
      pendingList.innerHTML = keys.pending.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-accept" onclick="acceptKey('${escapeHtml(key)}')">Accept</button>
            <button class="btn btn-reject" onclick="rejectKey('${escapeHtml(key)}')">Reject</button>
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }

    // Render accepted keys
    const acceptedList = document.getElementById('accepted-keys-list');
    if (keys.accepted.length === 0) {
      acceptedList.innerHTML = '<div class="keys-empty">No accepted keys</div>';
    } else {
      acceptedList.innerHTML = keys.accepted.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }

    // Render rejected keys
    const rejectedList = document.getElementById('rejected-keys-list');
    if (keys.rejected.length === 0) {
      rejectedList.innerHTML = '<div class="keys-empty">No rejected keys</div>';
    } else {
      rejectedList.innerHTML = keys.rejected.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-accept" onclick="acceptKey('${escapeHtml(key)}')">Accept</button>
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }

    // Render denied keys
    const deniedList = document.getElementById('denied-keys-list');
    if (keys.denied.length === 0) {
      deniedList.innerHTML = '<div class="keys-empty">No denied keys</div>';
    } else {
      deniedList.innerHTML = keys.denied.map(key => `
        <div class="key-item">
          <span class="key-item-name">${escapeHtml(key)}</span>
          <div class="key-item-actions">
            <button class="btn btn-accept" onclick="acceptKey('${escapeHtml(key)}')">Accept</button>
            <button class="btn btn-delete" onclick="deleteKey('${escapeHtml(key)}')">Delete</button>
          </div>
        </div>
      `).join('');
    }
  }

  async function acceptKey(minionId) {
    try {
      await api('/api/devices/keys/accept', {
        method: 'POST',
        body: JSON.stringify({ minionId })
      });
      showToast(`Key accepted for ${minionId}`, 'success');
      loadKeys();
      // Also refresh devices list
      loadDevices(true);
    } catch (error) {
      showToast('Failed to accept key: ' + error.message, 'error');
    }
  }

  async function rejectKey(minionId) {
    try {
      await api('/api/devices/keys/reject', {
        method: 'POST',
        body: JSON.stringify({ minionId })
      });
      showToast(`Key rejected for ${minionId}`, 'success');
      loadKeys();
    } catch (error) {
      showToast('Failed to reject key: ' + error.message, 'error');
    }
  }

  async function deleteKey(minionId) {
    showConfirmModal(
      'Delete Minion Key',
      `Are you sure you want to delete the key for "${minionId}"? This will remove the minion from Salt.`,
      async () => {
        try {
          await api(`/api/devices/keys/${encodeURIComponent(minionId)}`, {
            method: 'DELETE'
          });
          showToast(`Key deleted for ${minionId}`, 'success');
          loadKeys();
          loadDevices(true);
        } catch (error) {
          showToast('Failed to delete key: ' + error.message, 'error');
        }
      }
    );
  }

  async function acceptAllKeys() {
    showConfirmModal(
      'Accept All Pending Keys',
      'Are you sure you want to accept all pending minion keys?',
      async () => {
        try {
          const result = await api('/api/devices/keys/accept-all', {
            method: 'POST'
          });
          showToast(`Accepted ${result.accepted.length} keys`, 'success');
          loadKeys();
          loadDevices(true);
        } catch (error) {
          showToast('Failed to accept keys: ' + error.message, 'error');
        }
      }
    );
  }

  // Expose key functions to window for onclick handlers
  window.acceptKey = acceptKey;
  window.rejectKey = rejectKey;
  window.deleteKey = deleteKey;

  // ============================================================
  // Services Management
  // ============================================================

  function populateSingleDeviceSelects() {
    const selects = [
      document.getElementById('cmd-single-target'),
      document.getElementById('script-single-target'),
      document.getElementById('state-single-target'),
      document.getElementById('playbook-single-target'),
      document.getElementById('svc-single-target'),
      document.getElementById('proc-single-target'),
      document.getElementById('net-single-target'),
      document.getElementById('files-single-target'),
      document.getElementById('logs-single-target'),
      document.getElementById('susp-single-target'),
      document.getElementById('pwd-single-target'),
      document.getElementById('emergency-single-target')
    ];

    selects.forEach(select => {
      if (!select) return;
      const currentValue = select.value;
      select.innerHTML = '<option value="">Select device...</option>' +
        state.devices.map(d => `<option value="${escapeHtml(d.id)}">${escapeHtml(d.id)} (${escapeHtml(d.os || 'unknown')})</option>`).join('');
      select.value = currentValue;
    });
  }

  // Store services data for filtering
  let servicesData = [];
  let currentServiceTarget = null;

  async function loadServices() {
    const outputEl = document.getElementById('svc-output');
    const listEl = document.getElementById('services-list');
    const countEl = document.getElementById('svc-count');

    const target = document.getElementById('svc-single-target').value;
    if (!target) {
      showToast('Please select a device first', 'warning');
      return;
    }

    currentServiceTarget = target;
    listEl.innerHTML = '<div class="loading">Loading services...</div>';

    try {
      // Get list of services
      const result = await api(`/api/services/${encodeURIComponent(target)}`);
      const services = result.services?.[target] || [];

      if (services.length === 0) {
        listEl.innerHTML = '<div class="loading">No services found</div>';
        countEl.textContent = '0 services';
        servicesData = [];
        return;
      }

      // Store and initialize services data with unknown status
      servicesData = services.map(svc => ({
        name: svc,
        status: 'unknown'
      }));

      countEl.textContent = `${servicesData.length} services`;
      renderServicesList();

      // Check status for important services in background
      checkServiceStatuses(target, services.slice(0, 50));

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
      servicesData = [];
    }
  }

  async function checkServiceStatuses(target, services) {
    // Check status in batches to avoid overwhelming the API
    const batchSize = 10;
    for (let i = 0; i < services.length; i += batchSize) {
      const batch = services.slice(i, i + batchSize);
      await Promise.all(batch.map(async (svc) => {
        try {
          const result = await api(`/api/services/${encodeURIComponent(target)}/${encodeURIComponent(svc)}/status`);
          const status = result.status?.[target];
          const svcData = servicesData.find(s => s.name === svc);
          if (svcData) {
            svcData.status = status === true ? 'running' : 'stopped';
            renderServicesList();
          }
        } catch (e) {
          // Ignore individual status check failures
        }
      }));
    }
  }

  function renderServicesList() {
    const listEl = document.getElementById('services-list');
    const countEl = document.getElementById('svc-count');
    const filterText = document.getElementById('svc-filter').value.toLowerCase();
    const runningOnly = document.getElementById('svc-running-only').checked;

    let filtered = servicesData;

    if (filterText) {
      filtered = filtered.filter(svc => svc.name.toLowerCase().includes(filterText));
    }

    if (runningOnly) {
      filtered = filtered.filter(svc => svc.status === 'running');
    }

    countEl.textContent = `${filtered.length} / ${servicesData.length} services`;

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="loading">No matching services</div>';
      return;
    }

    listEl.innerHTML = filtered.map(svc => `
      <div class="service-item" data-name="${escapeHtml(svc.name)}">
        <span class="service-name">${escapeHtml(svc.name)}</span>
        <span class="service-status ${svc.status}">${svc.status}</span>
      </div>
    `).join('');

    // Click to select
    listEl.querySelectorAll('.service-item').forEach(item => {
      item.addEventListener('click', () => {
        listEl.querySelectorAll('.service-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        document.getElementById('svc-name').value = item.dataset.name;
      });
    });
  }

  async function serviceAction(action) {
    const service = document.getElementById('svc-name').value.trim();
    const outputEl = document.getElementById('svc-output');

    if (!service) {
      showToast('Enter a service name', 'warning');
      return;
    }

    const target = document.getElementById('svc-single-target').value;
    if (!target) {
      showToast('Please select a device first', 'warning');
      return;
    }
    const targets = [target];

    outputEl.textContent = `${action}ing service ${service}...`;

    try {
      const result = await api(`/api/services/${action}`, {
        method: 'POST',
        body: JSON.stringify({ targets, service })
      });

      let output = `Action: ${action}\nService: ${service}\n\n`;
      for (const [minion, data] of Object.entries(result.results || {})) {
        output += `-- ${minion} --\n`;
        output += typeof data === 'boolean' ? (data ? 'Success' : 'Failed') : JSON.stringify(data, null, 2);
        output += '\n\n';
      }
      outputEl.textContent = output;
      showToast(`Service ${action} completed`, 'success');

    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast(`Service ${action} failed`, 'error');
    }
  }

  // ============================================================
  // Process Management
  // ============================================================

  // Store process data for filtering
  let processesData = [];
  let currentProcessTarget = null;

  async function loadProcesses() {
    const outputEl = document.getElementById('proc-output');
    const listEl = document.getElementById('processes-list');
    const countEl = document.getElementById('proc-count');
    const limit = document.getElementById('proc-limit').value;

    const target = document.getElementById('proc-single-target').value;
    if (!target) {
      showToast('Please select a device first', 'warning');
      return;
    }

    listEl.innerHTML = '<div class="loading">Loading processes...</div>';
    currentProcessTarget = target;
    document.getElementById('proc-filter').value = '';

    try {
      const result = await api(`/api/processes/${encodeURIComponent(target)}?limit=${limit}`);
      const processes = result.processes?.[target];

      if (!processes || !Array.isArray(processes)) {
        listEl.innerHTML = '<div class="loading">No process data</div>';
        countEl.textContent = '0 processes';
        processesData = [];
        return;
      }

      // Normalize process data for storage
      processesData = processes.map(p => {
        const pid = p.pid || p.PID || '?';

        // Handle Salt's nested cpu object {user, system, ...}
        let cpu = '?';
        if (typeof p.cpu === 'object' && p.cpu !== null) {
          const cpuTotal = (p.cpu.user || 0) + (p.cpu.system || 0);
          cpu = cpuTotal.toFixed(1);
        } else if (typeof p.cpu_percent === 'number') {
          cpu = p.cpu_percent.toFixed(1);
        } else if (typeof p.cpu === 'number') {
          cpu = p.cpu.toFixed(1);
        }

        // Handle Salt's nested mem object {rss, vms, ...}
        let mem = '?';
        if (typeof p.mem === 'object' && p.mem !== null) {
          const memMB = Math.round((p.mem.rss || 0) / (1024 * 1024));
          mem = memMB.toString();
        } else if (typeof p.mem_percent === 'number') {
          mem = p.mem_percent.toFixed(1) + '%';
        } else if (typeof p.mem === 'number') {
          mem = p.mem.toString();
        }

        // Handle cmd as array or string
        let cmd = '?';
        if (Array.isArray(p.cmd)) {
          cmd = p.cmd.join(' ');
        } else if (p.cmd) {
          cmd = p.cmd;
        } else if (p.name) {
          cmd = p.name;
        } else if (p.cmdline) {
          cmd = p.cmdline;
        } else if (p.command) {
          cmd = p.command;
        }

        // Get user/owner if available
        const user = p.user || p.username || '';

        return { pid, cpu, mem, cmd: String(cmd), user };
      });

      renderProcessesList();

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
      processesData = [];
    }
  }

  function renderProcessesList() {
    const listEl = document.getElementById('processes-list');
    const countEl = document.getElementById('proc-count');
    const filterText = document.getElementById('proc-filter').value.toLowerCase();

    let filtered = processesData;

    if (filterText) {
      filtered = filtered.filter(p =>
        p.cmd.toLowerCase().includes(filterText) ||
        String(p.pid).includes(filterText) ||
        p.user.toLowerCase().includes(filterText)
      );
    }

    countEl.textContent = `${filtered.length} / ${processesData.length} processes`;

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="loading">No matching processes</div>';
      return;
    }

    let html = '<div class="process-header">PID | USER | CPU | MEM | COMMAND</div>';
    filtered.forEach(p => {
      const userDisplay = p.user ? p.user.substring(0, 10) : '-';
      html += `<div class="process-item" data-pid="${p.pid}">${p.pid} | ${userDisplay} | ${p.cpu} | ${p.mem} | ${escapeHtml(p.cmd.substring(0, 60))}</div>`;
    });

    listEl.innerHTML = html;

    // Click to select PID
    listEl.querySelectorAll('.process-item').forEach(item => {
      item.addEventListener('click', () => {
        listEl.querySelectorAll('.process-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
        document.getElementById('proc-pid').value = item.dataset.pid;
      });
    });
  }

  async function killProcess() {
    const pid = document.getElementById('proc-pid').value.trim();
    const outputEl = document.getElementById('proc-output');

    if (!pid) {
      showToast('Enter a PID', 'warning');
      return;
    }

    const target = document.getElementById('proc-single-target').value;
    if (!target) {
      showToast('Please select a device first', 'warning');
      return;
    }
    const targets = [target];

    outputEl.textContent = `Killing process ${pid}...`;

    try {
      const result = await api('/api/processes/kill', {
        method: 'POST',
        body: JSON.stringify({ targets, pid: parseInt(pid), signal: 9 })
      });

      outputEl.textContent = JSON.stringify(result.results, null, 2);
      showToast('Kill signal sent', 'success');

    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Kill failed', 'error');
    }
  }

  async function pkillProcess() {
    const pattern = document.getElementById('proc-pattern').value.trim();
    const outputEl = document.getElementById('proc-output');

    if (!pattern) {
      showToast('Enter a process name pattern', 'warning');
      return;
    }

    const target = document.getElementById('proc-single-target').value;
    if (!target) {
      showToast('Please select a device first', 'warning');
      return;
    }
    const targets = [target];

    showConfirmModal(
      'Confirm Kill',
      `Kill all processes matching "${pattern}"?`,
      async () => {
        outputEl.textContent = `Killing processes matching ${pattern}...`;

        try {
          const result = await api('/api/processes/pkill', {
            method: 'POST',
            body: JSON.stringify({ targets, pattern, signal: 9 })
          });

          outputEl.textContent = JSON.stringify(result.results, null, 2);
          showToast('Kill signal sent', 'success');

        } catch (error) {
          outputEl.textContent = `Error: ${error.message}`;
          showToast('Kill failed', 'error');
        }
      }
    );
  }

  // ============================================================
  // Network Connections
  // ============================================================

  // Store network data for filtering
  let networkData = [];
  let currentNetworkTarget = null;

  async function loadNetworkConnections() {
    const listEl = document.getElementById('network-list');
    const countEl = document.getElementById('net-count');
    const connType = document.getElementById('net-type').value;

    const target = document.getElementById('net-single-target').value;
    if (!target) {
      showToast('Please select a device first', 'warning');
      return;
    }

    listEl.innerHTML = '<div class="loading">Loading network connections...</div>';
    currentNetworkTarget = target;
    document.getElementById('net-filter').value = '';

    try {
      const endpoint = connType === 'listening'
        ? `/api/network/${encodeURIComponent(target)}/listening`
        : `/api/network/${encodeURIComponent(target)}`;

      const result = await api(endpoint);

      if (connType === 'listening') {
        networkData = (result.listening || []).map(p => ({
          protocol: p.protocol || 'tcp',
          state: 'LISTEN',
          local: `${p.address}:${p.port}`,
          remote: '*',
          process: p.process || ''
        }));
      } else {
        networkData = (result.connections || []).map(c => ({
          protocol: c.protocol || 'tcp',
          state: c.state || 'UNKNOWN',
          local: c.local || '',
          remote: c.remote || '',
          process: c.process || ''
        }));
      }

      renderNetworkList();

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
      networkData = [];
    }
  }

  function renderNetworkList() {
    const listEl = document.getElementById('network-list');
    const countEl = document.getElementById('net-count');
    const filterText = document.getElementById('net-filter').value.toLowerCase();

    let filtered = networkData;

    if (filterText) {
      filtered = filtered.filter(c =>
        c.local.toLowerCase().includes(filterText) ||
        c.remote.toLowerCase().includes(filterText) ||
        c.process.toLowerCase().includes(filterText) ||
        c.state.toLowerCase().includes(filterText)
      );
    }

    countEl.textContent = `${filtered.length} / ${networkData.length} connections`;

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="loading">No matching connections</div>';
      return;
    }

    let html = '<div class="network-header"><span>STATE</span><span>PROTO</span><span>LOCAL</span><span>REMOTE</span><span>PROCESS</span></div>';
    filtered.forEach(c => {
      const stateClass = c.state === 'LISTEN' || c.state === 'LISTENING'
        ? 'state-listen'
        : c.state === 'ESTABLISHED' || c.state === 'ESTAB'
          ? 'state-established'
          : 'state-other';

      html += `<div class="network-item">
        <span class="${stateClass}">${escapeHtml(c.state)}</span>
        <span>${escapeHtml(c.protocol)}</span>
        <span>${escapeHtml(c.local)}</span>
        <span>${escapeHtml(c.remote)}</span>
        <span>${escapeHtml(c.process)}</span>
      </div>`;
    });

    listEl.innerHTML = html;
  }

  // ============================================================
  // File Browser
  // ============================================================

  let currentFilesTarget = null;
  let currentFilesPath = '/';

  async function browseFiles() {
    const target = document.getElementById('files-single-target').value;
    const path = document.getElementById('files-path').value.trim() || '/';
    const listEl = document.getElementById('files-list');

    if (!target) {
      showToast('Select a device', 'warning');
      return;
    }

    listEl.innerHTML = '<div class="loading">Loading files...</div>';
    currentFilesTarget = target;
    currentFilesPath = path;

    try {
      const result = await api(`/api/files/${encodeURIComponent(target)}/list?path=${encodeURIComponent(path)}`);

      if (!result.files || result.files.length === 0) {
        listEl.innerHTML = '<div class="loading">No files found or access denied</div>';
        return;
      }

      renderFilesList(result.files);

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderFilesList(files) {
    const listEl = document.getElementById('files-list');

    if (!files || files.length === 0) {
      listEl.innerHTML = '<div class="loading">No files</div>';
      return;
    }

    let html = '';
    files.forEach(f => {
      const typeClass = f.type === 'directory' ? 'directory' : 'file';
      const sizeStr = f.type === 'directory' ? '-' : formatFileSize(f.size);

      html += `<div class="file-item ${typeClass}" data-name="${escapeHtml(f.name)}" data-type="${f.type}">
        <span class="file-name">${escapeHtml(f.name)}</span>
        <span class="file-size">${sizeStr}</span>
        <span class="file-perms">${escapeHtml(f.permissions || '-')}</span>
      </div>`;
    });

    listEl.innerHTML = html;

    // Add click handlers
    listEl.querySelectorAll('.file-item').forEach(item => {
      item.addEventListener('dblclick', () => {
        const name = item.dataset.name;
        const type = item.dataset.type;

        if (type === 'directory') {
          // Navigate into directory
          const newPath = currentFilesPath === '/'
            ? `/${name}`
            : `${currentFilesPath}/${name}`;
          document.getElementById('files-path').value = newPath;
          browseFiles();
        } else {
          // Open file for editing
          openFile(name);
        }
      });

      item.addEventListener('click', () => {
        listEl.querySelectorAll('.file-item').forEach(i => i.classList.remove('selected'));
        item.classList.add('selected');
      });
    });
  }

  function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function navigateUp() {
    if (currentFilesPath === '/' || currentFilesPath === '') return;

    const parts = currentFilesPath.split('/').filter(p => p);
    parts.pop();
    const newPath = parts.length === 0 ? '/' : '/' + parts.join('/');

    document.getElementById('files-path').value = newPath;
    browseFiles();
  }

  async function openFile(name) {
    const editorPanel = document.getElementById('files-editor-panel');
    const editorPath = document.getElementById('files-editor-path');
    const editor = document.getElementById('files-editor');

    const filePath = currentFilesPath === '/'
      ? `/${name}`
      : `${currentFilesPath}/${name}`;

    editorPanel.classList.remove('hidden');
    editorPath.textContent = filePath;
    editor.value = 'Loading...';

    try {
      const result = await api(`/api/files/${encodeURIComponent(currentFilesTarget)}/read?path=${encodeURIComponent(filePath)}`);

      if (result.truncated) {
        editor.value = `File too large. Size: ${formatFileSize(result.size)}`;
        showToast('File too large to display', 'warning');
      } else {
        editor.value = result.content || '';
      }
    } catch (error) {
      editor.value = `Error: ${error.message}`;
      showToast('Failed to read file', 'error');
    }
  }

  async function saveFile() {
    const editorPath = document.getElementById('files-editor-path').textContent;
    const editor = document.getElementById('files-editor');

    if (!editorPath || editorPath === 'No file selected') {
      showToast('No file selected', 'warning');
      return;
    }

    showConfirmModal(
      'Confirm Save',
      `Save changes to ${editorPath}?`,
      async () => {
        try {
          const result = await api(`/api/files/${encodeURIComponent(currentFilesTarget)}/write`, {
            method: 'POST',
            body: JSON.stringify({
              path: editorPath,
              content: editor.value,
              backup: true
            })
          });

          showToast('File saved successfully', 'success');
        } catch (error) {
          showToast(`Failed to save: ${error.message}`, 'error');
        }
      }
    );
  }

  function closeFileEditor() {
    document.getElementById('files-editor-panel').classList.add('hidden');
    document.getElementById('files-editor').value = '';
    document.getElementById('files-editor-path').textContent = 'No file selected';
  }

  // ============================================================
  // Log Viewer
  // ============================================================

  let logsData = [];
  let currentLogsTarget = null;
  let currentLogSources = [];
  let logTailEventSource = null;

  async function loadLogSources() {
    const target = document.getElementById('logs-single-target').value;
    const sourceSelect = document.getElementById('logs-source');

    if (!target) {
      sourceSelect.innerHTML = '<option value="">Select device first...</option>';
      currentLogSources = [];
      return;
    }

    try {
      const result = await api(`/api/logs/sources/${encodeURIComponent(target)}`);

      currentLogSources = result.sources || [];

      let options = '<option value="">Select log source...</option>';
      currentLogSources.forEach((src, i) => {
        const value = src.type === 'event' ? `event:${src.log}` : src.path;
        options += `<option value="${escapeHtml(value)}">${escapeHtml(src.name)}</option>`;
      });

      sourceSelect.innerHTML = options;

    } catch (error) {
      sourceSelect.innerHTML = '<option value="">Error loading sources</option>';
    }
  }

  async function loadLogs() {
    const target = document.getElementById('logs-single-target').value;
    const source = document.getElementById('logs-source').value;
    const lines = document.getElementById('logs-lines').value;
    const contentEl = document.getElementById('logs-content');
    const countEl = document.getElementById('logs-count');

    if (!target) {
      showToast('Select a device', 'warning');
      return;
    }

    if (!source) {
      showToast('Select a log source', 'warning');
      return;
    }

    contentEl.innerHTML = '<div class="loading">Loading logs...</div>';
    currentLogsTarget = target;
    document.getElementById('logs-filter').value = '';

    try {
      let result;

      if (source.startsWith('event:')) {
        // Windows event log
        const logName = source.replace('event:', '');
        result = await api(`/api/logs/${encodeURIComponent(target)}/events?log=${encodeURIComponent(logName)}&count=${lines}`);
        logsData = (result.events || []).map(e => {
          if (e.raw) return e.raw;
          const time = e.TimeGenerated ? new Date(e.TimeGenerated).toLocaleString() : '';
          return `[${time}] [${e.EntryType || ''}] ${e.Source || ''}: ${e.Message || ''}`;
        });
      } else {
        // File-based log
        result = await api(`/api/logs/${encodeURIComponent(target)}/read?path=${encodeURIComponent(source)}&lines=${lines}`);
        logsData = result.lines || [];
      }

      renderLogsList();

    } catch (error) {
      contentEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
      logsData = [];
    }
  }

  function renderLogsList() {
    const contentEl = document.getElementById('logs-content');
    const countEl = document.getElementById('logs-count');
    const filterText = document.getElementById('logs-filter').value.toLowerCase();

    let filtered = logsData;

    if (filterText) {
      filtered = filtered.filter(line =>
        line.toLowerCase().includes(filterText)
      );
    }

    countEl.textContent = `${filtered.length} / ${logsData.length} lines`;

    if (filtered.length === 0) {
      contentEl.innerHTML = '<div class="loading">No matching log lines</div>';
      return;
    }

    // Color-code lines based on content
    const html = filtered.map(line => {
      let lineClass = '';
      const lower = line.toLowerCase();
      if (lower.includes('error') || lower.includes('fail') || lower.includes('crit')) {
        lineClass = 'error';
      } else if (lower.includes('warn')) {
        lineClass = 'warning';
      } else if (lower.includes('info')) {
        lineClass = 'info';
      }
      return `<div class="log-line ${lineClass}">${escapeHtml(line)}</div>`;
    }).join('');

    contentEl.innerHTML = html;
  }

  function startLogTail() {
    const target = document.getElementById('logs-single-target').value;
    const source = document.getElementById('logs-source').value;
    const contentEl = document.getElementById('logs-content');
    const indicator = document.getElementById('logs-tail-indicator');
    const tailBtn = document.getElementById('logs-tail-btn');

    if (!target) { showToast('Select a device', 'warning'); return; }
    if (!source || source.startsWith('event:')) { showToast('Select a file-based log source', 'warning'); return; }

    // Stop any existing tail
    stopLogTail();

    contentEl.innerHTML = '<div class="loading">Starting live tail...</div>';
    indicator.classList.remove('hidden');
    tailBtn.textContent = 'Stop Tail';
    tailBtn.classList.add('btn-danger');

    const url = `${API_BASE}/api/logs/${encodeURIComponent(target)}/tail?path=${encodeURIComponent(source)}&lines=50`;
    const es = new EventSource(url, { withCredentials: true });
    logTailEventSource = es;
    let firstBatch = true;

    es.addEventListener('lines', (e) => {
      const data = JSON.parse(e.data);
      if (firstBatch) {
        contentEl.innerHTML = '';
        firstBatch = false;
      }
      for (const line of data.lines) {
        const div = document.createElement('div');
        div.className = 'log-line';
        const lower = line.toLowerCase();
        if (lower.includes('error') || lower.includes('fail') || lower.includes('crit')) {
          div.classList.add('error');
        } else if (lower.includes('warn')) {
          div.classList.add('warning');
        }
        div.textContent = line;
        contentEl.appendChild(div);
      }
      // Auto-scroll to bottom
      contentEl.scrollTop = contentEl.scrollHeight;
      // Update line count
      const countEl = document.getElementById('logs-count');
      if (countEl) countEl.textContent = `${contentEl.children.length} lines (live)`;
    });

    es.addEventListener('status', (e) => {
      const data = JSON.parse(e.data);
      if (data.status === 'timeout') {
        stopLogTail();
        showToast('Live tail timed out (30 min limit)', 'warning');
      }
    });

    es.addEventListener('error', () => {
      stopLogTail();
      showToast('Live tail connection lost', 'error');
    });

    es.onerror = () => {
      stopLogTail();
    };
  }

  function stopLogTail() {
    if (logTailEventSource) {
      logTailEventSource.close();
      logTailEventSource = null;
    }
    const indicator = document.getElementById('logs-tail-indicator');
    const tailBtn = document.getElementById('logs-tail-btn');
    if (indicator) indicator.classList.add('hidden');
    if (tailBtn) {
      tailBtn.textContent = 'Live Tail';
      tailBtn.classList.remove('btn-danger');
    }
  }

  function toggleLogTail() {
    if (logTailEventSource) {
      stopLogTail();
    } else {
      startLogTail();
    }
  }

  // ============================================================
  // Suspicious Items Scanner
  // ============================================================

  let suspiciousData = [];

  async function scanSuspicious(quick = false) {
    const targetType = document.getElementById('susp-target-type').value;
    const listEl = document.getElementById('suspicious-list');
    const countEl = document.getElementById('susp-count');

    let targets;
    if (targetType === 'selected') {
      const selectedDevices = getInlineSelectorSelection('susp');
      if (selectedDevices.length === 0) {
        showToast('No devices selected', 'warning');
        return;
      }
      targets = selectedDevices;
    } else {
      const target = document.getElementById('susp-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return;
      }
      targets = [target];
    }

    listEl.innerHTML = '<div class="loading">Scanning for suspicious items...</div>';
    suspiciousData = [];

    try {
      if (quick) {
        // Quick scan one at a time
        for (const target of targets) {
          const result = await api(`/api/suspicious/quick/${encodeURIComponent(target)}`);
          if (result.suspicious) {
            result.suspicious.forEach(item => {
              item.target = target;
              suspiciousData.push(item);
            });
          }
        }
      } else {
        // Full scan
        const result = await api('/api/suspicious/scan', {
          method: 'POST',
          body: JSON.stringify({ targets })
        });

        for (const [target, data] of Object.entries(result.results || {})) {
          if (data.suspicious) {
            data.suspicious.forEach(item => {
              item.target = target;
              suspiciousData.push(item);
            });
          }
        }
      }

      // Sort by severity
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      suspiciousData.sort((a, b) =>
        (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4)
      );

      renderSuspiciousList();

    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderSuspiciousList() {
    const listEl = document.getElementById('suspicious-list');
    const countEl = document.getElementById('susp-count');
    const severityFilter = document.getElementById('susp-severity-filter').value;

    let filtered = suspiciousData;

    if (severityFilter) {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const threshold = severityOrder[severityFilter] || 4;
      filtered = filtered.filter(item =>
        (severityOrder[item.severity] || 4) <= threshold
      );
    }

    countEl.textContent = `${filtered.length} / ${suspiciousData.length} findings`;

    if (filtered.length === 0) {
      listEl.innerHTML = suspiciousData.length === 0
        ? '<div class="loading">No suspicious items found</div>'
        : '<div class="loading">No matching findings</div>';
      return;
    }

    let html = '';
    filtered.forEach(item => {
      html += `<div class="suspicious-item">
        <div class="suspicious-header">
          <span class="suspicious-category">${escapeHtml(item.category)}</span>
          <span class="suspicious-severity ${item.severity}">${item.severity}</span>
        </div>
        <div class="suspicious-finding">${escapeHtml(item.finding)}</div>
        <div class="suspicious-details">${escapeHtml(item.details || 'No details')}</div>
        <div class="suspicious-remediation">${escapeHtml(item.remediation || '')}</div>
        <div class="suspicious-target">Target: ${escapeHtml(item.target)}</div>
      </div>`;
    });

    listEl.innerHTML = html;
  }

  // ============================================================
  // Reports
  // ============================================================

  let currentReportData = null;

  async function generateStatusReport() {
    const contentEl = document.getElementById('report-content');
    contentEl.textContent = 'Generating status report...';

    try {
      const result = await api('/api/reports/status');
      currentReportData = result.report;

      let output = `=== SYSTEM STATUS REPORT ===\n`;
      output += `Generated: ${result.report.generated}\n\n`;

      output += `SUMMARY\n`;
      output += `-------\n`;
      output += `Total Minions: ${result.report.summary.total}\n`;
      output += `Online: ${result.report.summary.online}\n`;
      output += `Offline: ${result.report.summary.offline}\n`;
      output += `Linux: ${result.report.summary.linux}\n`;
      output += `Windows: ${result.report.summary.windows}\n\n`;

      output += `MINION DETAILS\n`;
      output += `--------------\n`;
      for (const m of result.report.minions) {
        const status = m.status === 'online' ? '[ONLINE]' : '[OFFLINE]';
        output += `${status} ${m.id}\n`;
        output += `  OS: ${m.os} (${m.osFamily})\n`;
        output += `  Kernel: ${m.kernel}\n`;
        output += `  IP: ${m.ip}\n\n`;
      }

      contentEl.textContent = output;
      showToast('Status report generated', 'success');

    } catch (error) {
      contentEl.textContent = `Error: ${error.message}`;
      showToast('Failed to generate report', 'error');
    }
  }

  async function generateAuditReport() {
    const contentEl = document.getElementById('report-content');
    const hours = document.getElementById('report-audit-hours').value;
    contentEl.textContent = 'Generating audit report...';

    try {
      const result = await api(`/api/reports/audit?hours=${hours}`);
      currentReportData = result.report;

      let output = `=== AUDIT ACTIVITY REPORT ===\n`;
      output += `Generated: ${result.report.generated}\n`;
      output += `Period: ${result.report.period}\n\n`;

      output += `SUMMARY\n`;
      output += `-------\n`;
      output += `Total Actions: ${result.report.summary.totalActions}\n\n`;

      output += `Actions by Type:\n`;
      for (const [action, count] of Object.entries(result.report.summary.byAction)) {
        output += `  ${action}: ${count}\n`;
      }

      output += `\nActions by User:\n`;
      for (const [user, count] of Object.entries(result.report.summary.byUser)) {
        output += `  ${user}: ${count}\n`;
      }

      output += `\nRECENT ACTIVITY (Last 50)\n`;
      output += `-------------------------\n`;
      for (const entry of result.report.entries.slice(0, 50)) {
        const time = new Date(entry.timestamp).toLocaleString();
        output += `[${time}] ${entry.user || 'unknown'}: ${entry.action || 'unknown'}\n`;
        if (entry.targets) {
          output += `  Targets: ${entry.targets.join(', ')}\n`;
        }
      }

      contentEl.textContent = output;
      showToast('Audit report generated', 'success');

    } catch (error) {
      contentEl.textContent = `Error: ${error.message}`;
      showToast('Failed to generate report', 'error');
    }
  }

  async function generateSecurityReport() {
    const contentEl = document.getElementById('report-content');
    const targetSelect = document.getElementById('report-security-target');
    const target = targetSelect.value;

    if (!target) {
      showToast('Select a target', 'warning');
      return;
    }

    contentEl.textContent = 'Generating security report (this may take a while)...';

    try {
      const targets = target === '*'
        ? state.devices.map(d => d.id)
        : [target];

      const result = await api('/api/reports/security', {
        method: 'POST',
        body: JSON.stringify({ targets })
      });

      currentReportData = result.report;

      let output = `=== SECURITY SCAN REPORT ===\n`;
      output += `Generated: ${result.report.generated}\n`;
      output += `Targets Scanned: ${result.report.targets.length}\n\n`;

      output += `SUMMARY\n`;
      output += `-------\n`;
      output += `Critical: ${result.report.summary.critical}\n`;
      output += `High: ${result.report.summary.high}\n`;
      output += `Medium: ${result.report.summary.medium}\n`;
      output += `Low: ${result.report.summary.low}\n`;
      output += `Total Findings: ${result.report.summary.total}\n\n`;

      output += `FINDINGS BY TARGET\n`;
      output += `------------------\n`;
      for (const [target, data] of Object.entries(result.report.findings)) {
        output += `\n[${target}] (${data.kernel})\n`;
        output += `Scanned: ${data.scanned}\n`;

        if (data.findings.length === 0) {
          output += `  No suspicious items found.\n`;
        } else {
          for (const f of data.findings) {
            output += `  [${f.severity.toUpperCase()}] ${f.category}: ${f.finding}\n`;
            if (f.details) {
              output += `    Details: ${f.details.substring(0, 100)}...\n`;
            }
          }
        }
      }

      contentEl.textContent = output;
      showToast('Security report generated', 'success');

    } catch (error) {
      contentEl.textContent = `Error: ${error.message}`;
      showToast('Failed to generate report', 'error');
    }
  }

  function copyReport() {
    const content = document.getElementById('report-content').textContent;
    navigator.clipboard.writeText(content).then(() => {
      showToast('Report copied to clipboard', 'success');
    }).catch(() => {
      showToast('Failed to copy', 'error');
    });
  }

  function downloadReport() {
    const content = document.getElementById('report-content').textContent;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `salt-gui-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Report downloaded', 'success');
  }

  async function generateComprehensiveReport() {
    const target = document.getElementById('report-comprehensive-target').value;
    if (!target) { showToast('Select a target', 'warning'); return; }

    const contentEl = document.getElementById('report-content');
    contentEl.textContent = 'Generating comprehensive report...';

    try {
      const targets = target === '*' ? '*' : [target];
      const result = await api('/api/reports/comprehensive', {
        method: 'POST',
        body: JSON.stringify({ targets })
      });

      const report = result.report;
      let output = `=== Comprehensive System Report ===\nGenerated: ${report.generated}\n\n`;

      for (const [minion, data] of Object.entries(report.minions)) {
        output += `${'='.repeat(60)}\n  ${minion}\n${'='.repeat(60)}\n\n`;
        output += `--- System Status ---\n${data.status}\n\n`;
        output += `--- Users ---\n${data.users}\n\n`;
        output += `--- Running Services ---\n${data.running_services}\n\n`;
        output += `--- Top Processes ---\n${data.top_processes}\n\n`;
        output += `--- Listening Ports ---\n${data.listening_ports}\n\n`;
        output += `--- Log Files ---\n${data.log_files}\n\n`;
      }

      contentEl.textContent = output;

      // Auto-download JSON
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `comprehensive-report-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast('Comprehensive report generated and downloaded', 'success');
    } catch (error) {
      contentEl.textContent = `Error: ${error.message}`;
      showToast('Report generation failed', 'error');
    }
  }

  function populateSecurityTargetSelect() {
    const opts = '<option value="">Select target...</option>' +
      '<option value="*">All Minions</option>' +
      state.devices.map(d =>
        `<option value="${escapeHtml(d.id)}">${escapeHtml(d.id)}</option>`
      ).join('');

    const select = document.getElementById('report-security-target');
    select.innerHTML = opts;

    const compSelect = document.getElementById('report-comprehensive-target');
    if (compSelect) compSelect.innerHTML = opts;
  }

  // ============================================================
  // User Management
  // ============================================================

  // Helper to get targets from user management panel
  function getUserManagementTargets() {
    const targetType = document.getElementById('pwd-target-type').value;
    let targets;

    if (targetType === 'selected') {
      if (state.selectedDevices.size === 0) {
        showToast('No devices selected. Select devices from the list above.', 'warning');
        return null;
      }
      targets = Array.from(state.selectedDevices);
    } else if (targetType === 'single') {
      const target = document.getElementById('pwd-single-target').value;
      if (!target) {
        showToast('Select a device', 'warning');
        return null;
      }
      targets = [target];
    } else if (targetType === 'all') {
      targets = '*';
    } else {
      targets = document.getElementById('pwd-custom-target').value.trim();
      if (!targets) {
        showToast('Enter custom target pattern', 'warning');
        return null;
      }
    }

    return targets;
  }

  // Update shell selector visibility based on target OS
  function updateShellSelectorVisibility() {
    const targetType = document.getElementById('pwd-target-type').value;
    const shellGroup = document.getElementById('create-shell-group');
    const windowsNotice = document.getElementById('create-shell-windows-notice');

    if (!shellGroup || !windowsNotice) return;

    let allWindows = false;
    let hasTargets = false;

    if (targetType === 'selected') {
      if (state.selectedDevices.size > 0) {
        hasTargets = true;
        // Check if all selected devices are Windows
        allWindows = Array.from(state.selectedDevices).every(id => {
          const device = state.devices.find(d => d.id === id);
          return device && device.kernel === 'Windows';
        });
      }
    } else if (targetType === 'single') {
      const target = document.getElementById('pwd-single-target').value;
      if (target) {
        hasTargets = true;
        const device = state.devices.find(d => d.id === target);
        allWindows = device && device.kernel === 'Windows';
      }
    } else if (targetType === 'all') {
      hasTargets = state.devices.length > 0;
      // Check if all devices are Windows
      allWindows = state.devices.length > 0 && state.devices.every(d => d.kernel === 'Windows');
    }
    // For custom pattern, we can't easily determine OS, so show shell selector

    if (hasTargets && allWindows) {
      shellGroup.classList.add('hidden');
      windowsNotice.classList.remove('hidden');
    } else {
      shellGroup.classList.remove('hidden');
      windowsNotice.classList.add('hidden');
    }
  }

  // Toggle create user panel
  function toggleCreateUserPanel() {
    const panel = document.getElementById('create-user-panel');
    panel.classList.toggle('hidden');
  }

  // Toggle system users visibility
  function toggleSystemUsers() {
    const showSystem = document.getElementById('show-system-users').checked;
    document.querySelectorAll('.users-table').forEach(table => {
      table.classList.toggle('show-system', showSystem);
    });
  }

  // List users on selected targets
  async function listUsers() {
    const targets = getUserManagementTargets();
    if (!targets) return;

    const outputEl = document.getElementById('pwd-output');
    const resultsEl = document.getElementById('users-list-results');
    const showSystem = document.getElementById('show-system-users').checked;

    outputEl.textContent = 'Loading users...';
    resultsEl.innerHTML = '<div class="loading">Loading users...</div>';

    try {
      const result = await api('/api/users/list', {
        method: 'POST',
        body: JSON.stringify({ targets })
      });

      let output = '';
      let html = '';

      for (const [minion, data] of Object.entries(result.results)) {
        output += `== ${minion} ==\n`;

        if (data.success) {
          html += `<div class="users-minion-section" data-minion="${minion}">`;
          html += `<div class="users-minion-header">`;
          html += `<span>${minion}</span>`;
          html += `<span class="kernel-badge">${data.kernel}</span>`;
          if (data.isDC) html += `<span class="kernel-badge dc-badge">DC</span>`;
          html += `</div>`;
          html += `<table class="users-table${showSystem ? ' show-system' : ''}">`;
          html += `<thead><tr>`;
          const isWindows = data.kernel === 'Windows';
          const isDC = data.isDC || false;
          if (isWindows) {
            html += `<th>Username</th><th>Status</th><th>${isDC ? 'Domain Admin' : 'Admin'}</th><th>Last Logon</th><th>Actions</th>`;
          } else {
            html += `<th>Username</th><th>UID</th><th>Status</th><th>Sudo</th><th>Shell</th><th>Actions</th>`;
          }
          html += `</tr></thead><tbody>`;

          const users = data.users || [];
          // Sort: regular users first, then system users
          users.sort((a, b) => {
            if (a.isSystem && !b.isSystem) return 1;
            if (!a.isSystem && b.isSystem) return -1;
            return a.username.localeCompare(b.username);
          });

          for (const user of users) {
            const rowClass = [];
            if (user.isSystem) rowClass.push('system-user');
            if (!user.enabled) rowClass.push('disabled-user');

            output += isWindows ? `  ${user.username}` : `  ${user.username} (UID: ${user.uid})`;
            output += user.enabled ? '' : ' [DISABLED]';
            output += user.hasSudo ? (isDC ? ' [DOMAIN ADMIN]' : isWindows ? ' [ADMIN]' : ' [SUDO]') : '';
            output += '\n';

            // Build action buttons
            let actions = '';
            const sudoLabel = isDC ? 'Domain Admin' : isWindows ? 'Admin' : 'Sudo';
            if (!user.isSystem || user.username === 'root') {
              if (user.enabled) {
                actions += `<button class="btn btn-action-disable" onclick="userAction('disable', '${minion}', '${user.username}')">Disable</button>`;
              } else {
                actions += `<button class="btn btn-action-enable" onclick="userAction('enable', '${minion}', '${user.username}')">Enable</button>`;
              }
              if (user.hasSudo) {
                actions += `<button class="btn btn-action-sudo" onclick="userAction('revoke-sudo', '${minion}', '${user.username}')">-${sudoLabel}</button>`;
              } else {
                actions += `<button class="btn btn-action-sudo" onclick="userAction('grant-sudo', '${minion}', '${user.username}')">+${sudoLabel}</button>`;
              }
              actions += `<button class="btn btn-action-password" onclick="userAction('password', '${minion}', '${user.username}')">Password</button>`;
            }

            html += `<tr class="${rowClass.join(' ')}" data-username="${user.username}">`;
            html += `<td><strong>${user.username}</strong></td>`;
            if (isWindows) {
              html += `<td class="${user.enabled ? 'status-enabled' : 'status-disabled'}">${user.enabled ? 'Enabled' : 'Disabled'}</td>`;
              html += `<td class="${user.hasSudo ? 'has-sudo' : 'no-sudo'}">${user.hasSudo ? 'Yes' : 'No'}</td>`;
              html += `<td>${user.lastLogon || 'Never'}</td>`;
            } else {
              html += `<td>${user.uid}</td>`;
              html += `<td class="${user.enabled ? 'status-enabled' : 'status-disabled'}">${user.enabled ? 'Enabled' : 'Disabled'}</td>`;
              html += `<td class="${user.hasSudo ? 'has-sudo' : 'no-sudo'}">${user.hasSudo ? 'Yes' : 'No'}</td>`;
              html += `<td>${user.shell || 'N/A'}</td>`;
            }
            html += `<td class="user-actions">${actions}</td>`;
            html += `</tr>`;
          }

          html += `</tbody></table></div>`;
          output += '\n';
        } else {
          output += `  Error: ${data.error}\n\n`;
          html += `<div class="users-minion-section">`;
          html += `<div class="users-minion-header">${minion}</div>`;
          html += `<div style="padding: var(--spacing-sm); color: var(--status-error);">Error: ${data.error}</div>`;
          html += `</div>`;
        }
      }

      outputEl.textContent = output;
      resultsEl.innerHTML = html || '<div class="placeholder-text">No users found.</div>';
      showToast('Users loaded', 'success');

    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      resultsEl.innerHTML = `<div style="color: var(--status-error); padding: var(--spacing-md);">Error: ${error.message}</div>`;
      showToast('Failed to load users', 'error');
    }
  }

  // Handle user action from table buttons
  window.userAction = function(action, minion, username) {
    console.log('userAction called:', { action, minion, username });
    const outputEl = document.getElementById('pwd-output');

    if (action === 'password') {
      // Show password change modal
      showPasswordModal(minion, username);
      return;
    }

    let confirmTitle, confirmMessage, apiEndpoint, apiBody;

    switch (action) {
      case 'disable':
        confirmTitle = 'Disable User';
        confirmMessage = `Disable user "${username}" on ${minion}? This will lock the account and set shell to /sbin/nologin.`;
        apiEndpoint = '/api/users/disable';
        apiBody = { targets: [minion], username };
        break;
      case 'enable':
        confirmTitle = 'Enable User';
        confirmMessage = `Enable user "${username}" on ${minion}? This will unlock the account and restore the shell.`;
        apiEndpoint = '/api/users/enable';
        apiBody = { targets: [minion], username };
        break;
      case 'grant-sudo':
        confirmTitle = 'Grant Sudo Access';
        confirmMessage = `Grant sudo/admin access to user "${username}" on ${minion}?`;
        apiEndpoint = '/api/users/sudo';
        apiBody = { targets: [minion], username, grant: true };
        break;
      case 'revoke-sudo':
        confirmTitle = 'Revoke Sudo Access';
        confirmMessage = `Revoke sudo/admin access from user "${username}" on ${minion}?`;
        apiEndpoint = '/api/users/sudo';
        apiBody = { targets: [minion], username, grant: false };
        break;
      default:
        return;
    }

    showConfirmModal(confirmTitle, confirmMessage, async () => {
      outputEl.textContent = `Executing ${action} on ${username}...`;

      try {
        const result = await api(apiEndpoint, {
          method: 'POST',
          body: JSON.stringify(apiBody)
        });

        let output = `${confirmTitle}: ${username} on ${minion}\n\n`;
        const minionResult = result.results[minion];
        output += minionResult?.success ? `SUCCESS: ${minionResult.message}` : `FAILED: ${minionResult?.error || 'Unknown error'}`;

        outputEl.textContent = output;
        showToast(minionResult?.success ? `${action} successful` : `${action} failed`, minionResult?.success ? 'success' : 'error');

        // Refresh user list
        if (minionResult?.success) {
          listUsers();
        }

      } catch (error) {
        outputEl.textContent = `Error: ${error.message}`;
        showToast(`Failed to ${action}`, 'error');
      }
    });
  };

  // Show password change modal
  function showPasswordModal(minion, username) {
    const modal = document.getElementById('user-action-modal');
    const title = document.getElementById('user-action-title');
    const body = document.getElementById('user-action-body');

    title.textContent = `Change Password: ${username}`;
    body.innerHTML = `
      <p style="color: var(--text-secondary); font-size: 12px; margin-bottom: var(--spacing-sm);">
        Changing password on: <strong>${minion}</strong>
      </p>
      <div class="form-group">
        <label for="modal-password">New Password</label>
        <input type="password" id="modal-password" placeholder="8+ characters" minlength="8">
      </div>
      <div class="form-group">
        <label for="modal-confirm">Confirm Password</label>
        <input type="password" id="modal-confirm" placeholder="Confirm password">
      </div>
      <div class="form-actions">
        <button class="btn" onclick="closeUserActionModal()">Cancel</button>
        <button class="btn btn-primary" onclick="submitPasswordChange('${minion}', '${username}')">Change Password</button>
      </div>
    `;

    modal.classList.remove('hidden');
    document.getElementById('modal-password').focus();
  }

  // Close user action modal
  window.closeUserActionModal = function() {
    document.getElementById('user-action-modal').classList.add('hidden');
  };

  // Submit password change from modal
  window.submitPasswordChange = async function(minion, username) {
    const password = document.getElementById('modal-password').value;
    const confirm = document.getElementById('modal-confirm').value;
    const outputEl = document.getElementById('pwd-output');

    if (!password) {
      showToast('Enter a password', 'warning');
      return;
    }

    if (password !== confirm) {
      showToast('Passwords do not match', 'error');
      return;
    }

    if (password.length < 8) {
      showToast('Password must be at least 8 characters', 'warning');
      return;
    }

    closeUserActionModal();
    outputEl.textContent = `Changing password for ${username}...`;

    try {
      const result = await api('/api/users/change-password', {
        method: 'POST',
        body: JSON.stringify({ targets: [minion], username, password })
      });

      const minionResult = result.results[minion];
      outputEl.textContent = `Password change for ${username} on ${minion}\n\n` +
        (minionResult?.success ? 'SUCCESS: Password changed' : `FAILED: ${minionResult?.error || 'Unknown error'}`);

      showToast(minionResult?.success ? 'Password changed' : 'Password change failed', minionResult?.success ? 'success' : 'error');

    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Password change failed', 'error');
    }
  };

  // Create a new user
  async function createUser() {
    const targets = getUserManagementTargets();
    if (!targets) return;

    const username = document.getElementById('create-username').value.trim();
    const password = document.getElementById('create-password').value;
    const confirm = document.getElementById('create-confirm').value;
    const shell = document.getElementById('create-shell').value;
    const createHome = document.getElementById('create-home').checked;
    const sudo = document.getElementById('create-sudo').checked;
    const outputEl = document.getElementById('pwd-output');

    if (!username) {
      showToast('Enter a username', 'warning');
      return;
    }

    if (!password) {
      showToast('Enter a password', 'warning');
      return;
    }

    if (password !== confirm) {
      showToast('Passwords do not match', 'error');
      return;
    }

    if (password.length < 8) {
      showToast('Password must be at least 8 characters', 'warning');
      return;
    }

    const targetDesc = Array.isArray(targets) ? targets.join(', ') : targets;

    showConfirmModal(
      'Create User',
      `Create user "${username}"${sudo ? ' with sudo access' : ''} on: ${targetDesc}?`,
      async () => {
        outputEl.textContent = 'Creating user...';

        try {
          const result = await api('/api/users/create', {
            method: 'POST',
            body: JSON.stringify({ targets, username, password, shell, createHome, sudo })
          });

          let output = `Create user: ${username}\n`;
          output += `Total: ${result.summary.total}, Success: ${result.summary.success}, Failed: ${result.summary.failed}\n\n`;

          for (const [minion, data] of Object.entries(result.results)) {
            output += `-- ${minion} --\n`;
            output += data.success ? `SUCCESS: ${data.message}` : `FAILED: ${data.error || 'Unknown error'}`;
            output += '\n\n';
          }

          outputEl.textContent = output;
          showToast(`User created on ${result.summary.success}/${result.summary.total} devices`, result.summary.failed > 0 ? 'warning' : 'success');

          // Clear form and refresh list
          document.getElementById('create-password').value = '';
          document.getElementById('create-confirm').value = '';

          if (result.summary.success > 0) {
            listUsers();
          }

        } catch (error) {
          outputEl.textContent = `Error: ${error.message}`;
          showToast('Failed to create user', 'error');
        }
      }
    );
  }

  // ============================================================
  // Monitoring (Scheduled Checks with Change Detection)
  // ============================================================

  async function loadMonitoringView() {
    await Promise.all([loadBaselines(), loadSchedules(), loadChanges()]);
  }

  async function loadBaselines() {
    const listEl = document.getElementById('mon-baselines-list');
    try {
      const result = await api('/api/monitoring/baselines');
      const baselines = result.baselines || [];

      if (baselines.length === 0) {
        listEl.innerHTML = '<div class="loading">No baselines yet</div>';
      } else {
        let html = '<table class="results-table"><thead><tr><th>Name</th><th>Targets</th><th>Checks</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
        for (const b of baselines) {
          html += `<tr>
            <td>${escapeHtml(b.name)}</td>
            <td>${escapeHtml(b.targets)}</td>
            <td>${escapeHtml(b.checks.join(', '))}</td>
            <td>${new Date(b.created).toLocaleString()}</td>
            <td><button class="btn btn-small btn-danger" onclick="window._monDeleteBaseline('${escapeHtml(b.id)}')">Delete</button></td>
          </tr>`;
        }
        html += '</tbody></table>';
        listEl.innerHTML = html;
      }

      // Populate baseline dropdowns
      const opts = '<option value="">Select baseline...</option>' +
        baselines.map(b => `<option value="${escapeHtml(b.id)}">${escapeHtml(b.name)}</option>`).join('');
      document.getElementById('mon-schedule-baseline').innerHTML = opts;
      document.getElementById('mon-check-now-baseline').innerHTML = opts;
    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadSchedules() {
    const listEl = document.getElementById('mon-schedules-list');
    try {
      const result = await api('/api/monitoring/schedules');
      const schedules = result.schedules || [];

      if (schedules.length === 0) {
        listEl.innerHTML = '<div class="loading">No schedules</div>';
      } else {
        let html = '<table class="results-table"><thead><tr><th>Name</th><th>Interval</th><th>Baseline</th><th>Last Run</th><th>Actions</th></tr></thead><tbody>';
        for (const s of schedules) {
          html += `<tr>
            <td>${escapeHtml(s.name)}</td>
            <td>${s.intervalMinutes} min</td>
            <td>${escapeHtml(s.baselineId)}</td>
            <td>${s.lastRun ? new Date(s.lastRun).toLocaleString() : 'Never'}</td>
            <td><button class="btn btn-small btn-danger" onclick="window._monDeleteSchedule('${escapeHtml(s.id)}')">Delete</button></td>
          </tr>`;
        }
        html += '</tbody></table>';
        listEl.innerHTML = html;
      }
    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadChanges() {
    const feedEl = document.getElementById('mon-changes-feed');
    try {
      const result = await api('/api/monitoring/changes?limit=200');
      const changes = result.changes || [];

      if (changes.length === 0) {
        feedEl.innerHTML = '<div class="loading">No changes detected</div>';
      } else {
        let html = '';
        for (const c of changes) {
          const sevClass = c.severity === 'high' ? 'finding-critical' : c.severity === 'medium' ? 'finding-high' : 'finding-medium';
          const icon = c.changeType === 'added' ? '+' : '-';
          html += `<div class="suspicious-item ${sevClass}" style="padding: 8px; margin-bottom: 4px;">
            <div style="display: flex; justify-content: space-between;">
              <strong>[${escapeHtml(c.severity.toUpperCase())}] ${escapeHtml(c.minion)} - ${escapeHtml(c.checkType)} (${icon}${escapeHtml(c.changeType)})</strong>
              <span class="text-muted">${new Date(c.timestamp).toLocaleString()}</span>
            </div>
            <div style="margin-top: 4px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap;">${escapeHtml(c.items.slice(0, 10).join('\n'))}${c.items.length > 10 ? '\n... and ' + (c.items.length - 10) + ' more' : ''}</div>
          </div>`;
        }
        feedEl.innerHTML = html;
      }
    } catch (error) {
      feedEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function createBaseline() {
    const name = document.getElementById('mon-baseline-name').value.trim() || 'Baseline';
    const targets = document.getElementById('mon-baseline-target').value.trim() || '*';
    const checks = Array.from(document.querySelectorAll('.mon-check-type:checked')).map(cb => cb.value);

    if (checks.length === 0) { showToast('Select at least one check type', 'warning'); return; }

    try {
      showToast('Creating baseline...', 'info');
      await api('/api/monitoring/baseline', {
        method: 'POST',
        body: JSON.stringify({ name, targets, checks })
      });
      showToast('Baseline created', 'success');
      await loadBaselines();
    } catch (error) {
      showToast(`Failed: ${error.message}`, 'error');
    }
  }

  async function createSchedule() {
    const baselineId = document.getElementById('mon-schedule-baseline').value;
    const intervalMinutes = parseInt(document.getElementById('mon-schedule-interval').value) || 5;
    const name = document.getElementById('mon-schedule-name').value.trim();

    if (!baselineId) { showToast('Select a baseline', 'warning'); return; }

    try {
      await api('/api/monitoring/schedule', {
        method: 'POST',
        body: JSON.stringify({ baselineId, intervalMinutes, name: name || undefined })
      });
      showToast(`Schedule created: every ${intervalMinutes} min`, 'success');
      await loadSchedules();
    } catch (error) {
      showToast(`Failed: ${error.message}`, 'error');
    }
  }

  async function monitorCheckNow() {
    const baselineId = document.getElementById('mon-check-now-baseline').value;
    if (!baselineId) { showToast('Select a baseline', 'warning'); return; }

    try {
      showToast('Running check...', 'info');
      const result = await api('/api/monitoring/check', {
        method: 'POST',
        body: JSON.stringify({ baselineId })
      });
      showToast(`Check complete: ${result.total} change(s) detected`, result.total > 0 ? 'warning' : 'success');
      await loadChanges();
    } catch (error) {
      showToast(`Check failed: ${error.message}`, 'error');
    }
  }

  // Expose delete handlers to onclick
  window._monDeleteBaseline = async function(id) {
    try {
      await api(`/api/monitoring/baselines/${id}`, { method: 'DELETE' });
      showToast('Baseline deleted', 'success');
      await loadBaselines();
    } catch (error) {
      showToast(`Failed: ${error.message}`, 'error');
    }
  };

  window._monDeleteSchedule = async function(id) {
    try {
      await api(`/api/monitoring/schedules/${id}`, { method: 'DELETE' });
      showToast('Schedule deleted', 'success');
      await loadSchedules();
    } catch (error) {
      showToast(`Failed: ${error.message}`, 'error');
    }
  };

  // Bulk password rotation
  async function bulkRotatePassword() {
    const username = document.getElementById('bulk-rot-username').value.trim();
    const password = document.getElementById('bulk-rot-password').value;
    const confirm = document.getElementById('bulk-rot-confirm').value;
    const targetSel = document.getElementById('bulk-rot-target').value;
    const resultsEl = document.getElementById('bulk-rot-results');
    const outputEl = document.getElementById('pwd-output');

    if (!username) { showToast('Enter a username', 'warning'); return; }
    if (!password) { showToast('Enter a password', 'warning'); return; }
    if (password.length < 8) { showToast('Password must be at least 8 characters', 'warning'); return; }
    if (password !== confirm) { showToast('Passwords do not match', 'error'); return; }

    let targets;
    if (targetSel === 'selected') {
      const sel = getUserManagementTargets();
      if (!sel) return;
      targets = sel;
    } else {
      targets = '*';
    }

    const targetDesc = Array.isArray(targets) ? targets.join(', ') : targets;

    showConfirmModal(
      'Bulk Password Rotation',
      `Change password for "${username}" on: ${targetDesc}?`,
      async () => {
        outputEl.textContent = 'Rotating password...';
        resultsEl.classList.remove('hidden');
        resultsEl.innerHTML = '<div class="loading">Rotating password across minions...</div>';

        try {
          const result = await api('/api/passwords/change', {
            method: 'POST',
            body: JSON.stringify({ targets, username, password })
          });

          let output = `Bulk password rotation: ${username}\n`;
          output += `Total: ${result.summary.total}, Success: ${result.summary.success}, Failed: ${result.summary.failed}\n\n`;

          let tableHtml = '<table class="results-table"><thead><tr><th>Minion</th><th>Status</th><th>Details</th></tr></thead><tbody>';
          for (const [minion, data] of Object.entries(result.results)) {
            const ok = data.success;
            output += `-- ${minion} -- ${ok ? 'SUCCESS' : 'FAILED: ' + (data.error || 'Unknown')}\n`;
            tableHtml += `<tr><td>${escapeHtml(minion)}</td><td class="${ok ? 'status-online' : 'status-offline'}">${ok ? 'OK' : 'FAIL'}</td><td>${escapeHtml(ok ? (data.message || 'Password changed') : (data.error || 'Unknown error'))}</td></tr>`;
          }
          tableHtml += '</tbody></table>';

          resultsEl.innerHTML = tableHtml;
          outputEl.textContent = output;
          showToast(`Password rotated on ${result.summary.success}/${result.summary.total} devices`, result.summary.failed > 0 ? 'warning' : 'success');

          // Clear password fields
          document.getElementById('bulk-rot-password').value = '';
          document.getElementById('bulk-rot-confirm').value = '';
        } catch (error) {
          outputEl.textContent = `Error: ${error.message}`;
          resultsEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
          showToast('Bulk rotation failed', 'error');
        }
      }
    );
  }

  // ============================================================
  // Forensics
  // ============================================================

  let forensicsActiveTab = 'collect';
  let forensicsBrowseState = {
    selectedMinion: null,
    selectedArtifact: null,
    fileList: [],
    currentPath: '/',
    findings: [],
    allFindings: []
  };

  const forensicsLevelDescs = {
    quick: 'Quick: Basic system info snapshot — hostname, OS, uptime, IP addresses',
    standard: 'Standard: Processes, network connections, persistence mechanisms, user accounts',
    advanced: 'Advanced: + file hashing, file timeline, rootkit checks',
    comprehensive: 'Comprehensive: + memory dump, Volatility analysis, YARA scanning'
  };

  function switchForensicsTab(tabName) {
    forensicsActiveTab = tabName;
    document.querySelectorAll('.forensics-tab').forEach(t => t.classList.toggle('active', t.dataset.ftab === tabName));
    document.querySelectorAll('.forensics-tab-content').forEach(c => {
      const isActive = c.id === `ftab-${tabName}`;
      c.classList.toggle('active', isActive);
      c.classList.toggle('hidden', !isActive);
    });
    if (tabName === 'browse') loadForensicsCollectionsTree();
  }

  function populateForensicsTargetSelects() {
    const selects = ['fr-collect-single-target'];
    const onlineDevices = state.devices.filter(d => d.status === 'online');
    selects.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      const val = el.value;
      el.innerHTML = '<option value="">Select device...</option>' + onlineDevices.map(d => `<option value="${escapeHtml(d.id)}">${escapeHtml(d.id)}</option>`).join('');
      if (val) el.value = val;
    });
  }

  function renderForensicsDeviceChecklist() {
    const container = document.getElementById('fr-device-checklist');
    const type = document.getElementById('fr-collect-target-type').value;
    if (type !== 'selected') { container.classList.add('hidden'); return; }
    container.classList.remove('hidden');
    const devices = (state.devices || []).filter(d => d.status === 'online');
    if (devices.length === 0) {
      container.innerHTML = '<span style="color:var(--text-muted);">No online devices</span>';
      return;
    }
    container.innerHTML = devices.map(d => {
      const checked = state.selectedDevices.has(d.id) ? 'checked' : '';
      return `<label style="display:block;cursor:pointer;padding:1px 0;"><input type="checkbox" class="fr-dev-cb" value="${escapeHtml(d.id)}" ${checked}> ${escapeHtml(d.id)} <span style="color:var(--text-muted);">${escapeHtml(d.os || '')}</span></label>`;
    }).join('');
    container.querySelectorAll('.fr-dev-cb').forEach(cb => {
      cb.addEventListener('change', () => {
        if (cb.checked) state.selectedDevices.add(cb.value);
        else state.selectedDevices.delete(cb.value);
        const infoEl = document.getElementById('fr-selected-info');
        infoEl.textContent = `${state.selectedDevices.size} device(s) selected`;
        infoEl.classList.remove('hidden');
      });
    });
  }

  function getForensicsCollectTargets() {
    const type = document.getElementById('fr-collect-target-type').value;
    if (type === 'all') return '*';
    if (type === 'single') return document.getElementById('fr-collect-single-target').value;
    const selected = Array.from(state.selectedDevices);
    return selected.length > 0 ? selected : null;
  }

  async function forensicsCheckTools() {
    const targets = getForensicsCollectTargets();
    if (!targets || (Array.isArray(targets) && targets.length === 0)) {
      showToast('Select targets first', 'error');
      return;
    }
    const outputEl = document.getElementById('fr-collect-output');
    outputEl.textContent = 'Checking installed forensics tools...';
    const toolsList = [
      'tar', 'gzip', 'find', 'ss', 'netstat', 'lsof', 'ps',
      'sha256sum', 'md5sum', 'strings', 'strace', 'ltrace',
      'tcpdump', 'auditctl', 'ausearch', 'rkhunter', 'chkrootkit',
      'debsums', 'aide', 'yara', 'vol', 'clamscan', 'freshclam',
      'avml', 'uac'
    ];
    const cmd = `TOOLS="${toolsList.join(' ')}"; INSTALLED=0; MISSING=""; TOTAL=${toolsList.length}; for t in $TOOLS; do p=$(which "$t" 2>/dev/null); if [ -n "$p" ]; then printf "%-18s %-25s [INSTALLED]\\n" "$t" "$p"; INSTALLED=$((INSTALLED+1)); elif [ "$t" = "uac" ] && [ -x /opt/uac/uac ]; then printf "%-18s %-25s [INSTALLED]\\n" "$t" "/opt/uac/uac"; INSTALLED=$((INSTALLED+1)); elif [ "$t" = "avml" ] && [ -x /opt/avml/avml ]; then printf "%-18s %-25s [INSTALLED]\\n" "$t" "/opt/avml/avml"; INSTALLED=$((INSTALLED+1)); else printf "%-18s %-25s [NOT INSTALLED]\\n" "$t" "-"; MISSING="$MISSING $t"; fi; done; echo ""; echo "Installed: $INSTALLED/$TOTAL"; if [ -n "$MISSING" ]; then echo "Missing:$MISSING"; fi`;

    try {
      const result = await api('/api/commands/run', {
        method: 'POST',
        body: JSON.stringify({ targets, command: cmd, shell: 'bash', timeout: 30 })
      });
      if (result.success) {
        let out = '';
        const results = result.results || {};
        for (const [minion, data] of Object.entries(results)) {
          out += `── ${minion} ──────────────────────────────\n`;
          let stdout = '';
          if (typeof data === 'string') {
            stdout = data;
          } else if (data && typeof data === 'object') {
            stdout = data.output || data.stdout || data.return || '';
            if (!stdout && typeof stdout !== 'string') stdout = JSON.stringify(data, null, 2);
          }
          out += stdout + '\n\n';
        }
        outputEl.textContent = out || 'No results';
      } else {
        outputEl.textContent = `Error: ${result.error || 'Unknown'}`;
      }
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
    }
  }

  async function forensicsCollect() {
    const targets = getForensicsCollectTargets();
    if (!targets || (Array.isArray(targets) && targets.length === 0)) {
      showToast('Select targets first', 'error');
      return;
    }
    const level = document.getElementById('fr-collect-level').value;
    const timeout = parseInt(document.getElementById('fr-collect-timeout').value) || 300;
    const outputEl = document.getElementById('fr-collect-output');
    outputEl.textContent = 'Starting collection...';

    // Auto-install missing tools if checked
    const autoInstall = document.getElementById('fr-opt-autoinstall').checked;
    if (autoInstall) {
      outputEl.textContent = 'Installing missing forensics tools...';
      try {
        const installResult = await api('/api/forensics/install-tools', {
          method: 'POST',
          body: JSON.stringify({ targets, timeout: 300 })
        });
        if (installResult.job_id) {
          // Wait for install job to complete before proceeding
          await waitForForensicsInstallJob(installResult.job_id, outputEl);
        }
        outputEl.textContent = 'Tool installation complete. Starting collection...';
      } catch (e) {
        outputEl.textContent = `Install warning: ${e.message}. Proceeding with collection...`;
      }
    }

    const body = { targets, timeout };
    let endpoint = '/api/forensics/collect';

    if (level === 'quick') {
      endpoint = '/api/forensics/quick-collect';
    } else if (level === 'advanced') {
      endpoint = '/api/forensics/advanced';
    } else if (level === 'comprehensive') {
      endpoint = '/api/forensics/comprehensive';
      // Two-phase collection: skip inline scans for fast results, run scans separately
      body.skip_scans = true;
      if (document.getElementById('fr-opt-memory').checked) body.memory_dump = true;
      if (document.getElementById('fr-opt-volatility').checked) body.volatility = true;
      if (document.getElementById('fr-opt-quick').checked) body.quick_mode = true;
      if (document.getElementById('fr-opt-skip-logs').checked) body.skip_logs = true;
    } else {
      body.level = level;
    }

    try {
      const result = await api(endpoint, { method: 'POST', body: JSON.stringify(body) });
      // Async job (comprehensive) — has jid but no inline results
      const asyncId = result.jid ? result.collection_id : result.job_id;
      if (result.success && asyncId && !result.results) {
        outputEl.textContent = `Job started: ${asyncId}`;
        showToast('Collection started', 'success');
        pollForensicsJob(asyncId);
        loadForensicsJobs();
      } else if (result.success) {
        // Synchronous collection (quick/standard/advanced return inline results)
        let out = result.message || 'Collection complete';
        if (result.results) {
          out = formatForensicsResults(result.results);
        }
        if (result.tarball) out += `\nTarball: ${result.tarball}`;
        outputEl.textContent = out;
        showToast('Collection complete', 'success');
        loadForensicsJobs();
      } else {
        outputEl.textContent = `Error: ${result.error || 'Unknown'}`;
      }
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
      showToast('Collection failed', 'error');
    }
  }

  /**
   * Wait for a forensics install job to complete (blocking poll)
   */
  async function waitForForensicsInstallJob(jobId, outputEl, maxWaitMs = 300000) {
    const startTime = Date.now();
    while (Date.now() - startTime < maxWaitMs) {
      const result = await api(`/api/forensics/status/${jobId}`);
      const status = result.status || (result.job && result.job.status);
      if (status === 'completed') {
        // Parse results for any failures
        const results = result.results || (result.job && result.job.results);
        if (results) {
          let failCount = 0;
          for (const output of Object.values(results)) {
            if (typeof output === 'string' && output.includes('[RESULT] FAILED:')) {
              failCount += (output.match(/\[RESULT\] FAILED:/g) || []).length;
            }
          }
          if (failCount > 0) {
            outputEl.textContent = `Tool install complete (${failCount} tools failed - check logs). Starting collection...`;
          }
        }
        return result;
      }
      if (status === 'failed') {
        throw new Error(result.error || (result.job && result.job.error) || 'Install job failed');
      }
      const elapsed = Math.round((Date.now() - startTime) / 1000);
      outputEl.textContent = `Installing forensics tools... (${elapsed}s)`;
      await new Promise(r => setTimeout(r, 2000));
    }
    throw new Error('Timeout waiting for tool installation');
  }

  async function pollForensicsJob(jobId, scanJobId = null) {
    const outputEl = document.getElementById('fr-collect-output');
    let collectionOutput = '';
    let scanOutput = '';

    const poll = async () => {
      try {
        const result = await api(`/api/forensics/status/${jobId}`);
        const job = result.job || result;
        const status = job.status || 'unknown';
        const results = job.results;
        const error = job.error;
        const options = job.options || {};

        if (status === 'completed' && results) {
          collectionOutput = formatForensicsResults(results);
          loadForensicsJobs();

          // Check if this was a skip_scans collection (Phase 1)
          if (options.skip_scans && !scanJobId) {
            // Display collection results immediately
            outputEl.textContent = collectionOutput + '\n\n══ Phase 2: Security Scans ══\nRunning rkhunter, chkrootkit, ClamAV, AIDE, debsums, YARA, UAC...\nResults will be merged into the collection tarball.';
            showToast('Collection complete - starting security scans', 'success');

            // Kick off Phase 2 security scans
            // The scan script auto-discovers and updates the most recent tarball for each host
            try {
              const targets = job.targets;
              const scanResult = await api('/api/forensics/scan', {
                method: 'POST',
                body: JSON.stringify({
                  targets,
                  memory_dump: options.memory_dump || false,
                  timeout: 1200
                })
              });
              if (scanResult.success && scanResult.job_id) {
                // Continue polling with the scan job
                pollForensicsJob(jobId, scanResult.job_id);
              }
            } catch (scanErr) {
              outputEl.textContent = collectionOutput + `\n\n[SCAN ERROR] ${scanErr.message}`;
            }
            return;
          }

          // Normal completion (no skip_scans or scans already done)
          outputEl.textContent = collectionOutput;
          showToast('Collection complete', 'success');
          return;
        } else if (status === 'failed') {
          outputEl.textContent = `Job failed: ${error || 'Unknown error'}`;
          loadForensicsJobs();
          showToast('Collection failed', 'error');
          return;
        }

        // Still running - show progress
        const elapsed = result.elapsed_ms ? ` (${Math.round(result.elapsed_ms / 1000)}s)` : '';
        outputEl.textContent = `Collecting artifacts... ${status}${elapsed}`;
        loadForensicsJobs();
        setTimeout(poll, 3000);
      } catch (err) {
        outputEl.textContent = `Poll error: ${err.message}`;
      }
    };

    // If we have a scan job to poll, poll that instead
    if (scanJobId) {
      const pollScan = async () => {
        try {
          const result = await api(`/api/forensics/status/${scanJobId}`);
          const job = result.job || result;
          const status = job.status || 'unknown';
          const scanSummary = job.scan_summary;

          if (status === 'completed') {
            // Format scan summary
            scanOutput = '\n\n══════════════════════════════════════════\n';
            scanOutput += '           SECURITY SCAN RESULTS          \n';
            scanOutput += '══════════════════════════════════════════\n';
            if (scanSummary && Object.keys(scanSummary).length > 0) {
              let hasResults = false;
              for (const [minion, summary] of Object.entries(scanSummary)) {
                scanOutput += `\n── ${minion} ──\n`;
                if (Object.keys(summary).length > 0) {
                  hasResults = true;
                  for (const [scanner, result] of Object.entries(summary)) {
                    scanOutput += `  ${scanner}: ${result}\n`;
                  }
                } else {
                  // Check if scan timed out by looking at raw results
                  const rawResults = job.results || {};
                  const rawOutput = rawResults[minion] || '';
                  if (typeof rawOutput === 'string' && rawOutput.includes('Timed out')) {
                    scanOutput += '  Scans timed out — partial results may be in the tarball.\n';
                    scanOutput += '  Try increasing the timeout or running fewer scanners.\n';
                  } else {
                    scanOutput += '  No scan results parsed. Check /tmp/forensics/scanning/\n';
                  }
                }
              }
            } else {
              scanOutput += 'Scan results available in /tmp/forensics/scanning/\n';
            }
            outputEl.textContent = collectionOutput + scanOutput;
            loadForensicsJobs();
            showToast('Security scans complete', 'success');
            return;
          } else if (status === 'failed') {
            outputEl.textContent = collectionOutput + `\n\n[SCAN FAILED] ${job.error || 'Unknown error'}`;
            loadForensicsJobs();
            return;
          }

          // Still running - show progress with scan status
          const results = job.results;
          let scanProgress = '';
          if (results) {
            for (const output of Object.values(results)) {
              if (typeof output === 'string') {
                const statusMatch = output.match(/\[SCAN_STATUS\] (.+)/g);
                if (statusMatch) {
                  scanProgress = statusMatch[statusMatch.length - 1].replace('[SCAN_STATUS] ', '');
                }
              }
            }
          }
          outputEl.textContent = collectionOutput + `\n\n══ Phase 2: Security Scans ══\nRunning... ${scanProgress}`;
          setTimeout(pollScan, 3000);
        } catch (err) {
          outputEl.textContent = collectionOutput + `\n\n[SCAN ERROR] ${err.message}`;
        }
      };
      // Get the collection output first
      try {
        const result = await api(`/api/forensics/status/${jobId}`);
        const job = result.job || result;
        if (job.results) {
          collectionOutput = formatForensicsResults(job.results);
        }
      } catch (e) { /* ignore */ }
      setTimeout(pollScan, 1000);
      return;
    }

    setTimeout(poll, 2000);
  }

  function formatForensicsResults(results) {
    if (!results) return 'No results';
    let out = '';
    for (const [minion, output] of Object.entries(results)) {
      out += `── ${minion} ──────────────────────────────\n`;
      if (output === false) {
        out += '[ERROR] Salt returned false — minion may be offline or timed out.\n\n';
      } else if (output === '' || output === null || output === undefined) {
        out += '[WARNING] Empty response from minion.\n\n';
      } else if (typeof output === 'string') {
        // Look for FORENSICS_DONE marker to provide a concise summary
        if (output.includes('FORENSICS_DONE')) {
          const lines = output.split('\n');

          // Extract tarball path
          const tarballLine = lines.find(l => l.includes('[TARBALL]'));
          const tarball = tarballLine ? tarballLine.replace('[TARBALL] ', '').trim() : '';

          // Extract collection path
          const doneLine = lines.find(l => l.includes('FORENSICS_DONE:'));
          const path = doneLine ? doneLine.split('FORENSICS_DONE:')[1].trim() : '/tmp/forensics';

          // Extract key status markers ([SCAN], [ANALYSIS], [CLEANUP])
          const statusLines = lines.filter(l => /^\[(?:SCAN|ANALYSIS|CLEANUP)\]/.test(l.trim()));
          const statusSet = new Set(statusLines.map(l => l.trim()));

          // Extract completion markers not already in statusLines
          const completedSteps = lines
            .filter(l => /\bcomplete\b/i.test(l) && !/echo/i.test(l))
            .map(l => l.trim())
            .filter(l => !statusSet.has(l));

          // Extract warnings/errors (skip grep/echo noise)
          const issues = lines.filter(l =>
            /error|fail|not installed|not found|not available/i.test(l) &&
            !/grep|echo|timeout.*bash/i.test(l) &&
            !l.includes('FORENSICS_DONE')
          );

          // Build concise output
          if (tarball) out += `Tarball: ${tarball}\n`;
          else out += `Collection: ${path}\n`;

          if (statusLines.length > 0) {
            out += statusLines.map(l => l.trim()).join('\n') + '\n';
          }

          if (completedSteps.length > 0) {
            out += completedSteps.join('\n') + '\n';
          }

          if (issues.length > 0) {
            out += `\nWarnings (${issues.length}):\n${issues.slice(0, 10).map(s => `  ! ${s.trim()}`).join('\n')}\n`;
          }
          out += '\n';
        } else {
          // No FORENSICS_DONE marker — show raw but truncated
          const lines = output.split('\n');
          if (lines.length > 40) {
            out += lines.slice(0, 15).join('\n') + '\n';
            out += `  ... (${lines.length - 30} lines omitted) ...\n`;
            out += lines.slice(-15).join('\n') + '\n\n';
          } else {
            out += output + '\n\n';
          }
        }
      } else {
        out += JSON.stringify(output, null, 2) + '\n\n';
      }
    }
    return out || 'No results';
  }

  async function loadForensicsJobs() {
    const listEl = document.getElementById('fr-jobs-list');
    try {
      const result = await api('/api/forensics/jobs');
      if (result.success && result.jobs && result.jobs.length > 0) {
        listEl.innerHTML = result.jobs.map(job => {
          const jobKey = job.collection_id || job.id || job.jid || '';
          const jobType = job.type || job.level || '';
          const jobTime = job.started_at || job.created;
          const elapsed = job.elapsed_ms ? `${Math.round(job.elapsed_ms / 1000)}s` : '';
          return `
          <div class="forensics-job-item">
            <span class="forensics-job-status ${job.status}">${job.status}</span>
            <span>${escapeHtml(jobType)}</span>
            <span class="forensics-job-id">${escapeHtml(jobKey)}</span>
            <span style="color:var(--text-muted);font-size:11px;">${jobTime ? new Date(jobTime).toLocaleTimeString() : ''} ${elapsed}</span>
            <button class="btn btn-small fr-job-view-btn" data-jobid="${escapeHtml(jobKey)}">View</button>
          </div>`;
        }).join('');
        listEl.querySelectorAll('.fr-job-view-btn').forEach(btn => {
          btn.addEventListener('click', () => viewForensicsJob(btn.dataset.jobid));
        });
      } else {
        listEl.innerHTML = '<div class="loading">No jobs yet</div>';
      }
    } catch {
      // ignore
    }
  }

  async function viewForensicsJob(collectionId) {
    const outputEl = document.getElementById('fr-collect-output');
    outputEl.textContent = 'Loading...';
    try {
      const d = await api(`/api/forensics/status/${collectionId}`);
      if (d.results) {
        // Completed job with inline results
        outputEl.textContent = formatForensicsResults(d.results);
      } else if (d.job && d.job.results) {
        outputEl.textContent = formatForensicsResults(d.job.results);
      } else {
        const status = d.status || (d.job ? d.job.status : 'unknown');
        outputEl.textContent = `Status: ${status}`;
        if (status === 'running') {
          const elapsed = d.elapsed_ms ? ` (${Math.round(d.elapsed_ms / 1000)}s elapsed)` : '';
          outputEl.textContent += elapsed;
        }
      }
    } catch (error) {
      outputEl.textContent = `Error: ${error.message}`;
    }
  }

  // Browse & Analyze tab

  async function loadForensicsCollectionsTree() {
    const treeEl = document.getElementById('fr-collections-tree');
    treeEl.innerHTML = '<div class="loading">Loading collections...</div>';
    try {
      const result = await api('/api/forensics/collections');
      if (!result.success) {
        treeEl.innerHTML = '<div class="loading">Failed to load</div>';
        return;
      }
      const collections = result.collections;
      if (!collections || (Array.isArray(collections) ? collections.length === 0 : Object.keys(collections).length === 0)) {
        treeEl.innerHTML = '<div class="loading">No collections found</div>';
        return;
      }
      // Group by minion — collections is { minion: "file1\nfile2\n..." }
      const grouped = {};
      if (Array.isArray(collections)) {
        for (const c of collections) {
          if (!grouped[c.minion]) grouped[c.minion] = [];
          grouped[c.minion].push(c.path);
        }
      } else {
        for (const [minion, output] of Object.entries(collections)) {
          if (typeof output === 'string') {
            grouped[minion] = output.split('\n').map(l => l.trim()).filter(l => l && l !== 'No collections');
          } else {
            grouped[minion] = [];
          }
        }
      }
      let html = '';
      for (const [minion, files] of Object.entries(grouped)) {
        // Separate tarballs from plain files
        const tarballs = files.filter(f => f.endsWith('.tar.gz'));
        const plainFiles = files.filter(f => !f.endsWith('.tar.gz'));
        html += `<div class="fr-tree-minion" data-minion="${escapeHtml(minion)}">
          <div class="fr-tree-minion-label">${escapeHtml(minion)} (${files.length} files)</div>
          <div class="fr-tree-artifacts hidden">
            ${tarballs.map((f, i) => `<div class="fr-tree-artifact" data-minion="${escapeHtml(minion)}" data-path="/tmp/forensics/${escapeHtml(f)}" data-type="tarball">${escapeHtml(f)}${i === 0 ? ' <span style="color:var(--status-success);font-size:11px;">(latest)</span>' : ''}</div>`).join('')}
            ${plainFiles.map(f => `<div class="fr-tree-artifact" data-minion="${escapeHtml(minion)}" data-path="/tmp/forensics/${escapeHtml(f)}" data-type="file">${escapeHtml(f)}</div>`).join('')}
            ${files.length === 0 ? '<div class="loading" style="font-size:11px;">No artifacts</div>' : ''}
          </div>
        </div>`;
      }
      treeEl.innerHTML = html;

      // Delegated event listener for collections tree
      treeEl.onclick = (e) => {
        const label = e.target.closest('.fr-tree-minion-label');
        if (label) {
          const sub = label.parentElement.querySelector('.fr-tree-artifacts');
          sub.classList.toggle('hidden');
          label.classList.toggle('expanded');
          return;
        }
        const artifact = e.target.closest('.fr-tree-artifact');
        if (artifact) {
          selectForensicsCollection(artifact.dataset.minion, artifact.dataset.path, artifact.dataset.type);
        }
      };
    } catch (error) {
      treeEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function selectForensicsCollection(minion, artifactPath, artifactType) {
    forensicsBrowseState.selectedMinion = minion;
    forensicsBrowseState.selectedArtifact = artifactPath;
    forensicsBrowseState.artifactType = artifactType || (artifactPath.endsWith('.tar.gz') ? 'tarball' : 'file');
    forensicsBrowseState.currentPath = '/';
    forensicsBrowseState.allFindings = [];
    forensicsBrowseState.findings = [];

    // Highlight selection
    document.querySelectorAll('.fr-tree-artifact').forEach(el => el.classList.remove('selected'));
    document.querySelector(`.fr-tree-artifact[data-path="${CSS.escape(artifactPath)}"]`)?.classList.add('selected');

    // Show content panel
    document.getElementById('fr-browse-placeholder').classList.add('hidden');
    document.getElementById('fr-browse-content').classList.remove('hidden');
    document.getElementById('fr-browse-label').textContent = `${minion} / ${artifactPath.split('/').pop()}`;

    // Hide findings/timeline/metadata until requested
    document.getElementById('fr-findings-section').classList.add('hidden');
    document.getElementById('fr-timeline-section').classList.add('hidden');
    document.getElementById('fr-metadata-section').classList.add('hidden');

    const filetreeEl = document.getElementById('fr-filetree');
    const contentEl = document.getElementById('fr-file-content');
    const titleEl = document.getElementById('fr-file-viewer-title');

    if (forensicsBrowseState.artifactType === 'file') {
      // Plain file: show content directly, no file tree needed
      filetreeEl.innerHTML = '<div class="loading" style="font-size:11px;">Single file selected</div>';
      titleEl.textContent = artifactPath.split('/').pop();
      contentEl.textContent = 'Loading...';
      try {
        const filename = artifactPath.split('/').pop();
        const result = await api('/api/forensics/read-file', {
          method: 'POST',
          body: JSON.stringify({ target: minion, filename })
        });
        if (result.success) {
          let content = result.content;
          if (content && typeof content === 'object') {
            content = content[minion] || content[Object.keys(content)[0]] || '';
          }
          contentEl.textContent = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
        } else {
          contentEl.textContent = `Error: ${result.error || 'Unknown'}`;
        }
      } catch (error) {
        contentEl.textContent = `Error: ${error.message}`;
      }
      return;
    }

    // Tarball: load file list from tar
    filetreeEl.innerHTML = '<div class="loading">Loading contents...</div>';
    contentEl.textContent = 'Select a file to view its contents.';
    titleEl.textContent = 'No file selected';

    try {
      const result = await api('/api/forensics/artifact-contents', {
        method: 'POST',
        body: JSON.stringify({ target: minion, artifact_path: artifactPath })
      });
      if (result.success) {
        let files;
        if (result.contents && result.contents.files) {
          files = result.contents.files;
        } else if (result.files) {
          files = result.files[minion] || result.files[Object.keys(result.files)[0]] || [];
        } else {
          files = [];
        }
        forensicsBrowseState.fileList = files;
        forensicsBrowseState.currentPath = '/';
        renderForensicsFiletree();
      }
    } catch (error) {
      filetreeEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  function buildFileTreeStructure(flatFiles) {
    // Convert flat file list into nested tree structure
    const root = { name: '/', children: {}, files: [] };
    for (const f of flatFiles) {
      const clean = f.replace(/^\.\//, '').replace(/\/$/, '');
      if (!clean) continue;
      const parts = clean.split('/');
      let node = root;
      for (let i = 0; i < parts.length; i++) {
        if (i === parts.length - 1) {
          // Check if this is a directory entry (original path ended with /)
          if (f.endsWith('/')) {
            if (!node.children[parts[i]]) node.children[parts[i]] = { name: parts[i], children: {}, files: [] };
          } else {
            // Keep original path with ./ prefix for tar extraction
            node.files.push({ name: parts[i], path: f.startsWith('./') ? f : './' + clean });
          }
        } else {
          if (!node.children[parts[i]]) node.children[parts[i]] = { name: parts[i], children: {}, files: [] };
          node = node.children[parts[i]];
        }
      }
    }
    return root;
  }

  function renderTreeNode(node, depth = 0) {
    const DIR_PRIORITY = {
      persistence: 1, users: 2, processes: 3, network: 4,
      files: 5, system: 6, scanning: 7, logs: 8, memory: 9
    };
    let html = '';
    // Sort directories by IR priority (then alpha), then files
    const dirs = Object.values(node.children).sort((a, b) => {
      const pa = DIR_PRIORITY[a.name] || 100;
      const pb = DIR_PRIORITY[b.name] || 100;
      return pa !== pb ? pa - pb : a.name.localeCompare(b.name);
    });
    const files = (node.files || []).sort((a, b) => a.name.localeCompare(b.name));

    for (const dir of dirs) {
      const hasContent = Object.keys(dir.children).length > 0 || dir.files.length > 0;
      if (!hasContent) continue;
      html += `<div class="fr-folder">`;
      html += `<div class="fr-folder-name" style="padding-left:${depth * 16 + 8}px">${escapeHtml(dir.name)}</div>`;
      html += `<div class="fr-folder-contents">${renderTreeNode(dir, depth + 1)}</div>`;
      html += `</div>`;
    }
    for (const file of files) {
      html += `<div class="fr-tree-file" data-filepath="${escapeHtml(file.path)}" style="padding-left:${depth * 16 + 8}px">${escapeHtml(file.name)}</div>`;
    }
    return html;
  }

  function renderForensicsFiletree() {
    const files = forensicsBrowseState.fileList;
    const filetreeEl = document.getElementById('fr-filetree');

    if (!files || files.length === 0) {
      filetreeEl.innerHTML = '<div class="loading">No files found</div>';
      return;
    }

    const tree = buildFileTreeStructure(files);
    const html = renderTreeNode(tree);
    filetreeEl.innerHTML = html || '<div class="loading">Empty archive</div>';

    // Single delegated event listener for the entire tree
    filetreeEl.onclick = (e) => {
      const folderName = e.target.closest('.fr-folder-name');
      if (folderName) {
        folderName.parentElement.classList.toggle('expanded');
        return;
      }
      const fileEl = e.target.closest('.fr-tree-file');
      if (fileEl) {
        const prev = filetreeEl.querySelector('.fr-tree-file.selected');
        if (prev) prev.classList.remove('selected');
        fileEl.classList.add('selected');
        viewForensicsFile(fileEl.dataset.filepath);
      }
    };
  }

  async function viewForensicsFile(filePath) {
    const contentEl = document.getElementById('fr-file-content');
    const titleEl = document.getElementById('fr-file-viewer-title');
    titleEl.textContent = filePath;
    contentEl.textContent = 'Loading...';

    try {
      const result = await api('/api/forensics/artifact-file', {
        method: 'POST',
        body: JSON.stringify({
          target: forensicsBrowseState.selectedMinion,
          artifact_path: forensicsBrowseState.selectedArtifact,
          file_path: filePath
        })
      });
      if (result.success) {
        let content;
        if (typeof result.content === 'string') {
          content = result.content;
        } else if (result.content && typeof result.content === 'object') {
          const t = forensicsBrowseState.selectedMinion;
          content = result.content[t] || result.content[Object.keys(result.content)[0]] || '';
        } else {
          content = '';
        }
        contentEl.textContent = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
      }
    } catch (error) {
      contentEl.textContent = `Error: ${error.message}`;
    }
  }

  async function retrieveArtifact(target, artifactPath) {
    try {
      const result = await api('/api/forensics/retrieve', {
        method: 'POST',
        body: JSON.stringify({ target, artifact_path: artifactPath })
      });
      showToast(result.success ? 'Artifact retrieved to master' : (result.error || 'Failed'), result.success ? 'success' : 'error');
    } catch (error) {
      showToast(`Retrieve failed: ${error.message}`, 'error');
    }
  }

  async function forensicsCleanup() {
    const age = parseFloat(document.getElementById('fr-cleanup-age').value) || 24;
    showConfirmModal('Cleanup Artifacts', `Delete forensic artifacts older than ${age} hours?`, async () => {
      try {
        const result = await api('/api/forensics/cleanup', {
          method: 'POST',
          body: JSON.stringify({ age_hours: age })
        });
        showToast(result.success ? 'Cleanup complete' : (result.error || 'Failed'), result.success ? 'success' : 'error');
        if (result.success) loadForensicsCollectionsTree();
      } catch (error) {
        showToast(`Cleanup failed: ${error.message}`, 'error');
      }
    });
  }

  async function forensicsRunAnalysis() {
    const target = forensicsBrowseState.selectedMinion;
    if (!target) { showToast('Select a collection first', 'error'); return; }

    const findingsSection = document.getElementById('fr-findings-section');
    const findingsEl = document.getElementById('fr-findings-list');
    const summaryEl = document.getElementById('fr-severity-summary');
    findingsSection.classList.remove('hidden');
    document.getElementById('fr-timeline-section').classList.remove('hidden');
    document.getElementById('fr-metadata-section').classList.remove('hidden');
    findingsEl.innerHTML = '<div class="loading">Running analysis...</div>';
    summaryEl.classList.add('hidden');

    try {
      const result = await api('/api/forensics/analyze', {
        method: 'POST',
        body: JSON.stringify({ target })
      });
      if (result.success) {
        const all = extractFindings(result, target);
        forensicsBrowseState.allFindings = all;
        forensicsBrowseState.findings = all;
        renderForensicsFindings(all, findingsEl, summaryEl);
      }
    } catch (error) {
      findingsEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  function extractFindings(result, target) {
    const f = result.findings;
    if (Array.isArray(f)) return f;
    if (f && typeof f === 'object') return f[target] || f[Object.keys(f)[0]] || [];
    return [];
  }

  async function forensicsTargetedAnalyze() {
    const target = forensicsBrowseState.selectedMinion;
    if (!target) { showToast('Select a collection first', 'error'); return; }
    const types = [];
    if (document.getElementById('fr-type-rootkit').checked) types.push('rootkit');
    if (document.getElementById('fr-type-persistence').checked) types.push('persistence');
    if (document.getElementById('fr-type-network').checked) types.push('network');
    if (document.getElementById('fr-type-users').checked) types.push('users');
    if (document.getElementById('fr-type-processes').checked) types.push('processes');

    const findingsSection = document.getElementById('fr-findings-section');
    const findingsEl = document.getElementById('fr-findings-list');
    const summaryEl = document.getElementById('fr-severity-summary');
    findingsSection.classList.remove('hidden');
    findingsEl.innerHTML = '<div class="loading">Running targeted analysis...</div>';
    summaryEl.classList.add('hidden');

    try {
      const result = await api('/api/forensics/analysis', {
        method: 'POST',
        body: JSON.stringify({ target, types })
      });
      if (result.success) {
        const all = extractFindings(result, target);
        forensicsBrowseState.allFindings = all;
        forensicsBrowseState.findings = all;
        renderForensicsFindings(all, findingsEl, summaryEl);
      }
    } catch (error) {
      findingsEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  function renderForensicsFindings(findings, listEl, summaryEl) {
    if (!findings || findings.length === 0) {
      listEl.innerHTML = '<div class="loading">No findings</div>';
      summaryEl.classList.add('hidden');
      return;
    }

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { const s = (f.severity || '').toLowerCase(); counts[s] = (counts[s] || 0) + 1; });
    summaryEl.classList.remove('hidden');
    summaryEl.innerHTML = Object.entries(counts)
      .filter(([, c]) => c > 0)
      .map(([sev, c]) => `<span class="forensics-severity-count ${sev}">${sev.toUpperCase()}: ${c}</span>`)
      .join('');

    listEl.innerHTML = findings.map(f => {
      const sev = (f.severity || '').toLowerCase();
      return `
      <div class="forensics-finding-item">
        <span class="forensics-finding-severity ${sev}">${sev}</span>
        <span class="forensics-finding-category">${escapeHtml(f.category || '')}</span>
        <span class="forensics-finding-message">${escapeHtml(f.message || '')}</span>
      </div>`;
    }).join('');
  }

  function filterForensicsFindings() {
    const severity = document.getElementById('fr-findings-severity').value;
    const filtered = severity ? forensicsBrowseState.allFindings.filter(f => (f.severity || '').toLowerCase() === severity) : forensicsBrowseState.allFindings;
    forensicsBrowseState.findings = filtered;
    renderForensicsFindings(filtered, document.getElementById('fr-findings-list'), document.getElementById('fr-severity-summary'));
  }

  async function loadForensicsFindings() {
    const target = forensicsBrowseState.selectedMinion;
    if (!target) { showToast('Select a collection first', 'error'); return; }

    const findingsSection = document.getElementById('fr-findings-section');
    const findingsEl = document.getElementById('fr-findings-list');
    const summaryEl = document.getElementById('fr-severity-summary');
    findingsSection.classList.remove('hidden');
    findingsEl.innerHTML = '<div class="loading">Loading saved findings...</div>';
    summaryEl.classList.add('hidden');

    try {
      const result = await api(`/api/forensics/findings/${encodeURIComponent(target)}`);
      if (result.success) {
        const all = extractFindings(result, target);
        forensicsBrowseState.allFindings = all;
        forensicsBrowseState.findings = all;
        renderForensicsFindings(all, findingsEl, summaryEl);
      }
    } catch (error) {
      findingsEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadForensicsTimeline() {
    const target = forensicsBrowseState.selectedMinion;
    if (!target) { showToast('Select a collection first', 'error'); return; }
    const limit = parseInt(document.getElementById('fr-timeline-limit').value) || 100;
    document.getElementById('fr-timeline-section').classList.remove('hidden');
    const listEl = document.getElementById('fr-timeline-list');
    listEl.innerHTML = '<div class="loading">Loading timeline...</div>';

    try {
      const artifact = forensicsBrowseState.selectedArtifact || '';
      const result = await api(`/api/forensics/timeline/${encodeURIComponent(target)}?limit=${limit}&collection=${encodeURIComponent(artifact)}`);

      if (!result.success || !result.entries || result.entries.length === 0) {
        listEl.innerHTML = '<div class="loading">No timeline data</div>';
        return;
      }

      const entries = result.entries;
      const note = result.note ? `<div style="color:var(--text-secondary);margin-bottom:8px;font-style:italic;">${escapeHtml(result.note)}</div>` : '';

      listEl.innerHTML = note + `<div class="forensics-timeline-header"><span>Time</span><span>Path</span><span>Perms</span><span>Size</span><span>Owner</span><span>Flags</span><span>Last Editor</span></div>` +
        entries.map(e => {
          const time = e.time ? new Date(e.time).toLocaleString() : '';
          const flagsStyle = e.flags ? 'style="color:var(--status-warning);"' : '';
          // Highlight if non-root edited /etc files
          const editorStyle = (e.editor && !e.editor.startsWith('root') && !e.editor.startsWith('uid=0') && e.path && e.path.startsWith('/etc/')) ? 'style="color:var(--status-error);"' : '';
          return `
          <div class="forensics-timeline-item">
            <span>${escapeHtml(time)}</span>
            <span>${escapeHtml(e.path || '')}</span>
            <span>${escapeHtml(e.perms || '')}</span>
            <span>${e.size ? formatBytes(e.size) : ''}</span>
            <span>${escapeHtml(e.owner || '')}</span>
            <span ${flagsStyle}>${escapeHtml(e.flags || '')}</span>
            <span ${editorStyle}>${escapeHtml(e.editor || '')}</span>
          </div>`;
        }).join('');
    } catch (error) {
      listEl.innerHTML = `<div class="loading">Error: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadForensicsMetadata() {
    const target = forensicsBrowseState.selectedMinion;
    const artifact = forensicsBrowseState.selectedArtifact;
    if (!target || !artifact) { showToast('Select a collection first', 'error'); return; }
    const el = document.getElementById('fr-metadata-content');
    el.textContent = 'Loading...';

    try {
      // Extract metadata.json from the selected tarball
      const result = await api('/api/forensics/artifact-file', {
        method: 'POST',
        body: JSON.stringify({ target, artifact_path: artifact, file_path: './metadata.json' })
      });
      if (result.success) {
        let content = result.content;
        if (typeof content === 'object' && content !== null) {
          content = content[target] || content[Object.keys(content)[0]] || '';
        }
        // Try to pretty-print as JSON
        try {
          const parsed = JSON.parse(content);
          el.textContent = JSON.stringify(parsed, null, 2);
        } catch {
          el.textContent = content || 'No metadata found in this collection';
        }
      } else {
        el.textContent = 'No metadata.json found in this archive';
      }
    } catch (error) {
      el.textContent = `Error: ${error.message}`;
    }
  }

  // ============================================================
  // Event Listeners Setup
  // ============================================================

  function setupEventListeners() {
    // Login/Setup forms
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('setup-form').addEventListener('submit', handleSetup);

    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        if (item.dataset.view) {
          switchView(item.dataset.view);
        }
      });
    });

    // Devices
    document.getElementById('select-all-btn').addEventListener('click', selectAllDevices);
    document.getElementById('select-linux-btn').addEventListener('click', selectLinuxDevices);
    document.getElementById('select-windows-btn').addEventListener('click', selectWindowsDevices);
    document.getElementById('clear-selection-btn').addEventListener('click', clearDeviceSelection);
    document.getElementById('refresh-devices-btn').addEventListener('click', () => loadDevices(true));
    document.getElementById('device-filter').addEventListener('input', renderDeviceList);

    // Commands
    document.getElementById('cmd-execute-btn').addEventListener('click', executeCommand);
    document.getElementById('cmd-input').addEventListener('keydown', (e) => {
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        navigateCmdHistory('up');
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        navigateCmdHistory('down');
      }
    });
    document.getElementById('cmd-clear-btn').addEventListener('click', () => {
      document.getElementById('cmd-output').textContent = 'No output yet.';
    });
    document.getElementById('cmd-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('cmd-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });
    document.getElementById('cmd-target-type').addEventListener('change', (e) => {
      document.getElementById('cmd-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
      document.getElementById('cmd-single-target').classList.toggle('hidden', e.target.value !== 'single');
      toggleInlineSelectorVisibility('cmd', 'cmd-target-type', 'selected');
    });

    // Commands inline device selector
    document.getElementById('cmd-select-all').addEventListener('click', () => inlineSelectorSelectAll('cmd'));
    document.getElementById('cmd-select-linux').addEventListener('click', () => inlineSelectorSelectLinux('cmd'));
    document.getElementById('cmd-select-windows').addEventListener('click', () => inlineSelectorSelectWindows('cmd'));
    document.getElementById('cmd-select-none').addEventListener('click', () => inlineSelectorSelectNone('cmd'));

    // Scripts
    document.getElementById('refresh-scripts-btn').addEventListener('click', loadScripts);
    document.getElementById('script-execute-btn').addEventListener('click', executeScript);
    document.getElementById('script-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('script-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });
    document.getElementById('script-target-type').addEventListener('change', (e) => {
      document.getElementById('script-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
      document.getElementById('script-single-target').classList.toggle('hidden', e.target.value !== 'single');
      toggleInlineSelectorVisibility('script', 'script-target-type', 'selected');
    });
    document.getElementById('scripts-os-filter').addEventListener('change', (e) => {
      // Reload with filter
      loadScripts();
    });

    // Scripts inline device selector
    document.getElementById('script-select-all').addEventListener('click', () => inlineSelectorSelectAll('script'));
    document.getElementById('script-select-linux').addEventListener('click', () => inlineSelectorSelectLinux('script'));
    document.getElementById('script-select-windows').addEventListener('click', () => inlineSelectorSelectWindows('script'));
    document.getElementById('script-select-none').addEventListener('click', () => inlineSelectorSelectNone('script'));

    // States
    document.getElementById('refresh-states-btn').addEventListener('click', loadStates);
    document.getElementById('state-apply-btn').addEventListener('click', applyState);
    document.getElementById('state-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('state-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });
    document.getElementById('state-target-type').addEventListener('change', (e) => {
      document.getElementById('state-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
      document.getElementById('state-single-target').classList.toggle('hidden', e.target.value !== 'single');
      toggleInlineSelectorVisibility('state', 'state-target-type', 'selected');
    });
    document.getElementById('states-os-filter').addEventListener('change', loadStates);

    // States inline device selector
    document.getElementById('state-select-all').addEventListener('click', () => inlineSelectorSelectAll('state'));
    document.getElementById('state-select-linux').addEventListener('click', () => inlineSelectorSelectLinux('state'));
    document.getElementById('state-select-windows').addEventListener('click', () => inlineSelectorSelectWindows('state'));
    document.getElementById('state-select-none').addEventListener('click', () => inlineSelectorSelectNone('state'));

    // Playbooks
    document.getElementById('refresh-playbooks-btn').addEventListener('click', loadPlaybooks);
    document.getElementById('playbook-run-btn').addEventListener('click', runPlaybook);
    document.getElementById('playbook-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('playbook-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });
    document.getElementById('playbook-target-type').addEventListener('change', (e) => {
      document.getElementById('playbook-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
      document.getElementById('playbook-single-target').classList.toggle('hidden', e.target.value !== 'single');
      const showSelector = e.target.value === 'selected';
      document.getElementById('playbook-device-selector').classList.toggle('hidden', !showSelector);
    });
    document.getElementById('playbooks-os-filter').addEventListener('change', loadPlaybooks);

    // Playbooks inline device selector
    document.getElementById('playbook-select-all').addEventListener('click', () => inlineSelectorSelectAll('playbook'));
    document.getElementById('playbook-select-linux').addEventListener('click', () => inlineSelectorSelectLinux('playbook'));
    document.getElementById('playbook-select-windows').addEventListener('click', () => inlineSelectorSelectWindows('playbook'));
    document.getElementById('playbook-select-none').addEventListener('click', () => inlineSelectorSelectNone('playbook'));

    // Audit
    document.getElementById('refresh-audit-btn').addEventListener('click', loadAuditLog);
    document.getElementById('audit-action-filter').addEventListener('change', loadAuditLog);
    document.getElementById('audit-user-filter').addEventListener('change', loadAuditLog);
    document.getElementById('audit-limit').addEventListener('change', loadAuditLog);

    // Settings
    document.getElementById('salt-settings-form').addEventListener('submit', saveSaltSettings);
    document.getElementById('test-salt-btn').addEventListener('click', testSaltConnection);
    document.getElementById('change-password-form').addEventListener('submit', changePassword);

    // Emergency
    document.getElementById('lockdown-btn').addEventListener('click', initiateLockdown);
    document.getElementById('emergency-target-type').addEventListener('change', (e) => {
      document.getElementById('emergency-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
      document.getElementById('emergency-single-target').classList.toggle('hidden', e.target.value !== 'single');
      toggleInlineSelectorVisibility('emergency', 'emergency-target-type', 'selected');
    });

    // Emergency inline device selector
    document.getElementById('emergency-select-all').addEventListener('click', () => inlineSelectorSelectAll('emergency'));
    document.getElementById('emergency-select-linux').addEventListener('click', () => inlineSelectorSelectLinux('emergency'));
    document.getElementById('emergency-select-windows').addEventListener('click', () => inlineSelectorSelectWindows('emergency'));
    document.getElementById('emergency-select-none').addEventListener('click', () => inlineSelectorSelectNone('emergency'));

    // Services
    document.getElementById('svc-load-btn').addEventListener('click', loadServices);
    document.getElementById('svc-start-btn').addEventListener('click', () => serviceAction('start'));
    document.getElementById('svc-stop-btn').addEventListener('click', () => serviceAction('stop'));
    document.getElementById('svc-restart-btn').addEventListener('click', () => serviceAction('restart'));
    document.getElementById('svc-enable-btn').addEventListener('click', () => serviceAction('enable'));
    document.getElementById('svc-disable-btn').addEventListener('click', () => serviceAction('disable'));

    // Services filter and running-only toggle
    document.getElementById('svc-filter').addEventListener('input', renderServicesList);
    document.getElementById('svc-running-only').addEventListener('change', renderServicesList);

    // Processes
    document.getElementById('proc-load-btn').addEventListener('click', loadProcesses);
    document.getElementById('proc-kill-btn').addEventListener('click', killProcess);
    document.getElementById('proc-pkill-btn').addEventListener('click', pkillProcess);

    // Processes filter and refresh
    document.getElementById('proc-filter').addEventListener('input', renderProcessesList);
    document.getElementById('proc-refresh-btn').addEventListener('click', loadProcesses);

    // Network
    document.getElementById('net-load-btn').addEventListener('click', loadNetworkConnections);

    // Network filter and refresh
    document.getElementById('net-filter').addEventListener('input', renderNetworkList);
    document.getElementById('net-refresh-btn').addEventListener('click', loadNetworkConnections);

    // Files
    document.getElementById('files-browse-btn').addEventListener('click', browseFiles);
    document.getElementById('files-up-btn').addEventListener('click', navigateUp);
    document.getElementById('files-save-btn').addEventListener('click', saveFile);
    document.getElementById('files-close-btn').addEventListener('click', closeFileEditor);
    document.getElementById('files-path').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') browseFiles();
    });

    // Logs
    document.getElementById('logs-single-target').addEventListener('change', loadLogSources);
    document.getElementById('logs-load-btn').addEventListener('click', () => { stopLogTail(); loadLogs(); });
    document.getElementById('logs-refresh-btn').addEventListener('click', () => { stopLogTail(); loadLogs(); });
    document.getElementById('logs-filter').addEventListener('input', renderLogsList);
    document.getElementById('logs-tail-btn').addEventListener('click', toggleLogTail);

    // Suspicious
    document.getElementById('susp-scan-btn').addEventListener('click', () => scanSuspicious(false));
    document.getElementById('susp-quick-btn').addEventListener('click', () => scanSuspicious(true));
    document.getElementById('susp-severity-filter').addEventListener('change', renderSuspiciousList);
    document.getElementById('susp-target-type').addEventListener('change', (e) => {
      document.getElementById('susp-single-target').classList.toggle('hidden', e.target.value !== 'single');
      toggleInlineSelectorVisibility('susp', 'susp-target-type', 'selected');
    });

    // Suspicious inline device selector
    document.getElementById('susp-select-all').addEventListener('click', () => inlineSelectorSelectAll('susp'));
    document.getElementById('susp-select-linux').addEventListener('click', () => inlineSelectorSelectLinux('susp'));
    document.getElementById('susp-select-windows').addEventListener('click', () => inlineSelectorSelectWindows('susp'));
    document.getElementById('susp-select-none').addEventListener('click', () => inlineSelectorSelectNone('susp'));

    // Reports
    document.getElementById('report-status-btn').addEventListener('click', generateStatusReport);
    document.getElementById('report-audit-btn').addEventListener('click', generateAuditReport);
    document.getElementById('report-security-btn').addEventListener('click', generateSecurityReport);
    document.getElementById('report-copy-btn').addEventListener('click', copyReport);
    document.getElementById('report-download-btn').addEventListener('click', downloadReport);
    document.getElementById('report-comprehensive-btn').addEventListener('click', generateComprehensiveReport);

    // Forensics
    document.querySelectorAll('.forensics-tab').forEach(tab => {
      tab.addEventListener('click', () => switchForensicsTab(tab.dataset.ftab));
    });
    document.getElementById('fr-collect-btn').addEventListener('click', forensicsCollect);
    document.getElementById('fr-check-tools-btn').addEventListener('click', forensicsCheckTools);
    document.getElementById('fr-collect-level').addEventListener('change', (e) => {
      document.getElementById('fr-comprehensive-opts').classList.toggle('hidden', e.target.value !== 'comprehensive');
      const descEl = document.getElementById('fr-level-desc');
      if (descEl) descEl.textContent = forensicsLevelDescs[e.target.value] || '';
      // Auto-bump timeout for comprehensive/advanced scans
      const timeoutEl = document.getElementById('fr-collect-timeout');
      const currentTimeout = parseInt(timeoutEl.value) || 300;
      if (e.target.value === 'comprehensive' && currentTimeout < 900) {
        timeoutEl.value = 900;
      } else if (e.target.value === 'advanced' && currentTimeout < 600) {
        timeoutEl.value = 600;
      }
    });
    document.getElementById('fr-collect-target-type').addEventListener('change', (e) => {
      document.getElementById('fr-collect-single-target').classList.toggle('hidden', e.target.value !== 'single');
      const infoEl = document.getElementById('fr-selected-info');
      if (e.target.value === 'selected') {
        const count = state.selectedDevices.size;
        infoEl.textContent = count > 0 ? `${count} device(s) selected` : 'Select devices below';
        infoEl.classList.remove('hidden');
      } else {
        infoEl.classList.add('hidden');
      }
      renderForensicsDeviceChecklist();
    });
    document.getElementById('fr-collect-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('fr-collect-output').textContent);
      showToast('Copied', 'success');
    });
    document.getElementById('fr-cleanup-btn').addEventListener('click', forensicsCleanup);
    document.getElementById('fr-retrieve-btn').addEventListener('click', () => {
      if (forensicsBrowseState.selectedArtifact && forensicsBrowseState.selectedMinion) {
        retrieveArtifact(forensicsBrowseState.selectedMinion, forensicsBrowseState.selectedArtifact);
      } else {
        showToast('Select a collection first', 'error');
      }
    });
    document.getElementById('fr-run-analysis-btn').addEventListener('click', forensicsRunAnalysis);
    document.getElementById('fr-targeted-analyze-btn').addEventListener('click', forensicsTargetedAnalyze);
    document.getElementById('fr-file-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('fr-file-content').textContent);
      showToast('Copied', 'success');
    });
    document.getElementById('fr-findings-severity').addEventListener('change', filterForensicsFindings);
    document.getElementById('fr-load-saved-btn').addEventListener('click', loadForensicsFindings);
    document.getElementById('fr-load-timeline-btn').addEventListener('click', loadForensicsTimeline);
    document.getElementById('fr-load-metadata-btn').addEventListener('click', loadForensicsMetadata);
    document.getElementById('fr-fullscreen-btn').addEventListener('click', () => {
      const fb = document.getElementById('fr-filebrowser');
      fb.classList.toggle('forensics-filebrowser-fullscreen');
      const btn = document.getElementById('fr-fullscreen-btn');
      btn.textContent = fb.classList.contains('forensics-filebrowser-fullscreen') ? 'Exit Fullscreen' : 'Fullscreen';
    });

    // Theme toggle
    document.getElementById('theme-toggle-btn').addEventListener('click', toggleTheme);

    // User Management - Toggle create user panel
    document.getElementById('toggle-create-user-btn').addEventListener('click', toggleCreateUserPanel);
    document.getElementById('close-create-user-btn').addEventListener('click', toggleCreateUserPanel);

    // User Management - List users
    document.getElementById('users-list-btn').addEventListener('click', listUsers);

    // User Management - Create user
    document.getElementById('users-create-btn').addEventListener('click', createUser);

    // User Management - Show/hide system users
    document.getElementById('show-system-users').addEventListener('change', toggleSystemUsers);

    // User Management - Close action modal
    document.getElementById('close-user-action').addEventListener('click', closeUserActionModal);

    // User Management - Copy output
    document.getElementById('users-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('pwd-output').textContent);
      showToast('Output copied to clipboard', 'success');
    });

    // User Management - Target type change
    document.getElementById('pwd-target-type').addEventListener('change', (e) => {
      document.getElementById('pwd-custom-target').classList.toggle('hidden', e.target.value !== 'custom');
      document.getElementById('pwd-single-target').classList.toggle('hidden', e.target.value !== 'single');
      toggleInlineSelectorVisibility('pwd', 'pwd-target-type', 'selected');
      updateShellSelectorVisibility();
    });

    // User Management - Single device selection change
    document.getElementById('pwd-single-target').addEventListener('change', updateShellSelectorVisibility);

    // User Management - Inline device selector
    document.getElementById('pwd-select-all').addEventListener('click', () => { inlineSelectorSelectAll('pwd'); updateShellSelectorVisibility(); });
    document.getElementById('pwd-select-linux').addEventListener('click', () => { inlineSelectorSelectLinux('pwd'); updateShellSelectorVisibility(); });
    document.getElementById('pwd-select-windows').addEventListener('click', () => { inlineSelectorSelectWindows('pwd'); updateShellSelectorVisibility(); });
    document.getElementById('pwd-select-none').addEventListener('click', () => { inlineSelectorSelectNone('pwd'); updateShellSelectorVisibility(); });

    // Monitoring
    document.getElementById('mon-create-baseline-btn').addEventListener('click', createBaseline);
    document.getElementById('mon-create-schedule-btn').addEventListener('click', createSchedule);
    document.getElementById('mon-check-now-btn').addEventListener('click', monitorCheckNow);
    document.getElementById('mon-refresh-changes-btn').addEventListener('click', loadChanges);

    // Bulk password rotation
    document.getElementById('bulk-rot-btn').addEventListener('click', bulkRotatePassword);

    // Keys
    document.getElementById('refresh-keys-btn').addEventListener('click', loadKeys);
    document.getElementById('accept-all-keys-btn').addEventListener('click', acceptAllKeys);

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Ctrl+Enter to execute command
      if (e.ctrlKey && e.key === 'Enter') {
        if (state.currentView === 'commands') {
          executeCommand();
        } else if (state.currentView === 'scripts') {
          executeScript();
        }
      }
    });
  }

  // ============================================================
  // Initialization
  // ============================================================

  async function init() {
    setupEventListeners();

    // Check if setup is required
    const setupRequired = await checkSetupRequired();

    if (setupRequired) {
      showLoginScreen(true);
      return;
    }

    // Check if already authenticated
    const isAuthenticated = await checkAuth();

    if (isAuthenticated) {
      showAppScreen();
    } else {
      showLoginScreen(false);
    }

    // Periodic health checks
    setInterval(checkSaltConnection, HEALTH_CHECK_INTERVAL);
  }

  // Start the application
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
