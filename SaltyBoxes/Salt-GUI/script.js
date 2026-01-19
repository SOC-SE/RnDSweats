/**
 * Salt GUI Frontend - Enhanced Competition Edition
 * 
 * Cross-browser compatible (Chrome, Firefox, Safari, Edge)
 * Enhanced features for competition use
 * 
 * Samuel Brucker 2025-2026
 * Enhanced by Claude
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- Element References ---
    const elements = {
        // Device list
        deviceList: document.getElementById('device-list'),
        deviceSearch: document.getElementById('device-search'),
        selectAllDevices: document.getElementById('select-all-devices'),
        deselectAllDevices: document.getElementById('deselect-all-devices'),
        
        // Script list
        scriptList: document.getElementById('script-list'),
        scriptSearch: document.getElementById('script-search'),
        scriptArgsContainer: document.getElementById('script-args-container'),
        scriptTypeSelector: document.getElementById('script-type-selector'),
        
        // Console
        outputConsole: document.getElementById('output-console'),
        clearConsole: document.getElementById('clear-console'),
        toggleConsole: document.getElementById('toggle-console'),
        
        // Status
        notificationBadge: document.querySelector('.notification-badge'),
        minionCounter: document.querySelector('.minion-counter'),
        runningJobsCounter: document.querySelector('.running-scripts-counter'),
        saltStatus: document.getElementById('salt-status'),
        
        // Modals
        settingsModal: document.getElementById('settings-modal'),
        settingsIcon: document.getElementById('settings-icon'),
        settingsForm: document.getElementById('settings-form'),
        connectDeviceModal: document.getElementById('connect-device-modal'),
        terminalModal: document.getElementById('terminal-modal'),
        terminalOutput: document.getElementById('terminal-output'),
        terminalCommandInput: document.getElementById('terminal-command-input'),
        terminalTitle: document.getElementById('terminal-title'),
        scriptViewerModal: document.getElementById('script-viewer-modal'),
        emergencyModal: document.getElementById('emergency-modal'),
        
        // Monitoring
        monitoringDeviceSelect: document.getElementById('monitoring-device-select'),
        monitoringViewSelect: document.getElementById('monitoring-view-select'),
        monitoringContent: document.getElementById('monitoring-content'),
        
        // Services
        serviceDeviceSelect: document.getElementById('service-device-select'),
        serviceName: document.getElementById('service-name'),
        serviceOutput: document.getElementById('service-output'),
        
        // Playbooks
        playbooksList: document.getElementById('playbooks-list'),
        playbookTitle: document.getElementById('playbook-title'),
        playbookDescription: document.getElementById('playbook-description'),
        playbookSteps: document.getElementById('playbook-steps'),
        playbookTargets: document.getElementById('playbook-targets'),
        playbookResults: document.getElementById('playbook-results'),
        
        // Audit
        auditLogBody: document.getElementById('audit-log-body'),
        
        // Quick terminal
        quickTerminalDevice: document.getElementById('quick-terminal-device'),
        quickCommand: document.getElementById('quick-command'),
        quickOutput: document.getElementById('quick-output'),
        
        // Context menu
        contextMenu: document.getElementById('custom-script-context-menu')
    };

    // --- State ---
    let proxyUrl = 'http://localhost:3000';
    let currentArgSpec = null;
    let selectedPlaybook = null;
    let commandHistory = [];
    let historyIndex = -1;
    let deviceCache = {};
    let consoleCollapsed = false;

    // --- Utility Functions ---

    function logToConsole(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.classList.add('log-entry', `log-${type}`);
        
        // Sanitize HTML in message except for <pre> tags
        const sanitizedMessage = message.replace(/<(?!pre|\/pre)[^>]*>/g, '');
        logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${sanitizedMessage}`;
        
        elements.outputConsole.appendChild(logEntry);
        elements.outputConsole.scrollTop = elements.outputConsole.scrollHeight;
    }

    function showNotification(message, type = 'info') {
        // Create a toast notification for important messages
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        
        // Trigger animation
        requestAnimationFrame(() => {
            toast.classList.add('show');
        });
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function updateNotificationBadge(count) {
        if (count > 0) {
            elements.notificationBadge.textContent = count;
            elements.notificationBadge.style.display = 'block';
        } else {
            elements.notificationBadge.style.display = 'none';
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // --- API Functions ---

    async function fetchWithTimeout(url, options = {}, timeout = 30000) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        
        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(id);
            return response;
        } catch (error) {
            clearTimeout(id);
            throw error;
        }
    }

    async function loadSettings() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/settings`);
            const settings = await response.json();
            
            document.getElementById('proxyURL').value = settings.proxyURL || '';
            document.getElementById('saltAPIUrl').value = settings.saltAPIUrl || '';
            document.getElementById('username').value = settings.username || '';
            document.getElementById('password').value = settings.password || '';
            document.getElementById('eauth').value = settings.eauth || 'pam';
            document.getElementById('enableAuth').checked = settings.enableAuth || false;
            document.getElementById('authPassword').value = settings.authPassword || '';
            document.getElementById('alertWebhook').value = settings.alertWebhook || '';
            
            proxyUrl = settings.proxyURL || proxyUrl;
        } catch (error) {
            console.error('Error loading settings:', error);
            logToConsole('Error loading settings. Using defaults.', 'error');
        }
    }

    async function saveSettings(event) {
        event.preventDefault();
        const formData = new FormData(elements.settingsForm);
        const settings = Object.fromEntries(formData.entries());
        settings.enableAuth = document.getElementById('enableAuth').checked;

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/settings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings),
            });
            
            if (response.ok) {
                logToConsole('Settings saved successfully.', 'success');
                showNotification('Settings saved!', 'success');
                elements.settingsModal.style.display = 'none';
                proxyUrl = settings.proxyURL || proxyUrl;
            } else {
                const error = await response.json();
                throw new Error(error.message);
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            logToConsole(`Error saving settings: ${error.message}`, 'error');
        }
    }

    async function checkHealth() {
        const statusDot = elements.saltStatus.querySelector('.status-dot');
        const statusText = elements.saltStatus.querySelector('.status-text');
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/health`, {}, 5000);
            const health = await response.json();
            
            if (health.saltApi === 'ok') {
                statusDot.className = 'status-dot status-ok';
                statusText.textContent = 'Connected';
                
                // Update minion counts
                const up = health.minionStatus?.up?.length || 0;
                const down = health.minionStatus?.down?.length || 0;
                elements.minionCounter.textContent = `Devices: ${up}/${up + down}`;
            } else {
                statusDot.className = 'status-dot status-error';
                statusText.textContent = 'Salt API Error';
            }
            
            // Update job count
            elements.runningJobsCounter.textContent = `Jobs: ${health.activeJobs || 0}`;
        } catch (error) {
            statusDot.className = 'status-dot status-error';
            statusText.textContent = 'Disconnected';
        }
    }

    async function checkUnacceptedKeys() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys`);
            if (!response.ok) return;
            
            const data = await response.json();
            const keys = data.return[0]?.data?.return || {};
            const unacceptedKeys = keys.minions_pre || [];
            updateNotificationBadge(unacceptedKeys.length);
        } catch (error) {
            console.error('Error checking keys:', error);
        }
    }

    // --- Device Management ---

    async function fetchAvailableDevices() {
        logToConsole('Fetching available devices...');
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: '*',
                    fun: 'grains.item',
                    arg: ['os', 'kernel', 'ip4_interfaces']
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || response.statusText);
            }

            const data = await response.json();
            const minions = (data.return && typeof data.return[0] === 'object') ? data.return[0] : {};
            
            deviceCache = minions;
            const activeMinions = Object.keys(minions);
            
            logToConsole(`Found ${activeMinions.length} active devices.`, 'success');
            updateDeviceList(minions);
            populateDeviceSelects(minions);
            
            // Fetch scripts
            const scriptType = document.querySelector('input[name="script-type"]:checked').value;
            if (activeMinions.length > 0) {
                if (scriptType === 'salt') {
                    fetchAvailableScripts(activeMinions[0]);
                } else {
                    fetchCustomScripts();
                }
            }
        } catch (error) {
            console.error('Fetch Devices Error:', error);
            logToConsole(`Error fetching devices: ${error.message}`, 'error');
        }
    }

    function updateDeviceList(minions) {
        elements.deviceList.innerHTML = '';
        const deviceNames = Object.keys(minions);

        if (deviceNames.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No active devices found';
            li.classList.add('disabled');
            elements.deviceList.appendChild(li);
            return;
        }

        deviceNames.sort().forEach(deviceName => {
            const info = minions[deviceName] || {};
            const os = info.os || 'Unknown';
            const kernel = info.kernel || '';
            
            const li = document.createElement('li');
            li.innerHTML = `
                <span class="device-name">${escapeHtml(deviceName)}</span>
                <span class="device-info">${escapeHtml(os)} (${escapeHtml(kernel)})</span>
            `;
            li.dataset.deviceName = deviceName;
            li.dataset.os = os;
            li.dataset.kernel = kernel;
            elements.deviceList.appendChild(li);
        });
    }

    function populateDeviceSelects(minions) {
        const deviceNames = Object.keys(minions).sort();
        const selects = [
            elements.monitoringDeviceSelect,
            elements.serviceDeviceSelect,
            elements.quickTerminalDevice,
            document.getElementById('playbook-targets'),
            document.getElementById('emergency-targets')
        ];

        selects.forEach(select => {
            if (!select) return;
            
            const isMultiple = select.multiple;
            const currentValue = select.value;
            
            // Clear existing options (keep first if it's a placeholder)
            while (select.options.length > (isMultiple ? 0 : 1)) {
                select.remove(isMultiple ? 0 : 1);
            }
            
            deviceNames.forEach(deviceName => {
                const option = document.createElement('option');
                option.value = deviceName;
                option.textContent = deviceName;
                select.appendChild(option);
            });
            
            // Restore selection if possible
            if (currentValue && !isMultiple) {
                select.value = currentValue;
            }
        });
    }

    // --- Script Management ---

    async function fetchAvailableScripts(minionId) {
        logToConsole(`Fetching Salt functions from ${minionId}...`);
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: minionId,
                    fun: 'sys.list_functions'
                })
            });

            if (!response.ok) throw new Error('API request failed');

            const data = await response.json();
            const scripts = data.return?.[0]?.[minionId] || [];

            if (scripts.length > 0) {
                logToConsole(`Fetched ${scripts.length} Salt functions.`, 'success');
                updateScriptList(scripts);
            } else {
                logToConsole('No Salt functions returned.', 'warn');
                updateScriptList([]);
            }
        } catch (error) {
            console.error('Fetch Scripts Error:', error);
            logToConsole(`Error fetching scripts: ${error.message}`, 'error');
        }
    }

    async function fetchCustomScripts() {
        logToConsole('Fetching custom scripts...');
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/custom-scripts`);
            if (!response.ok) throw new Error('API request failed');
            
            const scripts = await response.json();
            
            if (scripts.length > 0) {
                logToConsole(`Fetched ${scripts.length} custom scripts.`, 'success');
                updateScriptList(scripts);
            } else {
                logToConsole('No custom scripts found.', 'warn');
                updateScriptList([]);
            }
        } catch (error) {
            console.error('Fetch Custom Scripts Error:', error);
            logToConsole(`Error fetching custom scripts: ${error.message}`, 'error');
        }
    }

    function updateScriptList(scripts) {
        elements.scriptList.innerHTML = '';

        if (scripts.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No scripts found';
            li.classList.add('disabled');
            elements.scriptList.appendChild(li);
            return;
        }

        scripts.sort().forEach(scriptName => {
            const li = document.createElement('li');
            li.textContent = scriptName;
            elements.scriptList.appendChild(li);
        });
    }

    async function displayScriptArguments(scriptName) {
        elements.scriptArgsContainer.innerHTML = '';
        currentArgSpec = null;
        
        const firstDevice = elements.deviceList.querySelector('li:not(.disabled)');
        if (!firstDevice) {
            logToConsole('No devices available to fetch script documentation.', 'warn');
            return;
        }
        
        const minionId = firstDevice.dataset.deviceName;
        logToConsole(`Fetching arguments for ${scriptName}...`);
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: minionId,
                    fun: 'sys.argspec',
                    arg: [scriptName]
                })
            });

            if (!response.ok) throw new Error('Failed to fetch argspec');

            const data = await response.json();
            const argspec = data.return?.[0]?.[minionId]?.[scriptName];
            currentArgSpec = argspec;

            if (argspec && Object.keys(argspec).length > 0) {
                const posArgs = argspec.args || [];
                const keywordArgs = Object.keys(argspec.kwargs || {});
                const allArgs = [...posArgs, ...keywordArgs];
                
                const ignoredArgs = new Set([
                    'timeout', 'job_id', 'expr_form', 'tgt_type', 'tgt',
                    'kwarg', 'fun', 'client', 'arg', 'user', 'password', 'eauth'
                ]);
                
                const filteredArgs = allArgs.filter(arg => 
                    arg && !ignoredArgs.has(arg.split('=')[0].trim())
                );

                if (filteredArgs.length > 0) {
                    logToConsole(`Found ${filteredArgs.length} arguments for ${scriptName}.`, 'info');
                    
                    const formHtml = filteredArgs.map(arg => {
                        const isKwarg = argspec.kwargs && arg in argspec.kwargs;
                        const argName = arg.split('=')[0].trim();
                        const defaultValue = isKwarg ? argspec.kwargs[arg] : '';
                        
                        return `
                            <div class="script-arg-item">
                                <label for="arg-${argName}">${argName}${isKwarg ? ' (optional)' : ''}</label>
                                <input type="text" id="arg-${argName}" name="${argName}" 
                                       placeholder="${defaultValue || 'Enter value'}">
                            </div>
                        `;
                    }).join('');
                    
                    elements.scriptArgsContainer.innerHTML = formHtml;
                }
            }
        } catch (error) {
            console.error('Fetch Argspec Error:', error);
            logToConsole(`Could not fetch arguments: ${error.message}`, 'warn');
        }
    }

    // --- Script Deployment ---

    async function deployScripts() {
        const selectedDevices = [...elements.deviceList.querySelectorAll('.selected')]
            .map(item => item.dataset.deviceName);
        const selectedScriptItems = [...elements.scriptList.querySelectorAll('.selected')];
        const manualArgsInput = document.getElementById('manual-args');
        const appendCommandInput = document.getElementById('append-command');
        const errorMessage = document.getElementById('error-message');

        errorMessage.textContent = '';

        if (selectedDevices.length === 0) {
            errorMessage.textContent = 'Please select at least one device.';
            logToConsole('Please select at least one device.', 'warn');
            return;
        }

        if (selectedScriptItems.length === 0) {
            errorMessage.textContent = 'Please select at least one script.';
            logToConsole('Please select at least one script to deploy.', 'warn');
            return;
        }

        const scriptType = document.querySelector('input[name="script-type"]:checked').value;
        const appendCommand = appendCommandInput.value.trim();

        for (const scriptItem of selectedScriptItems) {
            const scriptName = scriptItem.textContent;
            let payload;
            let saltArgs = [];
            let saltKwargs = {};

            // Parse arguments
            if (manualArgsInput.value.trim() !== '') {
                saltArgs = manualArgsInput.value.trim().split(',').map(s => s.trim()).filter(s => s);
            } else if (selectedScriptItems.length === 1) {
                const argInputs = elements.scriptArgsContainer.querySelectorAll('input');
                argInputs.forEach(input => {
                    if (input.value) {
                        if (currentArgSpec?.args?.includes(input.name)) {
                            saltArgs.push(input.value);
                        } else {
                            saltKwargs[input.name] = input.value;
                        }
                    }
                });
            }

            // Build payload
            if (scriptType === 'custom') {
                const customArgsString = saltArgs.join(' ');
                
                if (appendCommand) {
                    const command = `(salt-call --local cp.get_url salt://${scriptName} - | sh -s -- ${customArgsString}) ${appendCommand}`.trim();
                    payload = {
                        client: 'local',
                        tgt: selectedDevices,
                        tgt_type: 'list',
                        fun: 'cmd.run',
                        arg: [command]
                    };
                } else {
                    payload = {
                        client: 'local',
                        tgt: selectedDevices,
                        tgt_type: 'list',
                        fun: 'cmd.script',
                        arg: [`salt://${scriptName}`, customArgsString]
                    };
                }
            } else {
                if (appendCommand) {
                    const argsString = saltArgs.map(arg => `'${arg}'`).join(' ');
                    const kwargsString = Object.entries(saltKwargs)
                        .map(([key, value]) => `${key}='${value}'`).join(' ');
                    const command = `salt-call --local ${scriptName} ${argsString} ${kwargsString} ${appendCommand}`.trim();
                    
                    payload = {
                        client: 'local',
                        tgt: selectedDevices,
                        tgt_type: 'list',
                        fun: 'cmd.run',
                        arg: [command]
                    };
                } else {
                    payload = {
                        client: 'local',
                        tgt: selectedDevices,
                        tgt_type: 'list',
                        fun: scriptName,
                    };
                    if (saltArgs.length > 0) payload.arg = saltArgs;
                    if (Object.keys(saltKwargs).length > 0) payload.kwarg = saltKwargs;
                }
            }

            logToConsole(`Deploying ${scriptName} to ${selectedDevices.join(', ')}...`, 'info');

            try {
                const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || response.statusText);
                }

                const data = await response.json();
                logToConsole(`Result for ${scriptName}: <pre>${JSON.stringify(data.return[0], null, 2)}</pre>`, 'success');
                showNotification(`${scriptName} deployed successfully`, 'success');
            } catch (error) {
                console.error(`Error executing ${scriptName}:`, error);
                logToConsole(`Error executing ${scriptName}: ${error.message}`, 'error');
                showNotification(`Failed to deploy ${scriptName}`, 'error');
            }
        }
    }

    // --- Selection Handling ---

    function handleSelection(list, event) {
        const item = event.target.closest('li');
        if (!item || item.classList.contains('disabled')) return;

        if (!event.ctrlKey && !event.metaKey) {
            list.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
        }
        item.classList.toggle('selected');

        if (list.id === 'script-list') {
            const selectedScripts = list.querySelectorAll('.selected');
            const scriptType = document.querySelector('input[name="script-type"]:checked').value;

            document.getElementById('manual-args').value = '';
            document.getElementById('append-command').value = '';

            if (selectedScripts.length === 1 && scriptType === 'salt') {
                elements.scriptArgsContainer.style.display = 'block';
                displayScriptArguments(selectedScripts[0].textContent);
            } else {
                elements.scriptArgsContainer.innerHTML = '';
                elements.scriptArgsContainer.style.display = 'none';
                currentArgSpec = null;
            }
        }
    }

    // --- Terminal Functions ---

    function openTerminal() {
        const deviceId = elements.quickTerminalDevice.value || elements.monitoringDeviceSelect.value;
        if (!deviceId) {
            showNotification('Please select a device first', 'warn');
            return;
        }

        elements.terminalTitle.textContent = `📺 Terminal: ${deviceId}`;
        elements.terminalOutput.innerHTML = `<div class="terminal-welcome">Connected to ${escapeHtml(deviceId)}\nType commands below. Use Ctrl+L to clear.\n${'─'.repeat(50)}</div>`;
        elements.terminalCommandInput.value = '';
        elements.terminalModal.style.display = 'block';
        elements.terminalModal.dataset.deviceId = deviceId;
        
        // Focus input after modal animation
        setTimeout(() => elements.terminalCommandInput.focus(), 100);
    }

    async function executeTerminalCommand(event) {
        // Handle special keys
        if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                elements.terminalCommandInput.value = commandHistory[commandHistory.length - 1 - historyIndex];
            }
            return;
        }
        
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                elements.terminalCommandInput.value = commandHistory[commandHistory.length - 1 - historyIndex];
            } else if (historyIndex === 0) {
                historyIndex = -1;
                elements.terminalCommandInput.value = '';
            }
            return;
        }
        
        if (event.ctrlKey && event.key === 'l') {
            event.preventDefault();
            elements.terminalOutput.innerHTML = '';
            return;
        }
        
        if (event.key !== 'Enter') return;

        const command = elements.terminalCommandInput.value.trim();
        const deviceId = elements.terminalModal.dataset.deviceId;

        if (!command || !deviceId) return;

        // Add to history
        if (commandHistory[commandHistory.length - 1] !== command) {
            commandHistory.push(command);
            if (commandHistory.length > 100) commandHistory.shift();
        }
        historyIndex = -1;

        // Echo command
        const echoEntry = document.createElement('div');
        echoEntry.className = 'terminal-command';
        echoEntry.innerHTML = `<span class="terminal-prompt">$</span> ${escapeHtml(command)}`;
        elements.terminalOutput.appendChild(echoEntry);
        elements.terminalCommandInput.value = '';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: deviceId,
                    fun: 'cmd.run',
                    arg: [command]
                })
            });

            const data = await response.json();
            let result = data.return?.[0]?.[deviceId];

            if (result === null || result === undefined) {
                result = 'Error: No response from device';
            } else if (typeof result === 'string' && result.trim() === '') {
                result = '(command completed with no output)';
            }

            const resultEntry = document.createElement('div');
            resultEntry.className = response.ok ? 'terminal-result' : 'terminal-error';
            resultEntry.textContent = result;
            elements.terminalOutput.appendChild(resultEntry);
        } catch (error) {
            const errorEntry = document.createElement('div');
            errorEntry.className = 'terminal-error';
            errorEntry.textContent = `Error: ${error.message}`;
            elements.terminalOutput.appendChild(errorEntry);
        }

        elements.terminalOutput.scrollTop = elements.terminalOutput.scrollHeight;
    }

    // --- Quick Command ---

    async function executeQuickCommand() {
        const deviceId = elements.quickTerminalDevice.value;
        const command = elements.quickCommand.value.trim();

        if (!deviceId) {
            showNotification('Please select a device', 'warn');
            return;
        }
        if (!command) {
            showNotification('Please enter a command', 'warn');
            return;
        }

        elements.quickOutput.innerHTML = '<p class="loading">Executing...</p>';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/quick-cmd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: deviceId, cmd: command })
            });

            const data = await response.json();
            const result = data.return?.[0]?.[deviceId] || 'No output';
            
            elements.quickOutput.innerHTML = `<pre>${escapeHtml(result)}</pre>`;
        } catch (error) {
            elements.quickOutput.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    // --- Monitoring Functions ---

    async function fetchMonitoringData() {
        const deviceId = elements.monitoringDeviceSelect.value;
        const view = elements.monitoringViewSelect.value;

        if (!deviceId || !view) {
            elements.monitoringContent.innerHTML = '<p class="hint">Please select a device and view.</p>';
            return;
        }

        elements.monitoringContent.innerHTML = '<p class="loading">Loading...</p>';

        let payload;
        switch (view) {
            case 'firewall-rules':
                payload = { client: 'local', tgt: deviceId, fun: 'iptables.get_rules' };
                break;
            case 'running-processes':
                payload = { client: 'local', tgt: deviceId, fun: 'status.procs' };
                break;
            case 'network-connections':
                payload = { client: 'local', tgt: deviceId, fun: 'network.active_tcp' };
                break;
            case 'system-info':
                payload = { client: 'local', tgt: deviceId, fun: 'grains.items' };
                break;
            case 'users':
                payload = { client: 'local', tgt: deviceId, fun: 'user.list_users' };
                break;
            case 'services':
                payload = { client: 'local', tgt: deviceId, fun: 'service.get_all' };
                break;
            default:
                return;
        }

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error('API request failed');

            const data = await response.json();
            const result = data.return?.[0]?.[deviceId];

            elements.monitoringContent.innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>`;
            document.getElementById('mon-last-update').textContent = `Last Update: ${new Date().toLocaleTimeString()}`;
            document.getElementById('mon-device-status').textContent = `Device: ${deviceId}`;
            
            const deviceInfo = deviceCache[deviceId];
            if (deviceInfo) {
                document.getElementById('mon-os').textContent = `OS: ${deviceInfo.os || 'Unknown'}`;
            }
        } catch (error) {
            elements.monitoringContent.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    // --- Service Management ---

    async function manageService(action) {
        const deviceId = elements.serviceDeviceSelect.value;
        const serviceName = elements.serviceName.value.trim();

        if (!deviceId) {
            showNotification('Please select a device', 'warn');
            return;
        }
        if (!serviceName && action !== 'list') {
            showNotification('Please enter a service name', 'warn');
            return;
        }

        elements.serviceOutput.innerHTML = '<p class="loading">Processing...</p>';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/services/manage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    targets: [deviceId],
                    service: serviceName,
                    action: action
                })
            });

            const data = await response.json();
            elements.serviceOutput.innerHTML = `<pre>${JSON.stringify(data.result?.return?.[0] || data, null, 2)}</pre>`;
            showNotification(`Service ${action} completed`, 'success');
        } catch (error) {
            elements.serviceOutput.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    async function listServices(filter = 'all') {
        const deviceId = elements.serviceDeviceSelect.value;
        if (!deviceId) {
            showNotification('Please select a device', 'warn');
            return;
        }

        elements.serviceOutput.innerHTML = '<p class="loading">Loading services...</p>';

        const fun = filter === 'running' ? 'service.get_running' : 'service.get_all';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: deviceId,
                    fun: fun
                })
            });

            const data = await response.json();
            const services = data.return?.[0]?.[deviceId] || [];
            
            if (Array.isArray(services)) {
                elements.serviceOutput.innerHTML = `<pre>${services.sort().join('\n')}</pre>`;
            } else {
                elements.serviceOutput.innerHTML = `<pre>${JSON.stringify(services, null, 2)}</pre>`;
            }
        } catch (error) {
            elements.serviceOutput.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    // --- Playbooks ---

    async function loadPlaybooks() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/playbooks`);
            const playbooks = await response.json();

            elements.playbooksList.innerHTML = '';
            
            if (playbooks.length === 0) {
                elements.playbooksList.innerHTML = '<li class="disabled">No playbooks found</li>';
                return;
            }

            playbooks.forEach(pb => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span class="playbook-name">${escapeHtml(pb.name)}</span>
                    <span class="playbook-steps-count">${pb.steps} steps</span>
                `;
                li.dataset.filename = pb.filename;
                li.addEventListener('click', () => loadPlaybookDetails(pb.filename.replace('.json', '')));
                elements.playbooksList.appendChild(li);
            });
        } catch (error) {
            elements.playbooksList.innerHTML = `<li class="disabled">Error loading playbooks</li>`;
            console.error('Error loading playbooks:', error);
        }
    }

    async function loadPlaybookDetails(name) {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/playbooks/${name}`);
            const playbook = await response.json();

            selectedPlaybook = name;
            elements.playbookTitle.textContent = playbook.name;
            elements.playbookDescription.textContent = playbook.description || 'No description';

            elements.playbookSteps.innerHTML = playbook.steps.map((step, i) => `
                <div class="playbook-step">
                    <span class="step-number">${i + 1}</span>
                    <div class="step-content">
                        <strong>${escapeHtml(step.name)}</strong>
                        <code>${escapeHtml(step.function)}</code>
                        ${step.args ? `<small>Args: ${escapeHtml(JSON.stringify(step.args))}</small>` : ''}
                    </div>
                </div>
            `).join('');

            document.querySelector('.playbook-execute-section').style.display = 'block';
            elements.playbookResults.innerHTML = '';
        } catch (error) {
            elements.playbookTitle.textContent = 'Error Loading Playbook';
            elements.playbookDescription.textContent = error.message;
        }
    }

    async function executePlaybook() {
        if (!selectedPlaybook) {
            showNotification('Please select a playbook', 'warn');
            return;
        }

        const targets = [...elements.playbookTargets.selectedOptions].map(opt => opt.value);
        if (targets.length === 0) {
            showNotification('Please select target devices', 'warn');
            return;
        }

        elements.playbookResults.innerHTML = '<p class="loading">Executing playbook...</p>';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/playbooks/${selectedPlaybook}/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets })
            }, 300000); // 5 minute timeout for playbooks

            const data = await response.json();

            let resultsHtml = `<h4>Results (${data.completedSteps}/${data.totalSteps} steps)</h4>`;
            data.results.forEach(result => {
                const statusClass = result.status === 'completed' ? 'success' : 'error';
                resultsHtml += `
                    <div class="playbook-result ${statusClass}">
                        <strong>${escapeHtml(result.step)}</strong>: ${result.status}
                        ${result.error ? `<br><small>${escapeHtml(result.error)}</small>` : ''}
                    </div>
                `;
            });

            elements.playbookResults.innerHTML = resultsHtml;
            showNotification(`Playbook completed: ${data.completedSteps}/${data.totalSteps} steps`, 
                data.completedSteps === data.totalSteps ? 'success' : 'warn');
        } catch (error) {
            elements.playbookResults.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    // --- Audit Log ---

    async function loadAuditLog() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/audit?limit=100`);
            const entries = await response.json();

            if (entries.length === 0) {
                elements.auditLogBody.innerHTML = '<tr><td colspan="5">No audit entries found</td></tr>';
                return;
            }

            elements.auditLogBody.innerHTML = entries.map(entry => `
                <tr>
                    <td>${entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'N/A'}</td>
                    <td>${escapeHtml(entry.ip || 'N/A')}</td>
                    <td>${escapeHtml(entry.method || 'N/A')}</td>
                    <td>${escapeHtml(entry.path || 'N/A')}</td>
                    <td><code>${escapeHtml(JSON.stringify(entry.body || {}).substring(0, 100))}</code></td>
                </tr>
            `).join('');
        } catch (error) {
            elements.auditLogBody.innerHTML = `<tr><td colspan="5">Error: ${escapeHtml(error.message)}</td></tr>`;
        }
    }

    // --- Emergency Functions ---

    async function blockAllTraffic() {
        const targets = [...document.getElementById('emergency-targets').selectedOptions].map(opt => opt.value);
        if (targets.length === 0) {
            showNotification('Select target devices', 'warn');
            return;
        }

        if (!confirm(`⚠️ This will DROP all incoming traffic except SSH on ${targets.length} devices. Continue?`)) {
            return;
        }

        const output = document.getElementById('emergency-output');
        output.innerHTML = '<p class="loading">Applying emergency firewall rules...</p>';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/emergency/block-all-traffic`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets })
            });

            const data = await response.json();
            output.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
            showNotification('Emergency firewall rules applied', 'success');
            logToConsole('EMERGENCY: Blocked all traffic on ' + targets.join(', '), 'warn');
        } catch (error) {
            output.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    async function killConnections() {
        const targets = [...document.getElementById('emergency-targets').selectedOptions].map(opt => opt.value);
        const port = document.getElementById('emergency-port').value.trim();

        if (targets.length === 0) {
            showNotification('Select target devices', 'warn');
            return;
        }

        if (!confirm(`⚠️ This will kill ${port ? 'port ' + port : 'ALL'} connections on ${targets.length} devices. Continue?`)) {
            return;
        }

        const output = document.getElementById('emergency-output');
        output.innerHTML = '<p class="loading">Killing connections...</p>';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/emergency/kill-connections`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets, port: port || null })
            });

            const data = await response.json();
            output.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
            showNotification('Connections killed', 'success');
        } catch (error) {
            output.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    async function changePasswords() {
        const targets = [...document.getElementById('emergency-targets').selectedOptions].map(opt => opt.value);
        const usersInput = document.getElementById('emergency-users').value.trim();
        const newPassword = document.getElementById('emergency-new-password').value;

        if (targets.length === 0) {
            showNotification('Select target devices', 'warn');
            return;
        }
        if (!usersInput) {
            showNotification('Enter usernames', 'warn');
            return;
        }
        if (!newPassword) {
            showNotification('Enter new password', 'warn');
            return;
        }

        const users = usersInput.split(',').map(u => u.trim()).filter(u => u);

        if (!confirm(`⚠️ This will change passwords for ${users.length} users on ${targets.length} devices. Continue?`)) {
            return;
        }

        const output = document.getElementById('emergency-output');
        output.innerHTML = '<p class="loading">Changing passwords...</p>';

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/emergency/change-passwords`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets, users, newPassword })
            });

            const data = await response.json();
            output.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
            showNotification('Password changes attempted', 'success');
            logToConsole('EMERGENCY: Password change for ' + users.join(', '), 'warn');
        } catch (error) {
            output.innerHTML = `<p class="error">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    // --- Key Management ---

    async function openConnectDeviceModal() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys`);
            if (!response.ok) throw new Error('Failed to fetch keys');

            const data = await response.json();
            const keys = data.return?.[0]?.data?.return || {};
            const unacceptedKeys = keys.minions_pre || [];
            const acceptedKeys = keys.minions || [];

            updateNotificationBadge(unacceptedKeys.length);

            const unacceptedList = document.getElementById('unaccepted-keys-list');
            const acceptedList = document.getElementById('accepted-keys-list');

            unacceptedList.innerHTML = unacceptedKeys.length > 0 
                ? unacceptedKeys.map(key => `
                    <li>
                        <span>${escapeHtml(key)}</span>
                        <button class="btn btn-accept btn-small" data-minion-id="${escapeHtml(key)}">Accept</button>
                    </li>
                `).join('')
                : '<li class="disabled">No pending keys</li>';

            acceptedList.innerHTML = acceptedKeys.length > 0
                ? acceptedKeys.map(key => `
                    <li>
                        <span>${escapeHtml(key)}</span>
                        <button class="btn btn-remove btn-small" data-minion-id="${escapeHtml(key)}">Remove</button>
                    </li>
                `).join('')
                : '<li class="disabled">No accepted devices</li>';

            elements.connectDeviceModal.style.display = 'block';
        } catch (error) {
            console.error('Error fetching keys:', error);
            logToConsole(`Error fetching keys: ${error.message}`, 'error');
        }
    }

    async function acceptKey(minionId) {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys/accept`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ minionId })
            });

            if (!response.ok) throw new Error('Failed to accept key');

            logToConsole(`Accepted key for ${minionId}`, 'success');
            showNotification(`Key accepted: ${minionId}`, 'success');
            openConnectDeviceModal();
            fetchAvailableDevices();
        } catch (error) {
            logToConsole(`Error accepting key: ${error.message}`, 'error');
        }
    }

    async function removeKey(minionId) {
        if (!confirm(`Remove key for ${minionId}?`)) return;

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys/delete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ minionId })
            });

            if (!response.ok) throw new Error('Failed to remove key');

            logToConsole(`Removed key for ${minionId}`, 'success');
            openConnectDeviceModal();
            fetchAvailableDevices();
        } catch (error) {
            logToConsole(`Error removing key: ${error.message}`, 'error');
        }
    }

    async function acceptAllKeys() {
        if (!confirm('Accept ALL pending keys?')) return;

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys/accept-all`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) throw new Error('Failed to accept all keys');

            logToConsole('Accepted all pending keys', 'success');
            showNotification('All keys accepted', 'success');
            openConnectDeviceModal();
            fetchAvailableDevices();
        } catch (error) {
            logToConsole(`Error accepting all keys: ${error.message}`, 'error');
        }
    }

    // --- Script Viewer ---

    async function viewScriptContent(scriptName) {
        const titleEl = document.getElementById('script-viewer-title');
        const contentEl = document.getElementById('script-viewer-content');
        
        titleEl.textContent = `📄 ${scriptName}`;
        contentEl.innerHTML = '<pre><code>Loading...</code></pre>';
        elements.scriptViewerModal.style.display = 'block';

        try {
            const response = await fetchWithTimeout(
                `${proxyUrl}/custom-script-content?path=${encodeURIComponent(scriptName)}`
            );
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.message || 'Failed to fetch script');
            }

            const data = await response.json();
            contentEl.innerHTML = `<pre><code>${escapeHtml(data.content)}</code></pre>`;
        } catch (error) {
            contentEl.innerHTML = `<pre><code class="error">Error: ${escapeHtml(error.message)}</code></pre>`;
        }
    }

    // --- Tab Navigation ---

    function switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `tab-${tabName}`);
        });

        // Load data for tab
        switch (tabName) {
            case 'audit':
                loadAuditLog();
                break;
            case 'playbooks':
                loadPlaybooks();
                break;
        }
    }

    // --- Event Listeners ---

    // Tab navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Device list
    elements.deviceList.addEventListener('click', e => handleSelection(elements.deviceList, e));
    elements.selectAllDevices?.addEventListener('click', () => {
        elements.deviceList.querySelectorAll('li:not(.disabled)').forEach(li => li.classList.add('selected'));
    });
    elements.deselectAllDevices?.addEventListener('click', () => {
        elements.deviceList.querySelectorAll('.selected').forEach(li => li.classList.remove('selected'));
    });

    // Device search
    elements.deviceSearch?.addEventListener('input', debounce(e => {
        const term = e.target.value.toLowerCase();
        elements.deviceList.querySelectorAll('li').forEach(li => {
            const name = li.dataset.deviceName?.toLowerCase() || '';
            const os = li.dataset.os?.toLowerCase() || '';
            li.style.display = (name.includes(term) || os.includes(term)) ? '' : 'none';
        });
    }, 150));

    // Script list
    elements.scriptList.addEventListener('click', e => handleSelection(elements.scriptList, e));

    // Script search
    elements.scriptSearch?.addEventListener('input', debounce(e => {
        const term = e.target.value.toLowerCase();
        elements.scriptList.querySelectorAll('li').forEach(li => {
            li.style.display = li.textContent.toLowerCase().includes(term) ? '' : 'none';
        });
    }, 150));

    // Script type selector
    elements.scriptTypeSelector?.addEventListener('change', e => {
        const scriptType = e.target.value;
        elements.scriptArgsContainer.innerHTML = '';
        currentArgSpec = null;

        const firstDevice = elements.deviceList.querySelector('li:not(.disabled)');
        if (scriptType === 'salt' && firstDevice) {
            fetchAvailableScripts(firstDevice.dataset.deviceName);
        } else if (scriptType === 'custom') {
            fetchCustomScripts();
        }
    });

    // Deploy button
    document.querySelector('.btn-deploy')?.addEventListener('click', deployScripts);

    // Settings
    elements.settingsIcon?.addEventListener('click', () => {
        elements.settingsModal.style.display = 'block';
    });
    document.getElementById('settings-close-button')?.addEventListener('click', () => {
        elements.settingsModal.style.display = 'none';
    });
    elements.settingsForm?.addEventListener('submit', saveSettings);

    // Connect device modal
    document.querySelector('.btn-connect')?.addEventListener('click', openConnectDeviceModal);
    document.querySelector('#connect-device-modal .close-button')?.addEventListener('click', () => {
        elements.connectDeviceModal.style.display = 'none';
    });
    document.getElementById('accept-all-keys')?.addEventListener('click', acceptAllKeys);

    // Key accept/remove delegation
    document.getElementById('unaccepted-keys-list')?.addEventListener('click', e => {
        if (e.target.classList.contains('btn-accept')) {
            acceptKey(e.target.dataset.minionId);
        }
    });
    document.getElementById('accepted-keys-list')?.addEventListener('click', e => {
        if (e.target.classList.contains('btn-remove')) {
            removeKey(e.target.dataset.minionId);
        }
    });

    // Terminal
    document.getElementById('open-terminal-btn')?.addEventListener('click', openTerminal);
    document.getElementById('terminal-close-button')?.addEventListener('click', () => {
        elements.terminalModal.style.display = 'none';
    });
    elements.terminalCommandInput?.addEventListener('keydown', executeTerminalCommand);

    // Quick command
    document.getElementById('quick-cmd-btn')?.addEventListener('click', executeQuickCommand);
    elements.quickCommand?.addEventListener('keypress', e => {
        if (e.key === 'Enter') executeQuickCommand();
    });

    // Monitoring
    document.getElementById('monitoring-refresh')?.addEventListener('click', fetchMonitoringData);
    elements.monitoringDeviceSelect?.addEventListener('change', fetchMonitoringData);
    elements.monitoringViewSelect?.addEventListener('change', fetchMonitoringData);

    // Services
    document.querySelectorAll('.service-buttons .btn').forEach(btn => {
        btn.addEventListener('click', () => manageService(btn.dataset.action));
    });
    document.getElementById('list-all-services')?.addEventListener('click', () => listServices('all'));
    document.getElementById('list-running-services')?.addEventListener('click', () => listServices('running'));

    // Playbooks
    document.getElementById('refresh-playbooks')?.addEventListener('click', loadPlaybooks);
    document.getElementById('execute-playbook')?.addEventListener('click', executePlaybook);

    // Audit
    document.getElementById('refresh-audit')?.addEventListener('click', loadAuditLog);

    // Emergency
    document.getElementById('emergency-btn')?.addEventListener('click', () => {
        elements.emergencyModal.style.display = 'block';
    });
    document.getElementById('emergency-close-button')?.addEventListener('click', () => {
        elements.emergencyModal.style.display = 'none';
    });
    document.getElementById('emergency-block-traffic')?.addEventListener('click', blockAllTraffic);
    document.getElementById('emergency-kill-connections')?.addEventListener('click', killConnections);
    document.getElementById('emergency-change-passwords')?.addEventListener('click', changePasswords);

    // Script viewer
    document.getElementById('script-viewer-close-button')?.addEventListener('click', () => {
        elements.scriptViewerModal.style.display = 'none';
    });

    // Context menu
    elements.scriptList?.addEventListener('contextmenu', e => {
        e.preventDefault();
        const scriptType = document.querySelector('input[name="script-type"]:checked').value;
        const targetItem = e.target.closest('li');

        if (scriptType === 'custom' && targetItem && !targetItem.classList.contains('disabled')) {
            elements.contextMenu.style.top = `${e.clientY}px`;
            elements.contextMenu.style.left = `${e.clientX}px`;
            elements.contextMenu.style.display = 'block';
            elements.contextMenu.dataset.scriptName = targetItem.textContent;
        }
    });

    document.getElementById('context-menu-view')?.addEventListener('click', () => {
        viewScriptContent(elements.contextMenu.dataset.scriptName);
        elements.contextMenu.style.display = 'none';
    });

    document.getElementById('context-menu-copy')?.addEventListener('click', () => {
        navigator.clipboard?.writeText(elements.contextMenu.dataset.scriptName);
        showNotification('Script name copied', 'success');
        elements.contextMenu.style.display = 'none';
    });

    document.addEventListener('click', e => {
        if (!elements.contextMenu?.contains(e.target)) {
            elements.contextMenu.style.display = 'none';
        }
    });

    // Console controls
    elements.clearConsole?.addEventListener('click', () => {
        elements.outputConsole.innerHTML = '';
    });
    elements.toggleConsole?.addEventListener('click', () => {
        consoleCollapsed = !consoleCollapsed;
        elements.outputConsole.style.display = consoleCollapsed ? 'none' : 'block';
        elements.toggleConsole.textContent = consoleCollapsed ? '▲' : '▼';
    });

    // Close modals on outside click
    window.addEventListener('click', e => {
        if (e.target.classList.contains('modal')) {
            e.target.style.display = 'none';
        }
    });

    // Close modals on Escape
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(modal => {
                modal.style.display = 'none';
            });
        }
    });

    // --- Initialization ---

    async function initializeApp() {
        logToConsole('🧂 Salt GUI starting up...', 'info');
        
        await loadSettings();
        await fetchAvailableDevices();
        await checkHealth();
        await checkUnacceptedKeys();

        // Periodic updates
        setInterval(checkHealth, 30000);
        setInterval(checkUnacceptedKeys, 30000);

        logToConsole('✅ Salt GUI ready.', 'success');
    }

    initializeApp();
});
