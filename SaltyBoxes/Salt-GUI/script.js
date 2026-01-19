/**
 * Salt GUI Frontend - Competition Edition
 * 
 * Cross-browser compatible (Chrome, Firefox, Safari, Edge)
 * Samuel Brucker 2025-2026
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- Element References ---
    const elements = {
        deviceList: document.getElementById('device-list'),
        deviceSearch: document.getElementById('device-search'),
        selectAllDevices: document.getElementById('select-all-devices'),
        deselectAllDevices: document.getElementById('deselect-all-devices'),
        scriptList: document.getElementById('script-list'),
        scriptSearch: document.getElementById('script-search'),
        scriptArgsContainer: document.getElementById('script-args-container'),
        outputConsole: document.getElementById('output-console'),
        clearConsole: document.getElementById('clear-console'),
        toggleConsole: document.getElementById('toggle-console'),
        notificationBadge: document.querySelector('.notification-badge'),
        minionCounter: document.querySelector('.minion-counter'),
        runningJobsCounter: document.querySelector('.running-scripts-counter'),
        saltStatus: document.getElementById('salt-status'),
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
        monitoringDeviceSelect: document.getElementById('monitoring-device-select'),
        monitoringViewSelect: document.getElementById('monitoring-view-select'),
        monitoringContent: document.getElementById('monitoring-content'),
        serviceDeviceSelect: document.getElementById('service-device-select'),
        serviceName: document.getElementById('service-name'),
        serviceOutput: document.getElementById('service-output'),
        playbooksList: document.getElementById('playbooks-list'),
        playbookTitle: document.getElementById('playbook-title'),
        playbookDescription: document.getElementById('playbook-description'),
        playbookSteps: document.getElementById('playbook-steps'),
        playbookTargets: document.getElementById('playbook-targets'),
        playbookResults: document.getElementById('playbook-results'),
        auditLogBody: document.getElementById('audit-log-body'),
        quickTerminalDevice: document.getElementById('quick-terminal-device'),
        quickCommand: document.getElementById('quick-command'),
        quickOutput: document.getElementById('quick-output'),
        contextMenu: document.getElementById('custom-script-context-menu')
    };

    // --- State ---
    // CRITICAL: Use window.location.origin to get the actual server address
    // This ensures the client talks to the server it loaded from, not localhost
    let proxyUrl = window.location.origin;
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
        const sanitizedMessage = message.replace(/<(?!pre|\/pre)[^>]*>/g, '');
        logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${sanitizedMessage}`;
        elements.outputConsole.appendChild(logEntry);
        elements.outputConsole.scrollTop = elements.outputConsole.scrollHeight;
    }

    function showNotification(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('show'));
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
            const response = await fetch(url, { ...options, signal: controller.signal });
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
            
            if (document.getElementById('enableAuth')) {
                document.getElementById('enableAuth').checked = settings.enableAuth || false;
            }
            if (document.getElementById('authPassword')) {
                document.getElementById('authPassword').value = settings.authPassword || '';
            }
            if (document.getElementById('alertWebhook')) {
                document.getElementById('alertWebhook').value = settings.alertWebhook || '';
            }
        } catch (error) {
            logToConsole('Error loading settings. Using defaults.', 'warn');
        }
    }

    async function saveSettings(e) {
        e.preventDefault();
        const settings = {
            proxyURL: document.getElementById('proxyURL').value,
            saltAPIUrl: document.getElementById('saltAPIUrl').value,
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
            eauth: document.getElementById('eauth').value
        };
        
        if (document.getElementById('enableAuth')) {
            settings.enableAuth = document.getElementById('enableAuth').checked;
        }
        if (document.getElementById('authPassword')) {
            settings.authPassword = document.getElementById('authPassword').value;
        }
        if (document.getElementById('alertWebhook')) {
            settings.alertWebhook = document.getElementById('alertWebhook').value;
        }

        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/settings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            
            if (response.ok) {
                logToConsole('Settings saved successfully.', 'success');
                elements.settingsModal.style.display = 'none';
            } else {
                throw new Error('Failed to save');
            }
        } catch (error) {
            logToConsole('Error saving settings: ' + error.message, 'error');
        }
    }

    // --- Health Check ---

    async function checkHealth() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/health`, {}, 5000);
            const health = await response.json();
            
            const statusDot = elements.saltStatus.querySelector('.status-dot');
            const statusText = elements.saltStatus.querySelector('.status-text');
            
            if (health.saltApi === 'ok') {
                statusDot.className = 'status-dot status-ok';
                statusText.textContent = 'Connected';
            } else {
                statusDot.className = 'status-dot status-error';
                statusText.textContent = 'API Error';
            }
            
            elements.runningJobsCounter.textContent = `Jobs: ${health.activeJobs || 0}`;
        } catch (error) {
            const statusDot = elements.saltStatus.querySelector('.status-dot');
            const statusText = elements.saltStatus.querySelector('.status-text');
            statusDot.className = 'status-dot status-error';
            statusText.textContent = 'Disconnected';
        }
    }

    // --- Device Management ---

    async function fetchAvailableDevices() {
        logToConsole('Fetching available devices...');
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ client: 'local', tgt: '*', fun: 'test.ping' })
            });
            
            const data = await response.json();
            const devices = data.return ? data.return[0] : {};
            
            deviceCache = devices;
            renderDeviceList(devices);
            updateDeviceSelects(Object.keys(devices));
            elements.minionCounter.textContent = `Devices: ${Object.keys(devices).length}`;
            logToConsole(`Found ${Object.keys(devices).length} device(s).`, 'success');
        } catch (error) {
            logToConsole('Error fetching devices: ' + error.message, 'error');
            elements.deviceList.innerHTML = '<li class="disabled">Error loading devices</li>';
        }
    }

    function renderDeviceList(devices, filter = '') {
        elements.deviceList.innerHTML = '';
        const deviceNames = Object.keys(devices).filter(name => 
            name.toLowerCase().includes(filter.toLowerCase())
        );
        
        if (deviceNames.length === 0) {
            elements.deviceList.innerHTML = '<li class="disabled">No devices found</li>';
            return;
        }
        
        deviceNames.forEach(name => {
            const li = document.createElement('li');
            li.textContent = name;
            li.dataset.device = name;
            li.addEventListener('click', (e) => {
                if (e.ctrlKey || e.metaKey) {
                    li.classList.toggle('selected');
                } else {
                    elements.deviceList.querySelectorAll('li').forEach(el => el.classList.remove('selected'));
                    li.classList.add('selected');
                }
            });
            elements.deviceList.appendChild(li);
        });
    }

    function updateDeviceSelects(devices) {
        const selects = [
            elements.quickTerminalDevice,
            elements.monitoringDeviceSelect,
            elements.serviceDeviceSelect
        ];
        
        selects.forEach(select => {
            if (!select) return;
            const currentValue = select.value;
            select.innerHTML = '<option value="">Select device...</option>';
            devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device;
                option.textContent = device;
                select.appendChild(option);
            });
            if (currentValue && devices.includes(currentValue)) {
                select.value = currentValue;
            }
        });
        
        // Update playbook targets (multi-select)
        if (elements.playbookTargets) {
            elements.playbookTargets.innerHTML = '';
            devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device;
                option.textContent = device;
                elements.playbookTargets.appendChild(option);
            });
        }
        
        // Update emergency modal targets
        const emergencyTargets = document.getElementById('emergency-targets');
        if (emergencyTargets) {
            emergencyTargets.innerHTML = '';
            devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device;
                option.textContent = device;
                emergencyTargets.appendChild(option);
            });
        }
    }

    function getSelectedDevices() {
        const selected = elements.deviceList.querySelectorAll('li.selected');
        return Array.from(selected).map(li => li.dataset.device);
    }

    // --- Script Management ---

    async function fetchCustomScripts() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/custom-scripts`);
            const scripts = await response.json();
            renderScriptList(scripts);
        } catch (error) {
            logToConsole('Error fetching scripts: ' + error.message, 'error');
        }
    }

    async function fetchSaltFunctions() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ client: 'local', tgt: '*', fun: 'sys.list_functions' })
            });
            
            const data = await response.json();
            const functions = data.return ? Object.values(data.return[0])[0] || [] : [];
            renderScriptList(functions, true);
        } catch (error) {
            logToConsole('Error fetching Salt functions: ' + error.message, 'error');
        }
    }

    function renderScriptList(items, isSaltFunctions = false) {
        const filter = elements.scriptSearch.value.toLowerCase();
        elements.scriptList.innerHTML = '';
        
        const filtered = items.filter(item => item.toLowerCase().includes(filter));
        
        if (filtered.length === 0) {
            elements.scriptList.innerHTML = '<li class="disabled">No scripts found</li>';
            return;
        }
        
        filtered.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            li.dataset.script = item;
            li.dataset.type = isSaltFunctions ? 'salt' : 'custom';
            li.addEventListener('click', () => {
                elements.scriptList.querySelectorAll('li').forEach(el => el.classList.remove('selected'));
                li.classList.add('selected');
                if (isSaltFunctions) {
                    fetchArgSpec(item);
                }
            });
            elements.scriptList.appendChild(li);
        });
    }

    async function fetchArgSpec(functionName) {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: Object.keys(deviceCache)[0] || '*',
                    fun: 'sys.argspec',
                    arg: [functionName]
                })
            });
            
            const data = await response.json();
            const argSpec = data.return ? Object.values(data.return[0])[0] : null;
            currentArgSpec = argSpec;
            renderArgSpec(argSpec, functionName);
        } catch (error) {
            logToConsole('Error fetching argument spec: ' + error.message, 'error');
        }
    }

    function renderArgSpec(argSpec, functionName) {
        elements.scriptArgsContainer.innerHTML = '';
        
        if (!argSpec || !argSpec[functionName]) return;
        
        const spec = argSpec[functionName];
        const args = spec.args || [];
        const defaults = spec.defaults || [];
        
        args.forEach((arg, index) => {
            if (arg === 'self') return;
            
            const defaultIndex = index - (args.length - defaults.length);
            const defaultValue = defaultIndex >= 0 ? defaults[defaultIndex] : '';
            
            const div = document.createElement('div');
            div.className = 'script-arg-item';
            div.innerHTML = `
                <label for="arg-${arg}">${arg}</label>
                <input type="text" id="arg-${arg}" name="${arg}" value="${defaultValue || ''}" placeholder="${arg}">
            `;
            elements.scriptArgsContainer.appendChild(div);
        });
    }

    // --- Deployment ---

    async function deployScript() {
        const devices = getSelectedDevices();
        const selectedScript = elements.scriptList.querySelector('li.selected');
        
        if (devices.length === 0) {
            logToConsole('Please select at least one device.', 'warn');
            return;
        }
        
        if (!selectedScript) {
            logToConsole('Please select a script to deploy.', 'warn');
            return;
        }
        
        const scriptName = selectedScript.dataset.script;
        const scriptType = selectedScript.dataset.type;
        const manualArgs = document.getElementById('manual-args')?.value || '';
        const appendCmd = document.getElementById('append-command')?.value || '';
        
        logToConsole(`Deploying "${scriptName}" to ${devices.length} device(s)...`);
        
        let payload;
        
        if (scriptType === 'salt') {
            // Salt function
            const args = [];
            elements.scriptArgsContainer.querySelectorAll('input').forEach(input => {
                if (input.value) args.push(input.value);
            });
            if (manualArgs) {
                args.push(...manualArgs.split(',').map(a => a.trim()));
            }
            
            payload = {
                client: 'local',
                tgt: devices,
                tgt_type: 'list',
                fun: scriptName,
                arg: args
            };
        } else {
            // Custom script
            let scriptPath = `salt://${scriptName}`;
            let cmdArgs = manualArgs;
            if (appendCmd) {
                cmdArgs = cmdArgs ? `${cmdArgs} ${appendCmd}` : appendCmd;
            }
            
            payload = {
                client: 'local',
                tgt: devices,
                tgt_type: 'list',
                fun: 'cmd.script',
                arg: [scriptPath, cmdArgs].filter(Boolean)
            };
        }
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }, 120000);
            
            const data = await response.json();
            
            if (data.return) {
                Object.entries(data.return[0]).forEach(([device, result]) => {
                    logToConsole(`[${device}] Result:`, 'info');
                    if (typeof result === 'object') {
                        logToConsole(`<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`, 'info');
                    } else {
                        logToConsole(`<pre>${escapeHtml(String(result))}</pre>`, 'info');
                    }
                });
            }
            
            logToConsole('Deployment complete.', 'success');
        } catch (error) {
            logToConsole('Deployment error: ' + error.message, 'error');
        }
    }

    // --- Key Management ---

    async function checkUnacceptedKeys() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys`);
            const data = await response.json();
            const keys = data.return ? data.return[0].data.return : {};
            const unaccepted = keys.minions_pre || [];
            updateNotificationBadge(unaccepted.length);
        } catch (error) {
            logToConsole('Error fetching keys: ' + error.message, 'error');
        }
    }

    async function loadKeyLists() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/keys`);
            const data = await response.json();
            const keys = data.return ? data.return[0].data.return : {};
            
            const unacceptedList = document.getElementById('unaccepted-keys-list');
            const acceptedList = document.getElementById('accepted-keys-list');
            
            // Unaccepted keys
            unacceptedList.innerHTML = '';
            (keys.minions_pre || []).forEach(key => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>${escapeHtml(key)}</span>
                    <button class="btn btn-small btn-accept" data-key="${escapeHtml(key)}">Accept</button>
                `;
                unacceptedList.appendChild(li);
            });
            
            if ((keys.minions_pre || []).length === 0) {
                unacceptedList.innerHTML = '<li class="disabled">No pending keys</li>';
            }
            
            // Accepted keys
            acceptedList.innerHTML = '';
            (keys.minions || []).forEach(key => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <span>${escapeHtml(key)}</span>
                    <button class="btn btn-small btn-remove" data-key="${escapeHtml(key)}">Remove</button>
                `;
                acceptedList.appendChild(li);
            });
            
            if ((keys.minions || []).length === 0) {
                acceptedList.innerHTML = '<li class="disabled">No accepted keys</li>';
            }
        } catch (error) {
            logToConsole('Error loading keys: ' + error.message, 'error');
        }
    }

    async function acceptKey(minionId) {
        try {
            await fetchWithTimeout(`${proxyUrl}/keys/accept`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ minionId })
            });
            logToConsole(`Key accepted: ${minionId}`, 'success');
            loadKeyLists();
            checkUnacceptedKeys();
            fetchAvailableDevices();
        } catch (error) {
            logToConsole('Error accepting key: ' + error.message, 'error');
        }
    }

    async function acceptAllKeys() {
        try {
            await fetchWithTimeout(`${proxyUrl}/keys/accept-all`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            logToConsole('All keys accepted.', 'success');
            loadKeyLists();
            checkUnacceptedKeys();
            fetchAvailableDevices();
        } catch (error) {
            logToConsole('Error accepting all keys: ' + error.message, 'error');
        }
    }

    async function deleteKey(minionId) {
        if (!confirm(`Remove key for "${minionId}"?`)) return;
        
        try {
            await fetchWithTimeout(`${proxyUrl}/keys/delete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ minionId })
            });
            logToConsole(`Key removed: ${minionId}`, 'success');
            loadKeyLists();
            fetchAvailableDevices();
        } catch (error) {
            logToConsole('Error removing key: ' + error.message, 'error');
        }
    }

    // --- Terminal ---

    let terminalDevice = null;

    function openTerminal(device) {
        terminalDevice = device;
        elements.terminalTitle.textContent = `Terminal: ${device}`;
        elements.terminalOutput.innerHTML = `<div class="terminal-welcome">Connected to ${device}\nType commands and press Enter to execute.\n</div>`;
        elements.terminalModal.style.display = 'block';
        elements.terminalCommandInput.focus();
    }

    async function executeTerminalCommand(cmd) {
        if (!terminalDevice || !cmd.trim()) return;
        
        // Add to history
        commandHistory.unshift(cmd);
        if (commandHistory.length > 100) commandHistory.pop();
        historyIndex = -1;
        
        // Display command
        const cmdDiv = document.createElement('div');
        cmdDiv.className = 'terminal-command';
        cmdDiv.textContent = `$ ${cmd}`;
        elements.terminalOutput.appendChild(cmdDiv);
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/quick-cmd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: terminalDevice, cmd, timeout: 30 })
            });
            
            const data = await response.json();
            const result = data.return ? data.return[0][terminalDevice] : 'No response';
            
            const resultDiv = document.createElement('div');
            resultDiv.className = 'terminal-result';
            resultDiv.textContent = typeof result === 'object' ? JSON.stringify(result, null, 2) : result;
            elements.terminalOutput.appendChild(resultDiv);
        } catch (error) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'terminal-error';
            errorDiv.textContent = `Error: ${error.message}`;
            elements.terminalOutput.appendChild(errorDiv);
        }
        
        elements.terminalOutput.scrollTop = elements.terminalOutput.scrollHeight;
        elements.terminalCommandInput.value = '';
    }

    // --- Quick Terminal ---

    async function executeQuickCommand() {
        const device = elements.quickTerminalDevice.value;
        const cmd = elements.quickCommand.value;
        
        if (!device) {
            logToConsole('Select a device first.', 'warn');
            return;
        }
        
        if (!cmd.trim()) return;
        
        elements.quickOutput.textContent = 'Executing...';
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/quick-cmd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: device, cmd, timeout: 30 })
            });
            
            const data = await response.json();
            const result = data.return ? data.return[0][device] : 'No response';
            elements.quickOutput.textContent = typeof result === 'object' ? JSON.stringify(result, null, 2) : result;
        } catch (error) {
            elements.quickOutput.textContent = `Error: ${error.message}`;
        }
    }

    // --- Monitoring ---

    async function loadMonitoringView() {
        const device = elements.monitoringDeviceSelect?.value;
        const view = elements.monitoringViewSelect?.value;
        
        if (!device || !view) return;
        
        elements.monitoringContent.textContent = 'Loading...';
        
        const commands = {
            firewall: 'iptables -L -n 2>/dev/null || nft list ruleset 2>/dev/null || firewall-cmd --list-all 2>/dev/null || echo "No firewall found"',
            processes: 'ps aux --sort=-%cpu | head -30',
            connections: 'netstat -tulpn 2>/dev/null || ss -tulpn',
            sysinfo: 'echo "=== HOSTNAME ===" && hostname && echo "\\n=== UPTIME ===" && uptime && echo "\\n=== MEMORY ===" && free -h && echo "\\n=== DISK ===" && df -h | grep -v tmpfs',
            users: 'echo "=== LOGGED IN ===" && who && echo "\\n=== ALL USERS ===" && cat /etc/passwd | grep -v nologin | grep -v false',
            services: 'systemctl list-units --type=service --state=running 2>/dev/null | head -30 || service --status-all 2>/dev/null | grep "+"'
        };
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/quick-cmd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: device, cmd: commands[view], timeout: 30 })
            });
            
            const data = await response.json();
            const result = data.return ? data.return[0][device] : 'No response';
            elements.monitoringContent.textContent = result;
        } catch (error) {
            elements.monitoringContent.textContent = `Error: ${error.message}`;
        }
    }

    // --- Services ---

    async function manageService(action) {
        const device = elements.serviceDeviceSelect?.value;
        const service = elements.serviceName?.value;
        
        if (!device || !service) {
            logToConsole('Select device and enter service name.', 'warn');
            return;
        }
        
        elements.serviceOutput.textContent = `${action}ing ${service}...`;
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/services/manage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets: [device], service, action })
            });
            
            const data = await response.json();
            elements.serviceOutput.textContent = JSON.stringify(data, null, 2);
            logToConsole(`Service ${action}: ${service} on ${device}`, 'success');
        } catch (error) {
            elements.serviceOutput.textContent = `Error: ${error.message}`;
        }
    }

    async function checkServiceStatus() {
        const device = elements.serviceDeviceSelect?.value;
        const service = elements.serviceName?.value;
        
        if (!device || !service) return;
        
        elements.serviceOutput.textContent = 'Checking status...';
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/quick-cmd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    target: device, 
                    cmd: `systemctl status ${service} 2>/dev/null || service ${service} status 2>/dev/null`,
                    timeout: 10 
                })
            });
            
            const data = await response.json();
            const result = data.return ? data.return[0][device] : 'No response';
            elements.serviceOutput.textContent = result;
        } catch (error) {
            elements.serviceOutput.textContent = `Error: ${error.message}`;
        }
    }

    // --- Playbooks ---

    async function loadPlaybooks() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/playbooks`);
            const playbooks = await response.json();
            
            elements.playbooksList.innerHTML = '';
            playbooks.forEach(pb => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <div class="playbook-name">${escapeHtml(pb.name)}</div>
                    <div class="playbook-steps-count">${pb.steps} steps</div>
                `;
                li.dataset.name = pb.filename.replace('.json', '');
                li.addEventListener('click', () => loadPlaybookDetail(li.dataset.name));
                elements.playbooksList.appendChild(li);
            });
        } catch (error) {
            logToConsole('Error loading playbooks: ' + error.message, 'error');
        }
    }

    async function loadPlaybookDetail(name) {
        selectedPlaybook = name;
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/playbooks/${name}`);
            const playbook = await response.json();
            
            elements.playbookTitle.textContent = playbook.name;
            elements.playbookDescription.textContent = playbook.description || '';
            
            elements.playbookSteps.innerHTML = '';
            playbook.steps.forEach((step, index) => {
                const div = document.createElement('div');
                div.className = 'playbook-step';
                div.innerHTML = `
                    <div class="step-number">${index + 1}</div>
                    <div class="step-content">
                        <strong>${escapeHtml(step.name)}</strong>
                        <code>${escapeHtml(step.function || 'cmd.run')}</code>
                        ${step.command ? `<small>${escapeHtml(step.command.substring(0, 80))}${step.command.length > 80 ? '...' : ''}</small>` : ''}
                    </div>
                `;
                elements.playbookSteps.appendChild(div);
            });
            
            elements.playbookResults.innerHTML = '';
        } catch (error) {
            logToConsole('Error loading playbook: ' + error.message, 'error');
        }
    }

    async function executePlaybook() {
        if (!selectedPlaybook) {
            logToConsole('Select a playbook first.', 'warn');
            return;
        }
        
        const targets = Array.from(elements.playbookTargets.selectedOptions).map(o => o.value);
        
        if (targets.length === 0) {
            logToConsole('Select target devices.', 'warn');
            return;
        }
        
        elements.playbookResults.innerHTML = '<div class="loading">Executing playbook...</div>';
        logToConsole(`Executing playbook "${selectedPlaybook}" on ${targets.length} device(s)...`);
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/playbooks/${selectedPlaybook}/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets })
            }, 300000);
            
            const data = await response.json();
            
            elements.playbookResults.innerHTML = '';
            data.results.forEach(result => {
                const div = document.createElement('div');
                div.className = `playbook-result ${result.status === 'completed' ? 'success' : 'error'}`;
                div.innerHTML = `
                    <strong>${escapeHtml(result.step)}</strong>
                    <pre>${escapeHtml(JSON.stringify(result.result || result.error, null, 2))}</pre>
                `;
                elements.playbookResults.appendChild(div);
            });
            
            logToConsole(`Playbook complete: ${data.completedSteps}/${data.totalSteps} steps`, 'success');
        } catch (error) {
            elements.playbookResults.innerHTML = `<div class="playbook-result error">Error: ${escapeHtml(error.message)}</div>`;
            logToConsole('Playbook error: ' + error.message, 'error');
        }
    }

    // --- Audit Log ---

    async function loadAuditLog() {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/audit?limit=100`);
            const entries = await response.json();
            
            elements.auditLogBody.innerHTML = '';
            entries.forEach(entry => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${escapeHtml(entry.timestamp || '')}</td>
                    <td>${escapeHtml(entry.user || '')}</td>
                    <td>${escapeHtml(entry.ip || '')}</td>
                    <td>${escapeHtml(entry.action || '')}</td>
                    <td><code>${escapeHtml(JSON.stringify(entry.details || {}))}</code></td>
                `;
                elements.auditLogBody.appendChild(tr);
            });
        } catch (error) {
            logToConsole('Error loading audit log: ' + error.message, 'error');
        }
    }

    // --- Emergency Controls ---

    async function blockAllTraffic() {
        const targets = Array.from(document.getElementById('emergency-targets').selectedOptions).map(o => o.value);
        const allowSSH = document.getElementById('emergency-allow-ssh')?.checked !== false;
        
        if (targets.length === 0) {
            alert('Select target devices.');
            return;
        }
        
        if (!confirm(`BLOCK ALL TRAFFIC on ${targets.length} device(s)? SSH will ${allowSSH ? 'remain open' : 'be blocked'}.`)) {
            return;
        }
        
        document.getElementById('emergency-output').textContent = 'Blocking traffic...';
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/emergency/block-all-traffic`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets, allowSSH })
            });
            
            const data = await response.json();
            document.getElementById('emergency-output').textContent = JSON.stringify(data, null, 2);
            logToConsole('Traffic blocked on ' + targets.join(', '), 'success');
        } catch (error) {
            document.getElementById('emergency-output').textContent = `Error: ${error.message}`;
        }
    }

    async function killConnections() {
        const targets = Array.from(document.getElementById('emergency-targets').selectedOptions).map(o => o.value);
        const port = document.getElementById('emergency-port')?.value;
        
        if (targets.length === 0) {
            alert('Select target devices.');
            return;
        }
        
        if (!confirm(`KILL ${port ? 'port ' + port : 'ALL'} connections on ${targets.length} device(s)?`)) {
            return;
        }
        
        document.getElementById('emergency-output').textContent = 'Killing connections...';
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/emergency/kill-connections`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets, port: port || null })
            });
            
            const data = await response.json();
            document.getElementById('emergency-output').textContent = JSON.stringify(data, null, 2);
            logToConsole('Connections killed on ' + targets.join(', '), 'success');
        } catch (error) {
            document.getElementById('emergency-output').textContent = `Error: ${error.message}`;
        }
    }

    async function changePasswords() {
        const targets = Array.from(document.getElementById('emergency-targets').selectedOptions).map(o => o.value);
        const users = document.getElementById('emergency-users')?.value.split(',').map(u => u.trim()).filter(Boolean);
        const newPassword = document.getElementById('emergency-password')?.value;
        
        if (targets.length === 0 || users.length === 0 || !newPassword) {
            alert('Select targets, enter users (comma-separated), and provide new password.');
            return;
        }
        
        if (!confirm(`Change password for ${users.join(', ')} on ${targets.length} device(s)?`)) {
            return;
        }
        
        document.getElementById('emergency-output').textContent = 'Changing passwords...';
        
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/api/emergency/change-passwords`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targets, users, newPassword })
            });
            
            const data = await response.json();
            document.getElementById('emergency-output').textContent = JSON.stringify(data, null, 2);
            logToConsole('Passwords changed on ' + targets.join(', '), 'success');
        } catch (error) {
            document.getElementById('emergency-output').textContent = `Error: ${error.message}`;
        }
    }

    // --- Script Viewer ---

    async function viewScriptContent(scriptName) {
        try {
            const response = await fetchWithTimeout(`${proxyUrl}/custom-script-content?path=${encodeURIComponent(scriptName)}`);
            const data = await response.json();
            
            document.getElementById('script-viewer-title').textContent = scriptName;
            document.getElementById('script-code').textContent = data.content || 'Unable to load script.';
            elements.scriptViewerModal.style.display = 'block';
        } catch (error) {
            logToConsole('Error loading script: ' + error.message, 'error');
        }
    }

    // --- Tab Navigation ---

    function initTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tabId = btn.dataset.tab;
                
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                btn.classList.add('active');
                document.getElementById(`tab-${tabId}`).classList.add('active');
                
                // Load tab-specific data
                if (tabId === 'playbooks') loadPlaybooks();
                if (tabId === 'audit') loadAuditLog();
            });
        });
    }

    // --- Event Listeners ---

    // Settings
    elements.settingsIcon?.addEventListener('click', () => {
        elements.settingsModal.style.display = 'block';
        loadSettings();
    });
    
    elements.settingsForm?.addEventListener('submit', saveSettings);
    
    document.querySelectorAll('.close-button').forEach(btn => {
        btn.addEventListener('click', () => {
            btn.closest('.modal').style.display = 'none';
        });
    });

    // Device management
    document.querySelector('.btn-connect')?.addEventListener('click', () => {
        elements.connectDeviceModal.style.display = 'block';
        loadKeyLists();
    });
    
    elements.selectAllDevices?.addEventListener('click', () => {
        elements.deviceList.querySelectorAll('li:not(.disabled)').forEach(li => li.classList.add('selected'));
    });
    
    elements.deselectAllDevices?.addEventListener('click', () => {
        elements.deviceList.querySelectorAll('li').forEach(li => li.classList.remove('selected'));
    });

    // Device search
    elements.deviceSearch?.addEventListener('input', debounce((e) => {
        renderDeviceList(deviceCache, e.target.value);
    }, 150));

    // Script type toggle
    document.querySelectorAll('input[name="script-type"]')?.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'custom') {
                fetchCustomScripts();
            } else {
                fetchSaltFunctions();
            }
        });
    });

    // Script search
    elements.scriptSearch?.addEventListener('input', debounce(() => {
        const type = document.querySelector('input[name="script-type"]:checked')?.value;
        if (type === 'custom') {
            fetchCustomScripts();
        } else {
            fetchSaltFunctions();
        }
    }, 150));

    // Deploy button
    document.querySelector('.btn-deploy')?.addEventListener('click', deployScript);

    // Key management
    document.getElementById('unaccepted-keys-list')?.addEventListener('click', (e) => {
        if (e.target.classList.contains('btn-accept')) {
            acceptKey(e.target.dataset.key);
        }
    });
    
    document.getElementById('accepted-keys-list')?.addEventListener('click', (e) => {
        if (e.target.classList.contains('btn-remove')) {
            deleteKey(e.target.dataset.key);
        }
    });
    
    document.getElementById('accept-all-keys')?.addEventListener('click', acceptAllKeys);
    
    document.getElementById('refresh-devices')?.addEventListener('click', fetchAvailableDevices);

    // Terminal
    document.getElementById('open-terminal-btn')?.addEventListener('click', () => {
        const device = elements.quickTerminalDevice.value;
        if (device) {
            openTerminal(device);
        } else {
            logToConsole('Select a device first.', 'warn');
        }
    });
    
    elements.terminalCommandInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            executeTerminalCommand(elements.terminalCommandInput.value);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                elements.terminalCommandInput.value = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                elements.terminalCommandInput.value = commandHistory[historyIndex];
            } else {
                historyIndex = -1;
                elements.terminalCommandInput.value = '';
            }
        }
    });

    // Quick terminal
    document.getElementById('quick-cmd-btn')?.addEventListener('click', executeQuickCommand);
    elements.quickCommand?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') executeQuickCommand();
    });

    // Monitoring
    elements.monitoringDeviceSelect?.addEventListener('change', loadMonitoringView);
    elements.monitoringViewSelect?.addEventListener('change', loadMonitoringView);
    document.getElementById('refresh-monitoring')?.addEventListener('click', loadMonitoringView);

    // Services
    document.getElementById('service-start')?.addEventListener('click', () => manageService('start'));
    document.getElementById('service-stop')?.addEventListener('click', () => manageService('stop'));
    document.getElementById('service-restart')?.addEventListener('click', () => manageService('restart'));
    document.getElementById('service-status')?.addEventListener('click', checkServiceStatus);

    // Playbooks
    document.getElementById('execute-playbook')?.addEventListener('click', executePlaybook);

    // Audit
    document.getElementById('refresh-audit')?.addEventListener('click', loadAuditLog);

    // Emergency
    document.getElementById('emergency-btn')?.addEventListener('click', () => {
        elements.emergencyModal.style.display = 'block';
    });
    
    document.getElementById('btn-block-traffic')?.addEventListener('click', blockAllTraffic);
    document.getElementById('btn-kill-connections')?.addEventListener('click', killConnections);
    document.getElementById('btn-change-passwords')?.addEventListener('click', changePasswords);

    // Context menu for scripts
    elements.scriptList?.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        const scriptType = document.querySelector('input[name="script-type"]:checked')?.value;
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
        elements.toggleConsole.textContent = consoleCollapsed ? '+' : '-';
    });

    // Modal close on outside click
    window.addEventListener('click', e => {
        if (e.target.classList.contains('modal')) {
            e.target.style.display = 'none';
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(modal => modal.style.display = 'none');
        }
        if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            elements.outputConsole.innerHTML = '';
        }
    });

    // --- Initialization ---

    initTabs();

    async function initializeApp() {
        logToConsole('Salt GUI starting up...');
        
        await loadSettings();
        await fetchAvailableDevices();
        await fetchCustomScripts();
        await checkHealth();
        await checkUnacceptedKeys();

        setInterval(checkHealth, 30000);
        setInterval(checkUnacceptedKeys, 30000);

        logToConsole('Salt GUI ready.', 'success');
    }

    initializeApp();
});
