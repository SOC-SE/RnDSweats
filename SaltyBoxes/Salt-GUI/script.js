document.addEventListener('DOMContentLoaded', () => {
    const deviceList = document.getElementById('device-list');
    const scriptList = document.getElementById('script-list');
    const outputConsole = document.getElementById('output-console');
    const scriptArgsContainer = document.getElementById('script-args-container');
    const scriptTypeSelector = document.getElementById('script-type-selector');
    const notificationBadge = document.querySelector('.notification-badge');
    const settingsIcon = document.getElementById('settings-icon');
    const settingsModal = document.getElementById('settings-modal');
    const monitoringDeviceSelect = document.getElementById('monitoring-device-select');
    const monitoringViewSelect = document.getElementById('monitoring-view-select');
    const monitoringOutputContent = document.querySelector('.system-monitoring-output-content');
    const settingsCloseButton = document.getElementById('settings-close-button');
    const settingsForm = document.getElementById('settings-form');
    const scriptViewerModal = document.getElementById('script-viewer-modal');
    const scriptViewerCloseButton = document.getElementById('script-viewer-close-button');
    const scriptViewerTitle = document.getElementById('script-viewer-title');
    const scriptViewerContent = document.getElementById('script-viewer-content');
    const contextMenu = document.getElementById('custom-script-context-menu');
    // --- Terminal Modal Elements ---
    const openTerminalBtn = document.getElementById('open-terminal-btn'); // This ID is now in the HTML
    const terminalModal = document.getElementById('terminal-modal');
    const terminalCloseButton = document.getElementById('terminal-close-button');
    const terminalTitle = document.getElementById('terminal-title');
    const terminalOutput = document.getElementById('terminal-output');
    const terminalCommandInput = document.getElementById('terminal-command-input');

    let proxyUrl = 'http://localhost:3000'; // Default value, will be updated from settings
    let currentArgSpec = null; // Variable to cache the argspec

    // --- Settings Management ---
    async function loadSettings() {
        try {
            const response = await fetch('/api/settings');
            const settings = await response.json();
            document.getElementById('proxyURL').value = settings.proxyURL;
            document.getElementById('saltAPIUrl').value = settings.saltAPIUrl;
            document.getElementById('username').value = settings.username;
            document.getElementById('password').value = settings.password;
            document.getElementById('eauth').value = settings.eauth;
            proxyUrl = settings.proxyURL;
        } catch (error) {
            console.error('Error loading settings:', error);
            logToConsole('Error loading settings. Using default values.', 'error');
        }
    }

    async function saveSettings(event) {
        event.preventDefault();
        const formData = new FormData(settingsForm);
        const settings = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(settings),
            });
            if (response.ok) {
                logToConsole('Settings saved successfully.', 'success');
                settingsModal.style.display = 'none';
                proxyUrl = settings.proxyURL; // Update proxyUrl after saving
            } else {
                logToConsole('Failed to save settings.', 'error');
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            logToConsole('Error saving settings.', 'error');
        }
    }

    settingsIcon.addEventListener('click', () => {
        settingsModal.style.display = 'block';
    });

    settingsCloseButton.addEventListener('click', () => {
        settingsModal.style.display = 'none';
    });

    settingsForm.addEventListener('submit', saveSettings);

    // --- Helper Functions ---
    function logToConsole(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.classList.add('log-entry', `log-${type}`);
        logEntry.innerHTML = `<span class="timestamp">${timestamp}</span>${message}`;
        outputConsole.appendChild(logEntry);
        outputConsole.scrollTop = outputConsole.scrollHeight; // Auto-scroll
    }

    function updateNotificationBadge(count) {
        if (count > 0) {
            notificationBadge.textContent = count;
            notificationBadge.style.display = 'block';
        } else {
            notificationBadge.style.display = 'none';
        }
    }

    async function checkUnacceptedKeys() {
        try {
            const response = await fetch(`${proxyUrl}/keys`);
            if (!response.ok) {
                return; // Silently fail, maybe log to console instead of UI
            }
            const data = await response.json();
            const keys = data.return[0].data.return;
            const unacceptedKeys = keys.minions_pre;
            updateNotificationBadge(unacceptedKeys.length);
        } catch (error) {
            console.error('Error checking unaccepted keys:', error);
        }
    }

    const handleSelection = (list, event) => {
        const item = event.target;
        if (item.tagName !== 'LI') return;

        if (list.id === 'device-list') {
            // Device list multi-select with Ctrl key
            if (!event.ctrlKey) {
                const selectedItems = list.querySelectorAll('.selected');
                selectedItems.forEach(selected => selected.classList.remove('selected'));
            }
            item.classList.toggle('selected');
        } else if (list.id === 'script-list') {
            // Script list multi-select with Ctrl key
            if (!event.ctrlKey) {
                const selectedItems = list.querySelectorAll('.selected');
                selectedItems.forEach(selected => selected.classList.remove('selected'));
            }
            item.classList.toggle('selected');

            const selectedScripts = list.querySelectorAll('.selected');
            const scriptType = document.querySelector('input[name="script-type"]:checked').value;
            
            // Clear manual inputs when selection changes
            document.getElementById('manual-args').value = '';
            document.getElementById('append-command').value = '';

            if (selectedScripts.length > 1) {
                // Multiple scripts selected, clear and hide args
                scriptArgsContainer.innerHTML = '';
                scriptArgsContainer.style.display = 'none';
                currentArgSpec = null;
            } else if (selectedScripts.length === 1) {
                // Single script selected
                scriptArgsContainer.style.display = 'block';
                if (scriptType === 'salt') {
                    displayScriptArguments(selectedScripts[0].textContent);
                } else {
                    // For custom scripts, clear the arguments section
                    scriptArgsContainer.innerHTML = '';
                    currentArgSpec = null;
                }
            } else {
                // No scripts selected
                scriptArgsContainer.innerHTML = '';
                scriptArgsContainer.style.display = 'block';
                currentArgSpec = null;
            }
        }
    };

    // --- Salt API Functions ---

    async function fetchAvailableDevices() {
        logToConsole('Fetching available devices...');
        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    client: 'local',
                    tgt: '*',
                    fun: 'grains.item',
                    arg: ['os']
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`API request failed: ${errorData.message || response.statusText}`);
            }

            const data = await response.json();
            const minions = (data.return && typeof data.return[0] === 'object' && data.return[0] !== null) ? data.return[0] : {};
            const activeMinions = Object.keys(minions);
            const minionCounter = document.querySelector('.minion-counter');
            minionCounter.textContent = `Devices Connected: ${activeMinions.length}`;

            logToConsole(`Found ${activeMinions.length} active minions.`, 'info');
            updateDeviceList(minions);
            logToConsole('Successfully fetched and updated device list.', 'success');

            if (activeMinions.length > 0) {
                // Fetch scripts based on the selected script type
                const scriptType = document.querySelector('input[name="script-type"]:checked').value;
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

    async function fetchAvailableScripts(minionId) {
        logToConsole(`Fetching available scripts from ${minionId}...`);
        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: minionId,
                    fun: 'sys.list_functions'
                })
            });

            if (!response.ok) throw new Error('API request to fetch scripts failed');

            const data = await response.json();
            const scripts = data.return && data.return[0] && data.return[0][minionId] ? data.return[0][minionId] : [];

            if (scripts.length > 0) {
                logToConsole(`Successfully fetched ${scripts.length} scripts.`, 'success');
                updateScriptList(scripts);
            } else {
                logToConsole('No scripts returned from minion.', 'warn');
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
            const response = await fetch(`${proxyUrl}/custom-scripts`);
            if (!response.ok) {
                throw new Error('API request to fetch custom scripts failed');
            }
            const scripts = await response.json();
            if (scripts.length > 0) {
                logToConsole(`Successfully fetched ${scripts.length} custom scripts.`, 'success');
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

    async function displayScriptArguments(scriptName) {
        scriptArgsContainer.innerHTML = ''; // Clear previous arguments
        currentArgSpec = null; // Reset cached argspec
        const firstDevice = deviceList.querySelector('li:not(.disabled)');
        if (!firstDevice) {
            logToConsole('Please ensure at least one device is available to fetch script documentation.', 'warn');
            return;
        }
        const minionId = firstDevice.dataset.deviceName;

        logToConsole(`Fetching arguments for ${scriptName} using sys.argspec...`);
        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: minionId,
                    fun: 'sys.argspec',
                    arg: [scriptName]
                })
            });

            if (!response.ok) throw new Error('Failed to fetch script argspec.');

            const data = await response.json();
            const argspec = data.return[0][minionId][scriptName];
            currentArgSpec = argspec; // Cache the result

            logToConsole(`Raw argspec for ${scriptName}: <pre>${JSON.stringify(argspec, null, 2)}</pre>`);

            let allArgs = [];
            if (argspec && Object.keys(argspec).length > 0) {
                const posArgs = argspec.args || [];
                const keywordArgs = Object.keys(argspec.kwargs || {});
                allArgs = [...posArgs, ...keywordArgs];
                logToConsole(`Successfully parsed arguments from sys.argspec.`, 'success');
            } else {
                logToConsole('sys.argspec returned no data. Falling back to sys.doc parsing...', 'warn');
                await parseArgumentsFromDocstring(scriptName, minionId);
                return;
            }

            const ignoredArgs = new Set(['timeout', 'job_id', 'expr_form', 'tgt_type', 'tgt', 'kwarg', 'fun', 'client', 'arg', 'user', 'password', 'eauth']);
            const filteredArgs = allArgs.filter(argName => argName && !ignoredArgs.has(argName.split('=')[0].trim()));

            if (filteredArgs.length > 0) {
                logToConsole(`Found arguments for ${scriptName}: ${filteredArgs.join(', ')}`, 'info');
                const formHtml = filteredArgs.map(arg => {
                    const isKwarg = (argspec.kwargs && arg in argspec.kwargs);
                    const argName = arg.split('=')[0].trim();
                    const defaultValue = isKwarg ? argspec.kwargs[arg] : '';
                    return `
                        <div class="script-arg-item">
                            <label for="arg-${argName}">${argName} ${isKwarg ? '(optional)' : ''}</label>
                            <input type="text" id="arg-${argName}" name="${argName}" placeholder="${defaultValue || 'Enter value'}">
                        </div>
                    `;
                }).join('');
                scriptArgsContainer.innerHTML = formHtml;
            } else {
                logToConsole(`No user-configurable arguments found for ${scriptName}.`, 'info');
            }

        } catch (error) {
            console.error('Fetch Argspec Error:', error);
            logToConsole(`Error fetching arguments for ${scriptName}: ${error.message}. Trying to parse docstring...`, 'error');
            await parseArgumentsFromDocstring(scriptName, minionId);
        }
    }

    async function parseArgumentsFromDocstring(scriptName, minionId) {
        logToConsole(`Fetching docstring for ${scriptName} to parse arguments...`);
        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: minionId,
                    fun: 'sys.doc',
                    arg: [scriptName]
                })
            });

            if (!response.ok) throw new Error('Failed to fetch script documentation.');

            const data = await response.json();
            const docstring = data.return[0][minionId][scriptName];

            if (!docstring) {
                logToConsole(`No documentation found for ${scriptName}. Assuming no arguments needed.`, 'info');
                return;
            }

            const paramRegex = /:param(?:\s+\w+)?\s+([^:]+):/g;
            let match;
            const args = [];
            while ((match = paramRegex.exec(docstring)) !== null) {
                if (match.index === paramRegex.lastIndex) paramRegex.lastIndex++;
                args.push(match[1].trim());
            }

            const ignoredArgs = new Set(['timeout', 'job_id', 'expr_form', 'tgt_type', 'tgt', 'kwarg', 'fun', 'client', 'arg', 'user', 'password', 'eauth']);
            const filteredArgs = args.map(arg => arg.split('=')[0].trim()).filter(argName => argName && !ignoredArgs.has(argName));

            if (filteredArgs.length > 0) {
                logToConsole(`Found arguments via docstring for ${scriptName}: ${filteredArgs.join(', ')}`, 'info');
                const formHtml = filteredArgs.map(arg => `
                    <div class="script-arg-item">
                        <label for="arg-${arg}">${arg}</label>
                        <input type="text" id="arg-${arg}" name="${arg}" placeholder="Enter value for ${arg}">
                    </div>
                `).join('');
                scriptArgsContainer.innerHTML = formHtml;
            } else {
                logToConsole(`No user-configurable arguments found in docstring for ${scriptName}.`, 'info');
            }
        } catch (error) {
            console.error('Fetch Doc Error:', error);
            logToConsole(`Error parsing docstring for ${scriptName}: ${error.message}`, 'error');
            scriptArgsContainer.innerHTML = '<p style="color: red;">Could not fetch or parse argument details.</p>';
        }
    }

    async function deployScripts() {
        const selectedDevices = [...deviceList.querySelectorAll('.selected')].map(item => item.dataset.deviceName);
        const selectedScriptItems = [...scriptList.querySelectorAll('.selected')];
        const manualArgsInput = document.getElementById('manual-args');
        const appendCommandInput = document.getElementById('append-command');
        const errorMessage = document.getElementById('error-message');

        errorMessage.textContent = ''; // Clear previous error messages

        if (selectedDevices.length === 0) {
            logToConsole('Please select at least one device.', 'warn');
            return;
        }

        if (selectedScriptItems.length === 0) {
            logToConsole('Please select at least one script to deploy.', 'warn');
            return;
        }

        if (selectedScriptItems.length > 1 && (manualArgsInput.value.trim() !== '' || appendCommandInput.value.trim() !== '')) {
            errorMessage.textContent = 'Arguments or appended commands can only be provided when a single script is selected.';
            logToConsole('Arguments or appended commands can only be provided when a single script is selected.', 'error');
            return;
        }

        for (const scriptItem of selectedScriptItems) {
            const scriptName = scriptItem.textContent;
            const scriptType = document.querySelector('input[name="script-type"]:checked').value;
            const appendCommand = appendCommandInput.value.trim();
            
            let payload;
            let saltArgs = [];
            let saltKwargs = {};

            // Prioritize manual arguments if provided
            if (manualArgsInput.value.trim() !== '') {
                logToConsole('Using manual arguments.', 'info');
                saltArgs = manualArgsInput.value.trim().split(',').map(s => s.trim()).filter(s => s);
            } else if (selectedScriptItems.length === 1) {
                // Otherwise, use dynamic fields for single script selections
                const argInputs = scriptArgsContainer.querySelectorAll('input');
                if (argInputs.length > 0) {
                    logToConsole('Using dynamically generated argument fields.', 'info');
                    argInputs.forEach(input => {
                        if (input.value) {
                            if (currentArgSpec && currentArgSpec.args && currentArgSpec.args.includes(input.name)) {
                                saltArgs.push(input.value);
                            } else {
                                saltKwargs[input.name] = input.value;
                            }
                        }
                    });
                }
            }

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

            } else { // 'salt'
                if (appendCommand) {
                    // If there's an append command, we must use cmd.run with salt-call
                    const argsString = saltArgs.map(arg => `'${arg}'`).join(' ');
                    const kwargsString = Object.entries(saltKwargs).map(([key, value]) => `${key}='${value}'`).join(' ');
                    const command = `salt-call --local ${scriptName} ${argsString} ${kwargsString} ${appendCommand}`.trim();
                    
                    payload = {
                        client: 'local',
                        tgt: selectedDevices,
                        tgt_type: 'list',
                        fun: 'cmd.run',
                        arg: [command]
                    };
                } else {
                    // Standard Salt execution
                    payload = {
                        client: 'local',
                        tgt: selectedDevices,
                        tgt_type: 'list',
                        fun: scriptName,
                    };
                    if (saltArgs.length > 0) {
                        payload.arg = saltArgs;
                    }
                    if (Object.keys(saltKwargs).length > 0) {
                        payload.kwarg = saltKwargs;
                    }
                }
            }

            const kwargString = payload.kwarg ? ` with kwargs: ${JSON.stringify(payload.kwarg)}` : '';
            const argString = payload.arg ? ` with args: ${JSON.stringify(payload.arg)}` : '';
            logToConsole(`Deploying ${scriptName} to ${selectedDevices.join(', ')}${argString}${kwargString}...`, 'info');

            try {
                const response = await fetch(`${proxyUrl}/proxy`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(`Execution failed: ${errorData.message || response.statusText}`);
                }

                const data = await response.json();
                logToConsole(`Result for ${scriptName}: <pre>${JSON.stringify(data.return[0], null, 2)}</pre>`, 'success');
            } catch (error) {
                console.error(`Error executing ${scriptName}:`, error);
                logToConsole(`Error executing ${scriptName}: ${error.message}`, 'error');
            }
        }
    }

    function updateDeviceList(minions) {
        deviceList.innerHTML = '';
        monitoringDeviceSelect.innerHTML = '<option value="">Select a device</option>';

        const deviceNames = Object.keys(minions);

        if (deviceNames.length === 0) {
            logToConsole('No active devices found.', 'warn');
            const li = document.createElement('li');
            li.textContent = 'No active devices found';
            li.classList.add('disabled');
            deviceList.appendChild(li);
            return;
        }

        deviceNames.forEach(deviceName => {
            const os = minions[deviceName] && minions[deviceName]['os'] ? minions[deviceName]['os'] : 'N/A';
            const displayName = `${deviceName} (${os})`;

            const li = document.createElement('li');
            li.textContent = displayName;
            li.dataset.deviceName = deviceName;
            deviceList.appendChild(li);
            
            const option = document.createElement('option');
            option.text = displayName;
            option.value = deviceName;
            monitoringDeviceSelect.add(option);
        });
    }

    function updateScriptList(scripts) {
        scriptList.innerHTML = '';

        if (scripts.length === 0) {
            logToConsole('No scripts found.', 'warn');
            const li = document.createElement('li');
            li.textContent = 'No scripts found';
            li.classList.add('disabled');
            scriptList.appendChild(li);
            return;
        }

        scripts.forEach(scriptName => {
            const li = document.createElement('li');
            li.textContent = scriptName;
            scriptList.appendChild(li);
        });
    }

    // --- System Monitoring Functions ---
    async function getDeviceOS(deviceId) {
        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: 'local',
                    tgt: deviceId,
                    fun: 'grains.get',
                    arg: ['kernel'] // 'kernel' grain returns 'Windows', 'Linux', etc.
                })
            });
            if (!response.ok) return 'Unknown';
            const data = await response.json();
            return data.return[0][deviceId];
        } catch (error) {
            console.error(`Error fetching OS for ${deviceId}:`, error);
            logToConsole(`Could not determine OS for ${deviceId}.`, 'warn');
            return 'Unknown';
        }
    }


    async function fetchMonitoringData() {
        const deviceId = monitoringDeviceSelect.value;
        const view = monitoringViewSelect.value;

        if (!deviceId || !view) {
            monitoringOutputContent.innerHTML = '<p>Please select a device and a view.</p>';
            return;
        }

        logToConsole(`Fetching '${view}' for device '${deviceId}'...`, 'info');
        monitoringOutputContent.innerHTML = '<p>Loading...</p>';

        let payload;
        if (view === 'firewall-rules') {
            const os = await getDeviceOS(deviceId);
            logToConsole(`Detected OS: ${os} for ${deviceId}.`, 'info');

            if (os === 'Windows') {
                payload = { client: 'local', tgt: deviceId, fun: 'win_firewall.get_rules' };
            } else { // Assume Linux/other Unix-like
                payload = {
                    client: 'local',
                    tgt: deviceId,
                    fun: 'iptables.list',
                    arg: ['filter'] // List all chains in the filter table
                };
            }
        } else if (view === 'running-processes') {
            payload = {
                client: 'local',
                tgt: deviceId,
                fun: 'status.procs'
            };
        } else {
            return; // Should not happen
        }

        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`API request failed: ${errorData.message || response.statusText}`);
            }

            const data = await response.json();
            const result = data.return[0][deviceId];

            // Check for specific error indicating iptables is not installed and try fallbacks
            if (
                view === 'firewall-rules' &&
                typeof result === 'string' &&
                result.includes("'iptables' __virtual__ returned False")
            ) {
                logToConsole('iptables not found. Trying nftables...', 'warn');
                try {
                    // --- Try nftables ---
                    const nftResponse = await fetch(`${proxyUrl}/proxy`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ client: 'local', tgt: deviceId, fun: 'nftables.list_rules' })
                    });
                    if (!nftResponse.ok) throw new Error('nftables request failed');
                    const nftData = await nftResponse.json();
                    const nftResult = nftData.return[0][deviceId];

                    if (typeof nftResult === 'string' && nftResult.includes('is not available')) {
                        throw new Error('nftables module not available');
                    }

                    monitoringOutputContent.innerHTML = `<pre>${JSON.stringify(nftResult, null, 2)}</pre>`;
                    logToConsole(`Successfully fetched firewall rules using nftables for '${deviceId}'.`, 'success');
                } catch (nftError) {
                    logToConsole('nftables not found. Trying firewalld...', 'warn');
                    try {
                        // --- Try firewalld ---
                        const firewalldResponse = await fetch(`${proxyUrl}/proxy`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ client: 'local', tgt: deviceId, fun: 'firewalld.list_all' })
                        });
                        if (!firewalldResponse.ok) throw new Error('firewalld request failed');
                        const firewalldData = await firewalldResponse.json();
                        const firewalldResult = firewalldData.return[0][deviceId];

                        if (typeof firewalldResult === 'string' && firewalldResult.includes('is not available')) {
                             throw new Error('firewalld module not available');
                        }

                        monitoringOutputContent.innerHTML = `<pre>${JSON.stringify(firewalldResult, null, 2)}</pre>`;
                        logToConsole(`Successfully fetched firewall rules using firewalld for '${deviceId}'.`, 'success');
                    } catch (firewalldError) {
                        logToConsole('No compatible firewall module (iptables, nftables, firewalld) found on the minion.', 'error');
                        monitoringOutputContent.innerHTML = `<p style="color: orange;">Could not find a compatible firewall module on '${deviceId}'.</p>`;
                    }
                }
            } else {
                // Format the output as preformatted text to preserve spacing and line breaks
                monitoringOutputContent.innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>`;
                logToConsole(`Successfully fetched '${view}' for '${deviceId}'.`, 'success');
            }
        } catch (error) {
            console.error(`Error fetching monitoring data for ${deviceId}:`, error);
            logToConsole(`Error fetching '${view}' for '${deviceId}': ${error.message}`, 'error');
            monitoringOutputContent.innerHTML = `<p style="color: red;">Error fetching data: ${error.message}</p>`;
        }
    }

    async function viewScriptContent(scriptName) {
        scriptViewerTitle.textContent = `Viewing: ${scriptName}`;
        scriptViewerContent.innerHTML = '<pre><code>Loading script content...</code></pre>';
        scriptViewerModal.style.display = 'block';

        try {
            const response = await fetch(`${proxyUrl}/custom-script-content?path=${encodeURIComponent(scriptName)}`);
            if (!response.ok) {
                // Check if the response is JSON before trying to parse it
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || 'Failed to fetch script content.');
                } else {
                    const errorText = await response.text();
                    throw new Error(`Server returned a non-JSON error: ${errorText}`);
                }
            }
            const data = await response.json();
            // Escape HTML to prevent rendering issues and potential XSS
            const escapedContent = data.content.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            scriptViewerContent.innerHTML = `<pre><code>${escapedContent}</code></pre>`;
        } catch (error) {
            scriptViewerContent.innerHTML = `<pre><code style="color: red;">Error: ${error.message}</code></pre>`;
            console.error('Error viewing script content:', error);
        }
    }
    // --- Event Listeners ---
    deviceList.addEventListener('click', (event) => handleSelection(deviceList, event));
    scriptList.addEventListener('click', (event) => handleSelection(scriptList, event));

    document.querySelector('.btn-deploy').addEventListener('click', deployScripts);
    document.querySelector('.btn-refresh').addEventListener('click', fetchAvailableDevices);

    scriptTypeSelector.addEventListener('change', (event) => {
        const scriptType = event.target.value;
        scriptArgsContainer.innerHTML = ''; // Clear args on switch
        currentArgSpec = null;
        updateScriptList([]); // Clear script list while loading

        if (scriptType === 'salt') {
            const firstDevice = deviceList.querySelector('li:not(.disabled)');
            if (firstDevice) {
                fetchAvailableScripts(firstDevice.dataset.deviceName);
            } else {
                logToConsole('Select a device to fetch Salt scripts.', 'warn');
            }
        } else if (scriptType === 'custom') {
            fetchCustomScripts();
        }
    });

    const scriptSearch = document.getElementById('script-search');
    scriptSearch.addEventListener('input', () => {
        const searchTerm = scriptSearch.value.toLowerCase();
        const scripts = scriptList.getElementsByTagName('li');
        for (const script of scripts) {
            const scriptName = script.textContent.toLowerCase();
            if (scriptName.includes(searchTerm)) {
                script.style.display = '';
            } else {
                script.style.display = 'none';
            }
        }
    });

    monitoringDeviceSelect.addEventListener('change', fetchMonitoringData);
    monitoringViewSelect.addEventListener('change', fetchMonitoringData);

    scriptList.addEventListener('contextmenu', (event) => {
        event.preventDefault(); // Prevent the default browser right-click menu
        const scriptType = document.querySelector('input[name="script-type"]:checked').value;
        const targetItem = event.target.closest('li');

        if (scriptType === 'custom' && targetItem && !targetItem.classList.contains('disabled')) {
            contextMenu.style.top = `${event.clientY}px`;
            contextMenu.style.left = `${event.clientX}px`;
            contextMenu.style.display = 'block';
            contextMenu.dataset.scriptName = targetItem.textContent; // Store the script name
        }
    });

    document.addEventListener('click', (event) => {
        // Hide context menu if clicking anywhere else
        if (!contextMenu.contains(event.target)) {
            contextMenu.style.display = 'none';
        }
    });

    document.getElementById('context-menu-view').addEventListener('click', () => {
        const scriptName = contextMenu.dataset.scriptName;
        if (scriptName) {
            viewScriptContent(scriptName);
        }
        contextMenu.style.display = 'none'; // Hide menu after action
    });

    // --- Terminal Functions ---
    function openTerminal() {
        const deviceId = monitoringDeviceSelect.value;
        if (!deviceId) {
            logToConsole('Please select a device from the System Monitoring section to open a terminal.', 'warn');
            alert('Please select a device to open the terminal.');
            return;
        }

        terminalTitle.textContent = `Terminal: ${deviceId}`;
        terminalOutput.innerHTML = `<span>Connecting to ${deviceId}...</span><br>`;
        terminalCommandInput.value = '';
        terminalModal.style.display = 'block';
        terminalCommandInput.focus();
    }

    function closeTerminal() {
        terminalModal.style.display = 'none';
    }

    async function executeTerminalCommand(event) {
        if (event.key !== 'Enter') return;

        const command = terminalCommandInput.value.trim();
        const deviceId = monitoringDeviceSelect.value; // Assumes the device doesn't change while modal is open

        if (!command || !deviceId) return;

        // Echo the command to the terminal
        const echoEntry = document.createElement('div');
        echoEntry.innerHTML = `<span class="terminal-prompt">&gt;</span> <span class="command-echo">${command}</span>`;
        terminalOutput.appendChild(echoEntry);
        terminalCommandInput.value = ''; // Clear input
        terminalOutput.scrollTop = terminalOutput.scrollHeight;

        const payload = {
            client: 'local',
            tgt: deviceId,
            fun: 'cmd.run',
            arg: [command]
        };

        try {
            const response = await fetch(`${proxyUrl}/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            let result = data.return[0][deviceId];

            // If the result is an empty string, it's a successful command with no stdout.
            // Show a confirmation message. Also handle null/undefined cases. A non-empty string
            // (even with just whitespace) should be displayed.
            if (result === null || result === undefined) {
                result = 'Error executing command.';
            } else if (result.trim() === '') {
                result = 'Command finished successfully (no output).';
            }

            const resultEntry = document.createElement('div');
            resultEntry.className = response.ok ? 'command-result' : 'terminal-error';
            const pre = document.createElement('pre');
            pre.textContent = result;
            resultEntry.appendChild(pre);
            terminalOutput.appendChild(resultEntry);
        } catch (error) {
            const errorEntry = document.createElement('div');
            errorEntry.className = 'terminal-error';
            errorEntry.textContent = `Error: ${error.message}`;
            terminalOutput.appendChild(errorEntry);
        } finally {
            terminalOutput.scrollTop = terminalOutput.scrollHeight; // Auto-scroll
        }
    }
    // Terminal Event Listeners
    openTerminalBtn.addEventListener('click', openTerminal);
    terminalCloseButton.addEventListener('click', closeTerminal);
    terminalCommandInput.addEventListener('keydown', executeTerminalCommand);

    scriptViewerCloseButton.addEventListener('click', () => {
        scriptViewerModal.style.display = 'none';
    });

    const connectDeviceModal = document.getElementById('connect-device-modal');
    const closeButton = document.querySelector('.close-button');
    const unacceptedKeysList = document.getElementById('unaccepted-keys-list');
    const acceptedKeysList = document.getElementById('accepted-keys-list');
    const modalContent = document.querySelector('.modal-content');

    async function openConnectDeviceModal() {
        logToConsole('Fetching keys...');
        try {
            const response = await fetch(`${proxyUrl}/keys`);
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(JSON.stringify(errorData.error));
            }
            const data = await response.json();
            const keys = data.return[0].data.return;
            const unacceptedKeys = keys.minions_pre;
            const acceptedKeys = keys.minions;

            updateNotificationBadge(unacceptedKeys.length);

            unacceptedKeysList.innerHTML = ''; // Clear previous list
            acceptedKeysList.innerHTML = ''; // Clear previous list

            if (unacceptedKeys.length > 0) {
                unacceptedKeys.forEach(key => {
                    const li = document.createElement('li');
                    li.textContent = key;
                    const acceptButton = document.createElement('button');
                    acceptButton.textContent = 'Accept';
                    acceptButton.classList.add('btn', 'btn-accept');
                    acceptButton.dataset.minionId = key;
                    li.appendChild(acceptButton);
                    unacceptedKeysList.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.textContent = 'No devices awaiting acceptance.';
                unacceptedKeysList.appendChild(li);
            }

            if (acceptedKeys.length > 0) {
                acceptedKeys.forEach(key => {
                    const li = document.createElement('li');
                    li.textContent = key;
                    const removeButton = document.createElement('button');
                    removeButton.textContent = 'Remove';
                    removeButton.classList.add('btn', 'btn-remove');
                    removeButton.dataset.minionId = key;
                    li.appendChild(removeButton);
                    acceptedKeysList.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.textContent = 'No accepted devices found.';
                acceptedKeysList.appendChild(li);
            }

            connectDeviceModal.style.display = 'block';
        } catch (error) {
            console.error('Error fetching keys:', error);
            logToConsole(`Error fetching keys: ${error.message}`, 'error');
        }
    }

    function closeConnectDeviceModal() {
        connectDeviceModal.style.display = 'none';
    }

    async function acceptKey(minionId) {
        logToConsole(`Accepting key for ${minionId}...`);
        try {
            const response = await fetch(`${proxyUrl}/keys/accept`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ minionId })
            });

            if (!response.ok) {
                throw new Error(`Failed to accept key for ${minionId}.`);
            }

            logToConsole(`Successfully accepted key for ${minionId}.`, 'success');
            openConnectDeviceModal(); // Refresh the modal
            fetchAvailableDevices(); // Refresh the main device list
        } catch (error) {
            console.error('Error accepting key:', error);
            logToConsole(`Error accepting key for ${minionId}: ${error.message}`, 'error');
        }
    }

    async function removeKey(minionId) {
        logToConsole(`Removing key for ${minionId}...`);
        try {
            const response = await fetch(`${proxyUrl}/keys/delete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ minionId })
            });

            if (!response.ok) {
                throw new Error(`Failed to remove key for ${minionId}.`);
            }

            logToConsole(`Successfully removed key for ${minionId}.`, 'success');
            openConnectDeviceModal(); // Refresh the modal
            fetchAvailableDevices(); // Refresh the main device list
        } catch (error) {
            console.error('Error removing key:', error);
            logToConsole(`Error removing key for ${minionId}: ${error.message}`, 'error');
        }
    }

    document.querySelector('.btn-connect').addEventListener('click', openConnectDeviceModal);
    closeButton.addEventListener('click', closeConnectDeviceModal);
    modalContent.addEventListener('click', (event) => {
        if (event.target.classList.contains('btn-accept')) {
            const minionId = event.target.dataset.minionId;
            acceptKey(minionId);
        } else if (event.target.classList.contains('btn-remove')) {
            const minionId = event.target.dataset.minionId;
            removeKey(minionId);
        }
    });

    // --- Initial Load ---
    async function initializeApp() {
        await loadSettings();
        fetchAvailableDevices();
        checkUnacceptedKeys();
        setInterval(checkUnacceptedKeys, 30000); // Check every 30 seconds
    }

    initializeApp();
});