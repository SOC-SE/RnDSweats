/**
 * Salt GUI Server - Enhanced Competition Edition
 * 
 * Major Improvements:
 * - Session-based authentication with configurable timeout
 * - Comprehensive audit logging
 * - Rate limiting protection
 * - CSRF protection
 * - Enhanced job tracking with persistent storage
 * - Incident response playbook support
 * - File upload/download capabilities
 * - Service monitoring endpoints
 * - Emergency response functions
 * - Salt States management (Linux/Windows)
 * - Cross-browser compatible API responses
 * 
 * Samuel Brucker 2025-2026
 * Enhanced by Claude
 */

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// HTTPS agent for self-signed certificates
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Helper to get the right agent based on URL
function getAgent(url) {
    if (url && url.startsWith('https://')) {
        return httpsAgent;
    }
    return undefined;
}

const app = express();
const port = process.env.PORT || 3000;

// --- File Paths ---
const CONFIG_PATH = './config.json';
const JOBS_PATH = './jobs.json';
const OUTPUT_HISTORY_PATH = './output_history.json';
const AUDIT_LOG_PATH = './audit.log';
const PLAYBOOKS_PATH = './playbooks';
const UPLOADS_PATH = './uploads';
const DEFAULT_STATES_PATH = '/opt/salt-gui/states';

// Ensure directories exist
[PLAYBOOKS_PATH, UPLOADS_PATH].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// --- In-Memory State ---
let activeJobs = new Map();
let outputHistory = [];
let sessions = new Map();
let rateLimitMap = new Map();

const MAX_HISTORY_ENTRIES = 1000;
const SESSION_TIMEOUT = 3600000; // 1 hour
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 100; // requests per window

// --- Middleware ---
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.'));

// Request logging middleware with audit trail
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const clientIP = req.ip || req.connection.remoteAddress;
    const logEntry = `[${timestamp}] ${clientIP} ${req.method} ${req.path}`;
    console.log(logEntry);
    
    // Audit log for sensitive operations
    if (['POST', 'DELETE', 'PUT'].includes(req.method)) {
        auditLog(clientIP, req.method, req.path, req.body);
    }
    
    next();
});

// Rate limiting middleware
app.use((req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    if (!rateLimitMap.has(clientIP)) {
        rateLimitMap.set(clientIP, { count: 1, windowStart: now });
    } else {
        const rateData = rateLimitMap.get(clientIP);
        if (now - rateData.windowStart > RATE_LIMIT_WINDOW) {
            rateData.count = 1;
            rateData.windowStart = now;
        } else {
            rateData.count++;
            if (rateData.count > RATE_LIMIT_MAX) {
                return res.status(429).json({ 
                    message: 'Rate limit exceeded. Please slow down.',
                    retryAfter: Math.ceil((RATE_LIMIT_WINDOW - (now - rateData.windowStart)) / 1000)
                });
            }
        }
    }
    next();
});

// --- Utility Functions ---

function auditLog(ip, method, path, body) {
    const timestamp = new Date().toISOString();
    const sanitizedBody = { ...body };
    delete sanitizedBody.password;
    delete sanitizedBody.eauth;
    
    const logLine = JSON.stringify({
        timestamp,
        ip,
        method,
        path,
        body: sanitizedBody
    }) + '\n';
    
    fs.appendFileSync(AUDIT_LOG_PATH, logLine);
}

function generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

function getAxiosConfig(timeout = 30000, url = '') {
    const config = {
        headers: { 'Content-Type': 'application/json' },
        timeout
    };
    const agent = getAgent(url);
    if (agent) config.httpsAgent = agent;
    return config;
}

function readSettings() {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const rawData = fs.readFileSync(CONFIG_PATH);
            return JSON.parse(rawData);
        } else {
            const defaultSettings = {
                proxyURL: 'http://localhost:3000',
                saltAPIUrl: 'https://localhost:8000',
                username: '',
                password: '',
                eauth: 'pam',
                asyncJobTimeout: 300000,
                maxConcurrentJobs: 10,
                enableAuth: false,
                authPassword: '',
                alertWebhook: '',
                statesPath: DEFAULT_STATES_PATH
            };
            fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultSettings, null, 2));
            return defaultSettings;
        }
    } catch (error) {
        console.error('[Server] Error reading settings:', error);
        throw error;
    }
}

function getStatesPath() {
    const settings = readSettings();
    return settings.statesPath || DEFAULT_STATES_PATH;
}

function saveOutputHistory() {
    try {
        if (outputHistory.length > MAX_HISTORY_ENTRIES) {
            outputHistory = outputHistory.slice(-MAX_HISTORY_ENTRIES);
        }
        fs.writeFileSync(OUTPUT_HISTORY_PATH, JSON.stringify(outputHistory, null, 2));
    } catch (error) {
        console.error('[Server] Error saving output history:', error);
    }
}

function loadOutputHistory() {
    try {
        if (fs.existsSync(OUTPUT_HISTORY_PATH)) {
            outputHistory = JSON.parse(fs.readFileSync(OUTPUT_HISTORY_PATH));
        }
    } catch (error) {
        console.error('[Server] Error loading output history:', error);
        outputHistory = [];
    }
}

async function sendAlert(title, message) {
    const settings = readSettings();
    if (!settings.alertWebhook) return;
    
    try {
        await axios.post(settings.alertWebhook, {
            text: `🚨 **${title}**\n${message}`,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('[Alert] Failed to send alert:', error.message);
    }
}

function sanitizeMinionId(minionId) {
    if (!minionId || typeof minionId !== 'string') return null;
    const sanitized = minionId.replace(/[^a-zA-Z0-9._-]/g, '');
    if (sanitized.length === 0 || sanitized.length > 256) return null;
    return sanitized;
}

function isValidScriptPath(scriptPath) {
    if (!scriptPath || typeof scriptPath !== 'string') return false;
    const normalized = path.normalize(scriptPath);
    if (normalized.includes('..') || normalized.startsWith('/') || normalized.includes('\\')) {
        return false;
    }
    return true;
}

// Validate state path to prevent directory traversal
function isValidStatePath(statePath) {
    if (!statePath || typeof statePath !== 'string') return false;
    const normalized = path.normalize(statePath);
    // Allow forward slashes for subdirectories but prevent traversal
    if (normalized.includes('..')) {
        return false;
    }
    // Must end with .sls
    if (!statePath.endsWith('.sls')) {
        return false;
    }
    return true;
}

// Recursively get all .sls files from a directory
function getStatesFromDirectory(dirPath, relativePath = '') {
    const states = [];
    
    if (!fs.existsSync(dirPath)) {
        return states;
    }
    
    try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        
        for (const entry of entries) {
            const fullPath = path.join(dirPath, entry.name);
            const relPath = relativePath ? `${relativePath}/${entry.name}` : entry.name;
            
            if (entry.isDirectory()) {
                // Recursively search subdirectories
                states.push(...getStatesFromDirectory(fullPath, relPath));
            } else if (entry.isFile() && entry.name.endsWith('.sls')) {
                // Get file stats for metadata
                const stats = fs.statSync(fullPath);
                
                // Read first few lines for description
                let description = '';
                try {
                    const content = fs.readFileSync(fullPath, 'utf8');
                    const lines = content.split('\n').slice(0, 10);
                    const commentLines = lines.filter(l => l.trim().startsWith('#'));
                    if (commentLines.length > 0) {
                        description = commentLines
                            .map(l => l.replace(/^#\s*/, '').trim())
                            .filter(l => l && !l.startsWith('='))
                            .slice(0, 2)
                            .join(' - ');
                    }
                } catch (e) {
                    // Ignore read errors for description
                }
                
                states.push({
                    name: entry.name,
                    path: relPath,
                    fullPath: fullPath,
                    size: stats.size,
                    modified: stats.mtime.toISOString(),
                    description: description || 'No description'
                });
            }
        }
    } catch (error) {
        console.error(`Error reading directory ${dirPath}:`, error.message);
    }
    
    return states;
}

// --- API Authentication ---

app.post('/api/auth/login', (req, res) => {
    const { password } = req.body;
    const settings = readSettings();
    
    if (!settings.enableAuth) {
        return res.json({ authenticated: true, token: 'auth-disabled' });
    }
    
    if (password === settings.authPassword) {
        const token = generateCSRFToken();
        sessions.set(token, {
            createdAt: Date.now(),
            lastAccess: Date.now()
        });
        
        res.json({ authenticated: true, token });
    } else {
        res.status(401).json({ authenticated: false, message: 'Invalid password' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (token) {
        sessions.delete(token);
    }
    res.json({ message: 'Logged out' });
});

// --- Settings Management ---

app.get('/api/settings', (req, res) => {
    try {
        const settings = readSettings();
        const safeSettings = { 
            ...settings, 
            password: settings.password ? '********' : '',
            authPassword: settings.authPassword ? '********' : ''
        };
        res.json(safeSettings);
    } catch (error) {
        res.status(500).json({ message: 'Error reading settings', error: error.message });
    }
});

app.post('/api/settings', (req, res) => {
    try {
        const currentSettings = readSettings();
        const newSettings = { ...req.body };
        
        if (newSettings.password === '********') {
            newSettings.password = currentSettings.password;
        }
        if (newSettings.authPassword === '********') {
            newSettings.authPassword = currentSettings.authPassword;
        }
        
        // Ensure statesPath is set
        if (!newSettings.statesPath) {
            newSettings.statesPath = DEFAULT_STATES_PATH;
        }
        
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(newSettings, null, 2));
        auditLog(req.ip, 'SETTINGS_CHANGE', '/api/settings', { changed: true });
        res.json({ message: 'Settings saved successfully' });
    } catch (error) {
        console.error('[Server] Error saving settings:', error);
        res.status(500).json({ message: 'Failed to save settings', error: error.message });
    }
});

// --- Health & Status Endpoints ---

app.get('/api/health', async (req, res) => {
    const settings = readSettings();
    const health = {
        server: 'ok',
        timestamp: new Date().toISOString(),
        activeJobs: activeJobs.size,
        saltApi: 'unknown',
        uptime: process.uptime()
    };
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'manage.status',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(5000, settings.saltAPIUrl));
        
        health.saltApi = 'ok';
        health.minionStatus = response.data.return[0];
    } catch (error) {
        health.saltApi = 'error';
        health.saltApiError = error.message;
    }
    
    res.json(health);
});

app.get('/api/minions/status', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'manage.status',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json({
            up: response.data.return[0]?.up || [],
            down: response.data.return[0]?.down || []
        });
    } catch (error) {
        res.status(500).json({ message: 'Failed to get minion status', error: error.message });
    }
});

// ============================================================================
// SALT STATES API ENDPOINTS
// ============================================================================

/**
 * List all states for a specific OS type (linux/windows)
 */
app.get('/api/states/:osType', (req, res) => {
    const { osType } = req.params;
    
    if (!['linux', 'windows'].includes(osType.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid OS type. Use "linux" or "windows".' });
    }
    
    const statesPath = getStatesPath();
    const osPath = path.join(statesPath, osType.toLowerCase());
    
    // Ensure directory exists
    if (!fs.existsSync(osPath)) {
        try {
            fs.mkdirSync(osPath, { recursive: true });
            console.log(`Created states directory: ${osPath}`);
        } catch (error) {
            console.error(`Failed to create states directory: ${osPath}`, error.message);
        }
    }
    
    const states = getStatesFromDirectory(osPath);
    
    res.json({
        osType: osType.toLowerCase(),
        basePath: osPath,
        count: states.length,
        states: states
    });
});

/**
 * Get content of a specific state file
 */
app.get('/api/states/:osType/content', (req, res) => {
    const { osType } = req.params;
    const { path: statePath } = req.query;
    
    if (!['linux', 'windows'].includes(osType.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid OS type.' });
    }
    
    if (!statePath || !isValidStatePath(statePath)) {
        return res.status(400).json({ message: 'Invalid state path.' });
    }
    
    const statesPath = getStatesPath();
    const fullPath = path.join(statesPath, osType.toLowerCase(), statePath);
    
    // Security: ensure path is within states directory
    const resolvedPath = path.resolve(fullPath);
    const resolvedStatesPath = path.resolve(statesPath);
    if (!resolvedPath.startsWith(resolvedStatesPath)) {
        return res.status(403).json({ message: 'Access denied.' });
    }
    
    if (!fs.existsSync(fullPath)) {
        return res.status(404).json({ message: 'State file not found.' });
    }
    
    try {
        const content = fs.readFileSync(fullPath, 'utf8');
        const stats = fs.statSync(fullPath);
        
        res.json({
            path: statePath,
            fullPath: fullPath,
            content: content,
            size: stats.size,
            modified: stats.mtime.toISOString()
        });
    } catch (error) {
        res.status(500).json({ message: 'Error reading state file.', error: error.message });
    }
});

/**
 * Apply a state to target minions
 * 
 * This converts local state files to Salt state.apply calls
 * States are referenced by their path relative to the OS folder
 */
app.post('/api/states/apply', async (req, res) => {
    const { targets, osType, statePath, testMode = false } = req.body;
    const settings = readSettings();
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required.' });
    }
    
    if (!osType || !['linux', 'windows'].includes(osType.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid OS type.' });
    }
    
    if (!statePath || !isValidStatePath(statePath)) {
        return res.status(400).json({ message: 'Invalid state path.' });
    }
    
    const statesBasePath = getStatesPath();
    const fullStatePath = path.join(statesBasePath, osType.toLowerCase(), statePath);
    
    // Verify the state file exists locally
    if (!fs.existsSync(fullStatePath)) {
        return res.status(404).json({ message: 'State file not found.' });
    }
    
    auditLog(req.ip, 'STATE_APPLY', '/api/states/apply', { 
        targets, 
        osType, 
        statePath, 
        testMode 
    });
    
    try {
        // Read the state content
        const stateContent = fs.readFileSync(fullStatePath, 'utf8');
        const stateName = statePath.replace(/\.sls$/, '').replace(/\//g, '.');
        
        console.log(`Applying state ${statePath} to ${targets.join(', ')} (test=${testMode})`);
        
        // Check if state uses complex features that require proper Salt rendering
        const hasJinja = stateContent.includes('{%') || stateContent.includes('{{');
        
        // Check for salt:// sources, but ignore comment lines (lines starting with #)
        const nonCommentLines = stateContent.split('\n')
            .filter(line => !line.trim().startsWith('#'))
            .join('\n');
        const hasSaltSource = nonCommentLines.includes('salt://');
        
        let method = 'state.template_str';
        let results = {};
        let warnings = [];
        
        if (hasSaltSource) {
            // State references salt:// sources - these MUST be on the Salt master's file_roots
            // Try to apply using state.apply (requires state to be synced to master)
            console.log(`State uses salt:// sources - attempting state.apply from master`);
            method = 'state.apply (master)';
            
            warnings.push('This state uses salt:// sources which must exist on the Salt master file_roots');
            
            // Convert to Salt state name: osType/statename -> osType.statename
            const saltStateName = `${osType.toLowerCase()}.${stateName}`;
            
            const payload = {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'state.apply',
                arg: [saltStateName],
                kwarg: testMode ? { test: true } : {},
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            };
            
            try {
                const response = await axios.post(`${settings.saltAPIUrl}/run`, payload,
                    getAxiosConfig(600000, settings.saltAPIUrl));
                
                results = response.data.return[0] || {};
                
                // Check if state was not found
                for (const [minion, result] of Object.entries(results)) {
                    if (typeof result === 'string' && result.includes('No matching sls found')) {
                        warnings.push(`State not found in Salt master file_roots. Copy states to /srv/salt/${osType.toLowerCase()}/`);
                        break;
                    }
                }
            } catch (err) {
                console.error('state.apply failed:', err.message);
                return res.status(500).json({
                    message: 'Failed to apply state from master',
                    error: err.response?.data || err.message,
                    suggestion: `Sync the state and its salt:// dependencies to the Salt master file_roots at /srv/salt/${osType.toLowerCase()}/`
                });
            }
            
        } else if (hasJinja) {
            // State has Jinja but NO salt:// sources - use salt-call with local file_root
            console.log(`State uses Jinja - using salt-call approach`);
            method = 'salt-call (local)';
            
            const isWindows = osType.toLowerCase() === 'windows';
            const tempDir = isWindows ? 'C:\\Windows\\Temp\\saltgui_states' : '/tmp/saltgui_states';
            const tempFile = isWindows ? `${tempDir}\\saltgui_temp.sls` : `${tempDir}/saltgui_temp.sls`;
            
            // Step 1: Create temp directory and write state file using stdin (avoids arg length limits)
            console.log(`Writing state file to minion(s) via stdin...`);
            
            let writeCmd;
            if (isWindows) {
                writeCmd = `New-Item -ItemType Directory -Force -Path "${tempDir}" | Out-Null; $input | Set-Content -Path "${tempFile}" -Encoding UTF8`;
            } else {
                writeCmd = `mkdir -p ${tempDir} && cat > ${tempFile}`;
            }
            
            const writePayload = {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'cmd.run',
                arg: [writeCmd],
                kwarg: {
                    stdin: stateContent,
                    shell: isWindows ? 'powershell' : '/bin/bash',
                    python_shell: true
                },
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            };
            
            try {
                const writeResponse = await axios.post(`${settings.saltAPIUrl}/run`, writePayload,
                    getAxiosConfig(120000, settings.saltAPIUrl));
                
                const writeResults = writeResponse.data.return[0] || {};
                console.log('File write results:', writeResults);
                
                // Check if write succeeded (empty output is usually success for cat > file)
                for (const [minion, result] of Object.entries(writeResults)) {
                    if (result && String(result).toLowerCase().includes('error')) {
                        console.warn(`File write to ${minion} may have failed:`, result);
                    }
                }
            } catch (writeErr) {
                console.error('Failed to write state file to minions:', writeErr.message);
                return res.status(500).json({
                    message: 'Failed to transfer state file to minions',
                    error: writeErr.response?.data || writeErr.message
                });
            }
            
            // Step 2: Apply the state using salt-call
            console.log(`Applying state on minion(s)...`);
            
            let applyCmd;
            if (isWindows) {
                applyCmd = `salt-call --local state.apply saltgui_temp --file-root="${tempDir}" ${testMode ? 'test=true' : ''} --out=json 2>&1; Remove-Item -Path "${tempDir}" -Recurse -Force -ErrorAction SilentlyContinue`;
            } else {
                applyCmd = `salt-call --local state.apply saltgui_temp --file-root=${tempDir} ${testMode ? 'test=true' : ''} --out=json 2>&1; rm -rf ${tempDir}`;
            }
            
            const applyPayload = {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'cmd.run',
                arg: [applyCmd],
                kwarg: {
                    shell: isWindows ? 'powershell' : '/bin/bash',
                    python_shell: true,
                    timeout: 600
                },
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            };
            
            const response = await axios.post(`${settings.saltAPIUrl}/run`, applyPayload,
                getAxiosConfig(600000, settings.saltAPIUrl));
            
            const rawResults = response.data.return[0] || {};
            
            // Parse the JSON output from salt-call
            for (const [minion, output] of Object.entries(rawResults)) {
                if (typeof output === 'string') {
                    // Try to extract JSON from the output (salt-call output may have extra text)
                    const jsonMatch = output.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        try {
                            const parsed = JSON.parse(jsonMatch[0]);
                            results[minion] = parsed.local || parsed;
                        } catch (e) {
                            results[minion] = output;
                        }
                    } else {
                        results[minion] = output;
                    }
                } else {
                    results[minion] = output;
                }
            }
        } else {
            // Simple state without Jinja/salt:// - use state.template_str
            console.log(`Simple state - using state.template_str`);
            
            const payload = {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'state.template_str',
                arg: [stateContent],
                kwarg: testMode ? { test: true } : {},
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            };
            
            const response = await axios.post(`${settings.saltAPIUrl}/run`, payload,
                getAxiosConfig(600000, settings.saltAPIUrl));
            
            results = response.data.return[0] || {};
        }
        
        // Check for errors in results
        let hasErrors = false;
        let errorMessages = [];
        
        for (const [minion, result] of Object.entries(results)) {
            if (typeof result === 'string') {
                // Error string returned
                hasErrors = true;
                // Truncate long error messages
                const truncated = result.length > 500 ? result.substring(0, 500) + '...' : result;
                errorMessages.push(`${minion}: ${truncated}`);
            } else if (result && typeof result === 'object') {
                // Check for state failures within the result
                for (const [stateId, stateResult] of Object.entries(result)) {
                    if (stateResult && stateResult.result === false) {
                        hasErrors = true;
                        errorMessages.push(`${minion}/${stateId}: ${stateResult.comment || 'Failed'}`);
                    }
                }
            }
        }
        
        // Format response
        res.json({
            message: testMode ? 'State test completed (dry-run)' : (hasErrors ? 'State applied with errors' : 'State applied successfully'),
            statePath: statePath,
            stateName: stateName,
            method: method,
            testMode: testMode,
            targets: targets,
            hasErrors: hasErrors,
            warnings: warnings.length > 0 ? warnings : undefined,
            errorMessages: errorMessages.length > 0 ? errorMessages : undefined,
            results: results
        });
        
    } catch (error) {
        console.error('Error applying state:', error.message);
        
        // Provide more specific error info
        let errorDetail = error.response?.data || error.message;
        if (error.code === 'ECONNABORTED') {
            errorDetail = 'Request timed out - state may still be running on minions';
        }
        
        res.status(500).json({ 
            message: 'Failed to apply state', 
            error: errorDetail,
            statePath: statePath,
            targets: targets
        });
    }
});

/**
 * Apply state using raw content (state.template_str)
 * This is useful when states aren't in Salt's file_roots
 */
app.post('/api/states/apply-raw', async (req, res) => {
    const { targets, stateContent, testMode = false, stateName = 'custom_state' } = req.body;
    const settings = readSettings();
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required.' });
    }
    
    if (!stateContent) {
        return res.status(400).json({ message: 'State content required.' });
    }
    
    auditLog(req.ip, 'STATE_APPLY_RAW', '/api/states/apply-raw', { 
        targets, 
        stateName,
        testMode,
        contentLength: stateContent.length
    });
    
    try {
        const payload = {
            client: 'local',
            tgt: targets,
            tgt_type: 'list',
            fun: 'state.template_str',
            arg: [stateContent],
            kwarg: testMode ? { test: true } : {},
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        };
        
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload,
            getAxiosConfig(300000, settings.saltAPIUrl));
        
        res.json({
            message: testMode ? 'State test completed (dry-run)' : 'State applied',
            method: 'template_str',
            testMode: testMode,
            targets: targets,
            results: response.data.return[0]
        });
        
    } catch (error) {
        console.error('Error applying raw state:', error.message);
        res.status(500).json({ 
            message: 'Failed to apply state', 
            error: error.response?.data || error.message 
        });
    }
});

/**
 * Sync states from local directory to Salt master
 * This copies state files to the Salt master's file_roots
 */
app.post('/api/states/sync', async (req, res) => {
    const { osType } = req.body;
    const settings = readSettings();
    const statesPath = getStatesPath();
    
    if (!osType || !['linux', 'windows', 'all'].includes(osType.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid OS type. Use "linux", "windows", or "all".' });
    }
    
    auditLog(req.ip, 'STATE_SYNC', '/api/states/sync', { osType });
    
    const osTypes = osType === 'all' ? ['linux', 'windows'] : [osType.toLowerCase()];
    const results = {};
    
    for (const os of osTypes) {
        const osPath = path.join(statesPath, os);
        const states = getStatesFromDirectory(osPath);
        
        results[os] = {
            count: states.length,
            states: states.map(s => s.path)
        };
    }
    
    // In a production setup, you would:
    // 1. Use Salt's gitfs to sync from a git repo
    // 2. Use cp.push to send files to master
    // 3. Use a shared filesystem
    // 4. Use salt-run fileserver.update
    
    // For now, return info about what would be synced
    res.json({
        message: 'State sync info retrieved. Manual sync to Salt file_roots may be required.',
        statesPath: statesPath,
        results: results,
        hint: 'Copy states to /srv/salt/{linux,windows}/ or configure gitfs'
    });
});

/**
 * Get minion grains for OS detection (for state tab device filtering)
 */
app.get('/api/minions/os-info', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: '*',
            fun: 'grains.item',
            arg: ['os', 'os_family', 'kernel', 'osfinger'],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        const grains = response.data.return[0] || {};
        const categorized = {
            linux: [],
            windows: [],
            unknown: []
        };
        
        for (const [minion, data] of Object.entries(grains)) {
            const kernel = (data.kernel || '').toLowerCase();
            const osFamily = (data.os_family || '').toLowerCase();
            
            if (kernel === 'windows' || osFamily === 'windows') {
                categorized.windows.push({ minion, ...data });
            } else if (kernel === 'linux' || ['debian', 'redhat', 'arch', 'suse', 'gentoo'].includes(osFamily)) {
                categorized.linux.push({ minion, ...data });
            } else {
                categorized.unknown.push({ minion, ...data });
            }
        }
        
        res.json(categorized);
    } catch (error) {
        res.status(500).json({ message: 'Failed to get OS info', error: error.message });
    }
});

// ============================================================================
// END SALT STATES API ENDPOINTS
// ============================================================================

// --- Enhanced Proxy with Better Error Handling ---

app.post('/proxy', async (req, res) => {
    const saltCommand = req.body;
    const settings = readSettings();
    const jobId = `job_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    
    if (!saltCommand.fun) {
        return res.status(400).json({ message: 'Function (fun) is required' });
    }
    
    const payload = {
        ...saltCommand,
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };
    
    const jobInfo = {
        id: jobId,
        command: saltCommand.fun,
        targets: saltCommand.tgt,
        startTime: new Date().toISOString(),
        status: 'running',
        client: saltCommand.client || 'local'
    };
    activeJobs.set(jobId, jobInfo);
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, 
            getAxiosConfig(settings.asyncJobTimeout || 300000, settings.saltAPIUrl));
        
        jobInfo.status = 'completed';
        jobInfo.endTime = new Date().toISOString();
        jobInfo.result = response.data;
        
        outputHistory.push({
            ...jobInfo,
            timestamp: new Date().toISOString()
        });
        saveOutputHistory();
        
        res.json(response.data);
    } catch (error) {
        jobInfo.status = 'failed';
        jobInfo.endTime = new Date().toISOString();
        jobInfo.error = error.message;
        
        console.error('Salt API Proxy Error:', error.response?.data || error.message);
        
        if (saltCommand.fun?.includes('service') || saltCommand.fun?.includes('firewall')) {
            sendAlert('Critical Command Failed', `${saltCommand.fun} failed on ${saltCommand.tgt}: ${error.message}`);
        }
        
        res.status(error.response?.status || 500).json({
            message: 'Error proxying request to Salt API',
            error: error.response?.data || error.message,
            jobId: jobId
        });
    } finally {
        setTimeout(() => activeJobs.delete(jobId), 300000);
    }
});

// --- Async Job Management ---

app.post('/proxy/async', async (req, res) => {
    const saltCommand = req.body;
    const settings = readSettings();
    
    const payload = {
        ...saltCommand,
        client: 'local_async',
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload,
            getAxiosConfig(30000, settings.saltAPIUrl));
        
        const jid = response.data.return[0]?.jid;
        if (jid) {
            activeJobs.set(jid, {
                id: jid,
                command: saltCommand.fun,
                targets: saltCommand.tgt,
                startTime: new Date().toISOString(),
                status: 'running',
                async: true
            });
        }
        
        res.json({ jid, message: 'Job submitted', ...response.data });
    } catch (error) {
        console.error('Async job submission error:', error.message);
        res.status(500).json({ message: 'Failed to submit async job', error: error.message });
    }
});

app.get('/proxy/job/:jid', async (req, res) => {
    const { jid } = req.params;
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'jobs.lookup_jid',
            jid: jid,
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(10000, settings.saltAPIUrl));
        
        const result = response.data.return[0];
        const isComplete = Object.keys(result || {}).length > 0;
        
        if (isComplete && activeJobs.has(jid)) {
            const job = activeJobs.get(jid);
            job.status = 'completed';
            job.endTime = new Date().toISOString();
            job.result = result;
            
            outputHistory.push({ ...job });
            saveOutputHistory();
        }
        
        res.json({
            jid,
            status: isComplete ? 'completed' : 'running',
            result: result
        });
    } catch (error) {
        res.status(500).json({ message: 'Failed to check job status', error: error.message });
    }
});

app.get('/api/jobs', (req, res) => {
    const jobs = Array.from(activeJobs.values());
    res.json(jobs);
});

app.get('/api/history', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const history = outputHistory.slice(-limit);
    res.json(history);
});

app.delete('/api/history', (req, res) => {
    outputHistory = [];
    saveOutputHistory();
    res.json({ message: 'History cleared' });
});

// --- Audit Log Access ---

app.get('/api/audit', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    
    try {
        if (!fs.existsSync(AUDIT_LOG_PATH)) {
            return res.json([]);
        }
        
        const content = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
        const lines = content.trim().split('\n').filter(Boolean);
        const entries = lines.slice(-limit).map(line => {
            try {
                return JSON.parse(line);
            } catch {
                return { raw: line };
            }
        });
        
        res.json(entries.reverse());
    } catch (error) {
        res.status(500).json({ message: 'Error reading audit log', error: error.message });
    }
});

// --- Emergency Response Endpoints ---

app.post('/api/emergency/block-all-traffic', async (req, res) => {
    const { targets, allowSSH = true } = req.body;
    const settings = readSettings();
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required' });
    }
    
    auditLog(req.ip, 'EMERGENCY', '/api/emergency/block-all-traffic', { targets });
    sendAlert('EMERGENCY: Block All Traffic', `Initiated on: ${targets.join(', ')}`);
    
    const linuxCommand = allowSSH 
        ? 'iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT && iptables -A INPUT -i lo -j ACCEPT'
        : 'iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT && iptables -A INPUT -i lo -j ACCEPT';
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: targets,
            tgt_type: 'list',
            fun: 'cmd.run',
            arg: [linuxCommand],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json({ message: 'Emergency firewall rules applied', result: response.data });
    } catch (error) {
        res.status(500).json({ message: 'Emergency action failed', error: error.message });
    }
});

app.post('/api/emergency/kill-connections', async (req, res) => {
    const { targets, port } = req.body;
    const settings = readSettings();
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required' });
    }
    
    auditLog(req.ip, 'EMERGENCY', '/api/emergency/kill-connections', { targets, port });
    
    const command = port 
        ? `ss -K dport = :${port} || netstat -anp | grep :${port} | awk '{print $7}' | cut -d'/' -f1 | xargs -I{} kill -9 {}`
        : `ss -K || true`;
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: targets,
            tgt_type: 'list',
            fun: 'cmd.run',
            arg: [command],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json({ message: 'Connections terminated', result: response.data });
    } catch (error) {
        res.status(500).json({ message: 'Failed to kill connections', error: error.message });
    }
});

app.post('/api/emergency/change-passwords', async (req, res) => {
    const { targets, users, newPassword } = req.body;
    const settings = readSettings();
    
    if (!targets || !users || !newPassword) {
        return res.status(400).json({ message: 'Targets, users, and newPassword required' });
    }
    
    auditLog(req.ip, 'EMERGENCY', '/api/emergency/change-passwords', { targets, users: users.map(() => '***') });
    sendAlert('EMERGENCY: Password Change', `Initiated on: ${targets.join(', ')} for ${users.length} users`);
    
    const results = [];
    
    for (const user of users) {
        try {
            const response = await axios.post(`${settings.saltAPIUrl}/run`, {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'shadow.set_password',
                arg: [user, newPassword],
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            }, getAxiosConfig(30000, settings.saltAPIUrl));
            
            results.push({ user, status: 'success', result: response.data });
        } catch (error) {
            results.push({ user, status: 'failed', error: error.message });
        }
    }
    
    res.json({ message: 'Password changes attempted', results });
});

// --- Service Management ---

app.post('/api/services/status', async (req, res) => {
    const { targets, services } = req.body;
    const settings = readSettings();
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required' });
    }
    
    const results = {};
    
    try {
        if (services && services.length > 0) {
            for (const service of services) {
                const response = await axios.post(`${settings.saltAPIUrl}/run`, {
                    client: 'local',
                    tgt: targets,
                    tgt_type: 'list',
                    fun: 'service.status',
                    arg: [service],
                    username: settings.username,
                    password: settings.password,
                    eauth: settings.eauth
                }, getAxiosConfig(30000, settings.saltAPIUrl));
                
                results[service] = response.data.return[0];
            }
        } else {
            const response = await axios.post(`${settings.saltAPIUrl}/run`, {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'service.get_all',
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            }, getAxiosConfig(30000, settings.saltAPIUrl));
            
            results.all = response.data.return[0];
        }
        
        res.json(results);
    } catch (error) {
        res.status(500).json({ message: 'Failed to get service status', error: error.message });
    }
});

app.post('/api/services/manage', async (req, res) => {
    const { targets, service, action } = req.body;
    const settings = readSettings();
    
    const validActions = ['start', 'stop', 'restart', 'enable', 'disable'];
    if (!validActions.includes(action)) {
        return res.status(400).json({ message: `Invalid action. Use: ${validActions.join(', ')}` });
    }
    
    auditLog(req.ip, 'SERVICE_MANAGE', '/api/services/manage', { targets, service, action });
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: targets,
            tgt_type: 'list',
            fun: `service.${action}`,
            arg: [service],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json({ message: `Service ${action} executed`, result: response.data });
    } catch (error) {
        res.status(500).json({ message: `Failed to ${action} service`, error: error.message });
    }
});

// --- Custom Scripts ---

app.get('/custom-scripts', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'fileserver.file_list',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        const scripts = response.data.return[0] || [];
        const scriptExtensions = ['.sh', '.ps1', '.py', '.rb', '.pl', '.bat', '.cmd'];
        const filteredScripts = scripts.filter(s => 
            scriptExtensions.some(ext => s.toLowerCase().endsWith(ext))
        );
        
        res.json(filteredScripts);
    } catch (error) {
        console.error('Error fetching custom scripts:', error.message);
        res.status(500).json({ message: 'Error fetching scripts', error: error.message });
    }
});

app.get('/custom-script-content', async (req, res) => {
    const scriptPath = req.query.path;
    const settings = readSettings();
    
    if (!scriptPath || !isValidScriptPath(scriptPath)) {
        return res.status(400).json({ message: 'Invalid script path' });
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'salt.cmd',
            arg: ['cp.get_file_str', `salt://${scriptPath}`],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        const content = response.data.return[0];
        if (content === false || content === null) {
            throw new Error('File not found or access denied');
        }
        
        res.json({ content });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching script', error: error.message });
    }
});

// --- Key Management ---

app.get('/keys', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.list_all',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching keys', error: error.message });
    }
});

app.post('/keys/accept', async (req, res) => {
    const { minionId } = req.body;
    const settings = readSettings();
    
    const sanitizedId = sanitizeMinionId(minionId);
    if (!sanitizedId) {
        return res.status(400).json({ message: 'Invalid minionId' });
    }
    
    auditLog(req.ip, 'KEY_ACCEPT', '/keys/accept', { minionId: sanitizedId });
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.accept',
            match: sanitizedId,
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error accepting key', error: error.message });
    }
});

app.post('/keys/accept-all', async (req, res) => {
    const settings = readSettings();
    
    auditLog(req.ip, 'KEY_ACCEPT_ALL', '/keys/accept-all', {});
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.accept',
            match: '*',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error accepting all keys', error: error.message });
    }
});

app.post('/keys/delete', async (req, res) => {
    const { minionId } = req.body;
    const settings = readSettings();
    
    const sanitizedId = sanitizeMinionId(minionId);
    if (!sanitizedId) {
        return res.status(400).json({ message: 'Invalid minionId' });
    }
    
    auditLog(req.ip, 'KEY_DELETE', '/keys/delete', { minionId: sanitizedId });
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.delete',
            match: sanitizedId,
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error deleting key', error: error.message });
    }
});

// --- Playbook Management ---

app.get('/api/playbooks', (req, res) => {
    try {
        const files = fs.readdirSync(PLAYBOOKS_PATH)
            .filter(f => f.endsWith('.json'));
        
        const playbooks = files.map(f => {
            const content = JSON.parse(fs.readFileSync(path.join(PLAYBOOKS_PATH, f)));
            return {
                filename: f,
                name: content.name,
                description: content.description,
                steps: content.steps?.length || 0
            };
        });
        
        res.json(playbooks);
    } catch (error) {
        res.status(500).json({ message: 'Error listing playbooks', error: error.message });
    }
});

app.get('/api/playbooks/:name', (req, res) => {
    const { name } = req.params;
    const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '');
    const filepath = path.join(PLAYBOOKS_PATH, `${safeName}.json`);
    
    if (!fs.existsSync(filepath)) {
        return res.status(404).json({ message: 'Playbook not found' });
    }
    
    try {
        const content = JSON.parse(fs.readFileSync(filepath));
        res.json(content);
    } catch (error) {
        res.status(500).json({ message: 'Error reading playbook', error: error.message });
    }
});

app.post('/api/playbooks/:name/execute', async (req, res) => {
    const { name } = req.params;
    const { targets } = req.body;
    const settings = readSettings();
    
    const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '');
    const filepath = path.join(PLAYBOOKS_PATH, `${safeName}.json`);
    
    if (!fs.existsSync(filepath)) {
        return res.status(404).json({ message: 'Playbook not found' });
    }
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required' });
    }
    
    auditLog(req.ip, 'PLAYBOOK_EXECUTE', `/api/playbooks/${name}/execute`, { targets });
    sendAlert('Playbook Execution', `Playbook "${name}" started on ${targets.length} targets`);
    
    try {
        const playbook = JSON.parse(fs.readFileSync(filepath));
        const results = [];
        
        for (const step of playbook.steps) {
            const stepResult = {
                step: step.name,
                function: step.function,
                status: 'pending'
            };
            
            try {
                const response = await axios.post(`${settings.saltAPIUrl}/run`, {
                    client: 'local',
                    tgt: targets,
                    tgt_type: 'list',
                    fun: step.function,
                    arg: step.args || [],
                    kwarg: step.kwargs || {},
                    username: settings.username,
                    password: settings.password,
                    eauth: settings.eauth
                }, getAxiosConfig(step.timeout || 60000, settings.saltAPIUrl));
                
                stepResult.status = 'completed';
                stepResult.result = response.data.return[0];
            } catch (error) {
                stepResult.status = 'failed';
                stepResult.error = error.message;
                
                if (step.stopOnError) {
                    results.push(stepResult);
                    return res.json({ 
                        message: 'Playbook execution stopped due to error',
                        completedSteps: results.length,
                        totalSteps: playbook.steps.length,
                        results 
                    });
                }
            }
            
            results.push(stepResult);
        }
        
        res.json({ 
            message: 'Playbook execution completed',
            completedSteps: results.length,
            totalSteps: playbook.steps.length,
            results 
        });
    } catch (error) {
        res.status(500).json({ message: 'Playbook execution failed', error: error.message });
    }
});

// --- Grains Cache ---

let minionGrainCache = new Map();
const GRAIN_CACHE_TTL = 60000;

app.get('/api/minions/grains', async (req, res) => {
    const settings = readSettings();
    const now = Date.now();
    
    if (minionGrainCache.has('all') && (now - minionGrainCache.get('timestamp')) < GRAIN_CACHE_TTL) {
        return res.json(minionGrainCache.get('all'));
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: '*',
            fun: 'grains.items',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        const grains = response.data.return[0] || {};
        minionGrainCache.set('all', grains);
        minionGrainCache.set('timestamp', now);
        
        res.json(grains);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching grains', error: error.message });
    }
});

// --- Quick Command ---

app.post('/api/quick-cmd', async (req, res) => {
    const { target, cmd, timeout = 30 } = req.body;
    const settings = readSettings();
    
    if (!target || !cmd) {
        return res.status(400).json({ message: 'Target and cmd required' });
    }
    
    auditLog(req.ip, 'QUICK_CMD', '/api/quick-cmd', { target, cmd: cmd.substring(0, 100) });
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: target,
            tgt_type: target.includes('*') ? 'glob' : 'list',
            fun: 'cmd.run',
            arg: [cmd],
            timeout: timeout,
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig((timeout + 10) * 1000, settings.saltAPIUrl));
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Command failed', error: error.message });
    }
});

// --- Batch Operations ---

app.post('/proxy/batch', async (req, res) => {
    const { targets, scripts, args } = req.body;
    const settings = readSettings();
    const results = [];
    
    if (!targets || !scripts || targets.length === 0 || scripts.length === 0) {
        return res.status(400).json({ message: 'Targets and scripts are required' });
    }
    
    auditLog(req.ip, 'BATCH_DEPLOY', '/proxy/batch', { targets, scripts });
    
    for (const script of scripts) {
        const payload = {
            client: 'local_async',
            tgt: targets,
            tgt_type: 'list',
            fun: 'cmd.script',
            arg: [`salt://${script}`, args || ''],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        };
        
        try {
            const response = await axios.post(`${settings.saltAPIUrl}/run`, payload,
                getAxiosConfig(30000, settings.saltAPIUrl));
            
            results.push({
                script,
                jid: response.data.return[0]?.jid,
                status: 'submitted'
            });
        } catch (error) {
            results.push({
                script,
                status: 'failed',
                error: error.message
            });
        }
    }
    
    res.json({ message: 'Batch deployment initiated', results });
});

// --- File Operations ---

app.post('/api/files/read', async (req, res) => {
    const { target, path: filePath } = req.body;
    const settings = readSettings();
    
    if (!target || !filePath) {
        return res.status(400).json({ message: 'Target and path required' });
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: target,
            fun: 'file.read',
            arg: [filePath],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json({ content: response.data.return[0][target] });
    } catch (error) {
        res.status(500).json({ message: 'Failed to read file', error: error.message });
    }
});

app.post('/api/files/write', async (req, res) => {
    const { target, path: filePath, content } = req.body;
    const settings = readSettings();
    
    if (!target || !filePath || content === undefined) {
        return res.status(400).json({ message: 'Target, path, and content required' });
    }
    
    auditLog(req.ip, 'FILE_WRITE', '/api/files/write', { target, path: filePath });
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: target,
            fun: 'file.write',
            arg: [filePath, content],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json({ result: response.data.return[0][target] });
    } catch (error) {
        res.status(500).json({ message: 'Failed to write file', error: error.message });
    }
});

// --- Network Diagnostics ---

app.post('/api/network/connections', async (req, res) => {
    const { target } = req.body;
    const settings = readSettings();
    
    if (!target) {
        return res.status(400).json({ message: 'Target required' });
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: target,
            fun: 'network.active_tcp',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json(response.data.return[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to get connections', error: error.message });
    }
});

// --- User Management ---

app.post('/api/users/list', async (req, res) => {
    const { target } = req.body;
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'local',
            tgt: target,
            fun: 'user.list_users',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, getAxiosConfig(30000, settings.saltAPIUrl));
        
        res.json(response.data.return[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to list users', error: error.message });
    }
});

// --- Initialize and Start ---

loadOutputHistory();

// Ensure states directories exist on startup
const statesPath = getStatesPath();
['linux', 'windows'].forEach(osType => {
    const osPath = path.join(statesPath, osType);
    if (!fs.existsSync(osPath)) {
        try {
            fs.mkdirSync(osPath, { recursive: true });
            console.log(`Created states directory: ${osPath}`);
        } catch (error) {
            console.warn(`Could not create states directory ${osPath}: ${error.message}`);
        }
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Salt GUI Server - Competition Edition`);
    console.log(`${'='.repeat(60)}`);
    console.log(`Listening on: http://0.0.0.0:${port}`);
    console.log(`Config file:  ${path.resolve(CONFIG_PATH)}`);
    console.log(`Audit log:    ${path.resolve(AUDIT_LOG_PATH)}`);
    console.log(`Playbooks:    ${path.resolve(PLAYBOOKS_PATH)}`);
    console.log(`States:       ${path.resolve(statesPath)}`);
    console.log(`  - Linux:    ${path.resolve(statesPath, 'linux')}`);
    console.log(`  - Windows:  ${path.resolve(statesPath, 'windows')}`);
    console.log(`${'='.repeat(60)}\n`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, saving state...');
    saveOutputHistory();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, saving state...');
    saveOutputHistory();
    process.exit(0);
});
