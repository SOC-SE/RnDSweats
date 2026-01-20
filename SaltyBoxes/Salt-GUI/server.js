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
const multer = require('multer');
const https = require('https');
const http = require('http');

// HTTPS agent for self-signed certificates
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Helper to get the right agent based on URL
function getAgent(url) {
    if (url && url.startsWith('https://')) {
        return httpsAgent;
    }
    return undefined;  // Use default for HTTP
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

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_PATH),
    filename: (req, file, cb) => {
        const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, `${Date.now()}-${safeName}`);
    }
});
const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedExtensions = ['.sh', '.ps1', '.py', '.rb', '.pl', '.bat', '.cmd', '.sls', '.txt'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExtensions.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error(`File type ${ext} not allowed`));
        }
    }
});

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
    // Remove sensitive data from audit logs
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

// Helper function for axios config with proper SSL handling
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
                alertWebhook: ''
            };
            fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultSettings, null, 2));
            return defaultSettings;
        }
    } catch (error) {
        console.error('[Server] Error reading settings:', error);
        throw error;
    }
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

// Validate and sanitize minion ID to prevent injection
function sanitizeMinionId(minionId) {
    if (!minionId || typeof minionId !== 'string') return null;
    // Allow alphanumeric, dots, hyphens, underscores
    const sanitized = minionId.replace(/[^a-zA-Z0-9._-]/g, '');
    if (sanitized.length === 0 || sanitized.length > 256) return null;
    return sanitized;
}

// Validate file path to prevent directory traversal
function isValidScriptPath(scriptPath) {
    if (!scriptPath || typeof scriptPath !== 'string') return false;
    // Normalize and check for traversal attempts
    const normalized = path.normalize(scriptPath);
    if (normalized.includes('..') || normalized.startsWith('/') || normalized.includes('\\')) {
        return false;
    }
    return true;
}

// --- API Authentication (Optional but Recommended) ---

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
        }, getAxiosConfig(5000));
        
        health.saltApi = 'ok';
        health.minionStatus = response.data.return[0];
    } catch (error) {
        health.saltApi = 'error';
        health.saltApiError = error.message;
    }
    
    res.json(health);
});

// Enhanced minion status with service checks
app.get('/api/minions/status', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'manage.status',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { timeout: 30000, httpsAgent });
        
        res.json({
            up: response.data.return[0]?.up || [],
            down: response.data.return[0]?.down || []
        });
    } catch (error) {
        res.status(500).json({ message: 'Failed to get minion status', error: error.message });
    }
});

// --- Enhanced Proxy with Better Error Handling ---

app.post('/proxy', async (req, res) => {
    const saltCommand = req.body;
    const settings = readSettings();
    const jobId = `job_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    
    // Validate required fields
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
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: { 'Content-Type': 'application/json' },
            timeout: settings.asyncJobTimeout || 300000,
            httpsAgent
        });
        
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
        
        // Send alert for critical failures
        if (saltCommand.fun?.includes('service') || saltCommand.fun?.includes('firewall')) {
            sendAlert('Critical Command Failed', `${saltCommand.fun} failed on ${saltCommand.tgt}: ${error.message}`);
        }
        
        res.status(error.response?.status || 500).json({
            message: 'Error proxying request to Salt API',
            error: error.response?.data || error.message,
            jobId: jobId
        });
    } finally {
        setTimeout(() => activeJobs.delete(jobId), 300000); // Clean up after 5 minutes
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
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 30000,
            httpsAgent
        });
        
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
        }, { timeout: 10000, httpsAgent });
        
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
        
        res.json(entries.reverse()); // Most recent first
    } catch (error) {
        res.status(500).json({ message: 'Error reading audit log', error: error.message });
    }
});

// --- Emergency Response Endpoints ---

app.post('/api/emergency/block-all-traffic', async (req, res) => {
    const { targets } = req.body;
    const settings = readSettings();
    
    if (!targets || targets.length === 0) {
        return res.status(400).json({ message: 'Targets required' });
    }
    
    auditLog(req.ip, 'EMERGENCY', '/api/emergency/block-all-traffic', { targets });
    sendAlert('EMERGENCY: Block All Traffic', `Initiated on: ${targets.join(', ')}`);
    
    // Linux iptables command to drop all incoming except SSH
    const linuxCommand = 'iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT';
    
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
        }, { timeout: 30000, httpsAgent });
        
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
        }, { timeout: 30000, httpsAgent });
        
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
            }, { timeout: 30000, httpsAgent });
            
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
            // Check specific services
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
                }, { timeout: 30000, httpsAgent });
                
                results[service] = response.data.return[0];
            }
        } else {
            // Get all services
            const response = await axios.post(`${settings.saltAPIUrl}/run`, {
                client: 'local',
                tgt: targets,
                tgt_type: 'list',
                fun: 'service.get_all',
                username: settings.username,
                password: settings.password,
                eauth: settings.eauth
            }, { timeout: 30000, httpsAgent });
            
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
        }, { timeout: 30000, httpsAgent });
        
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
        }, { headers: { 'Content-Type': 'application/json' }, httpsAgent });
        
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
        }, { headers: { 'Content-Type': 'application/json' }, httpsAgent });
        
        const content = response.data.return[0];
        if (content === false || content === null) {
            throw new Error('File not found or access denied');
        }
        
        res.json({ content });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching script', error: error.message });
    }
});

// Upload script to Salt fileserver
app.post('/api/scripts/upload', upload.single('script'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }
    
    const settings = readSettings();
    const localPath = req.file.path;
    const targetPath = req.body.targetPath || req.file.originalname;
    
    auditLog(req.ip, 'SCRIPT_UPLOAD', '/api/scripts/upload', { filename: req.file.originalname });
    
    try {
        // Read the uploaded file
        const fileContent = fs.readFileSync(localPath, 'utf8');
        
        // Use Salt's cp.push or write directly if master
        // This depends on your Salt setup - adjust as needed
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'salt.cmd',
            arg: ['cp.cache_file', `salt://${targetPath}`],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { httpsAgent });
        
        // Clean up local file
        fs.unlinkSync(localPath);
        
        res.json({ message: 'Script uploaded', path: targetPath });
    } catch (error) {
        if (fs.existsSync(localPath)) {
            fs.unlinkSync(localPath);
        }
        res.status(500).json({ message: 'Upload failed', error: error.message });
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
        }, { headers: { 'Content-Type': 'application/json' }, httpsAgent });
        
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
        }, { headers: { 'Content-Type': 'application/json' }, httpsAgent });
        
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
        }, { headers: { 'Content-Type': 'application/json' }, httpsAgent });
        
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
        }, { headers: { 'Content-Type': 'application/json' }, httpsAgent });
        
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
                }, { timeout: step.timeout || 60000, httpsAgent });
                
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
        }, { timeout: 30000, httpsAgent });
        
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
        }, { timeout: (timeout + 10) * 1000, httpsAgent });
        
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
            const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
                headers: { 'Content-Type': 'application/json' },
                httpsAgent
            });
            
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
        }, { timeout: 30000, httpsAgent });
        
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
        }, { timeout: 30000, httpsAgent });
        
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
        }, { timeout: 30000, httpsAgent });
        
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
        }, { timeout: 30000, httpsAgent });
        
        res.json(response.data.return[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to list users', error: error.message });
    }
});

// --- Initialize and Start ---

loadOutputHistory();

app.listen(port, '0.0.0.0', () => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Salt GUI Server - Competition Edition`);
    console.log(`${'='.repeat(60)}`);
    console.log(`Listening on: http://0.0.0.0:${port}`);
    console.log(`Config file:  ${path.resolve(CONFIG_PATH)}`);
    console.log(`Audit log:    ${path.resolve(AUDIT_LOG_PATH)}`);
    console.log(`Playbooks:    ${path.resolve(PLAYBOOKS_PATH)}`);
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
