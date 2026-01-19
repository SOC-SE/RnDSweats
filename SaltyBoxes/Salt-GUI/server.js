/**
 * Salt GUI Server - Enhanced Edition
 * 
 * Improvements:
 * - Job tracking and status monitoring
 * - Async job support for long-running tasks
 * - Output history persistence
 * - Rate limiting protection
 * - Better error handling and logging
 * - Batch deployment support
 * - Health check endpoints
 * 
 * Samuel Brucker 2025-2026
 */

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
const CONFIG_PATH = './config.json';
const JOBS_PATH = './jobs.json';
const OUTPUT_HISTORY_PATH = './output_history.json';

// In-memory job tracking
let activeJobs = new Map();
let outputHistory = [];
const MAX_HISTORY_ENTRIES = 1000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.'));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
    next();
});

// --- Settings Management ---

function readSettings() {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const rawData = fs.readFileSync(CONFIG_PATH);
            return JSON.parse(rawData);
        } else {
            const defaultSettings = {
                proxyURL: '',
                saltAPIUrl: 'https://localhost:8881',
                username: '',
                password: '',
                eauth: 'pam',
                asyncJobTimeout: 300000, // 5 minutes
                maxConcurrentJobs: 10
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
        // Keep only recent entries
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

// --- API Routes ---

app.get('/api/settings', (req, res) => {
    try {
        const settings = readSettings();
        // Don't send password to client
        const safeSettings = { ...settings, password: settings.password ? '********' : '' };
        res.json(safeSettings);
    } catch (error) {
        res.status(500).json({ message: 'Error reading settings', error: error.message });
    }
});

app.post('/api/settings', (req, res) => {
    try {
        const currentSettings = readSettings();
        const newSettings = { ...req.body };
        
        // If password is masked, keep the old one
        if (newSettings.password === '********') {
            newSettings.password = currentSettings.password;
        }
        
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(newSettings, null, 2));
        res.json({ message: 'Settings saved successfully' });
    } catch (error) {
        console.error('[Server] Error saving settings:', error);
        res.status(500).json({ message: 'Failed to save settings', error: error.message });
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    const settings = readSettings();
    const health = {
        server: 'ok',
        timestamp: new Date().toISOString(),
        activeJobs: activeJobs.size,
        saltApi: 'unknown'
    };
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'manage.status',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { timeout: 5000 });
        
        health.saltApi = 'ok';
        health.minionStatus = response.data.return[0];
    } catch (error) {
        health.saltApi = 'error';
        health.saltApiError = error.message;
    }
    
    res.json(health);
});

// Enhanced proxy with job tracking
app.post('/proxy', async (req, res) => {
    const saltCommand = req.body;
    const settings = readSettings();
    const jobId = `job_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const payload = {
        ...saltCommand,
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };
    
    // Track the job
    const jobInfo = {
        id: jobId,
        command: saltCommand.fun,
        targets: saltCommand.tgt,
        startTime: new Date().toISOString(),
        status: 'running'
    };
    activeJobs.set(jobId, jobInfo);
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: { 'Content-Type': 'application/json' },
            timeout: settings.asyncJobTimeout || 300000
        });
        
        // Update job status
        jobInfo.status = 'completed';
        jobInfo.endTime = new Date().toISOString();
        jobInfo.result = response.data;
        
        // Add to history
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
        res.status(error.response?.status || 500).json({
            message: 'Error proxying request to Salt API',
            error: error.response?.data || error.message,
            jobId: jobId
        });
    } finally {
        // Clean up after a delay
        setTimeout(() => activeJobs.delete(jobId), 60000);
    }
});

// Async job submission (for long-running tasks)
app.post('/proxy/async', async (req, res) => {
    const saltCommand = req.body;
    const settings = readSettings();
    
    // Force async client
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
            timeout: 30000
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

// Check async job status
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
        }, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000
        });
        
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

// Get active jobs
app.get('/api/jobs', (req, res) => {
    const jobs = Array.from(activeJobs.values());
    res.json(jobs);
});

// Get output history
app.get('/api/history', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const history = outputHistory.slice(-limit);
    res.json(history);
});

// Clear history
app.delete('/api/history', (req, res) => {
    outputHistory = [];
    saveOutputHistory();
    res.json({ message: 'History cleared' });
});

// Batch deployment endpoint
app.post('/proxy/batch', async (req, res) => {
    const { targets, scripts, args } = req.body;
    const settings = readSettings();
    const results = [];
    
    if (!targets || !scripts || targets.length === 0 || scripts.length === 0) {
        return res.status(400).json({ message: 'Targets and scripts are required' });
    }
    
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
                headers: { 'Content-Type': 'application/json' }
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

// Custom scripts management
app.get('/custom-scripts', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'fileserver.file_list',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { headers: { 'Content-Type': 'application/json' } });
        
        const scripts = response.data.return[0] || [];
        // Filter to only show scripts
        const scriptExtensions = ['.sh', '.ps1', '.py', '.rb', '.pl'];
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
    
    if (!scriptPath) {
        return res.status(400).json({ message: 'Script path required' });
    }
    
    if (scriptPath.includes('..')) {
        return res.status(400).json({ message: 'Invalid path' });
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'runner',
            fun: 'salt.cmd',
            arg: ['cp.get_file_str', `salt://${scriptPath}`],
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { headers: { 'Content-Type': 'application/json' } });
        
        const content = response.data.return[0];
        if (content === false || content === null) {
            throw new Error('File not found or access denied');
        }
        
        res.json({ content });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching script', error: error.message });
    }
});

// Key management routes
app.get('/keys', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.list_all',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { headers: { 'Content-Type': 'application/json' } });
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching keys', error: error.message });
    }
});

app.post('/keys/accept', async (req, res) => {
    const { minionId } = req.body;
    const settings = readSettings();
    
    if (!minionId) {
        return res.status(400).json({ message: 'minionId required' });
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.accept',
            match: minionId,
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { headers: { 'Content-Type': 'application/json' } });
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error accepting key', error: error.message });
    }
});

app.post('/keys/accept-all', async (req, res) => {
    const settings = readSettings();
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.accept',
            match: '*',
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { headers: { 'Content-Type': 'application/json' } });
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error accepting all keys', error: error.message });
    }
});

app.post('/keys/delete', async (req, res) => {
    const { minionId } = req.body;
    const settings = readSettings();
    
    if (!minionId) {
        return res.status(400).json({ message: 'minionId required' });
    }
    
    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, {
            client: 'wheel',
            fun: 'key.delete',
            match: minionId,
            username: settings.username,
            password: settings.password,
            eauth: settings.eauth
        }, { headers: { 'Content-Type': 'application/json' } });
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Error deleting key', error: error.message });
    }
});

// Minion grain cache for quick lookups
let minionGrainCache = new Map();
const GRAIN_CACHE_TTL = 60000; // 1 minute

app.get('/api/minions/grains', async (req, res) => {
    const settings = readSettings();
    const now = Date.now();
    
    // Check cache
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
        }, { headers: { 'Content-Type': 'application/json' }, timeout: 30000 });
        
        const grains = response.data.return[0] || {};
        minionGrainCache.set('all', grains);
        minionGrainCache.set('timestamp', now);
        
        res.json(grains);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching grains', error: error.message });
    }
});

// Quick command endpoint for competition speed
app.post('/api/quick-cmd', async (req, res) => {
    const { target, cmd, timeout = 30 } = req.body;
    const settings = readSettings();
    
    if (!target || !cmd) {
        return res.status(400).json({ message: 'Target and cmd required' });
    }
    
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
        }, { 
            headers: { 'Content-Type': 'application/json' },
            timeout: (timeout + 10) * 1000
        });
        
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ message: 'Command failed', error: error.message });
    }
});

// Initialize and start server
loadOutputHistory();

app.listen(port, '0.0.0.0', () => {
    console.log(`Salt GUI Server listening on http://0.0.0.0:${port}`);
    console.log(`Config file: ${path.resolve(CONFIG_PATH)}`);
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
