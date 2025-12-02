const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');

const app = express();
const port = 3000;
const CONFIG_PATH = './config.json';

// Middleware to parse JSON bodies and enable CORS
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from the current directory

// --- Settings Management ---

function readSettings() {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const rawData = fs.readFileSync(CONFIG_PATH);
            return JSON.parse(rawData);
        } else {
            // Default settings
            const defaultSettings = {
                proxyURL: '',
                saltAPIUrl: '',
                username: '',
                password: '',
                eauth: ''
            };
            fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultSettings, null, 2));
            return defaultSettings;
        }
    } catch (error) {
        console.error('[Server] Error in readSettings:', error);
        throw error; // Re-throw the error to be caught by the route handler
    }
}

app.get('/api/settings', (req, res) => {
    try {
        const settings = readSettings();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ message: 'Error reading settings file.', error: error.message });
    }
});

app.post('/api/settings', (req, res) => {
    console.log('[Server] Received settings to save:', req.body);
    try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(req.body, null, 2));
        res.status(200).json({ message: 'Settings saved successfully.' });
    } catch (error) {
        console.error('[Server] Error saving settings:', error);
        res.status(500).json({ message: 'Failed to save settings.', error: error.message });
    }
});

// Proxy route for Salt API commands using tokenless authentication
app.post('/proxy', async (req, res) => {
    const saltCommand = req.body;
    const settings = readSettings();

    // Combine the command with authentication credentials
    const payload = {
        ...saltCommand,
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };

    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Salt API Proxy Error:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: 'Error proxying request to Salt API',
            error: error.response ? error.response.data : error.message
        });
    }
});

// Route to get custom scripts from the salt-master
app.get('/custom-scripts', async (req, res) => {
    const settings = readSettings();
    const payload = {
        client: 'runner',
        fun: 'fileserver.file_list',
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };

    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        // The return is a list of files
        const scripts = response.data.return[0];
        res.json(scripts);
    } catch (error) {
        console.error('Error fetching custom scripts:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: 'Error fetching custom scripts from Salt API',
            error: error.response ? error.response.data : error.message
        });
    }
});

// Route to get the content of a specific custom script
app.get('/custom-script-content', async (req, res) => {
    const scriptPath = req.query.path;
    const settings = readSettings();

    if (!scriptPath) {
        return res.status(400).json({ message: 'Script path is required.' });
    }
    // Security validation: still prevent directory traversal, but allow forward slashes for subdirectories.
    if (scriptPath.includes('..')) {
        return res.status(400).json({ message: 'Invalid script path.' });
    }

    const payload = {
        client: 'runner',
        fun: 'salt.cmd',
        // Execute 'cp.get_file_str' on the master with the script path as its argument.
        arg: ['cp.get_file_str', `salt://${scriptPath}`],
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };

    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: { 'Content-Type': 'application/json' }
        });
        // The return from salt.cmd will be the direct content of the file.
        const result = response.data.return[0];
        if (result === false || result === null || result === undefined) {
            throw new Error('Salt API did not return file content. The file might not exist or there was a permissions issue.');
        }
        const content = result;
        res.json({ content });
    } catch (error) {
        console.error(`Error fetching content for script ${scriptPath}:`, error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: `Error fetching content for script ${scriptPath} from Salt API`,
            error: error.response ? error.response.data : error.message
        });
    }
});

// Route to list all minion keys
app.get('/keys', async (req, res) => {
    const settings = readSettings();
    const payload = {
        client: 'wheel',
        fun: 'key.list_all',
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };

    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching keys:', error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: 'Error fetching keys from Salt API',
            error: error.response ? error.response.data : error.message
        });
    }
});

// Route to accept a minion key
app.post('/keys/accept', async (req, res) => {
    const { minionId } = req.body;
    const settings = readSettings();

    if (!minionId) {
        return res.status(400).json({ message: 'minionId is required' });
    }

    const payload = {
        client: 'wheel',
        fun: 'key.accept',
        match: minionId,
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };

    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error(`Error accepting key for minion ${minionId}:`, error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: `Error accepting key for minion ${minionId} from Salt API`,
            error: error.response ? error.response.data : error.message
        });
    }
});

// Route to delete a minion key
app.post('/keys/delete', async (req, res) => {
    const { minionId } = req.body;
    const settings = readSettings();

    if (!minionId) {
        return res.status(400).json({ message: 'minionId is required' });
    }

    const payload = {
        client: 'wheel',
        fun: 'key.delete',
        match: minionId,
        username: settings.username,
        password: settings.password,
        eauth: settings.eauth
    };

    try {
        const response = await axios.post(`${settings.saltAPIUrl}/run`, payload, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error(`Error deleting key for minion ${minionId}:`, error.response ? error.response.data : error.message);
        res.status(error.response ? error.response.status : 500).json({
            message: `Error deleting key for minion ${minionId} from Salt API`,
            error: error.response ? error.response.data : error.message
        });
    }
});

app.listen(port, () => {
    console.log(`Salt API proxy server listening at http://localhost:${port}`);
});