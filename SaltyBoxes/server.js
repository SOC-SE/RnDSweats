/**
 * Salt-GUI Server
 *
 * Web-based remote administration platform for SaltStack.
 * Designed for CCDC (Collegiate Cyber Defense Competition) environments.
 *
 * @author Samuel Brucker
 * @version 1.0.0
 */

const express = require('express');
const session = require('express-session');
const path = require('path');

// Core libraries
const { getAppConfig, checkConfigFiles } = require('./src/lib/config');
const { generateSessionSecret, hasUsers } = require('./src/lib/auth');
const logger = require('./src/lib/logger');
const { client: saltClient } = require('./src/lib/salt-client');

// Middleware
const { attachRequestInfo, sessionTimeout } = require('./src/middleware/auth');
const { auditAllMutations } = require('./src/middleware/audit');

// Route modules
const authRoutes = require('./src/routes/auth');
const devicesRoutes = require('./src/routes/devices');
const commandsRoutes = require('./src/routes/commands');
const scriptsRoutes = require('./src/routes/scripts');
const settingsRoutes = require('./src/routes/settings');
const auditRoutes = require('./src/routes/audit');
const servicesRoutes = require('./src/routes/services');
const processesRoutes = require('./src/routes/processes');
const passwordsRoutes = require('./src/routes/passwords');
const statesRoutes = require('./src/routes/states');
const playbooksRoutes = require('./src/routes/playbooks');
const emergencyRoutes = require('./src/routes/emergency');
const usersRoutes = require('./src/routes/users');
const networkRoutes = require('./src/routes/network');
const filesRoutes = require('./src/routes/files');
const logsRoutes = require('./src/routes/logs');
const suspiciousRoutes = require('./src/routes/suspicious');
const reportsRoutes = require('./src/routes/reports');
const forensicsRoutes = require('./src/routes/forensics');
const monitoringRoutes = require('./src/routes/monitoring');

// Initialize Express
const app = express();

// Load configuration
const config = getAppConfig();

// Check configuration files
const configStatus = checkConfigFiles();
if (!configStatus.salt) {
  logger.warn('Salt configuration not found. Copy config/salt.yaml.example to config/salt.yaml');
}
if (!configStatus.auth) {
  logger.warn('Auth configuration not found. Copy config/auth.yaml.example to config/auth.yaml');
}

// Generate session secret if not configured
const sessionSecret = config.session.secret || generateSessionSecret();

// Trust first proxy (for X-Forwarded-For header)
app.set('trust proxy', 1);

// Session configuration
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  name: 'salt-gui.sid',
  cookie: {
    secure: false, // Set true if using HTTPS
    httpOnly: true,
    maxAge: config.session.timeout_minutes * 60 * 1000,
    sameSite: 'lax'
  }
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request info attachment (IP, username)
app.use(attachRequestInfo);

// Request logging
app.use(logger.requestLogger());

// Session timeout check
app.use(sessionTimeout(config.session.timeout_minutes * 60 * 1000));

// Audit logging for mutations (skip for auth routes - they handle their own)
app.use((req, res, next) => {
  if (req.path.startsWith('/api/auth')) {
    return next();
  }
  return auditAllMutations(req, res, next);
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// Health Check Endpoint (no auth required)
// ============================================================

app.get('/api/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0',
    salt: {
      status: 'unknown',
      url: saltClient.baseUrl
    },
    setup: {
      required: !hasUsers(),
      configMissing: !configStatus.salt || !configStatus.auth
    }
  };

  try {
    const saltConnected = await saltClient.testConnection();
    health.salt.status = saltConnected ? 'connected' : 'disconnected';

    if (saltConnected) {
      const status = await saltClient.status();
      health.salt.minions = {
        online: (status.up || []).length,
        offline: (status.down || []).length
      };
    }
  } catch (error) {
    health.salt.status = 'error';
    health.salt.error = error.message;
  }

  res.json(health);
});

// ============================================================
// API Routes
// ============================================================

// Authentication routes (some don't require auth)
app.use('/api/auth', authRoutes);

// Device/minion management routes
app.use('/api/devices', devicesRoutes);

// Command execution routes
app.use('/api/commands', commandsRoutes);

// Settings routes
app.use('/api/settings', settingsRoutes);

// Audit log routes
app.use('/api/audit', auditRoutes);

// Script deployment routes
app.use('/api/scripts', scriptsRoutes);

// ============================================================
// Phase 5 Feature Routes
// ============================================================

// Service management routes
app.use('/api/services', servicesRoutes);

// Process management routes
app.use('/api/processes', processesRoutes);

// Password management routes
app.use('/api/passwords', passwordsRoutes);

// User management routes
app.use('/api/users', usersRoutes);

// State management routes
app.use('/api/states', statesRoutes);

// Playbook automation routes
app.use('/api/playbooks', playbooksRoutes);

// Emergency action routes
app.use('/api/emergency', emergencyRoutes);

// Network connection routes
app.use('/api/network', networkRoutes);

// File browser routes
app.use('/api/files', filesRoutes);

// Log viewer routes
app.use('/api/logs', logsRoutes);

// Suspicious items scanner routes
app.use('/api/suspicious', suspiciousRoutes);

// Reports routes
app.use('/api/reports', reportsRoutes);

// Forensics routes
app.use('/api/forensics', forensicsRoutes);

// Monitoring routes (scheduled checks with change detection)
app.use('/api/monitoring', monitoringRoutes);

// ============================================================
// Error Handling
// ============================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// SPA fallback - serve index.html for non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', err);

  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  });
});

// ============================================================
// Server Startup
// ============================================================

const PORT = config.server.port;
const HOST = config.server.host;

const server = app.listen(PORT, HOST, () => {
  console.log('');
  console.log('='.repeat(60));
  console.log('  Salt-GUI Server');
  console.log('='.repeat(60));
  console.log(`  Listening:     http://${HOST}:${PORT}`);
  console.log(`  Environment:   ${process.env.NODE_ENV || 'development'}`);
  console.log(`  Node.js:       ${process.version}`);
  console.log('='.repeat(60));

  // Status messages
  if (!hasUsers()) {
    console.log('');
    console.log('  [SETUP REQUIRED]');
    console.log('  No admin user configured. Visit the UI or POST to:');
    console.log(`  POST http://${HOST}:${PORT}/api/auth/setup`);
    console.log('  Body: {"username": "admin", "password": "yourpassword"}');
  }

  if (!configStatus.salt) {
    console.log('');
    console.log('  [CONFIG MISSING]');
    console.log('  Copy config/salt.yaml.example to config/salt.yaml');
    console.log('  Then configure your Salt API connection.');
  }

  console.log('');
  console.log('  API Endpoints Available:');
  console.log('    GET  /api/health           - System health check');
  console.log('    POST /api/auth/login       - User login');
  console.log('    POST /api/auth/logout      - User logout');
  console.log('    GET  /api/devices          - List minions');
  console.log('    POST /api/commands/run     - Execute commands');
  console.log('    GET  /api/scripts          - List scripts');
  console.log('    POST /api/scripts/run      - Execute scripts');
  console.log('    GET  /api/services/:target - List services');
  console.log('    POST /api/services/*       - Manage services');
  console.log('    GET  /api/processes/:target- List processes');
  console.log('    POST /api/processes/kill   - Kill processes');
  console.log('    POST /api/passwords/change - Change passwords');
  console.log('    POST /api/users/list       - List users');
  console.log('    POST /api/users/create     - Create user');
  console.log('    POST /api/users/disable    - Disable user');
  console.log('    POST /api/users/enable     - Enable user');
  console.log('    POST /api/users/sudo       - Manage sudo access');
  console.log('    POST /api/states/apply     - Apply Salt states');
  console.log('    GET  /api/playbooks        - List playbooks');
  console.log('    POST /api/playbooks/run    - Run playbook');
  console.log('    POST /api/emergency/*      - Emergency actions');
  console.log('    GET  /api/audit            - View audit log');
  console.log('');
  console.log('='.repeat(60));
  console.log('');
});

// Graceful shutdown
const shutdown = (signal) => {
  logger.info(`Received ${signal}, shutting down gracefully`);

  // Shut down monitoring scheduler
  try { require('./src/lib/scheduler').shutdown(); } catch {}

  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });

  // Force close after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Export for testing
module.exports = app;
