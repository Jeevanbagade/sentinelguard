const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 4000;

// Alerts file
const DATA_DIR = path.join(__dirname, 'data');
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');

// ✅ Ensure alerts file exists and is valid JSON array
function initAlertsFile() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (!fs.existsSync(ALERTS_FILE)) {
      fs.writeFileSync(ALERTS_FILE, '[]', 'utf8');
      return;
    }

    // Validate existing file is a JSON array
    const content = fs.readFileSync(ALERTS_FILE, 'utf8');
    const parsed = JSON.parse(content);
    if (!Array.isArray(parsed)) {
      console.warn('alerts.json is not an array. Reinitializing to empty array.');
      fs.writeFileSync(ALERTS_FILE, '[]', 'utf8');
    }
  } catch (err) {
    console.error('Failed to initialize alerts file:', err.message);
    // As a fallback, try to reset it
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(ALERTS_FILE, '[]', 'utf8');
    } catch (innerErr) {
      console.error('Failed to recover alerts file:', innerErr.message);
    }
  }
}

// ✅ Safe read/write helpers
function readAlertsSafe() {
  try {
    const data = fs.readFileSync(ALERTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Read alerts failed:', err.message);
    return [];
  }
}

function writeAlertsSafe(alerts) {
  try {
    fs.writeFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2));
    return true;
  } catch (err) {
    console.error('Write alerts failed:', err.message);
    return false;
  }
}

// ✅ Rate limit system with IP hashing and cleanup
const rateLimitMap = {};
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 20;

// Hash IP for privacy
function hashIp(ip) {
  return crypto.createHash('sha256').update(ip).digest('hex');
}

// Cleanup old entries to prevent memory leak
function cleanupRateLimitMap(now) {
  for (const key of Object.keys(rateLimitMap)) {
    const entry = rateLimitMap[key];
    if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
      delete rateLimitMap[key];
    }
  }
}

// ✅ Rate‑limit middleware
function rateLimiter(req, res, next) {
  const rawIp = req.ip;
  const ip = hashIp(rawIp);
  const now = Date.now();

  // Cleanup old entries on each request
  cleanupRateLimitMap(now);

  if (!rateLimitMap[ip]) {
    rateLimitMap[ip] = { count: 1, start: now };
    return next();
  }

  const entry = rateLimitMap[ip];

  if (now - entry.start > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap[ip] = { count: 1, start: now };
    return next();
  }

  if (entry.count >= MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({
      error: 'Too many requests. Please slow down.'
    });
  }

  entry.count++;
  next();
}

// ✅ Initialize alerts file on startup
initAlertsFile();

// Parse JSON bodies
app.use(express.json());

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// Health endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'SentinelGuard' });
});

// ✅ Save alert (with rate limiter)
app.post('/api/alert', rateLimiter, (req, res) => {
  const allowedSeverities = ['LOW', 'MEDIUM', 'HIGH'];
  const alert = req.body;

  if (
    typeof alert.type !== 'string' ||
    typeof alert.message !== 'string' ||
    !allowedSeverities.includes(alert.severity)
  ) {
    return res.status(400).json({
      error: 'Invalid alert format or severity'
    });
  }

  alert.time = new Date().toISOString();

  const existing = readAlertsSafe();
  existing.push(alert);

  const success = writeAlertsSafe(existing);
  if (!success) {
    return res.status(500).json({ error: 'Failed to save alert' });
  }

  res.json({ status: 'alert saved' });
});

// ✅ Get all alerts (safe)
app.get('/api/alerts', (req, res) => {
  const alerts = readAlertsSafe();
  res.json(alerts);
});

// SPA fallback (Express 5 safe)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`Backend + static frontend running at http://localhost:${port}`);
});
