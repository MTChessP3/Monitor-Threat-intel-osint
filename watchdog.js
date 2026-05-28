/**
 * Process watchdog - keeps Next.js server running.
 * If the server dies, restarts it automatically.
 */
const { spawn } = require('child_process');
const http = require('http');

const PORT = 3000;
const CHECK_INTERVAL = 5000; // Check every 5 seconds
const MAX_RESTARTS = 10;
let restartCount = 0;
let serverProcess = null;

function startServer() {
  console.log(`[Watchdog] Starting Next.js server (attempt ${restartCount + 1})...`);

  serverProcess = spawn('npx', ['next', 'start', '-p', '3000', '-H', '0.0.0.0'], {
    cwd: '/home/z/my-project',
    stdio: 'pipe',
    detached: false,
  });

  serverProcess.stdout?.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) console.log(`[Next.js] ${msg}`);
  });

  serverProcess.stderr?.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) console.error(`[Next.js] ${msg}`);
  });

  serverProcess.on('exit', (code) => {
    console.log(`[Watchdog] Server exited with code ${code}`);
    serverProcess = null;
  });
}

function checkServer() {
  const req = http.request({
    hostname: '127.0.0.1',
    port: PORT,
    path: '/',
    method: 'GET',
    timeout: 5000,
  }, (res) => {
    if (res.statusCode === 200) {
      // Server is healthy
      restartCount = 0; // Reset on successful check
    } else {
      console.log(`[Watchdog] Server returned ${res.statusCode}`);
    }
    res.resume();
  });

  req.on('error', () => {
    // Server is down
    if (!serverProcess && restartCount < MAX_RESTARTS) {
      restartCount++;
      console.log(`[Watchdog] Server is down, restarting...`);
      startServer();
    } else if (restartCount >= MAX_RESTARTS) {
      console.error(`[Watchdog] Max restarts reached. Giving up.`);
    }
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.end();
}

// Initial start
startServer();

// Check periodically
setInterval(checkServer, CHECK_INTERVAL);

console.log('[Watchdog] Started. Monitoring server on port ' + PORT);
