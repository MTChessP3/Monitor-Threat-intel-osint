// Simple watchdog - restarts the server if it crashes
const { spawn } = require('child_process');
const http = require('http');

function checkServer() {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:3000/', (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(3000, () => { req.destroy(); resolve(false); });
  });
}

function startServer() {
  console.log(`[${new Date().toISOString()}] Starting server...`);
  const child = spawn('node', ['.next/standalone/server.js'], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: 'production' },
    detached: true,
    stdio: 'ignore'
  });
  child.unref();
  return child.pid;
}

async function main() {
  // Check if already running
  if (await checkServer()) {
    console.log('Server already running');
  } else {
    const pid = startServer();
    // Wait for server to be ready
    for (let i = 0; i < 15; i++) {
      await new Promise(r => setTimeout(r, 1000));
      if (await checkServer()) {
        console.log(`Server started (PID: ${pid})`);
        break;
      }
    }
  }

  // Watchdog loop
  setInterval(async () => {
    if (!(await checkServer())) {
      console.log(`[${new Date().toISOString()}] Server down, restarting...`);
      const pid = startServer();
      for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 1000));
        if (await checkServer()) {
          console.log(`[${new Date().toISOString()}] Server restarted (PID: ${pid})`);
          break;
        }
      }
    }
  }, 15000);
}

main();
