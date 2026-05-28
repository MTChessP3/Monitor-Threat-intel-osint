const { spawn } = require('child_process');
const fs = require('fs');

function startServer() {
  console.log('[Watchdog] Starting server at', new Date().toISOString());
  
  const child = spawn('node', ['.next/standalone/server.js'], {
    cwd: '/home/z/my-project',
    env: { ...process.env, PORT: '3000', HOSTNAME: '0.0.0.0' },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const logStream = fs.createWriteStream('/home/z/my-project/server.log', { flags: 'a' });
  child.stdout.pipe(logStream);
  child.stderr.pipe(logStream);
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);

  child.on('exit', (code, signal) => {
    console.log('[Watchdog] Server exited with code', code, 'signal', signal);
    console.log('[Watchdog] Restarting in 3 seconds...');
    setTimeout(startServer, 3000);
  });

  // Save PID
  fs.writeFileSync('/home/z/my-project/server.pid', child.pid.toString());
  console.log('[Watchdog] Server PID:', child.pid);
}

startServer();
