#!/bin/bash
# Start and keep the VIP Protection server alive
cd /home/z/my-project

# Kill any existing server
pkill -f "node.*server.js" 2>/dev/null
sleep 2

# Function to start server
start_server() {
  echo "[$(date)] Starting server..."
  NODE_ENV=production node .next/standalone/server.js 2>&1 | tee -a server.log
  echo "[$(date)] Server exited with code $?"
}

# Start with auto-restart
while true; do
  start_server
  echo "[$(date)] Restarting in 3 seconds..."
  sleep 3
done
