#!/bin/bash
# Keep-alive watchdog for VIP Protection Report server
# Restarts the server if it crashes

cd /home/z/my-project

while true; do
  # Check if server is responding
  if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null | grep -q "200"; then
    echo "[$(date)] Server not responding, killing old process..."
    pkill -f "node.*server.js" 2>/dev/null
    sleep 2
    echo "[$(date)] Starting server..."
    NODE_ENV=production nohup node .next/standalone/server.js > /dev/null 2>&1 &
    echo $! > server.pid
    sleep 5
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null | grep -q "200"; then
      echo "[$(date)] Server started successfully (PID: $(cat server.pid))"
    else
      echo "[$(date)] Server failed to start, will retry in 10s"
    fi
  fi
  sleep 10
done
