#!/bin/bash
# VIP Protection Report - Server launcher with auto-restart
cd /home/z/my-project

# Kill any existing server
pkill -f "node.*standalone/server.js" 2>/dev/null
sleep 2

# Start server
NODE_ENV=production node .next/standalone/server.js &

# Wait for it to be ready
for i in $(seq 1 10); do
  if curl -s -o /dev/null http://127.0.0.1:3000/ 2>/dev/null; then
    echo "Server ready on port 3000 (PID: $!)"
    exit 0
  fi
  sleep 1
done

echo "Server failed to start"
exit 1
