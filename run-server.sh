#!/bin/bash
cd /home/z/my-project
# Kill existing server
pkill -f "next-server" 2>/dev/null
pkill -f "standalone/server" 2>/dev/null
sleep 2

# Start production server
NODE_ENV=production node .next/standalone/server.js -p 3000 -H 0.0.0.0 >> /home/z/my-project/server.log 2>&1 &
echo $! > /home/z/my-project/server.pid
echo "Server started with PID $(cat /home/z/my-project/server.pid)"
sleep 3

# Verify
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/ | grep -q "200"; then
  echo "Server is running and responding"
else
  echo "WARNING: Server may not be responding"
fi
