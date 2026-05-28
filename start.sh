#!/bin/bash
# Start script for VIP Protection Report
# Starts both backend AI server and Next.js frontend

cd /home/z/my-project

# Kill any existing processes
pkill -f "node backend-server.js" 2>/dev/null
pkill -f "next dev" 2>/dev/null
pkill -f "next start" 2>/dev/null
sleep 2

# Start backend AI server on port 3001
nohup node backend-server.js > backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# Wait for backend to be ready
for i in {1..10}; do
  if curl -s http://127.0.0.1:3001/health > /dev/null 2>&1; then
    echo "Backend is ready"
    break
  fi
  sleep 1
done

# Start Next.js dev server on port 3000
nohup npx next dev -p 3000 -H 0.0.0.0 > dev.log 2>&1 &
NEXT_PID=$!
echo "Next.js PID: $NEXT_PID"

# Wait for Next.js to be ready
for i in {1..15}; do
  if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/ 2>/dev/null | grep -q "200"; then
    echo "Next.js is ready"
    break
  fi
  sleep 1
done

echo "Both servers started"
echo "Backend: http://127.0.0.1:3001"
echo "Frontend: http://127.0.0.1:3000"
