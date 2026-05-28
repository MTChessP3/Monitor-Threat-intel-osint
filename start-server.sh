#!/bin/bash
cd /home/z/my-project
while true; do
  echo "Starting server at $(date)" >> server-watchdog.log
  node .next/standalone/server.js >> server.log 2>&1
  EXIT_CODE=$?
  echo "Server exited with code $EXIT_CODE at $(date)" >> server-watchdog.log
  sleep 2
done
