#!/bin/bash
# Build script for Vercel deployment
# Uses SQLite with a writable /tmp path for Vercel serverless

set -e

echo "🔧 Preparing Prisma for Vercel serverless..."

# Generate Prisma client
npx prisma generate

# Build Next.js
next build

echo "✅ Build complete!"
