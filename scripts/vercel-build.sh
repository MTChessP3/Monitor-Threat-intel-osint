#!/bin/bash
# Build script for Vercel deployment
# Uses SQLite for local dev and libSQL/Turso for production

set -e

echo "🔧 Preparing Prisma for Vercel serverless..."

# Generate Prisma client
npx prisma generate

# Build Next.js
npx next build

echo "✅ Build complete!"
