#!/bin/bash
set -e

echo "🔧 Preparing Prisma for Vercel serverless..."

# Generate Prisma client
npx prisma generate

# Build Next.js
npx next build

echo "✅ Build complete!"