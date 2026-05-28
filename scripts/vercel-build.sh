#!/bin/bash
# Build script for Vercel deployment
# Switches Prisma to PostgreSQL provider before building

set -e

echo "🔧 Switching Prisma schema to PostgreSQL for Vercel..."

# Replace SQLite with PostgreSQL in schema.prisma
sed -i 's/provider = "sqlite"/provider = "postgresql"/' prisma/schema.prisma
sed -i 's/url      = env("DATABASE_URL")/url       = env("POSTGRES_PRISMA_URL")\n  directUrl = env("POSTGRES_URL_NON_POOLING")/' prisma/schema.prisma

echo "✅ Schema switched to PostgreSQL"

# Generate Prisma client
npx prisma generate

# Deploy migrations
npx prisma migrate deploy

# Build Next.js
next build

echo "✅ Build complete!"
