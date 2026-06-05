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

# Push schema to database (only if DB vars are available)
# Using db push instead of migrate deploy to handle schema changes
# without requiring compatible migration files
if [ -n "$POSTGRES_PRISMA_URL" ] && [ -n "$POSTGRES_URL_NON_POOLING" ]; then
  echo "📦 Pushing schema to PostgreSQL database..."
  npx prisma db push --accept-data-loss 2>/dev/null || echo "⚠️ DB push failed, continuing build..."
else
  echo "⚠️ Database environment variables not set, skipping schema push"
fi

# Build Next.js
next build

echo "✅ Build complete!"
