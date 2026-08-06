import { PrismaClient } from '@prisma/client'
import { PrismaLibSQL } from '@prisma/adapter-libsql'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
  dbInitialized?: boolean;
}

/**
 * Create a Prisma client that works on both local dev (SQLite) and Vercel (libSQL/Turso)
 */
function createPrismaClient(): PrismaClient {
  const databaseUrl = process.env.DATABASE_URL || 'file:./db/custom.db';

  // On Vercel serverless, check if we have a Turso/libSQL URL
  const tursoUrl = process.env.TURSO_DATABASE_URL;
  const tursoAuth = process.env.TURSO_AUTH_TOKEN;

  if (tursoUrl) {
    // Use Turso/libSQL (SQLite-compatible cloud database that works on Vercel)
    console.log('[DB] Using Turso/libSQL adapter');
    const adapter = new PrismaLibSQL({
      url: tursoUrl,
      authToken: tursoAuth || undefined,
    });
    return new PrismaClient({ adapter } as any);
  }

  // On Vercel without Turso, use SQLite with /tmp path
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    console.log('[DB] Using SQLite with /tmp path on Vercel');
    return new PrismaClient({
      datasources: {
        db: {
          url: 'file:/tmp/vip-intelligence.db',
        },
      },
      log: [],
    });
  }

  // Local development - use regular SQLite
  console.log('[DB] Using local SQLite');
  return new PrismaClient({
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
    log: ['query'],
  });
}

export const db = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db;

// Ensure the database is initialized with schema and seed data.
// On Vercel serverless, /tmp is ephemeral so we need to create
// the schema on every cold start. The flag is stored on globalThis so
// all route bundles in the same instance only initialize once.
export async function ensureDatabaseInitialized(): Promise<void> {
  if (globalForPrisma.dbInitialized) return;

  // On Vercel serverless, ensure the schema exists.
  // - With Turso (persistent): create tables via raw SQL (idempotent).
  // - Without Turso (/tmp ephemeral SQLite): push schema, fallback to raw SQL.
  if (process.env.TURSO_DATABASE_URL) {
    try {
      console.log('[DB] Creating tables on Turso/libSQL...');
      await createTablesManually();
    } catch (error) {
      console.error('[DB] Manual table creation on Turso failed:', error instanceof Error ? error.message.substring(0, 300) : String(error).substring(0, 300));
    }
  } else if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    try {
      // Push the schema to create tables if they don't exist
      const { execSync } = await import('child_process');
      console.log('[DB] Pushing schema to SQLite database on Vercel...');
      execSync('npx prisma db push --skip-generate --accept-data-loss', {
        env: {
          ...process.env,
          DATABASE_URL: 'file:/tmp/vip-intelligence.db',
        },
        stdio: 'pipe',
        timeout: 30000,
      });
      console.log('[DB] Schema pushed successfully');
    } catch (error) {
      console.error('[DB] Schema push error:', error instanceof Error ? error.message.substring(0, 300) : String(error).substring(0, 300));
      // Fallback: create tables manually using raw SQL
      try {
        await createTablesManually();
      } catch (e2) {
        console.error('[DB] Manual table creation also failed:', e2 instanceof Error ? e2.message.substring(0, 300) : String(e2).substring(0, 300));
      }
    }
  }

  // Seed data if needed
  try {
    const userCount = await db.user.count();
    if (userCount === 0) {
      console.log('[DB] Seeding database with default admin user...');
      const { hashPassword } = await import('./auth');
      const hashedPassword = await hashPassword('Admin123!');

      await db.user.create({
        data: {
          name: 'Administrador',
          email: 'admin@vipintelligence.com',
          password: hashedPassword,
          role: 'admin',
        },
      });

      await db.reportTemplate.create({
        data: {
          id: 'default-template-vip',
          name: 'Plantilla Predeterminada - Informe VIP',
          content: '# INFORME EJECUTIVO DE PROTECCION VIP\n\n## Resumen Ejecutivo\n\n## Amenazas Detectadas\n\n## Recomendaciones',
          isDefault: true,
        },
      });

      console.log('[DB] Database seeded with admin user');
    }
  } catch (error) {
    console.error('[DB] Error seeding database:', error instanceof Error ? error.message.substring(0, 300) : String(error).substring(0, 300));
  }

  globalForPrisma.dbInitialized = true;
}

/**
 * Fallback: Create tables manually using raw SQL if prisma db push fails
 */
async function createTablesManually(): Promise<void> {
  console.log('[DB] Creating tables manually with raw SQL...');

  // User table
  await db.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "User" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "name" TEXT NOT NULL,
      "email" TEXT NOT NULL UNIQUE,
      "password" TEXT NOT NULL,
      "role" TEXT NOT NULL DEFAULT 'analyst',
      "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
      "mfaSecret" TEXT,
      "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Executive table
  await db.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "Executive" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "identificationNum" TEXT NOT NULL UNIQUE,
      "fullName" TEXT NOT NULL,
      "email" TEXT,
      "phone" TEXT,
      "position" TEXT,
      "organization" TEXT,
      "riskLevel" TEXT NOT NULL DEFAULT 'bajo',
      "notes" TEXT,
      "lastMetasearch" DATETIME,
      "lastMetasearchResults" TEXT NOT NULL DEFAULT '[]',
      "active" BOOLEAN NOT NULL DEFAULT true,
      "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // ReportTemplate table
  await db.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "ReportTemplate" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "name" TEXT NOT NULL,
      "content" TEXT NOT NULL,
      "isDefault" BOOLEAN NOT NULL DEFAULT false,
      "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Report table
  await db.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "Report" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "title" TEXT NOT NULL,
      "date" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "summary" TEXT NOT NULL,
      "threatLevel" TEXT NOT NULL DEFAULT 'bajo',
      "content" TEXT NOT NULL,
      "templateId" TEXT,
      "sourcesUsed" TEXT NOT NULL DEFAULT '[]',
      "generationMode" TEXT NOT NULL DEFAULT 'automatic',
      "abuseTypes" TEXT NOT NULL DEFAULT '[]',
      "severity" TEXT NOT NULL DEFAULT 'medio',
      "tlpLevel" TEXT NOT NULL DEFAULT 'GREEN',
      "inputUrls" TEXT NOT NULL DEFAULT '[]',
      "inputText" TEXT NOT NULL DEFAULT '',
      "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // NewsSource table
  await db.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "NewsSource" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "name" TEXT NOT NULL,
      "url" TEXT NOT NULL,
      "type" TEXT NOT NULL DEFAULT 'web',
      "category" TEXT NOT NULL DEFAULT 'seguridad',
      "active" BOOLEAN NOT NULL DEFAULT true,
      "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log('[DB] All tables created manually');
}
