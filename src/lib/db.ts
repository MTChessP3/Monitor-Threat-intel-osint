import { PrismaClient } from '@prisma/client'
import { PrismaLibSQL } from '@prisma/adapter-libsql'
import { createClient } from '@libsql/client'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
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
    const libsql = createClient({
      url: tursoUrl,
      authToken: tursoAuth || undefined,
    });
    const adapter = new PrismaLibSQL(libsql);
    return new PrismaClient({ adapter } as any);
  }

  // On Vercel without Turso, try SQLite with /tmp path
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

/**
 * Ensure the database is initialized with seed data on cold starts.
 * This is needed on Vercel serverless where /tmp is ephemeral.
 */
export async function ensureDatabaseInitialized(): Promise<void> {
  // Only on Vercel serverless (not with Turso which is persistent)
  if (!process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_NAME) return;
  if (process.env.TURSO_DATABASE_URL) return; // Turso is persistent, no need to re-seed

  try {
    const userCount = await db.user.count();
    if (userCount === 0) {
      console.log('[DB] Initializing fresh database with seed data...');
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
          content: '# INFORME EJECUTIVO DE PROTECCIÓN VIP\n\n## Resumen Ejecutivo\n\n## Amenazas Detectadas\n\n## Recomendaciones',
          isDefault: true,
        },
      });

      console.log('[DB] Database initialized with admin user');
    }
  } catch (error) {
    console.error('[DB] Error initializing database:', error);
    // Don't throw - allow the app to continue even if init fails
  }
}
