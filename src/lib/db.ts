import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

// On Vercel serverless, use /tmp for the SQLite database
// since it's the only writable directory
function getDatabaseUrl(): string {
  if (process.env.DATABASE_URL) {
    // If running on Vercel with a non-file URL, return as-is
    if (!process.env.DATABASE_URL.startsWith('file:')) {
      return process.env.DATABASE_URL;
    }
    // On Vercel production, remap file: paths to /tmp
    if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
      const originalPath = process.env.DATABASE_URL.replace('file:', '');
      // Use /tmp for the database on Vercel serverless
      return 'file:/tmp/vip-intelligence.db';
    }
  }
  return process.env.DATABASE_URL || 'file:./db/custom.db';
}

const databaseUrl = getDatabaseUrl();

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
    log: process.env.NODE_ENV === 'development' ? ['query'] : [],
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db

// Ensure database is initialized on Vercel serverless cold starts
export async function ensureDatabaseInitialized(): Promise<void> {
  // Only on Vercel serverless
  if (!process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_NAME) return;

  try {
    // Check if database has users (if not, it's a fresh cold start)
    const userCount = await db.user.count();
    if (userCount === 0) {
      console.log('[DB] Initializing fresh database with seed data...');
      // Import and run seed
      const { hashPassword } = await import('./auth');
      const hashedPassword = await hashPassword('Admin123!');

      // Create default admin user
      await db.user.create({
        data: {
          name: 'Administrador',
          email: 'admin@vipintelligence.com',
          password: hashedPassword,
          role: 'admin',
        },
      });

      // Create default report template
      await db.reportTemplate.create({
        data: {
          id: 'default-template-vip',
          name: 'Plantilla Predeterminada - Informe VIP',
          content: '# INFORME EJECUTIVO DE PROTECCIÓN VIP\n\n## Resumen Ejecutivo\n\n## Amenazas Detectadas\n\n## Recomendaciones',
          isDefault: true,
        },
      });

      console.log('[DB] Database initialized with admin user and template');
    }
  } catch (error) {
    console.error('[DB] Error initializing database:', error);
  }
}
