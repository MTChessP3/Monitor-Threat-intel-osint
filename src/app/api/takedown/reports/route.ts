import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export const runtime = 'nodejs';

export async function GET(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const { searchParams } = new URL(request.url);
    const batchId = searchParams.get('batchId');

    const where: Record<string, unknown> = {};
    if (batchId) where.batchId = batchId;

    const results = await db.serviceResult.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      include: { batch: { select: { name: true } } },
    });

    return NextResponse.json(results);
  } catch (error) {
    return NextResponse.json({ error: 'Error fetching service results' }, { status: 500 });
  }
}
