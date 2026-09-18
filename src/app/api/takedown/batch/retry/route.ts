import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';

export const runtime = 'edge';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { batchId } = body;

    if (!batchId) {
      return NextResponse.json({ error: 'batchId is required' }, { status: 400 });
    }

    await db.takeDownBatch.update({
      where: { id: batchId },
      data: { status: 'queued', processedUrls: 0, successfulUrls: 0, failedUrls: 0 },
    });

    await db.serviceResult.deleteMany({
      where: { batchId },
    });

    return NextResponse.json({
      success: true,
      message: `Batch ${batchId} retry queued`,
      batchId,
    });
  } catch (error) {
    return NextResponse.json({ error: 'Retry failed' }, { status: 500 });
  }
}
