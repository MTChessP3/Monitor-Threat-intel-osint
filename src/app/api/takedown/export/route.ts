import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { generateHtmlReport } from '@/lib/takedown/reportGenerator';
import { sha256 } from '@/lib/takedown/hashGenerator';

export const runtime = 'edge';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { batchId, format } = body;

    const batch = await db.takeDownBatch.findUnique({
      where: { id: batchId },
      include: { reports: true, serviceResults: true },
    });

    if (!batch) {
      return NextResponse.json({ error: 'Batch not found' }, { status: 404 });
    }

    if (format === 'json') {
      return NextResponse.json({
        batchId: batch.id,
        name: batch.name,
        status: batch.status,
        totalUrls: batch.totalUrls,
        processedUrls: batch.processedUrls,
        successfulUrls: batch.successfulUrls,
        failedUrls: batch.failedUrls,
        fingerprint: batch.fingerprint,
        fileHash: batch.fileHash,
        services: batch.services,
        reports: batch.reports,
        serviceResults: batch.serviceResults,
      });
    }

    if (format === 'csv') {
      const csvContent = generateCsv(batch);
      return new NextResponse(csvContent, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="takedown-${batchId}.csv"`,
        },
      });
    }

    return NextResponse.json({ error: 'Unsupported format' }, { status: 400 });
  } catch (error) {
    console.error('Export error:', error);
    return NextResponse.json({ error: 'Export failed' }, { status: 500 });
  }
}

function generateCsv(batch: Record<string, unknown>): string {
  const headers = ['URL', 'Status', 'Service', 'Message', 'Reference ID', 'Timestamp'];
  const rows = (batch.reports as Array<Record<string, unknown>> || []).map(r => [
    r.url as string, r.status as string, r.service as string || '',
    r.message as string || '', r.referenceId as string || '',
    r.createdAt ? new Date(r.createdAt as string).toISOString() : '',
  ]);
  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

