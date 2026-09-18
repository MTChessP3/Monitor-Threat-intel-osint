import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { reportUrlToService } from '@/lib/takedown/services';
import { generateTransactionId, sha256 } from '@/lib/takedown/hashGenerator';
import { defangUrl } from '@/lib/takedown/defang';

export const runtime = 'nodejs';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { url, services, notes, apiKeys, async: isAsync } = body;

    if (!url) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    const batchId = generateTransactionId();
    const timestamp = new Date().toISOString();
    const selectedServices = services || ['virustotal'];
    const selectedApiKeys = apiKeys || {};

    const fileHash = await sha256(url);
    const fingerprint = await sha256(`${batchId}-${url}-${timestamp}`);

    await db.takeDownBatch.create({
      data: {
        id: batchId,
        name: `Single: ${url.substring(0, 50)}`,
        status: 'processing',
        totalUrls: 1,
        processedUrls: 0,
        successfulUrls: 0,
        failedUrls: 0,
        userId: 'system',
        notes,
        fingerprint,
        fileHash,
        services: JSON.stringify(selectedServices),
      },
    });

    await db.takeDownReport.create({
      data: {
        id: generateTransactionId(),
        batchId,
        url: defangUrl(url),
        originalUrl: url,
        status: 'processing',
      },
    });

    if (!isAsync) {
      const results = await processUrlServices(url, selectedServices, selectedApiKeys, notes);
      const successCount = results.filter(r => r.status === 'success').length;
      const failedCount = results.filter(r => r.status === 'failed').length;
      const manualCount = results.filter(r => r.status === 'manual').length;

      await db.takeDownBatch.update({
        where: { id: batchId },
        data: {
          status: failedCount === selectedServices.length ? 'failed' : 'completed',
          processedUrls: 1,
          successfulUrls: successCount > 0 ? 1 : 0,
          failedUrls: failedCount > 0 ? 1 : 0,
          completedAt: new Date(),
        },
      });

      const reportHash = await sha256(JSON.stringify(results));

      return NextResponse.json({
        batchId,
        fingerprint,
        reportHash,
        status: 'completed',
        summary: { total: 1, success: successCount, failed: failedCount, manual: manualCount },
        results,
        timestamp,
      });
    }

    return NextResponse.json({
      batchId,
      fingerprint,
      status: 'queued',
      message: 'URL encolada para procesamiento asíncrono',
      timestamp,
    });
  } catch (error) {
    console.error('Single URL error:', error);
    return NextResponse.json({ error: 'Error processing URL' }, { status: 500 });
  }
}

async function processUrlServices(
  url: string,
  services: string[],
  apiKeys: Record<string, string>,
  notes?: string
): Promise<Array<{ service: string; serviceName: string; url: string; status: string; message: string; referenceId?: string }>> {
  const results = [];

  for (const service of services) {
    try {
      const result = await reportUrlToService(service, url, apiKeys, notes);
      results.push(result);

      await db.serviceResult.create({
        data: {
          batchId: '',
          reportId: undefined as unknown as string,
          service: result.service,
          serviceName: result.serviceName,
          url: result.url,
          status: result.status,
          message: result.message,
          referenceId: result.referenceId,
        },
      });
    } catch (error) {
      results.push({
        service,
        serviceName: service,
        url,
        status: 'failed',
        message: error instanceof Error ? error.message : 'Error desconocido',
      });
    }
  }

  if (services.includes('apwg') && notes) {
    console.log('APWG notification queued for batch:', batchId);
  }

  if (services.includes('cisa') && notes) {
    console.log('CISA notification queued for batch:', batchId);
  }

  return results;
}
