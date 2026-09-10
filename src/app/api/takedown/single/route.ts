import { NextResponse } from 'next/server';
import { createHash } from 'crypto';
import { PrismaClient } from '@prisma/client';
import { reportUrlToService, getEnabledServices, storeServiceResult, createAuditLog } from '@/lib/takedown/services';
import { addTakedownJob } from '@/lib/takedown/queue';

const prisma = new PrismaClient();

interface SingleUrlRequest {
  url: string;
  services?: string[];
  notes?: string;
  apiKeys?: Record<string, string>;
  async?: boolean;
}

interface ServiceReportResult {
  service: string;
  serviceName: string;
  url: string;
  status: 'success' | 'failed' | 'pending' | 'manual' | 'rate_limited';
  message: string;
  timestamp: string;
  referenceId?: string;
  requestPayload?: Record<string, unknown>;
  responsePayload?: Record<string, unknown>;
  errorDetails?: string;
}

function generateReportId(): string {
  return 'TD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
}

function generateFingerprint(data: string): string {
  return createHash('sha256').update(data).digest('hex').toUpperCase();
}

function validateUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export async function POST(request: Request) {
  try {
    const body: SingleUrlRequest = await request.json();
    const { url, services, notes, apiKeys, async = false } = body;

    if (!url) {
      return NextResponse.json({ error: 'URL es requerida' }, { status: 400 });
    }

    if (!validateUrl(url)) {
      return NextResponse.json({ error: 'URL inválida' }, { status: 400 });
    }

    const selectedServices = services && services.length > 0 ? services : getEnabledServices();
    const reportId = generateReportId();
    const timestamp = new Date().toISOString();
    const userId = 'system'; // TODO: Get from auth session

    const fingerprint = generateFingerprint(JSON.stringify({ reportId, url, services: selectedServices, timestamp, notes }));

    const batch = await prisma.takeDownBatch.create({
      data: {
        name: `Single URL - ${new Date().toLocaleString()}`,
        status: async ? 'processing' : 'completed',
        totalUrls: 1,
        userId,
        notes,
      },
    });

    const report = await prisma.takeDownReport.create({
      data: {
        batchId: batch.id,
        url,
        status: async ? 'processing' : 'pending',
        notes,
        fingerprint,
      },
    });

    await createAuditLog(userId, 'create_single_report', 'batch', batch.id, {
      url,
      services: selectedServices,
      reportId: report.id,
    });

    if (async) {
      await addTakedownJob({
        batchId: batch.id,
        reportId: report.id,
        url,
        services: selectedServices,
        notes,
        apiKeys,
        userId,
      });

      return NextResponse.json({
        reportId,
        batchId: batch.id,
        timestamp,
        url,
        services: selectedServices,
        status: 'queued',
        message: 'URL encolada para procesamiento asíncrono',
        fingerprint,
      });
    }

    const results: ServiceReportResult[] = [];

    for (const service of selectedServices) {
      try {
        const result = await reportUrlToService(service, url, apiKeys, notes);
        
        const serviceResult: ServiceReportResult = {
          service: result.service,
          serviceName: result.serviceName,
          url: result.url,
          status: result.status,
          message: result.message,
          timestamp: new Date().toISOString(),
          referenceId: result.referenceId,
          requestPayload: result.requestPayload,
          responsePayload: result.responsePayload,
          errorDetails: result.errorDetails,
        };

        results.push(serviceResult);
        
        await storeServiceResult(batch.id, report.id, result);
      } catch (error) {
        const errorResult: ServiceReportResult = {
          service,
          serviceName: service,
          url,
          status: 'failed',
          message: error instanceof Error ? error.message : 'Error desconocido',
          timestamp: new Date().toISOString(),
          errorDetails: error instanceof Error ? error.stack : String(error),
        };
        results.push(errorResult);
        
        await storeServiceResult(batch.id, report.id, errorResult);
      }
    }

    const successCount = results.filter(r => r.status === 'success').length;
    const failedCount = results.filter(r => r.status === 'failed').length;
    const manualCount = results.filter(r => r.status === 'manual').length;
    const pendingCount = results.filter(r => r.status === 'pending').length;

    await prisma.takeDownBatch.update({
      where: { id: batch.id },
      data: {
        status: failedCount === selectedServices.length ? 'failed' : 'completed',
        processedUrls: 1,
        successfulUrls: successCount > 0 ? 1 : 0,
        failedUrls: failedCount > 0 ? 1 : 0,
        completedAt: new Date(),
      },
    });

    await prisma.takeDownReport.update({
      where: { id: report.id },
      data: {
        status: failedCount === selectedServices.length ? 'failed' : 'completed',
        completedAt: new Date(),
      },
    });

    await createAuditLog(userId, 'single_report_complete', 'batch', batch.id, {
      reportId: report.id,
      url,
      total: results.length,
      success: successCount,
      failed: failedCount,
      manual: manualCount,
      pending: pendingCount,
    });

    return NextResponse.json({
      reportId,
      batchId: batch.id,
      timestamp,
      url,
      services: selectedServices,
      notes,
      results,
      fingerprint,
      summary: {
        total: results.length,
        success: successCount,
        failed: failedCount,
        pending: pendingCount,
        manual: manualCount,
      },
    });
  } catch (error: unknown) {
    console.error('Error processing single URL:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al procesar URL';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}