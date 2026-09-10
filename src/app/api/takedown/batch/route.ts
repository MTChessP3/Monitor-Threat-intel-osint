import { NextResponse } from 'next/server';
import * as XLSX from 'xlsx';
import { parse } from 'csv-parse/sync';
import { createHash } from 'crypto';
import { PrismaClient } from '@prisma/client';
import { getEnabledServices, createAuditLog } from '@/lib/takedown/services';
import { addBatchProcessJob } from '@/lib/takedown/queue';

const prisma = new PrismaClient();

const URL_REGEX = /(?:https?:\/\/)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?/gi;

function extractUrlsFromText(text: string): string[] {
  const urls = text.match(URL_REGEX) || [];
  const normalized = urls.map(u => {
    if (!u.startsWith('http://') && !u.startsWith('https://')) {
      return 'https://' + u;
    }
    return u;
  });
  return [...new Set(normalized)];
}

function parseTxt(content: string): string[] {
  return extractUrlsFromText(content);
}

function parseCsv(content: string): string[] {
  try {
    const records = parse(content, {
      columns: false,
      skip_empty_lines: true,
      trim: true,
    });
    const allText = records.flat().join(' ');
    return extractUrlsFromText(allText);
  } catch {
    return extractUrlsFromText(content);
  }
}

function parseXlsx(buffer: Buffer): string[] {
  try {
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    let allText = '';
    for (const sheetName of workbook.SheetNames) {
      const sheet = workbook.Sheets[sheetName];
      const json = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
      for (const row of json as string[][]) {
        allText += row.join(' ') + ' ';
      }
    }
    return extractUrlsFromText(allText);
  } catch {
    return [];
  }
}

function validateUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

function generateBatchId(): string {
  return 'BATCH-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
}

function generateFingerprint(data: string): string {
  return createHash('sha256').update(data).digest('hex').toUpperCase();
}

interface BatchProcessRequest {
  file?: File;
  urls?: string[];
  services?: string[];
  notes?: string;
  apiKeys?: Record<string, string>;
  batchName?: string;
  maxUrlsPerBatch?: number;
}

export async function POST(request: Request) {
  try {
    const contentType = request.headers.get('content-type') || '';
    
    let file: File | null = null;
    let urls: string[] = [];
    let services: string[] = [];
    let notes = '';
    let apiKeys: Record<string, string> = {};
    let batchName = '';
    let maxUrlsPerBatch = 500;

    if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData();
      file = formData.get('file') as File;
      services = JSON.parse(formData.get('services') as string || '[]');
      notes = formData.get('notes') as string || '';
      apiKeys = JSON.parse(formData.get('apiKeys') as string || '{}');
      batchName = formData.get('batchName') as string || '';
      maxUrlsPerBatch = parseInt(formData.get('maxUrlsPerBatch') as string || '500');
    } else {
      const body: BatchProcessRequest = await request.json();
      urls = body.urls || [];
      services = body.services || [];
      notes = body.notes || '';
      apiKeys = body.apiKeys || {};
      batchName = body.batchName || '';
      maxUrlsPerBatch = body.maxUrlsPerBatch || 500;
    }

    let extractedUrls: string[] = [];

    if (file) {
      const validExtensions = ['.txt', '.csv', '.xlsx'];
      const ext = '.' + file.name.split('.').pop()?.toLowerCase();
      
      if (!validExtensions.includes(ext)) {
        return NextResponse.json(
          { error: 'Formato no soportado. Use .txt, .csv o .xlsx' },
          { status: 400 }
        );
      }

      const arrayBuffer = await file.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);

      switch (ext) {
        case '.txt':
          extractedUrls = parseTxt(buffer.toString('utf-8'));
          break;
        case '.csv':
          extractedUrls = parseCsv(buffer.toString('utf-8'));
          break;
        case '.xlsx':
          extractedUrls = parseXlsx(buffer);
          break;
      }
    } else if (urls.length > 0) {
      extractedUrls = urls;
    } else {
      return NextResponse.json({ error: 'No se proporcionaron URLs ni archivo' }, { status: 400 });
    }

    const validUrls = extractedUrls
      .filter(validateUrl)
      .slice(0, maxUrlsPerBatch);

    if (validUrls.length === 0) {
      return NextResponse.json({ error: 'No se encontraron URLs válidas' }, { status: 400 });
    }

    const selectedServices = services.length > 0 ? services : getEnabledServices();
    const batchId = generateBatchId();
    const timestamp = new Date().toISOString();
    const userId = 'system'; // TODO: Get from auth session

    const batch = await prisma.takeDownBatch.create({
      data: {
        name: batchName || `${file?.name || 'Manual'} - ${new Date().toLocaleString()}`,
        status: 'pending',
        totalUrls: validUrls.length,
        userId,
        notes,
      },
    });

    const reports = await Promise.all(
      validUrls.map(url => 
        prisma.takeDownReport.create({
          data: {
            batchId: batch.id,
            url,
            status: 'pending',
            notes,
            fingerprint: generateFingerprint(JSON.stringify({ batchId: batch.id, url, services: selectedServices, timestamp })),
          },
        })
      )
    );

    await createAuditLog(userId, 'create_batch', 'batch', batch.id, {
      fileName: file?.name,
      totalUrls: validUrls.length,
      services: selectedServices,
      reportCount: reports.length,
    });

    await addBatchProcessJob({
      batchId: batch.id,
      userId,
    });

    return NextResponse.json({
      batchId: batch.id,
      batchName: batch.name,
      timestamp,
      fileName: file?.name,
      totalUrlsSubmitted: validUrls.length,
      validUrls,
      services: selectedServices,
      notes,
      status: 'queued',
      message: `${validUrls.length} URLs encoladas para procesamiento en ${selectedServices.length} servicios`,
      estimatedTime: `${Math.ceil(validUrls.length * selectedServices.length * 2 / 60)} minutos`,
    });
  } catch (error: unknown) {
    console.error('Error processing batch:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al procesar lote';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const batchId = searchParams.get('batchId');
    const status = searchParams.get('status');
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '20');

    if (batchId) {
      const batch = await prisma.takeDownBatch.findUnique({
        where: { id: batchId },
        include: {
          reports: {
            include: {
              serviceResults: {
                orderBy: { createdAt: 'asc' },
              },
            },
            orderBy: { createdAt: 'asc' },
          },
          serviceResults: {
            orderBy: { createdAt: 'asc' },
          },
        },
      });

      if (!batch) {
        return NextResponse.json({ error: 'Batch no encontrado' }, { status: 404 });
      }

      return NextResponse.json(batch);
    }

    const where: Record<string, unknown> = {};
    if (status) where.status = status;

    const [batches, total] = await Promise.all([
      prisma.takeDownBatch.findMany({
        where,
        include: {
          _count: {
            select: { reports: true, serviceResults: true },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.takeDownBatch.count({ where }),
    ]);

    return NextResponse.json({
      batches,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error: unknown) {
    console.error('Error fetching batches:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al obtener lotes';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}