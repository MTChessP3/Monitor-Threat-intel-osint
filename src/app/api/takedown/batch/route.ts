import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { generateTransactionId, sha256File, computeBatchHash } from '@/lib/takedown/hashGenerator';
import { virustotalPreCheckBatch } from '@/lib/takedown/virustotal';
import { extractUrlsFromText, normalizeUrl, isValidUrl } from '@/lib/takedown/defang';

export const runtime = 'edge';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { urls, services, notes, batchName, virustotalApiKey, maxUrlsPerBatch } = body;

    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return NextResponse.json({ error: 'No URLs provided' }, { status: 400 });
    }

    const normalizedUrls = urls
      .map(normalizeUrl)
      .filter(isValidUrl)
      .slice(0, maxUrlsPerBatch || 500);

    const invalidUrls = urls.filter(u => !isValidUrl(normalizeUrl(u)));
    const batchId = generateTransactionId();
    const timestamp = new Date().toISOString();
    const selectedServices = services || [
      'google', 'microsoft', 'netcraft', 'eset', 'phishfort',
      'phishreport', 'easydmarc', 'norton', 'fortinet', 'mcafee',
      'crdf', 'phishtank', 'antiphishing_ch', 'virustotal', 'apwg', 'cisa'
    ];

    const fileHash = sha256File(Buffer.from(normalizedUrls.join('\n')));
    const { batchHash } = computeBatchHash(Buffer.from(normalizedUrls.join('\n')), normalizedUrls, selectedServices);
    const fingerprint = sha256File(Buffer.from(`${batchId}-${batchHash}-${timestamp}`));

    let virustotalResults = [];
    if (virustotalApiKey && normalizedUrls.length > 0) {
      try {
        virustotalResults = await virustotalPreCheckBatch(normalizedUrls, virustotalApiKey);
      } catch {
        virustotalResults = normalizedUrls.map(url => ({ url, classification: 'NO_RECORD', maliciousEngines: 0 }));
      }
    }

    const batchData: Record<string, unknown> = {
      id: batchId,
      name: batchName || `Batch ${batchId.substring(0, 8)}`,
      status: 'queued',
      totalUrls: normalizedUrls.length,
      processedUrls: 0,
      successfulUrls: 0,
      failedUrls: 0,
      userId: 'system',
      notes,
      fingerprint,
      fileHash,
      services: JSON.stringify(selectedServices),
      virustotalResults: JSON.stringify(virustotalResults),
    };

    await db.takeDownBatch.create({ data: batchData });

    const reportPromises = normalizedUrls.map(url =>
      db.takeDownReport.create({
        data: {
          id: generateTransactionId(),
          batchId,
          url: defangUrl(url),
          originalUrl: url,
          status: 'pending',
          virustotalClassification: virustotalResults.find(v => v.url === url)?.classification,
          virustotalMaliciousEngines: virustotalResults.find(v => v.url === url)?.maliciousEngines || 0,
        },
      })
    );
    await Promise.all(reportPromises);

    return NextResponse.json({
      batchId,
      fingerprint,
      totalUrlsSubmitted: normalizedUrls.length,
      validUrls: normalizedUrls.length,
      invalidUrls,
      fileHash,
      virustotalPreCheck: virustotalResults,
      timestamp,
      status: 'queued',
    });
  } catch (error) {
    console.error('Batch error:', error);
    return NextResponse.json({ error: 'Error creating batch' }, { status: 500 });
  }
}

export async function GET(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '20');
    const batchId = searchParams.get('batchId');
    const status = searchParams.get('status');

    const where: Record<string, unknown> = {};
    if (batchId) where.id = batchId;
    if (status) where.status = status;

    const [batches, total] = await Promise.all([
      db.takeDownBatch.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: (page - 1) * limit,
        include: {
          reports: { select: { id: true, url: true, status: true } },
          _count: { select: { reports: true } },
        },
      }),
      db.takeDownBatch.count({ where }),
    ]);

    return NextResponse.json({
      batches,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  } catch (error) {
    return NextResponse.json({ error: 'Error fetching batches' }, { status: 500 });
  }
}

function defangUrl(url: string): string {
  return url.replace(/^https?:\/\//i, 'hxxps://').replace(/\./g, '[.]');
}
