import { NextResponse } from 'next/server';
import { parseFile } from '@/lib/takedown/fileParser';
import { generateTransactionId, sha256File, computeBatchHash } from '@/lib/takedown/hashGenerator';
import { virustotalPreCheckBatch } from '@/lib/takedown/virustotal';

export const runtime = 'edge';

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File | null;
    const services = formData.get('services') ? JSON.parse(formData.get('services') as string) : null;
    const notes = (formData.get('notes') as string) || '';
    const batchName = (formData.get('batchName') as string) || '';
    const maxUrlsPerBatch = parseInt(formData.get('maxUrlsPerBatch') as string) || 500;
    const virustotalApiKey = (formData.get('virustotalApiKey') as string) || process.env.VIRUSTOTAL_API_KEY || '';

    if (!file) {
      return NextResponse.json({ error: 'No file uploaded' }, { status: 400 });
    }

    const buffer = Buffer.from(await file.arrayBuffer());
    const fileHash = sha256File(buffer);

    let parseResult;
    try {
      parseResult = await parseFile(buffer, file.name);
    } catch (error) {
      return NextResponse.json({
        error: error instanceof Error ? error.message : 'Error parsing file',
      }, { status: 400 });
    }

    const { validUrls, invalidUrls } = parseResult;
    const urlsToProcess = validUrls.slice(0, maxUrlsPerBatch);

    const batchId = generateTransactionId();
    const timestamp = new Date().toISOString();
    const selectedServices = services || [
      'google', 'microsoft', 'netcraft', 'eset', 'phishfort',
      'phishreport', 'easydmarc', 'norton', 'fortinet', 'mcafee',
      'crdf', 'phishtank', 'antiphishing_ch', 'virustotal', 'apwg', 'cisa'
    ];

    const { fileHash: hashFile, urlsHash, batchHash } = computeBatchHash(buffer, urlsToProcess, selectedServices);
    const fingerprint = sha256File(Buffer.from(`${batchId}-${batchHash}-${timestamp}`));

    let virustotalResults = [];
    if (virustotalApiKey && urlsToProcess.length > 0) {
      try {
        virustotalResults = await virustotalPreCheckBatch(urlsToProcess, virustotalApiKey);
      } catch {
        virustotalResults = urlsToProcess.map(url => ({
          url,
          classification: 'NO_RECORD',
          maliciousEngines: 0,
        }));
      }
    }

    const db = (await import('@/lib/db')).db;

    await db.takeDownBatch.create({
      data: {
        id: batchId,
        name: batchName || `Batch ${batchId.substring(0, 8)}`,
        status: 'queued',
        totalUrls: urlsToProcess.length,
        processedUrls: 0,
        successfulUrls: 0,
        failedUrls: 0,
        userId: 'system',
        notes,
        fingerprint,
        fileHash,
        services: JSON.stringify(selectedServices),
        virustotalResults: JSON.stringify(virustotalResults),
      },
    });

    for (const url of urlsToProcess) {
      await db.takeDownReport.create({
        data: {
          id: generateTransactionId(),
          batchId,
          url: defangUrl(url),
          originalUrl: url,
          status: 'pending',
          virustotalClassification: virustotalResults.find(v => v.url === url)?.classification,
          virustotalMaliciousEngines: virustotalResults.find(v => v.url === url)?.maliciousEngines || 0,
        },
      });
    }

    return NextResponse.json({
      batchId,
      fingerprint,
      totalUrlsSubmitted: urlsToProcess.length,
      validUrls: urlsToProcess.length,
      invalidUrls: invalidUrls.length,
      fileHash,
      virustotalPreCheck: virustotalResults,
      timestamp,
      status: 'queued',
    });
  } catch (error) {
    console.error('Upload error:', error);
    return NextResponse.json({ error: 'Error processing upload' }, { status: 500 });
  }
}

function defangUrl(url: string): string {
  return url
    .replace(/^https?:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]');
}
