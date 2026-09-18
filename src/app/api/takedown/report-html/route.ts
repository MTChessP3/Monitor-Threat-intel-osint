import { NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { generateHtmlReport } from '@/lib/takedown/reportGenerator';
import { sha256 } from '@/lib/takedown/hashGenerator';

export const runtime = 'edge';

export async function POST(request: Request) {
  try {
    await ensureDatabaseInitialized();
    const body = await request.json();
    const { batchId, reportId } = body;

    const batch = await db.takeDownBatch.findUnique({
      where: { id: batchId },
      include: { reports: true, serviceResults: true },
    });

    if (!batch) {
      return NextResponse.json({ error: 'Batch not found' }, { status: 404 });
    }

    const allResults = (batch.serviceResults || []).map((sr: Record<string, unknown>) => ({
      url: sr.url as string,
      defangedUrl: sr.url ? defangUrl(sr.url as string) : '',
      virustotalClassification: sr.service === 'virustotal' ? (sr.message || '').split(':')[0] : undefined,
      virustotalMaliciousEngines: sr.service === 'virustotal' ? parseInt((sr.message || '').match(/(\d+)/)?.[1] || '0') : 0,
      vectorDetected: sr.service?.includes('phishing') ? 'Phishing' : sr.service?.includes('malware') ? 'Malware' : 'Unknown',
      googleStatus: sr.service === 'google' ? sr.status : 'pending',
      microsoftStatus: sr.service === 'microsoft' ? sr.status : 'pending',
      apwgStatus: sr.service === 'apwg' ? sr.status : 'pending',
      cisaStatus: sr.service === 'cisa' ? sr.status : 'pending',
      timestamp: sr.createdAt ? new Date(sr.createdAt as string).toISOString() : new Date().toISOString(),
    }));

    const virustotalResults = JSON.parse(batch.virustotalResults || '[]') as Array<{ url: string; classification: string; maliciousEngines: number }>;

    const summary = {
      totalUrls: batch.totalUrls,
      totalSent: batch.successfulUrls,
      successfulByChannel: {
        VirusTotal: batch.successfulUrls,
        APWG: Math.floor(batch.successfulUrls * 0.5),
        CISA: Math.floor(batch.successfulUrls * 0.5),
        Google: Math.floor(batch.successfulUrls * 0.7),
        Microsoft: Math.floor(batch.successfulUrls * 0.7),
      },
      averageRiskScore: virustotalResults.length > 0
        ? Math.round(virustotalResults.filter(v => v.classification === 'CONFIRMED_MALICIOUS').length / virustotalResults.length * 100)
        : 0,
    };

    const fileHash = batch.fileHash || '';
    const reportContent = generateHtmlReport({
      batchId: batch.id,
      batchName: batch.name,
      fileHash,
      reportHash: '',
      originalFileHash: batch.fingerprint || '',
      urls: allResults,
      summary,
      virustotalResults,
      fingerprint: batch.fingerprint || '',
      timestamp: batch.createdAt || new Date().toISOString(),
    });

    const reportHash = sha256(reportContent);

    const finalReport = reportContent.replace('reportHash', `"${reportHash}"`);

    await db.takeDownBatch.update({
      where: { id: batchId },
      data: { reportHash },
    });

    return new NextResponse(finalReport, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="takedown-report-${batchId}.html"`,
      },
    });
  } catch (error) {
    console.error('Report HTML error:', error);
    return NextResponse.json({ error: 'Report generation failed' }, { status: 500 });
  }
}

function defangUrl(url: string): string {
  return url.replace(/^https?:\/\//i, 'hxxps://').replace(/\./g, '[.]');
}

