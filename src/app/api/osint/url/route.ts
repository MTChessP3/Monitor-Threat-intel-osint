import { NextRequest, NextResponse } from 'next/server';
import { scanUrl } from '@/lib/intel/scanner';
import { upsertIOC, createAlert, generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';
import { lookupVirusTotalUrl } from '@/lib/intel/virustotal';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

const JOBS_KEY = 'nexus:url:jobs';

interface ScanJob {
  id: string;
  url: string;
  status: 'COMPLETED';
  verdict: string;
  score: number;
  startedAt: string;
}

export async function GET(request: NextRequest) {
  const { error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const searchParams = request.nextUrl.searchParams;
  const action = searchParams.get('action');

  if (action === 'jobs') {
    const jobs = await kvGetList<ScanJob>(JOBS_KEY);
    return NextResponse.json({ success: true, data: jobs.slice(0, 20), message: `${jobs.length} scan job(s)` });
  }

  const url = searchParams.get('url');
  if (!url) {
    return NextResponse.json(
      { success: false, error: 'URL is required', suggestion: 'Enter a valid URL (e.g., https://example.com/page)' },
      { status: 400 }
    );
  }

  try {
    const [result, vt] = await Promise.all([
      scanUrl(url),
      lookupVirusTotalUrl(url).catch(() => null),
    ]);

    const job: ScanJob = {
      id: generateId(),
      url: result.url,
      status: 'COMPLETED',
      verdict: result.verdict.level,
      score: result.verdict.score,
      startedAt: result.timestamp,
    };
    await kvPushList(JOBS_KEY, job, 50).catch(() => {});

    const effectiveLevel = vt?.verdict === 'MALICIOUS' && result.verdict.level !== 'MALICIOUS' ? result.verdict.level : result.verdict.level;

    try {
      await upsertIOC({
        type: 'URL',
        value: result.url,
        description: `URL Scanner: ${effectiveLevel} (${result.verdict.score}/100) — ${result.verdict.reasons.slice(0, 3).join('; ')}`,
        severity: effectiveLevel === 'MALICIOUS' ? 'HIGH' : effectiveLevel === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
        confidence: 80,
        status: effectiveLevel === 'MALICIOUS' ? 'MALICIOUS' : effectiveLevel === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'UNKNOWN',
        source: 'URL-Scanner',
        rawResponse: JSON.stringify({ result, vt }).substring(0, 8000),
        tags: ['url-scanner', effectiveLevel.toLowerCase(), ...result.kit.matches.map((m) => m.family.toLowerCase().replace(/\s+/g, '-')), ...(vt?.verdict ? [`vt:${vt.verdict.toLowerCase()}`] : [])],
      });
      if (result.verdict.level === 'MALICIOUS' || vt?.verdict === 'MALICIOUS') {
        await createAlert({
          iocId: job.id,
          title: `Malicious URL scanned: ${result.url}`,
          description: `Attack-surface score ${result.verdict.score}/100. ${result.verdict.reasons.slice(0, 4).join('; ')}${vt ? ` VirusTotal: ${vt.lastAnalysisStats.malicious}/${vt.totalEngines} malicious engines.` : ''}`,
          severity: 'HIGH',
          type: 'URL_SCAN',
        });
      }
    } catch (e) {
      console.error('Scanner store error (non-critical):', e);
    }

    return NextResponse.json({
      success: true,
      source: result.source,
      timestamp: result.timestamp,
      fetchedLive: true,
      url: result.url,
      domain: result.host,
      // VirusTotal current indicators (null when no key or no prior analysis)
      virusTotal: vt,
      riskAssessment: {
        level: effectiveLevel,
        score: result.verdict.score,
        status: effectiveLevel === 'MALICIOUS' ? 'MALICIOUS' : effectiveLevel === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'BENIGN',
        findings: result.verdict.reasons,
        safeBrowsing: 'Attack-surface scan (real)',
      },
      data: result,
      message: `URL scan complete: ${effectiveLevel} (${result.verdict.score}/100)`,
    });
  } catch (error) {
    console.error('URL Scanner Error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'URL scan failed' },
      { status: 500 }
    );
  }
}
