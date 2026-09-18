import { NextRequest, NextResponse } from 'next/server';
import { lookupCVE } from '@/lib/intel';
import { upsertIOC } from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

// CVE Database — real NIST NVD v2.0 integration
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const cveId = searchParams.get('cveId');
  const keyword = searchParams.get('keyword');

  const { module: cveModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }

  if (!cveId && !keyword) {
    return NextResponse.json(
      {
        success: false,
        error: 'CVE ID or search keyword is required',
        suggestion: 'Try "CVE-2024-3400" or search for "sql injection"',
        examples: ['CVE-2024-3400', 'CVE-2024-21887', 'log4j', 'rce', 'injection'],
      },
      { status: 400 }
    );
  }

  try {
    const input = cveId || keyword || '';
    const { live, source, results, total } = await lookupCVE(input);

    // Persist found CVEs as IOCs (non-blocking)
    for (const cve of results) {
      try {
        await upsertIOC({
          type: 'CVE',
          value: cve.id,
          description: cve.description?.substring(0, 500) || 'No description available',
          severity: mapCVSSSeverity(cve.cvssScore),
          confidence: 95,
          source: live ? 'NIST-NVD' : 'cached',
          rawResponse: JSON.stringify(cve),
          tags: cve.weaknesses || [`CVSS:${cve.cvssScore}`],
        });
      } catch (storeError) {
        /* non-critical */
      }
    }

    return NextResponse.json({
      success: true,
      module: cveModule,
      source: live ? 'NIST-NVD-v2.0' : 'cached-data',
      timestamp: new Date().toISOString(),
      fetchedLive: live,
      totalResults: total,
      resultsPerPage: results.length,
      vulnerabilities: results,
    });
  } catch (error) {
    console.error('CVE Lookup Error:', error);
    const { results } = await lookupCVE(cveId || keyword || '');
    return NextResponse.json({
      success: true,
      module: cveModule,
      source: 'emergency-fallback',
      timestamp: new Date().toISOString(),
      fetchedLive: false,
      totalResults: results.length,
      resultsPerPage: results.length,
      vulnerabilities: results,
      message: 'Using fallback CVE data',
    });
  }
}

function mapCVSSSeverity(score?: number): string {
  if (!score) return 'MEDIUM';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}
