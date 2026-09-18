import { NextRequest, NextResponse } from 'next/server';
import { lookupHash } from '@/lib/intel';
import { upsertIOC } from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

function getHashType(hash: string): string {
  const len = hash.length;
  if (len === 32) return 'MD5';
  if (len === 40) return 'SHA1';
  if (len === 64) return 'SHA256';
  return 'UNKNOWN';
}

// Hash Lookup — real MalwareBazaar (and optional VirusTotal)
export async function GET(request: NextRequest) {
  const { error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const searchParams = request.nextUrl.searchParams;
  const hash = searchParams.get('hash');

  if (!hash) {
    return NextResponse.json({ error: 'Hash is required (MD5, SHA1, or SHA256)' }, { status: 400 });
  }

  try {
    const hashType = getHashType(hash);
    const result = await lookupHash(hash);

    if (result.found) {
      try {
        await upsertIOC({
          type: 'HASH',
          value: hash,
          description: `Malware hash: ${result.data.signature || result.data.fileType || 'Known sample'}`,
          severity: 'HIGH',
          confidence: result.data.confidence || 90,
          status: 'MALICIOUS',
          source: result.source,
          rawResponse: JSON.stringify(result.data),
          tags: [...(result.data.tags || []).slice(0, 8), result.source],
        });
      } catch (storeError) {
        /* non-critical */
      }

      return NextResponse.json({
        success: true,
        hash,
        hashType,
        timestamp: new Date().toISOString(),
        fetchedLive: result.live,
        source: result.source,
        data: result.data,
        message: `Hash identified: ${result.data.signature || 'Known malware sample'} (${result.source})`,
      });
    }

    // Not found in any source
    return NextResponse.json({
      success: true,
      hash,
      hashType,
      timestamp: new Date().toISOString(),
      fetchedLive: result.live,
      source: result.source,
      data: null,
      message: 'Hash not found in malware databases. This could indicate a clean file or an unknown sample.',
      suggestions: [
        'If you set VIRUSTOTAL_API_KEY, hash lookups include multi-engine detection.',
      ],
    });
  } catch (error) {
    console.error('Hash Lookup Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to lookup hash',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
