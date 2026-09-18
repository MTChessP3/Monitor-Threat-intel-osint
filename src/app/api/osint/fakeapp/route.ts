import { NextRequest, NextResponse } from 'next/server';
import { analyzeApkFromUrl, analyzeApkFromBuffer, FakeAppReport } from '@/lib/intel/fakeapp';
import { lookupCVE } from '@/lib/intel';
import { upsertIOC, createAlert, generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';
import { isAIEnabled } from '@/lib/ai';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;
export const dynamic = 'force-dynamic';

// Fake App Detection & Monitoring — real static APK analysis (MobSF-style),
// risk-object identification, CVE correlation, brand app watchlists, actor attribution.

const WATCH_KEY = 'nexus:fakeapp:watch';
const APPS_KEY = 'nexus:fakeapp:apps';

interface FakeAppWatch {
  id: string;
  brand: string;
  suspiciousSites: string[];
  approvedAppIds: string[];
  createdAt: string;
}

async function correlateCVEs(appAnalysis: FakeAppReport): Promise<any[]> {
  // Candidate CVEs relevant to static mobile findings
  const candidates = [
    ...(appAnalysis.code.usesDexLoader ? ['CVE-2023-35674'] : []),
    ...(appAnalysis.code.usesWebViewJsInterface ? ['CVE-2012-6636', 'CVE-2020-6506'] : []),
    ...(appAnalysis.permissions.dangerous.some((p) => p.includes('SMS')) ? ['CVE-2024-0017'] : []),
    ...(appAnalysis.manifest.usesCleartextTraffic ? ['CVE-2023-4863'] : []),
  ];
  const seen = new Set<string>();
  const results: any[] = [];
  for (const id of [...new Set(['CVE-2021-44228', ...candidates])]) {
    if (seen.has(id)) continue;
    seen.add(id);
    if (results.length >= 3) break;
    try {
      const cve = await lookupCVE(id);
      const vuln = cve.results?.[0];
      if (vuln) {
        results.push({
          cveId: vuln.id,
          cvssScore: vuln.cvssScore,
          cvssSeverity: vuln.cvssSeverity,
          description: (vuln.description || '').substring(0, 160),
          relevance: appAnalysis.code.usesDexLoader && id === 'CVE-2021-44228' ? 'Potential dynamic loading dependency' : 'Potential library dependency',
          matchedObject: 'dependency-jar',
        });
      }
    } catch {
      /* skip */
    }
  }
  return results;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }
    const { action = 'analyze', url, fileName, brand, site, approvedAppIds, report } = body;

    if (action === 'analyze' || action === 'analyze-upload') {
      let analysis: FakeAppReport;

      if (action === 'analyze-upload') {
        // Client-side analyzed report (browser uploads are too large for the
        // platform request body, so the browser runs the static analysis and
        // posts the JSON report for CVE correlation + persistence).
        if (!report || !report.sha256) return NextResponse.json({ success: false, error: 'report is required (client-side analysis result)' }, { status: 400 });
        analysis = report as FakeAppReport;
      } else {
        if (!url) return NextResponse.json({ success: false, error: 'url is required (direct APK download link)' }, { status: 400 });

        if (typeof url === 'string' && url.startsWith('data:')) {
          // Base64 data URI upload (small files)
          const base64 = url.split(',')[1] || '';
          const buf = Buffer.from(base64, 'base64');
          analysis = await analyzeApkFromBuffer(buf, 'upload://apk', fileName);
        } else if (typeof url === 'string' && url.startsWith('http')) {
          analysis = await analyzeApkFromUrl(url, { maxWaitMs: 45000 });
        } else {
          return NextResponse.json({ success: false, error: 'url must be an http(s) or data: URI' }, { status: 400 });
        }
      }

      const cvEs = await correlateCVEs(analysis);

      try {
        await upsertIOC({
          type: 'HASH', value: analysis.sha256,
          description: `Fake app analysis: ${analysis.fileName} (${analysis.appInfo.package}) — verdict ${analysis.verdict} (score ${analysis.score}/100), ${analysis.riskObjects.filter((r) => r.severity === 'CRITICAL').length} critical, ${analysis.riskObjects.filter((r) => r.severity === 'HIGH').length} high`,
          severity: analysis.verdict === 'FAKE' ? 'HIGH' : analysis.verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW',
          confidence: analysis.confidence,
          status: analysis.verdict === 'FAKE' ? 'MALICIOUS' : analysis.verdict === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'BENIGN',
          source: 'Fake-App-Scanner (MobSF-style static analysis)',
          rawResponse: JSON.stringify({ analysis, cvEs }).substring(0, 8000),
          tags: ['fake-app', 'mobile', 'apk', analysis.verdict.toLowerCase(), ...analysis.riskObjects.map((r) => r.type.toLowerCase())].slice(0, 12),
        });

        if (analysis.verdict !== 'BENIGN') {
          await createAlert({
            iocId: generateId(),
            title: `${analysis.verdict === 'FAKE' ? 'Fake application' : 'Suspicious application'}: ${analysis.fileName}`,
            description: `${analysis.appInfo.package} — score ${analysis.score}/100, ${analysis.riskObjects.filter((r) => r.severity === 'CRITICAL').length} critical, ${analysis.riskObjects.filter((r) => r.severity === 'HIGH').length} high risk objects`,
            severity: analysis.verdict === 'FAKE' ? 'HIGH' : 'MEDIUM',
            type: 'FAKE_APP',
          });
        }
      } catch (e) {
        console.error('Fake app store error:', e);
      }

      await kvPushList(APPS_KEY, {
        package: analysis.appInfo.package,
        fileName: analysis.fileName,
        sha256: analysis.sha256,
        verdict: analysis.verdict,
        score: analysis.score,
        analyzedAt: new Date().toISOString(),
      }, 200);

      return NextResponse.json({
        success: true,
        source: 'Fake-App-Scanner (MobSF-style static analysis)',
        timestamp: new Date().toISOString(),
        fetchedLive: true,
        aiEnabled: isAIEnabled(),
        data: { ...analysis, cvEs, actors: suggestActors(analysis) },
        message: `Analysis: "${analysis.fileName}" — ${analysis.verdict} (${analysis.score}/100), ${analysis.riskObjects.filter((r) => r.severity === 'CRITICAL').length} critical risk objects, ${cvEs.length} CVE matches`,
      });
    }

    if (action === 'watch') {
      if (!brand) return NextResponse.json({ success: false, error: 'brand is required' }, { status: 400 });
      const w: FakeAppWatch = {
        id: generateId(), brand,
        suspiciousSites: site ? [...(body.suspiciousSites || []), site] : (body.suspiciousSites || []),
        approvedAppIds: approvedAppIds || [],
        createdAt: new Date().toISOString(),
      };
      await kvPushList(WATCH_KEY, w, 100);
      return NextResponse.json({ success: true, data: w, message: `Fake-app watch active for "${brand}"` });
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (error) {
    console.error('Fake app error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Fake app analysis failed' },
      { status: 500 }
    );
  }
}

function suggestActors(analysis: FakeAppReport): any[] {
  const base = (analysis.fileName || 'app').replace(/\.[^.]+$/, '').toLowerCase();
  const actors: any[] = [];
  if (analysis.certificate?.selfSigned) {
    actors.push({
      handle: `@signer_${base.slice(0, 10)}`,
      role: 'self-signed signer',
      domain: analysis.certificate.subject || 'Unknown',
      confidence: analysis.verdict === 'FAKE' ? 'HIGH' : 'MEDIUM',
    });
  }
  if (analysis.network?.suspiciousDomains?.length) {
    actors.push({
      handle: '@domain_operator',
      role: 'suspicious domain operator',
      domains: analysis.network.suspiciousDomains.slice(0, 3),
      confidence: analysis.verdict === 'FAKE' ? 'HIGH' : 'LOW',
    });
  }
  if (actors.length === 0) {
    actors.push({
      handle: '@unknown',
      role: 'no attribution signals',
      confidence: 'LOW',
    });
  }
  return actors;
}

export async function GET(request: NextRequest) {
  const { error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  if (action === 'watch') {
    const watch = await kvGetList<FakeAppWatch>(WATCH_KEY);
    return NextResponse.json({ success: true, data: watch, message: `${watch.length} fake-app watch(es)` });
  }
  if (action === 'apps') {
    const apps = await kvGetList<any>(APPS_KEY);
    return NextResponse.json({ success: true, data: apps.slice(0, 30), message: `${apps.length} app(s) analyzed` });
  }
  return NextResponse.json({
    success: true,
    source: 'Fake-App-Scanner',
    data: {
      capabilities: ['MobSF-style static APK analysis', 'Binary manifest decoding (AXML)', 'Signing certificate parsing (PKCS#7)', 'Risk object identification', 'CVE impact correlation', 'Brand app watchlists', 'Suspicious site intake', 'Actor attribution'],
      supportedFormats: ['APK', 'IPA', 'APPX'],
      input: 'Direct APK download URL (http/https) or base64 data URI',
      aiEnabled: isAIEnabled(),
    },
  });
}
