import { NextRequest, NextResponse } from 'next/server';
import { lookupDomain, detectType } from '@/lib/intel';
import { upsertIOC, createAlert, generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';
import { isAIEnabled } from '@/lib/ai';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

const WATCH_KEY = 'nexus:brand:watch';

interface BrandProfile {
  id: string;
  brand: string;
  domains: string[];
  keywords: string[];
  approvedApps?: string[];
  createdAt: string;
}

// Heuristic phishing-kit fingerprinting
const PHISH_KIT_MARKERS = [
  { pattern: /login|signin|verify|secure|update|account/i, weight: 2, label: 'Credential-theme path' },
  { pattern: /paypal|apple|microsoft|amazon|google|netflix|bbva|santander|citi/i, weight: 2, label: 'High-value brand impersonation' },
  { pattern: /\.top|\.xyz|\.click|\.link|\.live|\.cc|\.tk|\.ml|\.ga|\.cf|\.icu/i, weight: 3, label: 'Suspicious TLD' },
  { pattern: /[0-9]{4,}/, weight: 1, label: 'Numeric/randomized segment' },
  { pattern: /paypal-|amazon-|secure-|login-|verify-|account-/i, weight: 2, label: 'Hyphenated brand prefix' },
  { pattern: /verification|notification|alert|unusual|suspended|deactivat|confirm/i, weight: 2, label: 'Urgency bait language' },
  { pattern: /xn--/i, weight: 3, label: 'Punycode homograph' },
];

function scorePhishing(candidate: string, brand: string): { score: number; reasons: string[]; verdict: string } {
  const lower = candidate.toLowerCase();
  const brandLower = brand.toLowerCase();
  let score = 0;
  const reasons: string[] = [];

  // Homoglyph / brand misspelling detection (simple Levenshtein-lite)
  const brandInCandidate = lower.includes(brandLower);
  const brandLen = brandLower.replace(/[^a-z0-9]/g, '').length;
  let similar = false;
  if (brandLen >= 4 && !brandInCandidate) {
    let match = 0;
    for (const ch of brandLower.replace(/[^a-z0-9]/g, '')) {
      if (lower.includes(ch)) match++;
    }
    similar = match / brandLen >= 0.7;
  }
  if (brandInCandidate) { score += 2; reasons.push('Brand name present in candidate'); }
  if (similar) { score += 3; reasons.push('High character overlap with brand — possible typosquat'); }

  for (const m of PHISH_KIT_MARKERS) {
    if (m.pattern.test(lower)) { score += m.weight; reasons.push(m.label); }
  }

  const verdict = score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
  return { score: Math.min(score, 15), reasons: reasons.slice(0, 5), verdict };
}

function suggestLookalikeDomains(brand: string): string[] {
  const b = brand.toLowerCase().replace(/[^a-z0-9]/g, '');
  const lookalikes: string[] = [];
  const typos = [
    b.replace('o', '0'), b.replace('l', '1'), b.replace('i', '1'), b.replace('e', '3'),
    b + '-login', b + 'secure', 'secure-' + b, b + 'account', b + 'verify', 'my' + b, b + 'online',
    b + 'support', 'login-' + b, b + '.top', b + '.xyz', b + '.click', b + '-verify',
  ];
  for (const t of typos) {
    if (t !== b && !lookalikes.includes(t)) lookalikes.push(t);
  }
  return lookalikes.slice(0, 10);
}

// Seeded real-world style phishing kits for demo (no live dark web access)
function seedPhishingKits(brand: string): any[] {
  const kits = [
    { id: generateId(), name: `${brand} Login Portal v2`, platform: 'Telegram admin panel', ioc: `telegram.me/phish_${brand.toLowerCase()}`, confirmed: false },
    { id: generateId(), name: `${brand} Verification Kit`, platform: 'Public exploit forum', ioc: `exploit.in/thread-${Math.floor(Math.random() * 9000) + 1000}`, confirmed: false },
    { id: generateId(), name: `${brand} OTP Bypass`, platform: 'Dark market listing', ioc: `hxxp://${brand.toLowerCase()}verify[.]top`, confirmed: false },
  ];
  return kits;
}

async function checkCandidate(candidate: string, brand: string): Promise<any> {
  const clean = candidate.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const isDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean);
  const phish = scorePhishing(clean, brand);

  let live: boolean | null = null;
  let dns: Record<string, any> | null = null;
  let whois: any = null;
  if (isDomain) {
    try {
      const lookup = await lookupDomain(clean);
      live = lookup.live;
      dns = Object.keys(lookup.dns).length ? lookup.dns : null;
      whois = lookup.whois;
    } catch { live = null; }
  }

  return {
    candidate,
    clean,
    type: detectType(candidate),
    brand,
    phishing: phish,
    live,
    dns,
    whois,
    scannedAt: new Date().toISOString(),
  };
}

// ---------- POST: scan a suspicious URL/domain against a brand ----------
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { brand, candidate, mode = 'scan' } = body;

    const { module: brandModule, error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }

    if (!brand || !candidate) {
      return NextResponse.json({ success: false, error: 'brand and candidate are required' }, { status: 400 });
    }

    if (mode === 'scan') {
      const result = await checkCandidate(candidate, brand);
      try {
        await upsertIOC({
          type: result.type === 'ip' ? 'IP' : 'DOMAIN',
          value: result.clean,
          description: `Brand protection scan: ${brand} — ${result.phishing.verdict} phishing score ${result.phishing.score}/15`,
          severity: result.phishing.verdict === 'HIGH' ? 'HIGH' : result.phishing.verdict === 'MEDIUM' ? 'MEDIUM' : 'LOW',
          confidence: 70,
          status: result.phishing.verdict === 'HIGH' ? 'MALICIOUS' : 'SUSPICIOUS',
          source: 'Brand-Protection',
          rawResponse: JSON.stringify(result).substring(0, 5000),
          tags: ['phishing', 'brand-protection', brand.toLowerCase(), result.phishing.verdict.toLowerCase()],
        });
        if (result.phishing.verdict === 'HIGH') {
          await createAlert({
            iocId: generateId(),
            title: `Possible phishing for ${brand}: ${result.clean}`,
            description: `Scored ${result.phishing.score}/15. ${result.phishing.reasons.join('; ')}`,
            severity: 'HIGH',
            type: 'PHISHING',
          });
        }
      } catch (e) { console.error('Brand store error (non-critical):', e); }

      return NextResponse.json({
        success: true,
        module: brandModule,
        source: 'Brand-Protection Engine',
        timestamp: new Date().toISOString(),
        aiEnabled: isAIEnabled(),
        data: result,
        lookalikes: suggestLookalikeDomains(brand),
        kits: seedPhishingKits(brand),
        message: `Scan complete for ${brand}: ${result.phishing.verdict} (score ${result.phishing.score}/15)`,
      });
    }

    if (mode === 'watchlist') {
      const profile: BrandProfile = {
        id: generateId(),
        brand,
        domains: body.domains || [],
        keywords: body.keywords || [brand.toLowerCase(), 'login', 'verify', 'support'],
        approvedApps: body.approvedApps || [],
        createdAt: new Date().toISOString(),
      };
      await kvPushList(WATCH_KEY, profile, 100);
      return NextResponse.json({ success: true, data: profile, message: `Brand "${brand}" added to watchlist` });
    }

    return NextResponse.json({ success: false, error: 'Unknown mode' }, { status: 400 });
  } catch (error) {
    console.error('Brand protection error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Brand scan failed' },
      { status: 500 }
    );
  }
}

// ---------- GET: list watchlist / scan examples ----------
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const brand = searchParams.get('brand') || 'Acme';

  const { module: brandModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }

  if (action === 'watchlist') {
    const profiles = await kvGetList<BrandProfile>(WATCH_KEY);
    return NextResponse.json({ success: true, module: brandModule, data: profiles, message: `${profiles.length} brand(s) watched` });
  }

  // Demo scan of lookalikes for a brand
  const candidates = suggestLookalikeDomains(brand);
  const results = await Promise.all(candidates.slice(0, 6).map((c) => checkCandidate(c, brand)));
  return NextResponse.json({
    success: true,
    module: brandModule,
    source: 'Brand-Protection Engine',
    brand,
    lookalikes: candidates,
    results,
    kits: seedPhishingKits(brand),
    message: `Analyzed ${results.length} lookalike candidates for "${brand}"`,
  });
}
