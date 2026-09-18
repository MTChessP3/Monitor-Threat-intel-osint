import { NextRequest, NextResponse } from 'next/server';
import { generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';
import { isAIEnabled } from '@/lib/ai';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

// Executive Digital Protection — personal OSINT, Google-dorking style metasearch,
// social network footprint, family/related profiles, deep & dark web indicators.

const PROFILES_KEY = 'nexus:exec:profiles';
const FINDINGS_KEY = 'nexus:exec:findings';
const FAMILY_KEY = 'nexus:exec:family';

const GSEARCH_KEY = process.env.GOOGLE_SEARCH_API_KEY || '';
const GSEARCH_CX = process.env.GOOGLE_SEARCH_CX || '';
const gsearchConfigured = !!(GSEARCH_KEY && GSEARCH_CX);

interface ExecutiveProfile {
  id: string;
  name: string;
  emails: string[];
  phones: string[];
  domains: string[];
  socials: string[];
  documents: string[];
  createdAt: string;
}

// Demo indexed footprint builder
function buildFootprint(name: string, emails: string[], phones: string[], domains: string[]): any[] {
  const now = Date.now();
  const findings: any[] = [];
  const ts = (h: number) => new Date(now - h * 3600000).toISOString();

  emails.forEach((e, i) => {
    findings.push({
      id: generateId(), type: 'EMAIL', value: e, source: 'breach-index', severity: 'HIGH',
      detail: `Email exposed in public breach corpus (${2020 + i} incident)`, date: ts(9000 + i * 700),
    });
    findings.push({
      id: generateId(), type: 'EMAIL', value: e, source: 'public-repo', severity: 'MEDIUM',
      detail: 'Appears in public code repository / README', date: ts(40000 + i * 500),
    });
  });

  phones.forEach((p, i) => {
    findings.push({
      id: generateId(), type: 'PHONE', value: p, source: 'directory-scrape', severity: 'MEDIUM',
      detail: 'Phone number indexed in public directories', date: ts(20000 + i * 300),
    });
  });

  domains.forEach((d, i) => {
    findings.push({
      id: generateId(), type: 'DOMAIN', value: d, source: 'dns-public', severity: 'LOW',
      detail: 'Personal domain registered — WHOIS reveals full name/address', date: ts(6000 + i * 400),
    });
  });

  const socialPlatforms = ['linkedin', 'twitter', 'github', 'facebook', 'instagram', 'telegram', 'whatsapp', 'tiktok', 'youtube', 'reddit'];
  socialPlatforms.slice(0, 8).forEach((p, i) => {
    findings.push({
      id: generateId(), type: 'SOCIAL', value: `${p}.com/${name.toLowerCase().replace(/\s+/g, '.')}`, source: 'social-index', severity: 'LOW',
      detail: `Public profile on ${p} — potential account takeover target`, date: ts(30000 - i * 200),
    });
  });

  findings.push({
    id: generateId(), type: 'DORK', value: 'site:linkedin.com "executive"', source: 'google-dork', severity: 'INFO',
    detail: 'Google dork query returned public executive information', date: ts(12000),
  });
  findings.push({
    id: generateId(), type: 'DOCUMENT', value: `${name} resume.pdf`, source: 'public-docs', severity: 'MEDIUM',
    detail: 'Resume with personal data indexed on job portals', date: ts(5000),
  });
  findings.push({
    id: generateId(), type: 'DARKWEB', value: `dark://profile/${name.toLowerCase()}`, source: 'dark-web-index', severity: 'HIGH',
    detail: 'Name correlated with forum account on dark web index', date: ts(15000),
  });

  return findings;
}

// Real Google Programmable Search Engine queries (dorking) when configured
async function googleDorkQueries(name: string): Promise<any[]> {
  const dorks = [
    `"${name}" email OR contact`,
    `"${name}" site:linkedin.com OR site:github.com`,
    `"${name}" filetype:pdf OR filetype:docx resume`,
    `"${name}" phone OR whatsapp`,
  ];
  const out: any[] = [];
  for (const q of dorks) {
    try {
      const url = `https://www.googleapis.com/customsearch/v1?key=${GSEARCH_KEY}&cx=${GSEARCH_CX}&q=${encodeURIComponent(q)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      const data = await res.json();
      const items = data.items || [];
      out.push({
        total: data.searchInformation?.totalResults || items.length,
        results: items.slice(0, 5).map((it: any) => ({ title: it.title, url: it.link, snippet: it.snippet })),
      });
    } catch { out.push({ total: 0, results: [], error: 'Search API unavailable' }); }
  }
  return out;
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const name = searchParams.get('name') || '';

  const { module: execModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }

  if (action === 'profiles') {
    const profiles = await kvGetList<ExecutiveProfile>(PROFILES_KEY);
    return NextResponse.json({ success: true, module: execModule, data: profiles, message: `${profiles.length} executive profile(s)` });
  }

  if (action === 'family') {
    const family = await kvGetList<any>(FAMILY_KEY);
    return NextResponse.json({ success: true, module: execModule, data: family, message: `${family.length} related profile(s)` });
  }

  if (!name) {
    return NextResponse.json({ success: false, error: 'name is required', example: '/api/osint/exec?name=John%20Smith' }, { status: 400 });
  }

  const profiles = await kvGetList<ExecutiveProfile>(PROFILES_KEY);
  const profile = profiles.find((p) => p.name.toLowerCase() === name.toLowerCase());

  const emails = profile?.emails || [`${name.toLowerCase().split(' ')[0]}.${name.toLowerCase().split(' ')[1] || 'corp'}@example.com`];
  const phones = profile?.phones || [`+1 555 0${Math.floor(Math.random() * 90) + 10} ${String(Math.floor(Math.random() * 900) + 100)}`];
  const domains = profile?.domains || [`${name.toLowerCase().replace(/\s+/g, '')}.com`];
  const socials = profile?.socials || [];

  const findings = buildFootprint(name, emails, phones, domains);
  const dorks = gsearchConfigured ? await googleDorkQueries(name) : [];

  const socialMatrix = [
    { platform: 'LinkedIn', handle: `linkedin.com/in/${name.toLowerCase().replace(/\s+/g, '-')}`, risk: 'MEDIUM' },
    { platform: 'X/Twitter', handle: `x.com/${name.toLowerCase().split(' ')[0]}`, risk: 'LOW' },
    { platform: 'GitHub', handle: `github.com/${name.toLowerCase().replace(/\s+/g, '')}`, risk: 'MEDIUM' },
    { platform: 'Facebook', handle: `facebook.com/${name.toLowerCase().replace(/\s+/g, '.')}`, risk: 'LOW' },
    { platform: 'Instagram', handle: `instagram.com/${name.toLowerCase().split(' ')[0]}`, risk: 'LOW' },
    { platform: 'Telegram', handle: `t.me/${name.toLowerCase().split(' ')[0]}`, risk: 'MEDIUM' },
    ...socials.map((s) => ({ platform: 'Custom', handle: s, risk: 'LOW' })),
  ];

  try {
    await kvPushList(FINDINGS_KEY, findings[0], 200);
  } catch (e) { console.error('Exec store error:', e); }

  return NextResponse.json({
    success: true,
    module: execModule,
    source: gsearchConfigured ? 'Executive-OSINT (Google PSE + index)' : 'Executive-OSINT (indexed demo)',
    timestamp: new Date().toISOString(),
    fetchedLive: gsearchConfigured,
    gsearchConfigured,
    aiEnabled: isAIEnabled(),
    data: {
      subject: { name, emails, phones, domains, socials },
      exposureScore: Math.min(findings.length * 9, 95),
      riskLevel: findings.some((f) => f.severity === 'HIGH') ? 'HIGH' : findings.some((f) => f.severity === 'MEDIUM') ? 'MEDIUM' : 'LOW',
      findings,
      socialMatrix,
      dorkQueries: dorks,
      relatedProfiles: [
        { name: `${name} (spouse)`, relation: 'family', risk: 'LOW' },
        { name: `${name} — assistant`, relation: 'work-colleague', risk: 'LOW' },
      ],
    },
    message: `Executive exposure scan for "${name}" — ${findings.length} findings (${findings.filter((f) => f.severity === 'HIGH').length} high)`,
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, profile, family } = body;

    const { module: execModule, error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }

    if (action === 'add-profile') {
      if (!profile?.name) return NextResponse.json({ success: false, error: 'profile.name is required' }, { status: 400 });
      const p: ExecutiveProfile = {
        id: generateId(), name: profile.name,
        emails: profile.emails || [], phones: profile.phones || [],
        domains: profile.domains || [], socials: profile.socials || [],
        documents: profile.documents || [], createdAt: new Date().toISOString(),
      };
      await kvPushList(PROFILES_KEY, p, 100);
      return NextResponse.json({ success: true, module: execModule, data: p, message: `Executive profile "${p.name}" created` });
    }

    if (action === 'add-family') {
      if (!family?.name || !family?.relation) return NextResponse.json({ success: false, error: 'family.name and relation required' }, { status: 400 });
      const f = { id: generateId(), ...family, createdAt: new Date().toISOString() };
      await kvPushList(FAMILY_KEY, f, 100);
      return NextResponse.json({ success: true, module: execModule, data: f, message: `Related profile "${f.name}" linked` });
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Executive module failed' },
      { status: 500 }
    );
  }
}
