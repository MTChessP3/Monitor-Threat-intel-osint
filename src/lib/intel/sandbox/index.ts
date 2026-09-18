// URL Sandbox orchestrator + scoring.
// Runs a real dynamic capture (engine.ts) plus reputation lookups reusing the
// IP enrichment engine (DNSBL/Tor/URLhaus) and RDAP WHOIS, then produces a
// scored verdict from real observed signals. Optional: external dynamic detonation
// via Hybrid Analysis, Joe Sandbox, ANY.RUN (require API keys).

import type {
  ContentIndicator, DomainReputation, SandboxResult, SandboxVerdict, StaticFlag,
} from './types';
import { captureHttp, captureTls, analyzeContent, probeResources } from './engine';
import { submitExternal, pollExternal, configuredExternalSources, type ExternalJob } from './hybrid';
import { enrichIP } from '@/lib/intel/ipenrich';
import { lookupIP } from '@/lib/intel';
import { lookupWhois, daysSince } from '@/lib/intel/domain/whois';

const HIGH_RISK_TLDS = ['top', 'xyz', 'click', 'work', 'loan', 'gq', 'tk', 'ml', 'cf', 'ga', 'zip', 'mov', 'icu', 'cn', 'ru', 'buzz', 'online', 'site', 'live', 'info'];
const BRANDS = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'netflix', 'bbva', 'santander', 'citi', 'dropbox', 'whatsapp', 'facebook', 'instagram', 'binance', 'coinbase', 'telegram', 'icloud'];

export function staticFlags(url: string): StaticFlag[] {
  const lower = url.toLowerCase();
  const flags: { pattern: RegExp; weight: number; label: string; category: string }[] = [
    { pattern: /login|signin|verify|secure|account|password|credential|otp|2fa/i, weight: 3, label: 'Credential harvesting keywords', category: 'credential-harvesting' },
    { pattern: /(?:^|\.)(?:top|xyz|click|work|loan|gq|tk|ml|cf|ga|zip|mov|icu|cn|ru|buzz|online|site|live|info)(?:[/:.]|$)/i, weight: 3, label: 'High-risk TLD', category: 'malicious-tld' },
    { pattern: /xn--/i, weight: 4, label: 'Punycode homograph attack', category: 'homograph' },
    { pattern: /%[0-9a-f]{2}/i, weight: 2, label: 'URL-encoded obfuscation', category: 'obfuscation' },
    { pattern: /@/, weight: 2, label: 'Credential-style @ (userinfo)', category: 'obfuscation' },
    { pattern: /-.*-.*-/i, weight: 1, label: 'Multi-hyphen randomized', category: 'obfuscation' },
    { pattern: /cgi-bin|\.php|\.asp|\.exe|\.jar|\.zip|\.scr|\.hta/i, weight: 2, label: 'Executable/script payload path', category: 'payload-delivery' },
    { pattern: /javascript:|data:text\/html/i, weight: 4, label: 'Inline script protocol', category: 'payload-delivery' },
    { pattern: /\d{4,}/, weight: 1, label: 'Numeric segment in path', category: 'obfuscation' },
  ];
  const out: StaticFlag[] = [];
  for (const f of flags) {
    if (f.pattern.test(lower)) out.push({ label: f.label, weight: f.weight, category: f.category });
  }
  return out;
}

// Lookalike detection: brand followed by anything other than an exact match
// or a known subdomain of the real brand domain.
export function detectBrandImpersonation(host: string): StaticFlag | null {
  const h = host.toLowerCase().split('.')[0];
  const registered = host.toLowerCase().split('.').slice(-2).join('.');
  for (const brand of BRANDS) {
    if (registered === `${brand}.com` || registered === `${brand}.org` || registered === `${brand}.net`) continue;
    if (h.includes(brand)) {
      return { label: `Brand impersonation (${brand})`, weight: 3, category: 'impersonation' };
    }
  }
  return null;
}

function tldOf(host: string): string {
  const parts = host.toLowerCase().split('.');
  return parts.length >= 2 ? parts[parts.length - 1] : '';
}

function scoreVerdict(params: {
  staticFlags: StaticFlag[];
  content: ContentIndicator[];
  httpStatus: number | null;
  redirects: { url: string; status: number | null }[];
  tlsExpired: boolean;
  tlsSelfSigned: boolean;
  tlsMismatch: boolean;
  rep: DomainReputation;
}): SandboxVerdict {
  let score = 0;
  const reasons: string[] = [];

  for (const f of params.staticFlags) {
    score += f.weight;
    reasons.push(f.label);
  }

  for (const ind of params.content) {
    const w = ind.severity === 'CRITICAL' ? 8 : ind.severity === 'HIGH' ? 5 : ind.severity === 'MEDIUM' ? 3 : 1;
    score += w;
    reasons.push(ind.label);
  }

  const distinctRedirectHosts = new Set(params.redirects.map((r) => r.url && (() => { try { return new URL(r.url).hostname; } catch { return ''; } })()).filter(Boolean));
  if (params.redirects.length >= 3) {
    score += 4;
    reasons.push(`Long redirect chain (${params.redirects.length} hops)`);
  }
  if (distinctRedirectHosts.size >= 2) {
    score += 3;
    reasons.push('Redirects cross multiple hosts');
  }

  if (params.tlsExpired) { score += 5; reasons.push('TLS certificate expired'); }
  if (params.tlsSelfSigned) { score += 4; reasons.push('Self-signed TLS certificate'); }
  if (params.tlsMismatch) { score += 4; reasons.push('TLS certificate hostname mismatch'); }

  if (params.httpStatus === null) { score += 5; reasons.push('Host unreachable / TLS handshake failed'); }
  if (params.rep.dnsblListed > 0) { score += Math.min(params.rep.dnsblListed * 4, 12); reasons.push(`${params.rep.dnsblListed} DNSBL listing(s)`); }
  if (params.rep.torExit) { score += 8; reasons.push('IP is a Tor exit node'); }
  if (params.rep.urlhausCount > 0) { score += Math.min(params.rep.urlhausCount * 2, 10); reasons.push(`${params.rep.urlhausCount} URLhaus hit(s)`); }
  if (params.rep.proxy) { score += 4; reasons.push('IP flagged as proxy/VPN'); }
  if (params.rep.domainAgeDays !== null && params.rep.domainAgeDays < 30) { score += 6; reasons.push(`Very young domain (${params.rep.domainAgeDays} days)`); }
  if (params.rep.domainAgeDays !== null && params.rep.domainAgeDays < 365) { score += 3; reasons.push(`Young domain (${params.rep.domainAgeDays} days)`); }

  const level: SandboxVerdict['level'] = score >= 30 ? 'MALICIOUS' : score >= 12 ? 'SUSPICIOUS' : 'BENIGN';
  const verdict =
    score >= 30
      ? 'Strong malicious signals — do not visit without isolation.'
      : score >= 12
        ? 'Suspicious signals present — treat as untrusted.'
        : 'No significant malicious signals observed.';

  return { score: Math.min(score, 100), level, verdict, reasons };
}

export async function runSandbox(url: string, opts?: { external?: boolean }): Promise<SandboxResult & { external?: ExternalJob[] }> {
  let clean = url.trim();
  if (!/^https?:\/\//i.test(clean)) clean = `https://${clean}`;

  let host: string;
  try {
    host = new URL(clean).hostname;
  } catch {
    host = clean;
  }

  const flags = staticFlags(clean);
  const impersonation = detectBrandImpersonation(host);
  if (impersonation) flags.push(impersonation);

  // Real dynamic capture
  const [httpResult, tls] = await Promise.all([
    captureHttp(clean),
    (() => { try { return captureTls(clean); } catch { return null; } })(),
  ]);
  const { http, redirects } = httpResult;

  const content = http?.html ? analyzeContent(http.html, host) : null;
  const resources = http?.html ? await probeResources(http.html, http.finalUrl) : [];

  // Reputation: resolve first A record → ip-api geo + DNSBL/Tor/URLhaus via enrichIP
  const rep: DomainReputation = {
    ip: null, geo: null, asn: null, isp: null,
    dnsblListed: 0, dnsblBlocked: 0, torExit: false, urlhausCount: 0,
    hosting: false, proxy: false,
    whoisCreated: null, domainAgeDays: null, domainExpires: null,
  };
  try {
    const ip = host;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      rep.ip = host;
    } else {
      const recs = await import('@/lib/intel/domain/dns').then((m) => m.resolveType(host, 'A'));
      rep.ip = recs[0]?.data || null;
    }
  } catch {
    /* ignore */
  }

  if (rep.ip) {
    try {
      const geo = await lookupIP(rep.ip);
      if (geo.live && geo.data?.country) {
        rep.geo = [geo.data.country, geo.data.city].filter(Boolean).join(' · ');
        rep.asn = geo.data.as || null;
        rep.isp = geo.data.isp || null;
        rep.hosting = !!geo.data.hosting;
        rep.proxy = !!geo.data.proxy;
      }
    } catch { /* ignore */ }
    try {
      const enr = await enrichIP(rep.ip, { scan: false });
      rep.dnsblListed = enr.reputation.dnsbl.filter((d) => d.listed).length;
      rep.dnsblBlocked = enr.reputation.dnsbl.filter((d) => d.blocked).length;
      rep.torExit = enr.reputation.torExit;
      rep.urlhausCount = enr.reputation.urlhaus.urlCount;
    } catch { /* ignore */ }
  }

  // WHOIS age (only for domain, not raw IP)
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    try {
      const whois = await lookupWhois(host);
      if (whois) {
        rep.whoisCreated = whois.created;
        rep.domainExpires = whois.expires;
        rep.domainAgeDays = daysSince(whois.created);
      }
    } catch { /* ignore */ }
  }

  const verdict = scoreVerdict({
    staticFlags: flags,
    content: content?.indicators || [],
    httpStatus: http?.status ?? null,
    redirects,
    tlsExpired: !!tls?.expired,
    tlsSelfSigned: !!tls?.selfSigned,
    tlsMismatch: !!tls?.hostnameMismatch,
    rep,
  });

  // WordPress mshots — keyless real screenshot service
  const screenshotUrl = `https://s.wordpress.com/mshots/v1/${encodeURIComponent(http?.finalUrl || clean)}?w=960`;

  const baseResult = {
    url: clean,
    host,
    timestamp: new Date().toISOString(),
    source: 'NEXUS Real Sandbox (HTTP/TLS/content capture + DNSBL/WHOIS)',
    live: true,
    http: http ? { ...http, html: null } : null,
    redirects,
    tls,
    content,
    resources,
    reputation: rep,
    staticFlags: flags,
    verdict,
    screenshotUrl,
  };

  // External dynamic detonation — phase 1 (submit). Detonation takes minutes,
  // so we only submit and return job IDs. The client polls the results via
  // GET /api/osint/sandbox?action=poll.
  let external: ExternalJob[] | undefined;
  if (opts?.external) {
    try {
      const sources = configuredExternalSources();
      if (sources.length > 0) {
        const submitted = await Promise.allSettled(submitExternal(clean));
        external = submitted
          .map((s, i) => (s.status === 'fulfilled' && s.value ? s.value : { source: sources[i], jobId: '', status: 'error' as const, error: 'Submit failed' }))
          .filter((j) => j.status !== 'error');
      }
    } catch {
      /* external sandbox errors are non-fatal */
    }
  }

  return external && external.length > 0 ? { ...baseResult, external } : baseResult;
}

// Merges completed external results into a base result, producing a combined
// verdict (highest score + severity, deduped reasons/indicators).
export function mergeExternalResults(base: SandboxResult, jobs: ExternalJob[]): SandboxResult {
  const completed = jobs.filter((j) => j.status === 'completed' && j.result);
  if (completed.length === 0) return base;

  let maxScore = base.verdict.score;
  let maxLevel = base.verdict.level;
  const levelOrder = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS'];
  const allReasons = [...base.verdict.reasons];
  const allIndicators = [...(base.content?.indicators || [])];
  const allStaticFlags = [...base.staticFlags];

  for (const job of completed) {
    const r = job.result!;
    if (r.verdict.score > maxScore) maxScore = r.verdict.score;
    if (levelOrder.indexOf(r.verdict.level) > levelOrder.indexOf(maxLevel)) maxLevel = r.verdict.level;
    allReasons.push(...r.verdict.reasons.map((reason) => `[${job.source}] ${reason}`));
    if (r.content) allIndicators.push(...r.content.indicators);
    allStaticFlags.push(...r.staticFlags);
  }

  return {
    ...base,
    content: base.content ? { ...base.content, indicators: allIndicators } : base.content,
    staticFlags: allStaticFlags,
    verdict: {
      score: Math.min(maxScore, 100),
      level: maxLevel,
      verdict:
        maxScore >= 30
          ? 'Strong malicious signals (including external detonation).'
          : maxScore >= 12
            ? 'Suspicious signals (including external detonation).'
            : 'No significant malicious signals.',
      reasons: allReasons,
    },
  };
}

// Polls a single external job (phase 2).
export function pollSandboxJob(url: string, host: string, job: ExternalJob): Promise<ExternalJob> {
  return pollExternal(job, url, host);
}
