// URL Scanner orchestrator + scoring.
// Builds on the sandbox's real HTTP/TLS/content capture, then adds attack-
// surface analysis: sensitive-path fuzzing, phishing-kit download & hashing,
// exfiltration attribution and artifact (IoC) collection. Keyless — all
// signals come from real requests against the target plus free reputation
// lookups (ip-api, DNSBL, Tor, URLhaus, RDAP WHOIS).

import type {
  SandboxVerdict,
  UrlScannerResult,
} from './types';
import type { ContentIndicator, DomainReputation, StaticFlag } from '@/lib/intel/sandbox/types';
import { captureHttp, captureTls, analyzeContent, probeResources } from '@/lib/intel/sandbox/engine';
import { staticFlags, detectBrandImpersonation } from '@/lib/intel/sandbox/index';
import { fuzzPaths, probeBaseline, looksLikeBaseline, downloadKitFiles, fingerprintKitFiles, collectExfil, collectArtifacts } from './engine';
import { enrichIP } from '@/lib/intel/ipenrich';
import { lookupIP } from '@/lib/intel';
import { lookupWhois, daysSince } from '@/lib/intel/domain/whois';

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function scoreScanner(params: {
  staticFlags: StaticFlag[];
  content: ContentIndicator[];
  httpStatus: number | null;
  tlsExpired: boolean;
  tlsSelfSigned: boolean;
  tlsMismatch: boolean;
  rep: DomainReputation;
  exposedSensitive: number;
  kitDetected: boolean;
  kitConfidence: number;
  exfilCount: number;
  youngDomainDays: number | null;
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

  if (params.tlsExpired) { score += 5; reasons.push('TLS certificate expired'); }
  if (params.tlsSelfSigned) { score += 4; reasons.push('Self-signed TLS certificate'); }
  if (params.tlsMismatch) { score += 4; reasons.push('TLS hostname mismatch'); }
  if (params.httpStatus === null) { score += 4; reasons.push('Host unreachable / handshake failed'); }

  if (params.exposedSensitive > 0) {
    score += Math.min(params.exposedSensitive * 3, 15);
    reasons.push(`${params.exposedSensitive} sensitive path(s) exposed`);
  }

  if (params.kitDetected) {
    score += Math.round(10 + params.kitConfidence * 10);
    reasons.push('Phishing-kit signature matched');
  }

  if (params.exfilCount > 0) {
    score += Math.min(params.exfilCount * 4, 16);
    reasons.push(`${params.exfilCount} exfiltration endpoint(s)`);
  }

  if (params.rep.dnsblListed >= 2) { score += Math.min(params.rep.dnsblListed * 3, 12); reasons.push(`${params.rep.dnsblListed} DNSBL listing(s)`); }
  if (params.rep.torExit) { score += 8; reasons.push('IP is a Tor exit node'); }
  if (params.rep.urlhausCount > 0) { score += Math.min(params.rep.urlhausCount * 2, 10); reasons.push(`${params.rep.urlhausCount} URLhaus hit(s)`); }
  if (params.rep.proxy) { score += 4; reasons.push('IP flagged as proxy/VPN'); }
  if (params.rep.hosting) { score += 2; reasons.push('Hosting / data-center range'); }
  if (params.youngDomainDays !== null && params.youngDomainDays < 30) { score += 6; reasons.push(`Very young domain (${params.youngDomainDays} days)`); }
  else if (params.youngDomainDays !== null && params.youngDomainDays < 365) { score += 3; reasons.push(`Young domain (${params.youngDomainDays} days)`); }

  const level: SandboxVerdict['level'] = score >= 30 ? 'MALICIOUS' : score >= 12 ? 'SUSPICIOUS' : 'BENIGN';
  const verdict =
    score >= 30
      ? 'High-risk attack surface: exposed files, kit signatures and/or exfiltration channels.'
      : score >= 12
        ? 'Suspicious attack surface — additional verification recommended.'
        : 'No significant attack-surface signals observed.';

  return { score: Math.min(score, 100), level, verdict, reasons };
}

export async function scanUrl(url: string): Promise<UrlScannerResult> {
  let clean = url.trim();
  if (!/^https?:\/\//i.test(clean)) clean = `https://${clean}`;
  const host = hostOf(clean);
  const origin = originOf(clean);

  const flags = staticFlags(clean);
  const impersonation = detectBrandImpersonation(host);
  if (impersonation) flags.push(impersonation);

  // Real HTTP + TLS capture
  const [httpResult, tls] = await Promise.all([
    captureHttp(clean),
    (() => { try { return captureTls(clean); } catch { return null; } })(),
  ]);
  const { http, redirects } = httpResult;

  const content = http?.html ? analyzeContent(http.html, host) : null;
  const resources = http?.html ? await probeResources(http.html, http.finalUrl) : [];

  // Attack surface — fuzz from origin root
  const [fuzz, baseline] = await Promise.all([fuzzPaths(origin + '/'), probeBaseline(origin + '/')]);
  // Only 2xx counts as truly exposed (3xx redirects are common on legit panels),
  // and responses identical to the catch-all baseline (SPA) are discounted.
  const exposedSensitive = fuzz.filter(
    (f) => f.sensitive && f.status !== null && f.status >= 200 && f.status < 300 && !looksLikeBaseline(f, baseline)
  ).length;

  // Attribution + artifacts
  const exfil = collectExfil(content, http?.finalUrl || clean);
  const artifacts = collectArtifacts({ content, resources, exfil, host });

  // Download + fingerprint kit files (generic families need strong exfil evidence:
  // telegram bot, off-domain form post, or http-post receiver — not just an email)
  const kitFiles = await downloadKitFiles(http?.finalUrl || clean, content, resources);
  const hasStrongExfil = exfil.some((e) => e.kind !== 'email');
  const kitMatches = fingerprintKitFiles(kitFiles, hasStrongExfil);
  const kitDetected = kitMatches.length > 0;
  const kitConfidence = kitMatches.reduce((acc, m) => Math.max(acc, m.confidence), 0);

  // Reputation: resolve first A record → ip-api geo + DNSBL/Tor/URLhaus via enrichIP
  const rep: DomainReputation = {
    ip: null, geo: null, asn: null, isp: null,
    dnsblListed: 0, dnsblBlocked: 0, torExit: false, urlhausCount: 0,
    hosting: false, proxy: false,
    whoisCreated: null, domainAgeDays: null, domainExpires: null,
  };
  try {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      rep.ip = host;
    } else {
      const recs = await import('@/lib/intel/domain/dns').then((m) => m.resolveType(host, 'A'));
      rep.ip = recs[0]?.data || null;
    }
  } catch { /* ignore */ }

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

  const verdict = scoreScanner({
    staticFlags: flags,
    content: content?.indicators || [],
    httpStatus: http?.status ?? null,
    tlsExpired: !!tls?.expired,
    tlsSelfSigned: !!tls?.selfSigned,
    tlsMismatch: !!tls?.hostnameMismatch,
    rep,
    exposedSensitive,
    kitDetected,
    kitConfidence,
    exfilCount: exfil.filter((e) => e.kind !== 'email').length,
    youngDomainDays: rep.domainAgeDays,
  });

  const screenshotUrl = `https://s.wordpress.com/mshots/v1/${encodeURIComponent(http?.finalUrl || clean)}?w=960`;

  return {
    url: clean,
    host,
    timestamp: new Date().toISOString(),
    source: 'NEXUS URL Scanner (attack-surface + kit fingerprint + attribution)',
    live: true,
    http: http ? { ...http, html: null } : null,
    redirects,
    tls,
    content,
    resources,
    fuzz,
    kitFiles,
    kit: { detected: kitDetected, matches: kitMatches },
    exfil,
    artifacts,
    staticFlags: flags,
    verdict,
    screenshotUrl,
  };
}
