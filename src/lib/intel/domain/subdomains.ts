// Subdomain enumeration for the Domain Intel module.
// Passive sources: crt.sh (Certificate Transparency) + a bounded brute-force
// via Google DoH. All results are deduplicated and normalized.

import type { DnsRecord, SubdomainInfo } from './types';
import { resolveType } from './dns';

const CT_TIMEOUT = 12000;
const BRUTE_MAX_WORDS = 24;
const IP4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

const BRUTE_WORDS = [
  'www', 'mail', 'api', 'dev', 'staging', 'blog', 'shop', 'app', 'admin',
  'portal', 'vpn', 'cdn', 'mx', 'smtp', 'ns1', 'ns2', 'ftp', 'gateway',
  'remote', 'webmail', 'owa', 'autodiscover', 'git', 'jira',
];

interface CtCert {
  name_value?: string;
  common_name?: string;
  not_before?: string;
}

async function fromCertificateTransparency(domain: string): Promise<SubdomainInfo[]> {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(CT_TIMEOUT),
      headers: { 'User-Agent': 'NEXUS-INTEL/1.0' },
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (!Array.isArray(data)) return [];

    const seen = new Set<string>();
    const out: SubdomainInfo[] = [];
    for (const cert of data as CtCert[]) {
      const names = String(cert.name_value || cert.common_name || '')
        .split('\n')
        .map((n) => n.trim().replace(/^\*\./, ''))
        .filter((n) => n.endsWith(domain) && n.length > domain.length);
      for (const name of names) {
        if (seen.has(name)) continue;
        seen.add(name);
        out.push({ name, ips: [], cname: null, source: 'ct' });
        if (out.length >= 60) return out;
      }
    }
    return out;
  } catch {
    return [];
  }
}

async function fromBruteForce(domain: string): Promise<SubdomainInfo[]> {
  const words = BRUTE_WORDS.slice(0, BRUTE_MAX_WORDS);
  const settled = await Promise.allSettled(
    words.map(async (w): Promise<SubdomainInfo | null> => {
      const recs = await resolveType(`${w}.${domain}`, 'A');
      const ips = recs.map((r) => r.data).filter((d) => IP4_RE.test(d));
      if (ips.length === 0) return null;
      return {
        name: `${w}.${domain}`,
        ips,
        cname: null,
        source: 'brute' as const,
      };
    })
  );
  return settled
    .filter((s): s is PromiseFulfilledResult<SubdomainInfo | null> => s.status === 'fulfilled')
    .map((s) => s.value)
    .filter((v): v is SubdomainInfo => v !== null);
}

export async function enumerateSubdomains(domain: string): Promise<SubdomainInfo[]> {
  const [ct, brute] = await Promise.all([fromCertificateTransparency(domain), fromBruteForce(domain)]);
  const seen = new Set<string>();
  const merged: SubdomainInfo[] = [];
  for (const sub of [...brute, ...ct]) {
    if (seen.has(sub.name)) continue;
    seen.add(sub.name);
    merged.push(sub);
  }
  return merged;
}

// Resolve A/CNAME for each subdomain (bounded concurrency) so the graph can
// link subdomains -> IPs. Only runs for a capped set to respect rate limits.
export async function resolveSubdomainRecords(
  subs: SubdomainInfo[],
  max = 40
): Promise<SubdomainInfo[]> {
  const targets = subs.slice(0, max);
  const settled = await Promise.allSettled(
    targets.map(async (sub) => {
      const [a, cname] = await Promise.all([
        resolveType(sub.name, 'A'),
        resolveType(sub.name, 'CNAME'),
      ]);
      sub.ips = a.map((r: DnsRecord) => r.data).filter((d) => IP4_RE.test(d));
      sub.cname = cname[0]?.data || null;
      return sub;
    })
  );
  return settled
    .filter((s): s is PromiseFulfilledResult<SubdomainInfo> => s.status === 'fulfilled')
    .map((s) => s.value);
}
