// Domain Intel orchestrator.
// Assembles DNS records, email security, WHOIS, subdomain enumeration,
// IP/ASN infrastructure, the relationship graph and a risk verdict into a
// single normalized result consumed by the API route and the UI panel.

import type { DomainIntelResult } from './types';
import { resolveDns, analyzeEmailSecurity } from './dns';
import { enumerateSubdomains, resolveSubdomainRecords } from './subdomains';
import { enrichIps, enrichMxHosts } from './infra';
import { lookupWhois } from './whois';
import { buildDomainGraph } from './graph';
import { scoreDomain } from './risk';

export { type DomainIntelResult } from './types';

export async function buildDomainIntel(domain: string): Promise<DomainIntelResult> {
  const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  const [records, email, whois, subdomains] = await Promise.all([
    resolveDns(clean),
    analyzeEmailSecurity(clean),
    lookupWhois(clean),
    enumerateSubdomains(clean),
  ]);

  const resolvedSubs = await resolveSubdomainRecords(subdomains);

  const rootIps = records.A.map((r) => r.data);
  const subIps = resolvedSubs.flatMap((s) => s.ips);
  const mxIps = records.MX.map((r) => r.data.split(/\s+/).pop() || '').filter((h) => h.includes('.'));
  const uniqueIps = [...new Set([...rootIps, ...subIps])].slice(0, 30);

  const [ips, mxHosts] = await Promise.all([
    enrichIps(uniqueIps),
    enrichMxHosts(
      records.MX.map((r) => {
        const parts = r.data.trim().split(/\s+/);
        const priority = parseInt(parts[0], 10) || 10;
        const host = parts[parts.length - 1] || '';
        return { host, priority };
      })
    ),
  ]);

  const graph = buildDomainGraph({ domain: clean, records, subdomains: resolvedSubs, ips, mxHosts });

  const risk = scoreDomain({
    domain: clean,
    records,
    email,
    whois,
    ips,
    subdomainCount: resolvedSubs.length,
  });

  const aCount = records.A.length;
  const summary = records.A.length === 0 && records.NS.length === 0
    ? 'Domain does not resolve (NXDOMAIN)'
    : `Active domain — ${aCount} A record(s), ${records.MX.length} MX, ${records.NS.length} NS, ${resolvedSubs.length} subdomains, ${ips.length} IP(s)`;

  return {
    domain: clean,
    timestamp: new Date().toISOString(),
    source: 'Google-DoH + RDAP + crt.sh + ip-api',
    live: true,
    records,
    emailSecurity: email,
    whois,
    subdomains: resolvedSubs,
    ips,
    mxHosts,
    graph,
    risk,
    summary,
  };
}
