// Infrastructure enrichment for the Domain Intel module.
// Geo/ASN via ip-api.com (free tier), BGP prefix via BGPView, reverse DNS via
// ip-api reverse field (fallback: node dns). Bounded concurrency to respect
// the free-tier rate limits.

import { promises as dns } from 'dns';
import type { IpInfo, MxHostInfo } from './types';

const IPAPI = 'http://ip-api.com/json';
const IPAPI_FIELDS = 'status,message,country,countryCode,regionName,city,isp,org,as,asname,lat,lon,reverse,hosting,proxy,query';
const MAX_CONCURRENT = 6;
const MAX_IPS = 12;

async function lookupIp(ip: string): Promise<IpInfo | null> {
  try {
    const res = await fetch(`${IPAPI}/${encodeURIComponent(ip)}?fields=${IPAPI_FIELDS}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const d = await res.json();
    if (d.status !== 'success') return null;
    return {
      ip: d.query,
      reverse: d.reverse || null,
      country: d.country || 'Unknown',
      countryCode: d.countryCode || '',
      region: d.regionName || '',
      city: d.city || '',
      isp: d.isp || 'Unknown ISP',
      org: d.org || '',
      asn: (d.as || '').replace(/\s.*$/, ''),
      asname: d.asname || '',
      lat: d.lat || 0,
      lon: d.lon || 0,
      hosting: !!d.hosting,
      proxy: !!d.proxy,
    };
  } catch {
    return null;
  }
}

async function reverseFallback(ip: string): Promise<string | null> {
  try {
    const records = await dns.reverse(ip);
    return records[0] || null;
  } catch {
    return null;
  }
}

export async function enrichIps(ips: string[]): Promise<IpInfo[]> {
  const unique = [...new Set(ips.filter((ip) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)))].slice(0, MAX_IPS);
  const out: IpInfo[] = [];
  for (let i = 0; i < unique.length; i += MAX_CONCURRENT) {
    const chunk = unique.slice(i, i + MAX_CONCURRENT);
    const settled = await Promise.allSettled(chunk.map((ip) => lookupIp(ip)));
    for (let j = 0; j < chunk.length; j++) {
      const s = settled[j];
      if (s.status === 'fulfilled' && s.value) {
        out.push(s.value);
      } else {
        const reverse = await reverseFallback(chunk[j]);
        out.push({
          ip: chunk[j],
          reverse,
          country: 'Unknown',
          countryCode: '',
          region: '',
          city: '',
          isp: 'Unknown ISP',
          org: '',
          asn: '',
          asname: '',
          lat: 0,
          lon: 0,
          hosting: false,
          proxy: false,
        });
      }
    }
  }
  return out;
}

export async function enrichMxHosts(hosts: { host: string; priority: number }[]): Promise<MxHostInfo[]> {
  const out: MxHostInfo[] = [];
  for (const h of hosts) {
    let ip: string | null = null;
    let asn: string | null = null;
    let asname: string | null = null;
    try {
      const recs = await dns.resolve4(h.host);
      ip = recs[0] || null;
    } catch {
      ip = null;
    }
    if (ip) {
      try {
        const res = await fetch(`${IPAPI}/${encodeURIComponent(ip)}?fields=${IPAPI_FIELDS}`, {
          signal: AbortSignal.timeout(6000),
        });
        const d = await res.json();
        if (d.status === 'success') {
          asn = (d.as || '').replace(/\s.*$/, '') || null;
          asname = d.asname || null;
        }
      } catch {
        /* ignore */
      }
    }
    out.push({ host: h.host, priority: h.priority, ip, asn, asname });
  }
  return out;
}

// BGPView prefix info — used to show the announced prefix for an IP.
export async function lookupBgpPrefix(ip: string): Promise<{ prefix: string | null; name: string | null }> {
  try {
    const res = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return { prefix: null, name: null };
    const d = await res.json();
    const prefix = d?.data?.prefixes?.[0]?.prefix || null;
    const name = d?.data?.asn?.name || null;
    return { prefix, name };
  } catch {
    return { prefix: null, name: null };
  }
}
