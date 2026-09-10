import { NextResponse } from 'next/server';

export const maxDuration = 60;

interface IpIntelRequest {
  ip: string;
  version: 'ipv4' | 'ipv6';
}

const VT_BASE = 'https://www.virustotal.com/api/v3';

function vtAuth(headers: Record<string, string>): Record<string, string> {
  if (process.env.VIRUSTOTAL_API_KEY) {
    headers['x-apikey'] = process.env.VIRUSTOTAL_API_KEY;
  }
  return headers;
}

function vtEnabled(): boolean {
  return Boolean(process.env.VIRUSTOTAL_API_KEY);
}

const EMPTY_STATS = { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 };

async function lookupVirusTotalIp(ip: string): Promise<null | {
  source: string;
  analyzed: boolean;
  url: string;
  reputation: number;
  lastAnalysisDate: string | null;
  lastAnalysisStats: { malicious: number; suspicious: number; undetected: number; harmless: number; timeout: number };
  totalEngines: number;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  categories: string[];
  votes: { harmless: number; malicious: number };
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  asn?: string;
  country?: string;
}> {
  if (!vtEnabled()) return null;
  try {
    const res = await fetch(`${VT_BASE}/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY || '' },
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const attrs = data.data?.attributes;
    if (!attrs) return null;
    const stats = attrs.last_analysis_stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 };
    const vTtl = stats.malicious + stats.suspicious;
    return {
      source: 'VirusTotal',
      analyzed: true,
      url: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
      reputation: attrs.reputation ?? 0,
      lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      lastAnalysisStats: stats,
      totalEngines: stats.malicious + stats.suspicious + stats.undetected + stats.harmless + stats.timeout,
      verdict: stats.malicious > 0 ? 'MALICIOUS' : stats.suspicious > 0 ? 'SUSPICIOUS' : (stats.malicious + stats.suspicious) === 0 && stats.harmless > 0 ? 'CLEAN' : 'UNKNOWN',
      categories: Object.values(attrs.categories || {}),
      votes: attrs.total_votes || { harmless: 0, malicious: 0 },
      tags: (attrs.tags || []).slice(0, 12),
      firstSeen: attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toISOString() : null,
      lastSeen: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      asn: attrs.asn,
      country: attrs.country,
    };
  } catch (e) {
    console.log('[VT] IP lookup failed:', e);
    return null;
  }
}

interface IpIntelResponse {
  ip: string;
  version: 'ipv4' | 'ipv6';
  reputation: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  threatScore: number;
  categories: string[];
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  asn: string;
  isp: string;
  org: string;
  range: string;
  recentReports: Array<{
    timestamp: string;
    description: string;
    source: string;
  }>;
  sources: string[];
}

function mockIpIntel(ip: string, version: 'ipv4' | 'ipv6'): IpIntelResponse {
  const reputations: Array<'clean' | 'suspicious' | 'malicious' | 'unknown'> = ['clean', 'suspicious', 'malicious', 'unknown'];
  const categories = ['botnet', 'scanner', 'tor', 'vpn', 'proxy', 'malware', 'phishing', 'spam', 'brute-force', 'ddos'];
  const countries = [
    { name: 'United States', code: 'US', region: 'California', city: 'San Francisco', lat: 37.7749, lon: -122.4194 },
    { name: 'China', code: 'CN', region: 'Beijing', city: 'Beijing', lat: 39.9042, lon: 116.4074 },
    { name: 'Russia', code: 'RU', region: 'Moscow', city: 'Moscow', lat: 55.7558, lon: 37.6173 },
    { name: 'Brazil', code: 'BR', region: 'São Paulo', city: 'São Paulo', lat: -23.5505, lon: -46.6333 },
    { name: 'Germany', code: 'DE', region: 'Bavaria', city: 'Munich', lat: 48.1374, lon: 11.5755 },
    { name: 'Colombia', code: 'CO', region: 'Bogotá', city: 'Bogotá', lat: 4.7110, lon: -74.0721 },
  ];
  
  const country = countries[Math.floor(Math.random() * countries.length)];
  const reputation = reputations[Math.floor(Math.random() * reputations.length)];
  const threatScore = reputation === 'malicious' ? 70 + Math.floor(Math.random() * 30) : 
                      reputation === 'suspicious' ? 30 + Math.floor(Math.random() * 40) : 
                      Math.floor(Math.random() * 30);
  const selectedCategories = categories.slice(0, Math.floor(Math.random() * 4) + 1).sort(() => Math.random() - 0.5);

  return {
    ip,
    version,
    reputation,
    threatScore,
    categories: selectedCategories,
    country: country.name,
    countryCode: country.code,
    region: country.region,
    city: country.city,
    lat: country.lat,
    lon: country.lon,
    asn: `AS${Math.floor(Math.random() * 65535) + 1}`,
    isp: ['Cloudflare', 'Google', 'Amazon', 'Microsoft', 'DigitalOcean', 'OVH', 'Hetzner'][Math.floor(Math.random() * 7)],
    org: ['Cloudflare Inc.', 'Google LLC', 'Amazon Technologies', 'Microsoft Corporation', 'DigitalOcean LLC'][Math.floor(Math.random() * 5)],
    range: version === 'ipv4' ? `${ip.split('.').slice(0, 3).join('.')}.0/24` : `${ip.split(':').slice(0, 4).join(':')}::/64`,
    recentReports: Array.from({ length: Math.floor(Math.random() * 5) + 1 }, (_, i) => ({
      timestamp: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
      description: ['Intento de fuerza bruta SSH', 'Escaneo de puertos masivo', 'Tráfico de botnet detectado', 'Conexión a C2 conocida', 'Phishing hosting'][Math.floor(Math.random() * 5)],
      source: ['AbuseIPDB', 'AlienVault OTX', 'Spamhaus', 'Emerging Threats', 'FireHOL'][Math.floor(Math.random() * 5)],
    })),
    sources: ['AbuseIPDB', 'AlienVault OTX', 'Spamhaus', 'Emerging Threats', 'FireHOL', 'Greynoise', 'Shodan'].slice(0, Math.floor(Math.random() * 4) + 3),
  };
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { ip, version } = body;

    if (!ip || !version) {
      return NextResponse.json(
        { error: 'IP y versión (ipv4/ipv6) son requeridas' },
        { status: 400 }
      );
    }

    if (version !== 'ipv4' && version !== 'ipv6') {
      return NextResponse.json(
        { error: 'Versión debe ser ipv4 o ipv6' },
        { status: 400 }
      );
    }

    const validation = {
      ipv4: /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/,
      ipv6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{1,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?\d?)\d)\.){3,3}(25[0-5]|(2[0-4]|1?\d?)\d)|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?\d?)\d)\.){3,3}(25[0-5]|(2[0-4]|1?\d?)\d))$/,
    };

    if (!validation[version].test(ip)) {
      return NextResponse.json(
        { error: `Dirección ${version.toUpperCase()} inválida` },
        { status: 400 }
      );
    }

    const result = mockIpIntel(ip, version);
    const vt = await lookupVirusTotalIp(ip);

    return NextResponse.json({
      success: true,
      scanId: `ipintel_${Date.now()}`,
      timestamp: new Date().toISOString(),
      ...result,
      virusTotal: vt,
    });

  } catch (error: unknown) {
    console.error('IP Intel error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error en el análisis IP';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = searchParams.get('ip');
  const version = searchParams.get('version') as 'ipv4' | 'ipv6' | null;
  
  if (!ip || !version) {
    return NextResponse.json(
      { error: 'Parámetros ip y version requeridos' },
      { status: 400 }
    );
  }

  const validation = {
    ipv4: /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/,
    ipv6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{1,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/,
  };

  if (!validation[version].test(ip)) {
    return NextResponse.json(
      { error: `Dirección ${version.toUpperCase()} inválida` },
      { status: 400 }
    );
  }

  const result = mockIpIntel(ip, version);
  
  return NextResponse.json({
    success: true,
    scanId: `ipintel_${Date.now()}`,
    timestamp: new Date().toISOString(),
    ...result,
  });
}