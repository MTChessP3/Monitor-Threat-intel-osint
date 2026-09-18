// Intelligence source registry.
// Manages a dynamic list of OSINT/threat-intel sources that the platform can
// query. Built-in sources are seeded on first run; users can add custom ones
// at runtime (persisted to KV).

import { kvGet, kvSet, kvPushList, kvGetList, kvRemoveFromList, kvHealth } from '@/lib/kv';

export type SourceType =
  | 'THREAT_FEED'
  | 'GEO_IP'
  | 'DNS'
  | 'CVE'
  | 'REPUTATION'
  | 'BREACH'
  | 'AI'
  | 'CUSTOM';

export interface IntelSource {
  id: string;
  name: string;
  type: SourceType;
  method: 'GET' | 'POST';
  endpoint: string;
  apiKeyEnv?: string;
  enabled: boolean;
  builtin: boolean;
  description: string;
  createdAt: string;
  lastTested?: string;
  lastStatus?: 'ok' | 'error';
}

const SOURCES_KEY = 'nexus:sources';

const BUILTIN_SOURCES: Omit<IntelSource, 'createdAt'>[] = [
  {
    id: 'src-cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities',
    type: 'THREAT_FEED',
    method: 'GET',
    endpoint: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    enabled: true,
    builtin: true,
    description: 'Official CISA catalog of actively exploited vulnerabilities (free, no key).',
  },
  {
    id: 'src-malwarebazaar',
    name: 'MalwareBazaar (Abuse.ch)',
    type: 'THREAT_FEED',
    method: 'POST',
    endpoint: 'https://mb-api.abuse.ch/api/v1/',
    enabled: true,
    builtin: true,
    description: 'Recent malware samples and hashes from Abuse.ch (free, no key).',
  },
  {
    id: 'src-abusech-sslbl',
    name: 'Abuse.ch SSL Blacklist',
    type: 'THREAT_FEED',
    method: 'GET',
    endpoint: 'https://sslbl.abuse.ch/blacklist/json/',
    enabled: true,
    builtin: true,
    description: 'Malicious SSL certificates associated with botnets (free, no key).',
  },
  {
    id: 'src-nvd',
    name: 'NIST NVD (CVE Database)',
    type: 'CVE',
    method: 'GET',
    endpoint: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    apiKeyEnv: 'NVD_API_KEY',
    enabled: true,
    builtin: true,
    description: 'National Vulnerability Database — official CVE catalog.',
  },
  {
    id: 'src-ip-api',
    name: 'ip-api.com (Geolocation)',
    type: 'GEO_IP',
    method: 'GET',
    endpoint: 'http://ip-api.com/json/{query}',
    enabled: true,
    builtin: true,
    description: 'Free IP geolocation and ISP intelligence (HTTP, 45 req/min free).',
  },
  {
    id: 'src-google-doh',
    name: 'Google DNS-over-HTTPS',
    type: 'DNS',
    method: 'GET',
    endpoint: 'https://dns.google/resolve?name={query}&type=A',
    enabled: true,
    builtin: true,
    description: 'Public DNS resolution via Google DoH.',
  },
  {
    id: 'src-virustotal',
    name: 'VirusTotal',
    type: 'REPUTATION',
    method: 'GET',
    endpoint: 'https://www.virustotal.com/api/v3/search?query={query}',
    apiKeyEnv: 'VIRUSTOTAL_API_KEY',
    enabled: false,
    builtin: true,
    description: 'Multi-engine file/IP/domain reputation (requires VIRUSTOTAL_API_KEY).',
  },
  {
    id: 'src-groq-ai',
    name: 'Groq AI (LLM Analysis)',
    type: 'AI',
    method: 'POST',
    endpoint: 'https://api.groq.com/openai/v1/chat/completions',
    apiKeyEnv: 'GROQ_API_KEY',
    enabled: true,
    builtin: true,
    description: 'Fast open-source LLMs for AI threat analysis (requires GROQ_API_KEY).',
  },
];

export async function getSources(): Promise<IntelSource[]> {
  const sources = await kvGetList<IntelSource>(SOURCES_KEY);
  if (sources.length === 0) {
    const seeded = BUILTIN_SOURCES.map((s) => ({
      ...s,
      createdAt: new Date().toISOString(),
    }));
    await kvSet(SOURCES_KEY, seeded);
    return seeded;
  }
  return sources;
}

export async function getEnabledSources(type?: SourceType): Promise<IntelSource[]> {
  const sources = await getSources();
  return sources.filter((s) => s.enabled && (!type || s.type === type));
}

export async function getSourceById(id: string): Promise<IntelSource | null> {
  const sources = await getSources();
  return sources.find((s) => s.id === id) || null;
}

export function generateSourceId(name: string): string {
  return `src-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
}

export async function addSource(data: {
  name: string;
  type: SourceType;
  method?: 'GET' | 'POST';
  endpoint: string;
  apiKeyEnv?: string;
  enabled?: boolean;
  description?: string;
}): Promise<IntelSource> {
  const source: IntelSource = {
    id: generateSourceId(data.name),
    name: data.name,
    type: data.type,
    method: data.method || 'GET',
    endpoint: data.endpoint,
    apiKeyEnv: data.apiKeyEnv,
    enabled: data.enabled ?? true,
    builtin: false,
    description: data.description || '',
    createdAt: new Date().toISOString(),
  };
  await kvPushList(SOURCES_KEY, source, 100);
  return source;
}

export async function updateSource(
  id: string,
  patch: Partial<Pick<IntelSource, 'name' | 'type' | 'method' | 'endpoint' | 'apiKeyEnv' | 'enabled' | 'description' | 'lastTested' | 'lastStatus'>>
): Promise<IntelSource | null> {
  const sources = await getSources();
  const index = sources.findIndex((s) => s.id === id);
  if (index === -1) return null;
  sources[index] = { ...sources[index], ...patch };
  await kvSet(SOURCES_KEY, sources);
  return sources[index];
}

export async function deleteSource(id: string): Promise<boolean> {
  const sources = await getSources();
  const target = sources.find((s) => s.id === id);
  if (!target) return false;
  if (target.builtin) {
    // Built-in sources can only be disabled, not removed
    await updateSource(id, { enabled: false });
    return false;
  }
  await kvRemoveFromList<IntelSource>(SOURCES_KEY, (s) => s.id === id);
  return true;
}

export async function testSource(id: string): Promise<{ ok: boolean; message: string; status?: number }> {
  const source = await getSourceById(id);
  if (!source) return { ok: false, message: 'Source not found' };

  const apiKey = source.apiKeyEnv ? process.env[source.apiKeyEnv] || '' : '';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const headers: Record<string, string> = {
      'User-Agent': 'NEXUS-INTEL/1.0',
      Accept: 'application/json',
    };
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
      headers['X-Apikey'] = apiKey;
    }

    const endpoint = source.endpoint.replace('{query}', 'example.com');
    const response =
      source.method === 'POST'
        ? await fetch(endpoint, {
            method: 'POST',
            headers,
            body: 'query=get_recent&limit=1',
            signal: controller.signal,
          })
        : await fetch(endpoint, { method: 'GET', headers, signal: controller.signal });

    clearTimeout(timeoutId);

    await updateSource(id, {
      lastTested: new Date().toISOString(),
      lastStatus: response.ok ? 'ok' : 'error',
    });

    return {
      ok: response.ok,
      status: response.status,
      message: response.ok
        ? `Source reachable (HTTP ${response.status})`
        : `Source returned HTTP ${response.status}`,
    };
  } catch (error) {
    await updateSource(id, {
      lastTested: new Date().toISOString(),
      lastStatus: 'error',
    });
    return {
      ok: false,
      message: error instanceof Error ? error.message : 'Connection failed',
    };
  }
}

export async function getSourcesHealth() {
  const sources = await getSources();
  const kv = await kvHealth();
  return {
    kv,
    totalSources: sources.length,
    enabledSources: sources.filter((s) => s.enabled).length,
    builtin: sources.filter((s) => s.builtin).length,
    custom: sources.filter((s) => !s.builtin).length,
  };
}
