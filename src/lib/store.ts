// Data store backed by Vercel KV (Upstash Redis) with in-memory fallback.
// Persists IOCs, analyses and alerts across serverless invocations.

import {
  kvGet,
  kvSet,
  kvPushList,
  kvGetList,
  kvRemoveFromList,
  kvListKeys,
  kvHealth,
  getStorageBackend,
} from '@/lib/kv';

export { kvGet, kvSet, kvDel, kvListKeys, kvHealth, isKVConfigured, getStorageBackend } from '@/lib/kv';

export interface IOC {
  id: string;
  type: string;
  value: string;
  description: string;
  severity: string;
  confidence: number;
  status: string;
  source: string;
  tags: string[];
  firstSeen: string;
  lastUpdated: string;
  rawResponse?: string;
}

export interface Analysis {
  id: string;
  iocId: string;
  source: string;
  sourceType: string;
  rawData: string;
  summary?: string;
  findings: string[];
  verified: boolean;
  timestamp: string;
}

export interface Alert {
  id: string;
  iocId?: string;
  title: string;
  description: string;
  severity: string;
  type: string;
  status: string;
  createdAt: string;
}

const IOCS_KEY = 'nexus:iocs';
const ANALYSES_KEY = 'nexus:analyses';
const ALERTS_KEY = 'nexus:alerts';
const MAX_IOCS = 500;
const MAX_ANALYSES = 2000;
const MAX_ALERTS = 500;

// Seed sample IOCs so the dashboard always has meaningful data
const SAMPLE_IOCS: IOC[] = [
  {
    id: 'ioc-001',
    type: 'IP',
    value: '185.220.101.34',
    description: 'Known Tor exit node - Berlin, Germany',
    severity: 'MEDIUM',
    confidence: 92,
    status: 'SUSPICIOUS',
    source: 'ip-api.com',
    tags: ['tor', 'exit-node', 'proxy'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  },
  {
    id: 'ioc-002',
    type: 'DOMAIN',
    value: 'evil.com',
    description: 'Known malicious domain - phishing infrastructure',
    severity: 'HIGH',
    confidence: 95,
    status: 'MALICIOUS',
    source: 'ThreatIntel',
    tags: ['phishing', 'malware', 'c2'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  },
  {
    id: 'ioc-003',
    type: 'HASH',
    value: '44d88612fea8a8f36de82e1278abb02f',
    description: 'MD5 test hash - EICAR test file',
    severity: 'LOW',
    confidence: 100,
    status: 'BENIGN',
    source: 'VirusTotal',
    tags: ['test', 'eicar'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  },
  {
    id: 'ioc-004',
    type: 'CVE',
    value: 'CVE-2024-3400',
    description: 'PAN-OS Command Injection Vulnerability - Critical RCE in GlobalProtect',
    severity: 'CRITICAL',
    confidence: 98,
    status: 'MALICIOUS',
    source: 'NIST-NVD',
    tags: ['rce', 'palo-alto', 'vpn', 'critical'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  },
  {
    id: 'ioc-005',
    type: 'URL',
    value: 'https://phishing-bank.com/login',
    description: 'Active phishing site targeting bank customers',
    severity: 'CRITICAL',
    confidence: 99,
    status: 'MALICIOUS',
    source: 'PhishTank',
    tags: ['phishing', 'banking', 'credential-theft'],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  },
];

let seeded = false;

async function ensureSeeded(): Promise<void> {
  if (seeded) return;
  seeded = true;
  try {
    const existing = await kvGetList<IOC>(IOCS_KEY);
    if (existing.length === 0) {
      await kvSet(IOCS_KEY, SAMPLE_IOCS);
    }
  } catch (error) {
    console.error('Seed error:', error);
  }
}

// Generate unique ID
export function generateId(prefix: string = 'id'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function getStorageBackendName(): string {
  return getStorageBackend();
}

async function loadIOCs(): Promise<IOC[]> {
  await ensureSeeded();
  return kvGetList<IOC>(IOCS_KEY);
}

// IOC Operations
export async function getIOCs(filters?: {
  type?: string;
  status?: string;
  severity?: string;
  search?: string;
  page?: number;
  limit?: number;
}): Promise<{ data: IOC[]; total: number; page: number; limit: number; totalPages: number }> {
  let filtered = await loadIOCs();

  if (filters?.type) filtered = filtered.filter((i) => i.type === filters.type!.toUpperCase());
  if (filters?.status) filtered = filtered.filter((i) => i.status === filters.status!.toUpperCase());
  if (filters?.severity) filtered = filtered.filter((i) => i.severity === filters.severity!.toUpperCase());
  if (filters?.search) {
    const searchLower = filters.search.toLowerCase();
    filtered = filtered.filter(
      (i) =>
        i.value.toLowerCase().includes(searchLower) ||
        (i.description && i.description.toLowerCase().includes(searchLower)) ||
        (i.source && i.source.toLowerCase().includes(searchLower))
    );
  }

  const page = filters?.page || 1;
  const limit = filters?.limit || 50;
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const start = (page - 1) * limit;

  return {
    data: filtered.slice(start, start + limit),
    total,
    page,
    limit,
    totalPages,
  };
}

export async function getIOCById(id: string): Promise<IOC | null> {
  const all = await loadIOCs();
  return all.find((i) => i.id === id) || null;
}

export async function getIOCByValue(value: string): Promise<IOC | null> {
  const all = await loadIOCs();
  return all.find((i) => i.value.toLowerCase() === value.toLowerCase()) || null;
}

export async function createIOC(data: {
  type: string;
  value: string;
  description?: string;
  severity?: string;
  confidence?: number;
  status?: string;
  source?: string;
  tags?: string[];
}): Promise<IOC> {
  const all = await loadIOCs();
  const existing = all.find(
    (i) => i.value.toLowerCase() === data.value.toLowerCase() && i.type === data.type.toUpperCase()
  );
  if (existing) {
    throw new Error('IOC already exists');
  }

  const newIOC: IOC = {
    id: generateId('ioc'),
    type: data.type.toUpperCase(),
    value: data.value,
    description: data.description || `${data.type}: ${data.value}`,
    severity: (data.severity || 'MEDIUM').toUpperCase(),
    confidence: data.confidence || 50,
    status: (data.status || 'UNKNOWN').toUpperCase(),
    source: data.source || 'manual',
    tags: data.tags || [],
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
  };

  await kvSet(IOCS_KEY, [newIOC, ...all].slice(0, MAX_IOCS));

  try {
    await createAlert({
      iocId: newIOC.id,
      title: `New ${data.type} Added: ${data.value}`,
      description: data.description || 'Manually added indicator of compromise',
      severity: newIOC.severity,
      type: 'IOC_DETECTED',
    });
  } catch (e) {
    /* non-critical */
  }

  return newIOC;
}

export async function updateIOC(
  id: string,
  data: {
    description?: string;
    severity?: string;
    status?: string;
    confidence?: number;
    tags?: string[];
  }
): Promise<IOC | null> {
  const all = await loadIOCs();
  const index = all.findIndex((i) => i.id === id);
  if (index === -1) return null;

  all[index] = { ...all[index], ...data, lastUpdated: new Date().toISOString() };
  await kvSet(IOCS_KEY, all);
  return all[index];
}

export async function deleteIOC(id: string): Promise<boolean> {
  const all = await loadIOCs();
  const index = all.findIndex((i) => i.id === id);
  if (index === -1) return false;

  all.splice(index, 1);
  await kvSet(IOCS_KEY, all);

  // Clean up related records
  const analyses = await kvGetList<Analysis>(ANALYSES_KEY);
  await kvSet(ANALYSES_KEY, analyses.filter((a) => a.iocId !== id));

  const alerts = await kvGetList<Alert>(ALERTS_KEY);
  await kvSet(ALERTS_KEY, alerts.filter((a) => a.iocId !== id));

  return true;
}

export async function upsertIOC(data: {
  type: string;
  value: string;
  description?: string;
  severity?: string;
  confidence?: number;
  status?: string;
  source?: string;
  rawResponse?: string;
  tags?: string[];
}): Promise<IOC> {
  const all = await loadIOCs();
  const index = all.findIndex(
    (i) => i.value.toLowerCase() === data.value.toLowerCase() && i.type === data.type.toUpperCase()
  );

  if (index !== -1) {
    all[index] = {
      ...all[index],
      ...(data.description && { description: data.description }),
      ...(data.severity && { severity: data.severity.toUpperCase() }),
      ...(data.confidence && { confidence: data.confidence }),
      ...(data.status && { status: data.status.toUpperCase() }),
      ...(data.source && { source: data.source }),
      ...(data.rawResponse && { rawResponse: data.rawResponse }),
      ...(data.tags && { tags: data.tags }),
      lastUpdated: new Date().toISOString(),
    };
    await kvSet(IOCS_KEY, all);
    return all[index];
  }

  return createIOC(data);
}

// Analysis Operations
export async function createAnalysis(data: {
  iocId: string;
  source: string;
  sourceType: string;
  rawData: string;
  summary?: string;
  findings?: string[];
  verified?: boolean;
}): Promise<Analysis> {
  const newAnalysis: Analysis = {
    id: generateId('analysis'),
    ...data,
    findings: data.findings || [],
    verified: data.verified || false,
    timestamp: new Date().toISOString(),
  };

  await kvPushList(ANALYSES_KEY, newAnalysis, MAX_ANALYSES);
  return newAnalysis;
}

export async function getAnalysesByIOC(iocId: string): Promise<Analysis[]> {
  const all = await kvGetList<Analysis>(ANALYSES_KEY);
  return all.filter((a) => a.iocId === iocId).slice(0, 3);
}

export async function getRecentAnalyses(limit = 20): Promise<Analysis[]> {
  const all = await kvGetList<Analysis>(ANALYSES_KEY);
  return all.slice(0, limit);
}

// Alert Operations
export async function createAlert(data: {
  iocId?: string;
  title: string;
  description: string;
  severity: string;
  type: string;
}): Promise<Alert> {
  const newAlert: Alert = {
    id: generateId('alert'),
    ...data,
    status: 'ACTIVE',
    createdAt: new Date().toISOString(),
  };

  await kvPushList(ALERTS_KEY, newAlert, MAX_ALERTS);
  return newAlert;
}

export async function getAlerts(options?: { iocId?: string; status?: string }): Promise<Alert[]> {
  let filtered = await kvGetList<Alert>(ALERTS_KEY);

  if (options?.iocId) filtered = filtered.filter((a) => a.iocId === options.iocId);
  if (options?.status) filtered = filtered.filter((a) => a.status === options.status);

  return filtered.slice(0, 20);
}

export async function updateAlertStatus(id: string, status: string): Promise<Alert | null> {
  const all = await kvGetList<Alert>(ALERTS_KEY);
  const index = all.findIndex((a) => a.id === id);
  if (index === -1) return null;
  all[index] = { ...all[index], status };
  await kvSet(ALERTS_KEY, all);
  return all[index];
}

export async function removeAlert(id: string): Promise<boolean> {
  let removed = false;
  await kvRemoveFromList<Alert>(ALERTS_KEY, (a) => {
    if (a.id === id) removed = true;
    return a.id === id;
  });
  return removed;
}

// Stats
export async function getStoreStats() {
  const iocs = await loadIOCs();
  const alerts = await kvGetList<Alert>(ALERTS_KEY);
  return {
    totalIOCs: iocs.length,
    totalAlerts: alerts.filter((a) => a.status === 'ACTIVE').length,
    severityBreakdown: {
      CRITICAL: iocs.filter((i) => i.severity === 'CRITICAL').length,
      HIGH: iocs.filter((i) => i.severity === 'HIGH').length,
      MEDIUM: iocs.filter((i) => i.severity === 'MEDIUM').length,
      LOW: iocs.filter((i) => i.severity === 'LOW').length,
      INFO: iocs.filter((i) => i.severity === 'INFO').length,
    },
    typeBreakdown: {
      IP: iocs.filter((i) => i.type === 'IP').length,
      DOMAIN: iocs.filter((i) => i.type === 'DOMAIN').length,
      URL: iocs.filter((i) => i.type === 'URL').length,
      HASH: iocs.filter((i) => i.type === 'HASH').length,
      CVE: iocs.filter((i) => i.type === 'CVE').length,
      EMAIL: iocs.filter((i) => i.type === 'EMAIL').length,
    },
  };
}
