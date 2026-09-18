// Persistent storage layer for serverless environments (Vercel KV / Upstash Redis)
// Falls back to in-memory storage when no KV credentials are configured.
//
// Configure in Vercel: KV_REST_API_URL and KV_REST_API_TOKEN (from a Vercel KV Store)
// or KV_URL. When unset, data lives in memory and resets per invocation.

export interface KVOptions {
  ttl?: number;
}

type MemoryStore = Map<string, string>;

// Shared in-memory store for local dev / no-KV fallback (module singleton)
const memory = new Map<string, string>() as MemoryStore;

const REST_URL = process.env.KV_REST_API_URL || process.env.KV_URL || '';
const REST_TOKEN = process.env.KV_REST_API_TOKEN || process.env.KV_REST_TOKEN || '';

export function isKVConfigured(): boolean {
  return Boolean(REST_URL && REST_TOKEN);
}

export function getStorageBackend(): 'vercel-kv' | 'memory' {
  return isKVConfigured() ? 'vercel-kv' : 'memory';
}

// Encode/decode handles Upstash base64 responses (non-UTF8 payloads)
function decodeResult(raw: unknown, isBase64?: boolean): string | null {
  if (raw === null || raw === undefined) return null;
  if (isBase64 && typeof raw === 'string') {
    try {
      return Buffer.from(raw, 'base64').toString('utf-8');
    } catch {
      return raw;
    }
  }
  return String(raw);
}

async function redisCommand(command: string, args: unknown[]): Promise<unknown> {
  if (!REST_URL) throw new Error('KV not configured');
  const response = await fetch(REST_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${REST_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify([command, ...args]),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) {
    throw new Error(`KV ${command} failed: HTTP ${response.status}`);
  }
  const data = await response.json();
  return data?.result ?? null;
}

export async function kvGet<T>(key: string): Promise<T | null> {
  if (isKVConfigured()) {
    const isBase64 = false;
    const raw = await redisCommand('GET', [key]);
    const value = decodeResult(raw, isBase64);
    if (value === null) return null;
    try {
      return JSON.parse(value) as T;
    } catch {
      return value as unknown as T;
    }
  }
  const mem = memory.get(key);
  if (mem === undefined) return null;
  try {
    return JSON.parse(mem) as T;
  } catch {
    return mem as unknown as T;
  }
}

export async function kvSet<T>(key: string, value: T, options?: KVOptions): Promise<void> {
  const serialized = JSON.stringify(value);
  if (isKVConfigured()) {
    const args: unknown[] = [key, serialized];
    if (options?.ttl) args.push('EX', String(Math.max(1, Math.floor(options.ttl / 1000))));
    await redisCommand('SET', args);
    return;
  }
  memory.set(key, serialized);
}

export async function kvDel(key: string): Promise<void> {
  if (isKVConfigured()) {
    await redisCommand('DEL', [key]);
    return;
  }
  memory.delete(key);
}

export async function kvListKeys(prefix: string): Promise<string[]> {
  if (isKVConfigured()) {
    try {
      const cursor = '0';
      const raw = await redisCommand('SCAN', [cursor, 'MATCH', `${prefix}*`, 'COUNT', '200']);
      if (Array.isArray(raw) && Array.isArray(raw[1])) {
        return raw[1] as string[];
      }
      return [];
    } catch {
      return [];
    }
  }
  return [...memory.keys()].filter((k) => k.startsWith(prefix));
}

export async function kvPushList(key: string, item: unknown, maxLength = 200): Promise<void> {
  const current = (await kvGet<unknown[]>(key)) || [];
  current.unshift(item);
  const trimmed = current.slice(0, maxLength);
  await kvSet(key, trimmed);
}

export async function kvGetList<T>(key: string): Promise<T[]> {
  return (await kvGet<T[]>(key)) || [];
}

export async function kvRemoveFromList<T>(
  key: string,
  predicate: (item: T) => boolean
): Promise<void> {
  const current = await kvGetList<T>(key);
  await kvSet(key, current.filter((i) => !predicate(i)));
}

export async function kvHealth(): Promise<{ backend: string; ok: boolean; message: string }> {
  if (!isKVConfigured()) {
    return {
      backend: 'memory',
      ok: true,
      message: 'In-memory storage active. Configure KV_REST_API_URL + KV_REST_API_TOKEN for persistence.',
    };
  }
  try {
    await redisCommand('PING', []);
    return { backend: 'vercel-kv', ok: true, message: 'Vercel KV connected successfully.' };
  } catch (error) {
    return {
      backend: 'vercel-kv',
      ok: false,
      message: error instanceof Error ? error.message : 'KV ping failed',
    };
  }
}
