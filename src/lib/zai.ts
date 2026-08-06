/**
 * ZAI Public Platform Integration
 *
 * Talks to Z.AI's PUBLIC developer API (https://api.z.ai/api/paas/v4/).
 * The original integration pointed at internal-api.z.ai, an Alibaba Cloud
 * internal load balancer with RFC1918 private IPs that is NOT reachable from
 * public serverless environments (Vercel) - every call hung ~10s and then
 * failed with "fetch failed".
 *
 * Endpoints used:
 *  - POST {baseUrl}/web_search        -> dedicated web search engine
 *  - POST {baseUrl}/chat/completions  -> OpenAI-compatible chat (GLM models)
 *
 * Requires only a Z.AI API key (https://z.ai/manage-apikey/apikey-list).
 */

// ============================================================================
// ZAI Configuration from environment variables
// ============================================================================
const ZAI_BASE_URL = process.env.ZAI_BASE_URL || 'https://api.z.ai/api/paas/v4';
const ZAI_API_KEY = process.env.ZAI_API_KEY || '';
const ZAI_MODEL = process.env.ZAI_MODEL || 'glm-5.2';

export interface ZAIConfig {
  baseUrl: string;
  apiKey: string;
}

/**
 * Returns the ZAI config. Throws if the API key is not configured.
 */
export function getZAI(): ZAIConfig {
  if (!ZAI_API_KEY) {
    throw new Error('ZAI_API_KEY is not configured. Create one at https://z.ai/manage-apikey/apikey-list and set ZAI_API_KEY (and ZAI_BASE_URL) in the environment.');
  }
  return { baseUrl: ZAI_BASE_URL, apiKey: ZAI_API_KEY };
}

/**
 * Safe config getter - never throws, returns null if unavailable.
 */
export function getZAISafe(): ZAIConfig | null {
  try {
    return getZAI();
  } catch {
    console.error('[ZAI] SDK unavailable - ZAI_API_KEY is not configured');
    return null;
  }
}

/**
 * Check if ZAI is available without throwing.
 */
export function isZAIConfigured(): boolean {
  return !!ZAI_API_KEY;
}

/**
 * Execute a ZAI chat completion with automatic retry logic.
 * Never throws - returns null on failure after all retries.
 */
export async function zaiChatCompletion(
  messages: Array<{ role: string; content: string }>,
  options: {
    temperature?: number;
    max_tokens?: number;
    maxRetries?: number;
    retryDelay?: number;
  } = {}
): Promise<string | null> {
  const { temperature = 0.2, max_tokens = 8000, maxRetries = 3, retryDelay = 2000 } = options;

  const config = getZAISafe();
  if (!config) {
    console.error('[ZAI] Cannot execute chat completion - not configured');
    return null;
  }

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(`${config.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept-Language': 'en-US,en',
          'Authorization': `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          model: ZAI_MODEL,
          messages,
          temperature,
          max_tokens,
          stream: false,
          thinking: { type: 'disabled' },
        }),
        signal: AbortSignal.timeout(90000),
      });

      if (!res.ok) {
        const body = await res.text();
        throw new Error(`ZAI chat HTTP ${res.status}: ${body.substring(0, 300)}`);
      }

      const data = await res.json();
      const content = data.choices?.[0]?.message?.content || '';
      if (content.length > 0) {
        console.log(`[ZAI] Chat completion succeeded on attempt ${attempt + 1}: ${content.length} chars`);
        return content;
      }
      console.log(`[ZAI] Chat completion returned empty on attempt ${attempt + 1}`);
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error(`[ZAI] Chat completion error (attempt ${attempt + 1}/${maxRetries}): ${msg.substring(0, 150)}`);

      if (msg.includes('429')) {
        const waitTime = retryDelay * Math.pow(2, attempt);
        console.log(`[ZAI] Rate limited, waiting ${waitTime / 1000}s before retry...`);
        await new Promise(r => setTimeout(r, waitTime));
        continue;
      }

      if (attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, retryDelay));
      }
    }
  }

  console.error(`[ZAI] Chat completion failed after ${maxRetries} attempts`);
  return null;
}

/**
 * Diagnostic outcome for a single zaiWebSearch call.
 */
export type ZAIWebSearchStatus = 'ok' | 'empty' | 'timeout' | 'error' | 'bad_shape';

export interface ZAIWebSearchDiagnostics {
  query: string;
  status: ZAIWebSearchStatus;
  attempts: number;
  elapsedMs: number;
  error?: string;
  raw?: string;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/**
 * Execute a Z.AI web search via the public /web_search endpoint.
 * Never throws - returns empty array on failure.
 *
 * Maps the platform's search_result items to the same shape the app's callers
 * expect ({url, name, snippet, host_name, rank, date, favicon}).
 */
export async function zaiWebSearch(
  query: string,
  options: {
    num?: number;
    maxRetries?: number;
    timeoutMs?: number;
    onDiagnostics?: (diagnostics: ZAIWebSearchDiagnostics) => void;
  } = {}
): Promise<Array<{
  url: string;
  name: string;
  snippet: string;
  host_name: string;
  rank: number;
  date: string;
  favicon: string;
}>> {
  const { num = 10, maxRetries = 2, timeoutMs, onDiagnostics } = options;
  const startedAt = Date.now();

  const config = getZAISafe();
  if (!config) {
    console.error('[ZAI] Cannot execute web search - not configured');
    onDiagnostics?.({ query, status: 'error', attempts: 0, elapsedMs: Date.now() - startedAt, error: 'ZAI_API_KEY not configured' });
    return [];
  }

  let status: ZAIWebSearchStatus = 'empty';
  let lastError = '';
  let rawShape = '';
  let attempts = 0;

  const finish = (finalStatus: ZAIWebSearchStatus, results: Array<any>): Array<any> => {
    const diagnostics: ZAIWebSearchDiagnostics = {
      query,
      status: finalStatus,
      attempts,
      elapsedMs: Date.now() - startedAt,
    };
    if (lastError) diagnostics.error = lastError;
    if (rawShape) diagnostics.raw = rawShape;
    onDiagnostics?.(diagnostics);
    return results;
  };

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    attempts++;
    try {
      const res = await fetch(`${config.baseUrl}/web_search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept-Language': 'en-US,en',
          'Authorization': `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          search_engine: 'search-prime',
          search_query: query,
          count: num,
        }),
        signal: timeoutMs && timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
      });

      if (!res.ok) {
        const body = await res.text();
        throw new Error(`ZAI web_search HTTP ${res.status}: ${body.substring(0, 300)}`);
      }

      const data = await res.json();
      const rawItems = data.search_result;

      if (!Array.isArray(rawItems)) {
        status = 'bad_shape';
        try { rawShape = JSON.stringify(data).substring(0, 300); } catch { rawShape = String(data).substring(0, 300); }
        console.log(`[ZAI] Web search unexpected shape: "${query.substring(0, 50)}" -> ${rawShape}`);
        continue;
      }

      const mapped = rawItems
        .map((item: any, index: number) => ({
          url: item.link || '',
          name: item.title || '',
          snippet: item.content || '',
          host_name: item.media || hostOf(item.link || ''),
          rank: index + 1,
          date: item.publish_date || '',
          favicon: item.icon || '',
        }))
        .filter((r: any) => r.url && r.url.startsWith('http'));

      if (mapped.length > 0) {
        console.log(`[ZAI] Web search succeeded: "${query.substring(0, 60)}" -> ${mapped.length} results`);
        return finish('ok', mapped);
      }

      status = 'empty';
      console.log(`[ZAI] Web search returned no results: "${query.substring(0, 60)}"`);
      continue;
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      lastError = msg;
      const isAbort = error instanceof Error && (error.name === 'AbortError' || msg.includes('abort'));
      status = isAbort ? 'timeout' : 'error';
      console.error(`[ZAI] Web search ${status} (attempt ${attempt + 1}/${maxRetries}): "${query.substring(0, 50)}" - ${msg.substring(0, 150)}`);

      if (msg.includes('429') && attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  }

  return finish(status, []);
}
