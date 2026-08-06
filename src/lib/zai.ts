/**
 * Web Search + AI Analysis Integration
 *
 * WEB SEARCH (free): DuckDuckGo HTML scraping (primary) with Bing HTML as
 * fallback. No API key required.
 *   - The old Z.AI public /web_search endpoint is paid (error 1113
 *     "Insufficient balance") and the original internal-api.z.ai endpoint is
 *     an Alibaba Cloud internal ALB with RFC1918 private IPs that is NOT
 *     reachable from public serverless environments (Vercel).
 *   - DuckDuckGo honours OSINT operators like `filetype:` and `site:`, but it
 *     rate-limits aggressively from server IPs (anti-bot challenge), so we
 *     fall back to Bing's HTML results when it gets blocked.
 *
 * AI CHAT (free tier): Z.AI public developer API (https://api.z.ai/api/paas/v4/).
 *   - Uses glm-4.5-flash, which is genuinely free (no balance needed).
 *   - Requires a Z.AI API key (https://z.ai/manage-apikey/apikey-list).
 */

// ============================================================================
// ZAI Configuration from environment variables
// ============================================================================
const ZAI_BASE_URL = process.env.ZAI_BASE_URL || 'https://api.z.ai/api/paas/v4';
const ZAI_API_KEY = process.env.ZAI_API_KEY || '';
const ZAI_MODEL = process.env.ZAI_MODEL || 'glm-4.5-flash';

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

      const rateLimited = msg.includes('429') || /temporarily overloaded|1305|1302/i.test(msg);
      if (rateLimited) {
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
  engine?: string;
}

interface WebSearchResult {
  url: string;
  name: string;
  snippet: string;
  host_name: string;
  rank: number;
  date: string;
  favicon: string;
}

// ============================================================================
// HTML scraping helpers
// ============================================================================
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function stripTags(html: string): string {
  return html.replace(/<[^>]*>/g, '');
}

function decodeEntities(text: string): string {
  return text
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)));
}

function pageTitle(html: string): string {
  const m = html.match(/<title>([\s\S]*?)<\/title>/i);
  const t = m ? decodeEntities(stripTags(m[1])).replace(/\s+/g, ' ').trim() : '';
  return t.length > 60 ? t.slice(0, 60) + '...' : t;
}

function makeItem(url: string, name: string, snippet: string): WebSearchResult | null {
  if (!/^https?:\/\//i.test(url)) return null;
  const cleanName = decodeEntities(stripTags(name)).replace(/\s+/g, ' ').trim();
  if (!cleanName) return null;
  const cleanSnippet = decodeEntities(stripTags(snippet)).replace(/\s+/g, ' ').trim();
  const host = hostOf(url);
  return {
    url,
    name: cleanName.substring(0, 300),
    snippet: cleanSnippet.substring(0, 500),
    host_name: host,
    rank: 0,
    date: '',
    favicon: host ? `https://icons.duckduckgo.com/ip3/${host}.ico` : '',
  };
}

// --- DuckDuckGo ---
function ddgRealUrl(href: string): string {
  const cleanHref = href.replace(/&amp;/g, '&');
  const m = cleanHref.match(/[?&]uddg=([^&]+)/);
  if (m) {
    try {
      const decoded = decodeURIComponent(m[1]);
      if (/^https?:\/\//i.test(decoded)) return decoded;
    } catch { /* fall through to raw href */ }
  }
  if (cleanHref.startsWith('//')) return `https:${cleanHref}`;
  return cleanHref;
}

function parseDdgHtml(html: string): WebSearchResult[] {
  const results: WebSearchResult[] = [];
  const blockRe = /<div[^>]*class="result[ "]([\s\S]*?)(?=<div[^>]*class="result[ "]|$)/gi;
  let blockMatch: RegExpExecArray | null;

  while ((blockMatch = blockRe.exec(html)) !== null) {
    const block = blockMatch[1];
    const titleMatch = block.match(/<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    if (!titleMatch) continue;

    const snipMatch = block.match(/<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>/);
    const url = ddgRealUrl(titleMatch[1]);
    if (url.includes('duckduckgo.com/y.js') || url.includes('duckduckgo.com/l/')) continue;
    const item = makeItem(url, titleMatch[2], snipMatch ? snipMatch[1] : '');
    if (item) results.push(item);
  }
  return results;
}

async function fetchDdgHtml(query: string, timeoutMs: number): Promise<string> {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
  const res = await fetch(url, {
    headers: {
      'User-Agent': BROWSER_UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
    },
    signal: timeoutMs && timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
  });
  if (!res.ok) throw new Error(`DuckDuckGo HTTP ${res.status}`);
  const html = await res.text();
  if (/anomaly|challenge|captcha/i.test(html)) {
    throw new Error(`DuckDuckGo bot challenge (blocked) [len=${html.length}, title='${pageTitle(html)}']`);
  }
  return html;
}

// --- Bing ---
function b64decode(s: string): string {
  try {
    return atob(s);
  } catch {
    return '';
  }
}

function bingRealUrl(href: string): string {
  let cleanHref = href.replace(/&amp;/g, '&');
  if (cleanHref.startsWith('/')) cleanHref = `https://www.bing.com${cleanHref}`;
  if (cleanHref.includes('bing.com/ck/a') || cleanHref.includes('r.bing.com')) {
    const m = cleanHref.match(/[?&]u=a1([^&]+)/);
    if (m) {
      const decoded = b64decode(m[1]);
      if (/^https?:\/\//i.test(decoded)) return decoded;
    }
  }
  return cleanHref;
}

function parseBingHtml(html: string): WebSearchResult[] {
  const results: WebSearchResult[] = [];
  const blockRe = /class="b_algo[^"]*"([\s\S]*?)(?=class="b_algo[^"]*"|<\/ol>|$)/gi;
  let blockMatch: RegExpExecArray | null;

  while ((blockMatch = blockRe.exec(html)) !== null) {
    const block = blockMatch[1];
    let m = block.match(/<h2[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>/i);
    let href = '';
    let title = '';
    if (m) {
      href = m[1];
      title = m[2];
    } else {
      const anyAnchor = block.match(/<a[^>]*href="(https?:[^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
      if (anyAnchor) {
        href = anyAnchor[1];
        title = anyAnchor[2];
      }
    }
    if (!href) continue;

    const snipMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    const item = makeItem(bingRealUrl(href), title, snipMatch ? snipMatch[1] : '');
    if (item) results.push(item);
  }
  return results;
}

async function fetchBingHtml(query: string, timeoutMs: number): Promise<string> {
  const variants = [
    { url: `https://www.bing.com/search?q=${encodeURIComponent(query)}&count=15&setlang=es`, cookie: 'SRCHHPGUSR=SRCHLANG=es' },
    { url: `https://www.bing.com/search?q=${encodeURIComponent(query)}&count=15&setmkt=en-US&cc=us`, cookie: undefined },
  ];
  let lastHtml = '';
  for (let i = 0; i < variants.length; i++) {
    const v = variants[i];
    const headers: Record<string, string> = {
      'User-Agent': BROWSER_UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
    };
    if (v.cookie) headers['Cookie'] = v.cookie;
    const res = await fetch(v.url, {
      headers,
      signal: timeoutMs && timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
    });
    if (!res.ok) {
      if (i === variants.length - 1) throw new Error(`Bing HTTP ${res.status}`);
      continue;
    }
    const html = await res.text();
    const blocked = /captcha|challenge|verify|consent/i.test(html) && !/<li class="b_algo"/.test(html);
    if (!blocked || i === variants.length - 1) return html;
    lastHtml = html;
  }
  throw new Error(`Bing blocked [len=${lastHtml.length}, title='${pageTitle(lastHtml)}']`);
}

// --- Bing RSS (tolerant of datacenter IPs that get the HTML consent wall) ---
function parseBingRss(xml: string): WebSearchResult[] {
  const results: WebSearchResult[] = [];
  const itemRe = /<item>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRe.exec(xml)) !== null) {
    const block = m[1];
    const title = (block.match(/<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/) || [])[1] || '';
    const link = (block.match(/<link>([\s\S]*?)<\/link>/) || [])[1] || '';
    const desc = (block.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/) || [])[1] || '';
    const item = makeItem(link.trim(), title, desc);
    if (item) results.push(item);
  }
  return results;
}

async function fetchBingRss(query: string, timeoutMs: number): Promise<string> {
  const url = `https://www.bing.com/search?q=${encodeURIComponent(query)}&format=rss&setmkt=en-US`;
  const res = await fetch(url, {
    headers: {
      'User-Agent': BROWSER_UA,
      'Accept': 'application/rss+xml,application/xml;q=0.9,text/xml;q=0.8,*/*;q=0.7',
    },
    signal: timeoutMs && timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
  });
  if (!res.ok) throw new Error(`Bing RSS HTTP ${res.status}`);
  const xml = await res.text();
  if (!/<item>/.test(xml)) throw new Error(`Bing RSS no items [len=${xml.length}, title='${pageTitle(xml)}']`);
  return xml;
}

// ============================================================================
// WEB SEARCH (free)
// ============================================================================
/**
 * Execute a web search via free HTML/RSS scraping: DuckDuckGo primary, then
 * Bing HTML, then Bing RSS as last-resort fallback (DDG and Bing both
 * rate-limit server IPs aggressively, so we try several endpoints).
 * Never throws - returns empty array on failure.
 *
 * Returns items in the shape the app's callers expect
 * ({url, name, snippet, host_name, rank, date, favicon}).
 */
export async function zaiWebSearch(
  query: string,
  options: {
    num?: number;
    maxRetries?: number;
    timeoutMs?: number;
    onDiagnostics?: (diagnostics: ZAIWebSearchDiagnostics) => void;
  } = {}
): Promise<WebSearchResult[]> {
  const { num = 10, maxRetries = 2, timeoutMs = 12000, onDiagnostics } = options;
  const startedAt = Date.now();
  let status: ZAIWebSearchStatus = 'empty';
  let lastError = '';
  let attempts = 0;

  const finish = (finalStatus: ZAIWebSearchStatus, results: WebSearchResult[]): WebSearchResult[] => {
    const diagnostics: ZAIWebSearchDiagnostics = {
      query,
      status: finalStatus,
      attempts,
      elapsedMs: Date.now() - startedAt,
    };
    if (lastError) diagnostics.error = lastError;
    if (lastEngine) diagnostics.engine = lastEngine;
    onDiagnostics?.(diagnostics);
    return results;
  };

  const engines: Array<{ name: string; fetch: () => Promise<string>; parse: (html: string) => WebSearchResult[] }> = [
    { name: 'DuckDuckGo', fetch: () => fetchDdgHtml(query, timeoutMs), parse: parseDdgHtml },
    { name: 'Bing', fetch: () => fetchBingHtml(query, timeoutMs), parse: parseBingHtml },
    { name: 'Bing RSS', fetch: () => fetchBingRss(query, timeoutMs), parse: parseBingRss },
  ];
  let lastEngine = '';

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    attempts++;
    let attemptStatus: ZAIWebSearchStatus = 'empty';

    for (const engine of engines) {
      try {
        const html = await engine.fetch();
        const mapped = engine.parse(html).slice(0, num);
        if (mapped.length > 0) {
          mapped.forEach((r, i) => { r.rank = i + 1; });
          lastEngine = engine.name;
          lastError = '';
          console.log(`[SEARCH] ${engine.name} succeeded: "${query.substring(0, 60)}" -> ${mapped.length} results`);
          return finish('ok', mapped);
        }
        lastError = `${engine.name}: no results [len=${html.length}, title='${pageTitle(html)}', b_algo=${(html.match(/class="b_algo/g) || []).length}]`;
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        lastError = `${engine.name}: ${msg}`;
        const isAbort = error instanceof Error && (error.name === 'AbortError' || msg.includes('abort'));
        attemptStatus = isAbort ? 'timeout' : 'error';
        console.error(`[SEARCH] ${engine.name} ${attemptStatus} (attempt ${attempt + 1}/${maxRetries}): "${query.substring(0, 50)}" - ${msg.substring(0, 150)}`);
      }
    }

    status = attemptStatus;
    if (attempt < maxRetries - 1) {
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  return finish(status, []);
}
