import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import * as cheerio from 'cheerio';
import * as fs from 'fs';
import * as path from 'path';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

// ============================================================================
// AUTH
// ============================================================================
async function getAuthenticatedUser(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload as { id: string; email: string; role: string };
}

// ============================================================================
// TYPES
// ============================================================================
interface MetasearchResult {
  title: string;
  url: string;
  snippet: string;
  source: string;
  position: number;
  fileType?: string;
  isDownloadable?: boolean;
  downloaded?: boolean;
  localPath?: string;
  querySource?: string;
  exposureLevel?: string;
}

interface EvidenceDetail {
  url: string;
  sourceDomain: string;
  discoveredAt: string;
  title: string;
  fileType: string;
  fileName: string;
  downloadStatus: 'success' | 'failed' | 'skipped';
  localPath: string;
  fileSize: number;
  error?: string;
  httpStatus?: number;
  contentType?: string;
  captureTimestamp?: string;
}

interface SearchQueryGroup {
  label: string;
  queries: string[];
  blockType: 'name' | 'email' | 'id' | 'combined' | 'custom';
}

// ============================================================================
// ANTI-BLOCK SYSTEM
// Rotating user agents, enterprise headers, session simulation, random delays
// ============================================================================

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
];

const ACCEPT_LANGUAGES = [
  'es-CO,es;q=0.9,en;q=0.8',
  'es-ES,es;q=0.9,en;q=0.8',
  'es;q=0.9,en-US;q=0.8,en;q=0.7',
  'es-CO,es-419;q=0.9,en;q=0.8',
  'en-US,en;q=0.9,es;q=0.8',
];

const sessionCookies: Record<string, string> = {};

function getRandomElement<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomDelay(minMs: number, maxMs: number): Promise<void> {
  const delay = minMs + Math.random() * (maxMs - minMs);
  return new Promise(r => setTimeout(r, delay));
}

function buildDynamicHeaders(engine: string): Record<string, string> {
  const ua = getRandomElement(USER_AGENTS);
  const lang = getRandomElement(ACCEPT_LANGUAGES);

  const headers: Record<string, string> = {
    'User-Agent': ua,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': lang,
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Ch-Ua': '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
  };

  if (sessionCookies[engine]) {
    headers['Cookie'] = sessionCookies[engine];
  }

  return headers;
}

function extractAndStoreCookies(response: Response, engine: string): void {
  try {
    const setCookies = response.headers.getSetCookie?.() || [];
    if (setCookies.length > 0) {
      const existing = sessionCookies[engine] || '';
      const newCookies = setCookies.map(c => c.split(';')[0]).join('; ');
      sessionCookies[engine] = existing ? `${existing}; ${newCookies}` : newCookies;
    }
  } catch { /* ignore */ }
}

// ============================================================================
// OSINT DORKING MATRIX v4.0
// Uses CORRECT operators per engine:
//   Google/Bing: filetype: (not ext:)
//   ZAI Web Search: plain queries (no operators)
//   Keeps queries SHORT (max 3-4 filetype terms per query)
// ============================================================================

const PRIMARY_EXTENSIONS = [
  'pdf', 'xlsx', 'xls', 'ppt', 'pptx', 'doc', 'docx', 'txt',
  'rar', 'zip', '7z', 'htm', 'html', 'csv', 'rtf',
  'env', 'conf', 'config', 'ini', 'json', 'xml', 'yaml',
  'bak', 'old', 'sql', 'db',
];

const SECONDARY_EXTENSIONS = [
  'odt', 'ods', 'odp', 'yml', 'tmp', 'sqlite',
  'tar.gz', 'tgz', 'png', 'jpg', 'jpeg', 'svg',
];

const ALL_EXTENSIONS = [...PRIMARY_EXTENSIONS, ...SECONDARY_EXTENSIONS];

// High-value extensions for targeted dorking
const HIGH_VALUE_EXTS = ['pdf', 'xlsx', 'doc', 'pptx', 'sql', 'env', 'conf', 'bak'];

interface EngineQuerySet {
  google: string[];   // Uses filetype: operator
  bing: string[];     // Uses filetype: operator
  zai: string[];      // Plain queries (no operators)
}

function buildOsintQueryMatrix(executive: {
  fullName: string;
  identificationNum: string;
  email: string | null;
}): { groups: SearchQueryGroup[]; engineQueries: EngineQuerySet } {
  const name = executive.fullName;
  const id = executive.identificationNum;
  const email = executive.email;
  const nameParts = name.toLowerCase().split(' ');
  const lastName = nameParts[nameParts.length - 1] || '';
  const firstName = nameParts[0] || '';
  const secondLastName = nameParts.length > 2 ? nameParts[nameParts.length - 2] : '';

  const groups: SearchQueryGroup[] = [];
  const googleQueries: string[] = [];
  const bingQueries: string[] = [];
  const zaiQueries: string[] = [];

  // =========================================================================
  // BLOQUE 1: Por Nombre Completo
  // =========================================================================
  const nameGroupQueries: string[] = [];

  // 1a: Simple name search (always works)
  nameGroupQueries.push(`"${name}"`);
  googleQueries.push(`"${name}"`);
  bingQueries.push(`"${name}"`);
  zaiQueries.push(`"${name}"`);

  // 1b: Name + filetype:pdf (Google/Bing)
  googleQueries.push(`"${name}" filetype:pdf`);
  bingQueries.push(`"${name}" filetype:pdf`);
  zaiQueries.push(`"${name}" PDF documento`);
  nameGroupQueries.push(`"${name}" filetype:pdf`);

  // 1c: Name + filetype:xlsx OR filetype:doc
  googleQueries.push(`"${name}" filetype:xlsx OR filetype:doc`);
  bingQueries.push(`"${name}" filetype:xlsx OR filetype:doc`);
  zaiQueries.push(`"${name}" Excel Word documento`);
  nameGroupQueries.push(`"${name}" (filetype:xlsx OR filetype:doc)`);

  // 1d: Name + sensitive file types (env, conf, sql, bak)
  googleQueries.push(`"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak`);
  bingQueries.push(`"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak`);
  zaiQueries.push(`"${name}" configuracion credenciales base datos`);
  nameGroupQueries.push(`"${name}" (filetype:env OR filetype:conf OR filetype:sql OR filetype:bak)`);

  // 1e: Name + ID
  googleQueries.push(`"${name}" "${id}"`);
  bingQueries.push(`"${name}" "${id}"`);
  zaiQueries.push(`"${name}" ${id}`);
  nameGroupQueries.push(`"${name}" "${id}"`);

  // 1f: Name + filetype:pptx OR filetype:csv
  googleQueries.push(`"${name}" filetype:pptx OR filetype:csv`);
  bingQueries.push(`"${name}" filetype:pptx OR filetype:csv`);
  zaiQueries.push(`"${name}" presentacion datos`);
  nameGroupQueries.push(`"${name}" (filetype:pptx OR filetype:csv)`);

  groups.push({ label: `Nombre: ${name}`, queries: nameGroupQueries, blockType: 'name' });

  // =========================================================================
  // BLOQUE 2: Por Correo Electronico
  // =========================================================================
  if (email) {
    const emailGroupQueries: string[] = [];
    const emailUser = email.split('@')[0];
    const domain = email.split('@')[1];

    // 2a: Exact email
    googleQueries.push(`"${email}"`);
    bingQueries.push(`"${email}"`);
    zaiQueries.push(`"${email}"`);
    emailGroupQueries.push(`"${email}"`);

    // 2b: Email + filetype:pdf
    googleQueries.push(`"${email}" filetype:pdf`);
    bingQueries.push(`"${email}" filetype:pdf`);
    zaiQueries.push(`"${email}" PDF documento`);
    emailGroupQueries.push(`"${email}" filetype:pdf`);

    // 2c: Email + sensitive types
    googleQueries.push(`"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`);
    bingQueries.push(`"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`);
    zaiQueries.push(`"${email}" Excel Word base datos`);
    emailGroupQueries.push(`"${email}" (filetype:xlsx OR filetype:doc OR filetype:sql)`);

    // 2d: Email username part
    if (emailUser && emailUser !== email) {
      googleQueries.push(`"${emailUser}" filetype:pdf OR filetype:xlsx`);
      bingQueries.push(`"${emailUser}" filetype:pdf OR filetype:xlsx`);
      zaiQueries.push(`"${emailUser}" documento`);
      emailGroupQueries.push(`"${emailUser}" (filetype:pdf OR filetype:xlsx)`);
    }

    // 2e: Name + site:domain
    if (domain) {
      googleQueries.push(`"${name}" site:${domain}`);
      bingQueries.push(`"${name}" site:${domain}`);
      zaiQueries.push(`"${name}" ${domain}`);
      emailGroupQueries.push(`"${name}" site:${domain}`);
    }

    groups.push({ label: `Email: ${email}`, queries: emailGroupQueries, blockType: 'email' });
  }

  // =========================================================================
  // BLOQUE 3: Por Identificacion
  // =========================================================================
  const idGroupQueries: string[] = [];

  // 3a: ID simple search
  googleQueries.push(`"${id}"`);
  bingQueries.push(`"${id}"`);
  zaiQueries.push(`"${id}"`);
  idGroupQueries.push(`"${id}"`);

  // 3b: ID + filetype:pdf
  googleQueries.push(`"${id}" filetype:pdf`);
  bingQueries.push(`"${id}" filetype:pdf`);
  zaiQueries.push(`"${id}" PDF documento`);
  idGroupQueries.push(`"${id}" filetype:pdf`);

  // 3c: ID + sensitive types
  googleQueries.push(`"${id}" filetype:xlsx OR filetype:doc OR filetype:csv`);
  bingQueries.push(`"${id}" filetype:xlsx OR filetype:doc OR filetype:csv`);
  zaiQueries.push(`"${id}" Excel Word datos`);
  idGroupQueries.push(`"${id}" (filetype:xlsx OR filetype:doc OR filetype:csv)`);

  // 3d: ID + inurl
  googleQueries.push(`"${id}" inurl:${id}`);
  bingQueries.push(`"${id}" inurl:${id}`);
  zaiQueries.push(`"${id}" ${id}`);
  idGroupQueries.push(`"${id}" inurl:${id}`);

  groups.push({ label: `ID: ${id}`, queries: idGroupQueries, blockType: 'id' });

  // =========================================================================
  // BLOQUE COMBINADO: Cross-reference queries
  // =========================================================================
  const combinedGroupQueries: string[] = [];

  if (email) {
    googleQueries.push(`"${name}" "${email}"`);
    bingQueries.push(`"${name}" "${email}"`);
    zaiQueries.push(`"${name}" "${email}"`);
    combinedGroupQueries.push(`"${name}" "${email}"`);
  }

  if (lastName) {
    googleQueries.push(`"${id}" "${lastName}"`);
    bingQueries.push(`"${id}" "${lastName}"`);
    zaiQueries.push(`"${id}" "${lastName}"`);
    combinedGroupQueries.push(`"${id}" "${lastName}"`);
  }

  groups.push({ label: 'Cruzamiento Multi-Campo', queries: combinedGroupQueries, blockType: 'combined' });

  return {
    groups,
    engineQueries: {
      google: Array.from(new Set(googleQueries)),
      bing: Array.from(new Set(bingQueries)),
      zai: Array.from(new Set(zaiQueries)),
    },
  };
}

// ============================================================================
// FLEXIBLE SEMANTIC HTML PARSER
// ============================================================================

function flexibleHtmlParse(html: string, engineSource: string, query: string): MetasearchResult[] {
  const results: MetasearchResult[] = [];
  const $ = cheerio.load(html);
  const seenInPage = new Set<string>();

  // Strategy 1: Engine-specific selectors
  const engineSelectors: Record<string, { container: string; link: string; title: string; snippet: string }> = {
    Google: { container: 'div.g, div[data-hveid], div[data-ved], div[data-sokoban-container]', link: 'a[href^="http"], a[href^="/url"]', title: 'h3, [data-header-feature] h3', snippet: '.VwiC3b, .st, [data-sncf], .IsZvec, .kb0PBd' },
    Bing: { container: 'li.b_algo, li.b_vlhit, .b_algo', link: 'h2 a, a[href^="http"]', title: 'h2, .b_promotionText', snippet: '.b_caption p, .b_lineclamp2, p, .b_factrow' },
    Yandex: { container: 'li.serp-item, div.serp-item, .Organic, .organic__url', link: 'a[href^="http"]', title: '.organic__title, h2, .Typs-heading, span.OrganicTextContentSpan', snippet: '.organic__content-wrapper, .text-container, .Typs-text, .organic__text' },
    DuckDuckGo: { container: 'div.result, div.web-result, .result', link: 'a.result__a, a[href^="http"]', title: 'a.result__a, h2 a, .result__title', snippet: '.result__snippet, a.result__snippet, .result__body' },
  };

  const sel = engineSelectors[engineSource];
  if (sel) {
    $(sel.container).each((_, el) => {
      if (results.length >= 20) return false;
      const container = $(el);
      const linkEl = container.find(sel.link).first();
      let href = linkEl.attr('href') || '';
      const titleEl = container.find(sel.title).first();
      const title = titleEl.text().trim() || linkEl.text().trim();
      const snippetEl = container.find(sel.snippet).first();
      const snippet = snippetEl.text().trim() || container.text().trim().substring(0, 300);

      href = cleanRedirectUrl(href, engineSource);
      if (!href.startsWith('http')) href = normalizeUrl(href);

      const urlKey = href.toLowerCase().split('?')[0].split('#')[0];
      if (title && href.startsWith('http') && !isSearchEngineUrl(href, engineSource) && !seenInPage.has(urlKey)) {
        seenInPage.add(urlKey);
        results.push({
          title: title.substring(0, 300),
          url: href,
          snippet: snippet.substring(0, 500),
          source: engineSource,
          position: results.length + 1,
          isDownloadable: isDocumentUrl(href),
          querySource: query.substring(0, 80),
        });
      }
    });
  }

  // Strategy 2: Semantic extraction (all links with meaningful text)
  if (results.length === 0) {
    console.log(`[METASEARCH] ${engineSource}: Selectors failed, semantic extraction...`);
    $('a[href]').each((_, el) => {
      if (results.length >= 20) return false;
      const linkEl = $(el);
      let href = linkEl.attr('href') || '';
      const title = linkEl.text().trim();

      href = cleanRedirectUrl(href, engineSource);
      if (!href.startsWith('http')) href = normalizeUrl(href);

      const urlKey = href.toLowerCase().split('?')[0].split('#')[0];

      if (
        title.length > 8 &&
        href.startsWith('http') &&
        !isSearchEngineUrl(href, engineSource) &&
        !seenInPage.has(urlKey) &&
        !isNavOrFooterLink(title)
      ) {
        seenInPage.add(urlKey);
        const parent = linkEl.closest('div, li, article, section');
        const parentText = parent.text().trim();
        const snippetRaw = parentText.replace(title, '').trim().substring(0, 500);

        results.push({
          title: title.substring(0, 300),
          url: href,
          snippet: snippetRaw,
          source: engineSource,
          position: results.length + 1,
          isDownloadable: isDocumentUrl(href),
          querySource: query.substring(0, 80),
        });
      }
    });
  }

  // Strategy 3: URL pattern extraction
  if (results.length === 0) {
    console.log(`[METASEARCH] ${engineSource}: Trying URL pattern matching...`);
    const urlPattern = /https?:\/\/[^\s"'<>\]\)]+/g;
    const foundUrls = html.match(urlPattern) || [];
    const cleanUrls = Array.from(new Set(foundUrls.map(u => u.split(/[<>"'\]\)]/)[0])));

    for (const url of cleanUrls) {
      if (results.length >= 15) break;
      const urlKey = url.toLowerCase().split('?')[0].split('#')[0];
      if (!isSearchEngineUrl(url, engineSource) && !seenInPage.has(urlKey) && (isDocumentUrl(url) || url.length > 20)) {
        seenInPage.add(urlKey);
        try {
          const urlObj = new URL(url);
          results.push({
            title: urlObj.pathname.split('/').pop() || urlObj.hostname,
            url,
            snippet: '',
            source: engineSource,
            position: results.length + 1,
            isDownloadable: isDocumentUrl(url),
            querySource: query.substring(0, 80),
          });
        } catch { /* skip invalid URLs */ }
      }
    }
  }

  return results;
}

function cleanRedirectUrl(href: string, engine: string): string {
  if (!href) return '';

  // Google redirect
  if (href.includes('google.com/url?') || href.includes('google.com/search?')) {
    const match = href.match(/[?&](?:q|url)=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }
  // Google /url?q= redirect
  if (href.startsWith('/url?q=')) {
    const match = href.match(/[?&]q=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }

  // DuckDuckGo redirect
  if (href.startsWith('//duckduckgo.com/l/') || href.includes('uddg=')) {
    const match = href.match(/uddg=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }

  // Yandex redirect
  if (href.includes('yandex.com/clck/')) {
    const match = href.match(/[?&]url=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }

  // Protocol-relative URLs
  if (href.startsWith('//')) return 'https:' + href;

  return href;
}

function normalizeUrl(href: string): string {
  if (!href) return '';
  if (href.startsWith('//')) return 'https:' + href;
  if (href.startsWith('/')) return '';
  return href;
}

function isSearchEngineUrl(url: string, engine: string): boolean {
  const engineDomains: Record<string, string[]> = {
    Google: ['google.com', 'google.co', 'gstatic.com', 'googleapis.com', 'googleusercontent.com'],
    Bing: ['bing.com', 'microsoft.com', 'msn.com'],
    Yandex: ['yandex.com', 'yandex.ru', 'yandex.net'],
    DuckDuckGo: ['duckduckgo.com'],
    Brave: ['brave.com', 'search.brave.com'],
  };
  const domains = engineDomains[engine] || [];
  return domains.some(d => url.includes(d));
}

function isNavOrFooterLink(text: string): boolean {
  const navPatterns = /^(login|sign|register|home|about|contact|privacy|terms|cookies|buscar|inicio|privacidad|mapa|images|videos|news|maps|translate|mail|signin|signup|log out|log in|cached|similar|more|next|previous)$/i;
  return navPatterns.test(text.trim()) || text.length < 5;
}

// ============================================================================
// SEARCH ENGINE IMPLEMENTATIONS
// ============================================================================

// --- GOOGLE (with filetype: operator support) ---
async function searchGoogle(query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  try {
    await randomDelay(800, 2000);
    const encodedQuery = encodeURIComponent(query);
    const endpoints = [
      `https://www.google.com/search?q=${encodedQuery}&num=15&hl=es-419&start=0`,
      `https://www.google.com.co/search?q=${encodedQuery}&num=15&hl=es`,
    ];

    for (const url of endpoints) {
      const headers = buildDynamicHeaders('Google');
      const response = await fetch(url, {
        headers,
        redirect: 'follow',
        signal: AbortSignal.timeout(15000),
      });

      extractAndStoreCookies(response, 'Google');

      if (!response.ok) {
        console.log(`[METASEARCH] Google HTTP ${response.status}`);
        continue;
      }

      const html = await response.text();

      if (html.includes('captcha') || html.includes('unusual traffic') || html.includes('Sorry') || html.length < 500) {
        console.log(`[METASEARCH] Google: Block/empty detected from ${url.substring(0, 50)}`);
        continue;
      }

      const parsed = flexibleHtmlParse(html, 'Google', query);
      if (parsed.length > 0) return parsed;
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Google error: ${msg.substring(0, 80)}`);
  }
  return results;
}

// --- BING (with filetype: operator support) ---
async function searchBing(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(600, 1500);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://www.bing.com/search?q=${encodedQuery}&count=15&setlang=es-419&cc=co`;
    const headers = buildDynamicHeaders('Bing');

    const response = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    extractAndStoreCookies(response, 'Bing');

    if (!response.ok) {
      console.log(`[METASEARCH] Bing HTTP ${response.status}`);
      return [];
    }

    const html = await response.text();
    return flexibleHtmlParse(html, 'Bing', query);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Bing error: ${msg.substring(0, 80)}`);
  }
  return [];
}

// --- DUCKDUCKGO ---
async function searchDuckDuckGo(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(500, 1200);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://html.duckduckgo.com/html/?q=${encodedQuery}`;
    const headers = buildDynamicHeaders('DuckDuckGo');

    const response = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    extractAndStoreCookies(response, 'DuckDuckGo');

    if (!response.ok) return [];

    const html = await response.text();
    return flexibleHtmlParse(html, 'DuckDuckGo', query);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] DuckDuckGo error: ${msg.substring(0, 80)}`);
  }
  return [];
}

// ============================================================================
// ZAI WEB SEARCH - PRIMARY ENGINE (Most Reliable from Server)
// Runs FIRST with simplified plain queries (no filetype operators)
// ============================================================================
async function searchZAI(query: string): Promise<MetasearchResult[]> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    const searchResult = await zai.functions.invoke('web_search', {
      query,
      num: 20,
    });

    if (searchResult && Array.isArray(searchResult)) {
      return searchResult
        .filter((item: any) => item.url && item.url.startsWith('http'))
        .map((item: any, index: number) => ({
          title: (item.name || 'Sin titulo').substring(0, 300),
          url: item.url,
          snippet: (item.snippet || '').substring(0, 500),
          source: 'Web Search',
          position: index + 1,
          isDownloadable: isDocumentUrl(item.url),
          querySource: query.substring(0, 80),
        }));
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] ZAI web_search error: ${msg.substring(0, 200)}`);
  }
  return [];
}

// ============================================================================
// AI-POWERED SEMANTIC EXTRACTION
// ============================================================================
async function aiExtractFromHtml(html: string, engineSource: string, query: string): Promise<MetasearchResult[]> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    const htmlSample = html.substring(0, 10000);

    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a web scraping expert. Extract search results from HTML of a ${engineSource} search results page. Return ONLY a JSON array of objects with: title, url, snippet. Maximum 15 results. If no results found, return empty array [].`
        },
        {
          role: 'user',
          content: `Query was: "${query}"\n\nHTML:\n${htmlSample}`
        },
      ],
      temperature: 0.1,
      max_tokens: 3000,
    });

    const responseText = completion.choices?.[0]?.message?.content || '';
    const jsonMatch = responseText.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      if (Array.isArray(parsed)) {
        return parsed.filter((item: any) => item.url && item.url.startsWith('http')).map((item: any, idx: number) => ({
          title: (item.title || 'Sin titulo').substring(0, 300),
          url: item.url,
          snippet: (item.snippet || '').substring(0, 500),
          source: `${engineSource} (AI)`,
          position: idx + 1,
          isDownloadable: isDocumentUrl(item.url),
          querySource: query.substring(0, 80),
        }));
      }
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] AI extraction error for ${engineSource}: ${msg.substring(0, 100)}`);
  }
  return [];
}

// ============================================================================
// URL HELPERS
// ============================================================================
function isDocumentUrl(url: string): boolean {
  const urlLower = url.toLowerCase().split('?')[0].split('#')[0];
  return ALL_EXTENSIONS.some(ext => {
    if (ext.includes('.')) {
      return urlLower.endsWith(`.${ext}`) || urlLower.endsWith(`.${ext.replace('.', '_')}`);
    }
    return urlLower.endsWith(`.${ext}`);
  });
}

function extractFileType(url: string): string {
  const urlPath = url.toLowerCase().split('?')[0].split('#')[0];
  for (const ext of ALL_EXTENSIONS) {
    if (ext.includes('.')) {
      if (urlPath.endsWith(`.${ext.replace('.', '_')}`) || urlPath.endsWith(`.${ext}`)) return ext;
    } else {
      if (urlPath.endsWith(`.${ext}`)) return ext;
    }
  }
  return 'html';
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

function sanitizeFileName(name: string): string {
  return name.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ_\- ]/g, '').replace(/\s+/g, '_').substring(0, 100);
}

// ============================================================================
// AI ANALYSIS OF RESULTS
// ============================================================================
async function analyzeResultsWithAI(
  executive: { fullName: string; identificationNum: string; email: string | null },
  results: MetasearchResult[]
): Promise<string> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    const resultsSummary = results.slice(0, 40).map((r, i) =>
      `${i + 1}. [${r.fileType?.toUpperCase() || 'WEB'}] "${r.title}" - ${r.url} | Fuente: ${r.source} | Snippet: ${r.snippet.substring(0, 200)}`
    ).join('\n');

    const prompt = `Eres un analista de inteligencia OSINT especializado en proteccion ejecutiva. Analiza los siguientes resultados de metabusqueda para el ejecutivo y genera un informe de amenazas/exposicion digital.

EJECUTIVO:
- Nombre: ${executive.fullName}
- Identificacion: ${executive.identificationNum}
- Email: ${executive.email || 'No disponible'}

RESULTADOS DE METABUSQUEDA OSINT (${results.length} resultados de multiples motores):
${resultsSummary}

INSTRUCCIONES:
1. Clasifica cada resultado segun nivel de exposicion: CRITICO, ALTO, MEDIO, BAJO
2. Identifica documentos que contengan datos personales del ejecutivo
3. Detecta posibles filtraciones de informacion sensible
4. Genera recomendaciones de proteccion especificas y accionables
5. Identifica vectores de ataque potenciales

FORMATO DE RESPUESTA:
- Resumen Ejecutivo
- Hallazgos Criticos
- Hallazgos de Seguridad
- Hallazgos Moderados
- Vectores de Ataque Potenciales
- Recomendaciones de Proteccion`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista de inteligencia OSINT experto en proteccion ejecutiva, ciberseguridad y contrainteligencia. Respondes siempre en espanol de forma clara, detallada y profesional.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 3000,
    });

    return completion.choices?.[0]?.message?.content || 'Analisis no disponible';
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] AI analysis error: ${msg.substring(0, 200)}`);
    return 'Analisis IA no disponible en este momento.';
  }
}

// ============================================================================
// FILE DOWNLOAD AND STORAGE
// ============================================================================
async function downloadAndStoreFile(
  url: string,
  executiveName: string,
  baseDir: string
): Promise<{ success: boolean; localPath: string; fileName: string; fileSize: number; error?: string; httpStatus?: number; contentType?: string }> {
  const execDir = path.join(baseDir, sanitizeFileName(executiveName));

  try {
    fs.mkdirSync(execDir, { recursive: true });
  } catch (e) {
    console.log(`[METASEARCH] Error creating directory ${execDir}: ${e}`);
  }

  let originalName: string;
  try {
    const urlPathName = new URL(url).pathname;
    originalName = path.basename(urlPathName) || `document_${Date.now()}`;
  } catch {
    originalName = `document_${Date.now()}`;
  }
  const ext = path.extname(originalName) || '.bin';
  const baseName = path.basename(originalName, ext).substring(0, 50);
  const fileName = `${sanitizeFileName(baseName)}${ext}`;
  const localPath = path.join(execDir, fileName);

  if (fs.existsSync(localPath)) {
    const stats = fs.statSync(localPath);
    return { success: true, localPath, fileName, fileSize: stats.size };
  }

  try {
    console.log(`[METASEARCH] Downloading: ${url.substring(0, 100)}`);

    const response = await fetch(url, {
      headers: {
        ...buildDynamicHeaders('download'),
        'Accept': '*/*',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(45000),
    });

    const contentType = response.headers.get('content-type') || 'unknown';

    if (!response.ok) {
      return { success: false, localPath: '', fileName, fileSize: 0, error: `HTTP ${response.status}`, httpStatus: response.status, contentType };
    }

    const contentLength = parseInt(response.headers.get('content-length') || '0');
    if (contentLength > 50 * 1024 * 1024) {
      return { success: false, localPath: '', fileName, fileSize: contentLength, error: 'File too large (>50MB)', contentType };
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(localPath, buffer);
    console.log(`[METASEARCH] Saved: ${localPath} (${buffer.length} bytes)`);

    return { success: true, localPath, fileName, fileSize: buffer.length, httpStatus: response.status, contentType };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Download error: ${msg.substring(0, 100)}`);
    return { success: false, localPath: '', fileName, fileSize: 0, error: msg.substring(0, 200) };
  }
}

// ============================================================================
// EVIDENCE DETAIL FILE GENERATOR
// ============================================================================
function writeEvidenceDetail(
  executiveName: string,
  baseDir: string,
  evidence: EvidenceDetail[],
  aiAnalysis: string,
  queryGroups: SearchQueryGroup[],
  engineStats: Record<string, number>,
): string {
  const execDir = path.join(baseDir, sanitizeFileName(executiveName));

  try {
    fs.mkdirSync(execDir, { recursive: true });
  } catch { /* ignore */ }

  const detailPath = path.join(execDir, 'detalle_identificado.json');

  const detailData = {
    caseInfo: {
      executiveName,
      generatedAt: new Date().toISOString(),
      captureTimestamp: new Date().toISOString(),
      generatorAgent: 'ActorTrace OSINT Metasearch v4.0',
      queryMatrixUsed: queryGroups.map(g => ({
        block: g.blockType,
        label: g.label,
        queriesExecuted: g.queries.length,
      })),
    },
    statistics: {
      totalFindings: evidence.length,
      downloadedFiles: evidence.filter(e => e.downloadStatus === 'success').length,
      failedDownloads: evidence.filter(e => e.downloadStatus === 'failed').length,
      skippedFiles: evidence.filter(e => e.downloadStatus === 'skipped').length,
      engineStats,
    },
    aiAnalysis,
    findings: evidence.map(e => ({
      url: e.url,
      sourceDomain: e.sourceDomain,
      discoveredAt: e.discoveredAt,
      captureTimestamp: e.captureTimestamp || e.discoveredAt,
      title: e.title,
      fileType: e.fileType,
      fileName: e.fileName,
      downloadStatus: e.downloadStatus,
      localPath: e.localPath,
      fileSize: e.fileSize,
      httpStatus: e.httpStatus,
      contentType: e.contentType,
      error: e.error,
    })),
  };

  fs.writeFileSync(detailPath, JSON.stringify(detailData, null, 2), 'utf-8');
  console.log(`[METASEARCH] Evidence detail written: ${detailPath}`);

  // Human-readable TXT version
  const txtPath = path.join(execDir, 'detalle_identificado.txt');
  const txtContent = [
    `ACTORTRACE - REPORTE DE EVIDENCIA DIGITAL OSINT`,
    ``,
    `Ejecutivo: ${executiveName}`,
    `Fecha de captura: ${new Date().toLocaleString('es-CO')}`,
    `Agente: ActorTrace OSINT Metasearch v4.0`,
    ``,
    `ESTADISTICAS`,
    `Total hallazgos: ${evidence.length}`,
    `Archivos descargados: ${evidence.filter(e => e.downloadStatus === 'success').length}`,
    `Descargas fallidas: ${evidence.filter(e => e.downloadStatus === 'failed').length}`,
    `Archivos omitidos: ${evidence.filter(e => e.downloadStatus === 'skipped').length}`,
    ``,
    `Motores consultados:`,
    ...Object.entries(engineStats).map(([engine, count]) => `  - ${engine}: ${count} resultados`),
    ``,
    `MATRIZ DE CONSULTAS EJECUTADAS`,
    ...queryGroups.map(g => `  [${g.blockType.toUpperCase()}] ${g.label} (${g.queries.length} consultas)`),
    ``,
    `HALLAZGOS DETALLADOS`,
    ...evidence.map((e, i) => [
      ``,
      `  Hallazgo #${i + 1}:`,
      `  URL: ${e.url}`,
      `  Dominio: ${e.sourceDomain}`,
      `  Fecha de captura: ${e.discoveredAt}`,
      `  Titulo: ${e.title}`,
      `  Tipo de archivo: ${e.fileType}`,
      `  Estado de descarga: ${e.downloadStatus}`,
      e.localPath ? `  Ruta local: ${e.localPath}` : '',
      e.fileSize ? `  Tamano: ${(e.fileSize / 1024).toFixed(1)} KB` : '',
      e.error ? `  Error: ${e.error}` : '',
    ].filter(Boolean).join('\n')),
    ``,
    `ANALISIS DE IA`,
    aiAnalysis || 'No disponible',
  ].join('\n');

  fs.writeFileSync(txtPath, txtContent, 'utf-8');
  console.log(`[METASEARCH] Evidence TXT written: ${txtPath}`);

  return detailPath;
}

// ============================================================================
// ADD RESULTS WITH DEDUP
// ============================================================================
function addResults(
  newResults: MetasearchResult[],
  allResults: MetasearchResult[],
  seenUrls: Set<string>,
  enginesUsed: string[],
  engineName: string,
): number {
  let added = 0;
  if (newResults.length > 0 && !enginesUsed.includes(engineName)) {
    enginesUsed.push(engineName);
  }
  for (const result of newResults) {
    const urlKey = result.url.toLowerCase().split('?')[0].split('#')[0];
    if (!seenUrls.has(urlKey) && result.url.startsWith('http')) {
      seenUrls.add(urlKey);
      result.fileType = extractFileType(result.url);
      allResults.push(result);
      added++;
    }
  }
  return added;
}

// ============================================================================
// MAIN POST HANDLER - v4.0
// Strategy: ZAI Web Search FIRST (most reliable), then scraping engines
// ============================================================================
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  try {
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { executiveId, query: customQuery, downloadFiles = true } = body;

    if (!executiveId && !customQuery) {
      return NextResponse.json(
        { error: 'Se requiere executiveId o query' },
        { status: 400 }
      );
    }

    let executive = null;
    let queryGroups: SearchQueryGroup[] = [];
    let engineQueries: EngineQuerySet = { google: [], bing: [], zai: [] };

    if (executiveId) {
      executive = await db.executive.findUnique({ where: { id: executiveId } });
      if (!executive) {
        return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
      }

      const matrix = buildOsintQueryMatrix({
        fullName: executive.fullName,
        identificationNum: executive.identificationNum,
        email: executive.email,
      });
      queryGroups = matrix.groups;
      engineQueries = matrix.engineQueries;

      console.log(`[METASEARCH] Built ${queryGroups.length} query groups, ZAI=${engineQueries.zai.length}, Google=${engineQueries.google.length}, Bing=${engineQueries.bing.length} queries`);
    } else {
      queryGroups = [{ label: 'Busqueda personalizada', queries: [customQuery], blockType: 'custom' }];
      engineQueries = { google: [customQuery], bing: [customQuery], zai: [customQuery] };
    }

    const allResults: MetasearchResult[] = [];
    const seenUrls = new Set<string>();
    const enginesUsed: string[] = [];
    const engineStats: Record<string, number> = {
      google: 0, bing: 0, yandex: 0, duckduckgo: 0, brave: 0, webSearch: 0,
    };

    // =========================================================================
    // PHASE 1: ZAI WEB SEARCH (PRIMARY - Most reliable from server)
    // Execute ALL ZAI queries in parallel
    // =========================================================================
    console.log(`[METASEARCH] Phase 1: ZAI Web Search (${engineQueries.zai.length} queries)...`);

    const zaiBatchSize = 3;
    for (let i = 0; i < engineQueries.zai.length; i += zaiBatchSize) {
      const batch = engineQueries.zai.slice(i, i + zaiBatchSize);
      const zaiPromises = batch.map(query =>
        searchZAI(query).catch(() => [] as MetasearchResult[])
      );
      const zaiResultsArray = await Promise.all(zaiPromises);

      for (const queryResults of zaiResultsArray) {
        engineStats.webSearch += queryResults.length;
        addResults(queryResults, allResults, seenUrls, enginesUsed, 'Web Search');
      }

      if (i + zaiBatchSize < engineQueries.zai.length) {
        await randomDelay(500, 1000);
      }
    }
    console.log(`[METASEARCH] ZAI phase done: ${engineStats.webSearch} results, Total unique=${allResults.length}`);

    // =========================================================================
    // PHASE 2: SCRAPING ENGINES (Google + Bing + DuckDuckGo)
    // Execute in batches, max 3 queries per engine
    // =========================================================================
    console.log('[METASEARCH] Phase 2: Scraping engines (Google + Bing + DuckDuckGo)...');

    const maxScrapingQueries = 4; // Keep it short to avoid rate limiting
    const googleQueries = engineQueries.google.slice(0, maxScrapingQueries);
    const bingQueries = engineQueries.bing.slice(0, maxScrapingQueries);
    const ddgQueries = engineQueries.zai.slice(0, maxScrapingQueries); // DDG uses plain queries

    // Process scraping queries one at a time per engine to avoid blocks
    for (let i = 0; i < Math.max(googleQueries.length, bingQueries.length, ddgQueries.length); i++) {
      const promises: Promise<void>[] = [];

      if (i < googleQueries.length) {
        promises.push(
          searchGoogle(googleQueries[i])
            .then(results => {
              engineStats.google += results.length;
              addResults(results, allResults, seenUrls, enginesUsed, 'Google');
            })
            .catch(() => {})
        );
      }

      if (i < bingQueries.length) {
        promises.push(
          searchBing(bingQueries[i])
            .then(results => {
              engineStats.bing += results.length;
              addResults(results, allResults, seenUrls, enginesUsed, 'Bing');
            })
            .catch(() => {})
        );
      }

      if (i < ddgQueries.length) {
        promises.push(
          searchDuckDuckGo(ddgQueries[i])
            .then(results => {
              engineStats.duckduckgo += results.length;
              addResults(results, allResults, seenUrls, enginesUsed, 'DuckDuckGo');
            })
            .catch(() => {})
        );
      }

      await Promise.all(promises);
      // Delay between scraping rounds
      await randomDelay(1500, 3000);
    }

    console.log(`[METASEARCH] Scraping phase done: Google=${engineStats.google}, Bing=${engineStats.bing}, DDG=${engineStats.duckduckgo}, Total unique=${allResults.length}`);

    // =========================================================================
    // PHASE 3: AI EXTRACTION FALLBACK (if scraping returned nothing)
    // =========================================================================
    if (allResults.length < 3) {
      console.log('[METASEARCH] Phase 3: AI extraction fallback (few results)...');
      try {
        const primaryQuery = engineQueries.bing[0] || engineQueries.zai[0];
        if (primaryQuery) {
          const bingUrl = `https://www.bing.com/search?q=${encodeURIComponent(primaryQuery)}&count=20`;
          const response = await fetch(bingUrl, {
            headers: buildDynamicHeaders('Bing'),
            redirect: 'follow',
            signal: AbortSignal.timeout(15000),
          });

          if (response.ok) {
            const html = await response.text();
            const aiResults = await aiExtractFromHtml(html, 'Bing', primaryQuery);
            if (aiResults.length > 0) {
              engineStats.bing += aiResults.length;
              addResults(aiResults, allResults, seenUrls, enginesUsed, 'Bing (AI)');
              console.log(`[METASEARCH] AI extraction from Bing: ${aiResults.length} results`);
            }
          }
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        console.log(`[METASEARCH] AI extraction phase error: ${msg.substring(0, 80)}`);
      }
    }

    // Sort results: downloadable first, then by position
    allResults.sort((a, b) => {
      if (a.isDownloadable && !b.isDownloadable) return -1;
      if (!a.isDownloadable && b.isDownloadable) return 1;
      return a.position - b.position;
    });

    // Re-number positions
    allResults.forEach((r, i) => { r.position = i + 1; });

    const searchEngine = enginesUsed.length > 0
      ? `OSINT Multi-Engine v4.0 [${enginesUsed.join(' + ')}]`
      : 'Sin resultados';

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[METASEARCH] Final (${elapsed}s): Google=${engineStats.google}, Bing=${engineStats.bing}, Yandex=${engineStats.yandex}, DDG=${engineStats.duckduckgo}, Brave=${engineStats.brave}, ZAI=${engineStats.webSearch}, Total unique=${allResults.length}`);

    // =========================================================================
    // AI ANALYSIS
    // =========================================================================
    let aiAnalysis = '';
    if (executive && allResults.length > 0) {
      console.log('[METASEARCH] Running AI analysis on results...');
      aiAnalysis = await analyzeResultsWithAI(
        {
          fullName: executive.fullName,
          identificationNum: executive.identificationNum,
          email: executive.email,
        },
        allResults
      );
      console.log('[METASEARCH] AI analysis completed');
    }

    // =========================================================================
    // DOWNLOAD AND STORE FILES
    // =========================================================================
    const evidenceDetails: EvidenceDetail[] = [];
    const baseDir = '/home/z/my-project/Evidencias_Ejecutivos';
    const downloadableResults = allResults.filter(r => r.isDownloadable);

    if (downloadFiles && downloadableResults.length > 0 && executive) {
      console.log(`[METASEARCH] Starting download of ${downloadableResults.length} files...`);

      const downloadPromises: Promise<void>[] = [];
      let running = 0;

      for (const result of downloadableResults.slice(0, 20)) { // Cap at 20 downloads
        const downloadPromise = (async () => {
          while (running >= 3) {
            await new Promise(r => setTimeout(r, 500));
          }
          running++;

          try {
            const downloadResult = await downloadAndStoreFile(
              result.url,
              executive.fullName,
              baseDir
            );

            const detail: EvidenceDetail = {
              url: result.url,
              sourceDomain: extractDomain(result.url),
              discoveredAt: new Date().toISOString(),
              title: result.title,
              fileType: result.fileType || extractFileType(result.url),
              fileName: downloadResult.fileName,
              downloadStatus: downloadResult.success ? 'success' : 'failed',
              localPath: downloadResult.localPath,
              fileSize: downloadResult.fileSize,
              error: downloadResult.error,
              httpStatus: downloadResult.httpStatus,
              contentType: downloadResult.contentType,
              captureTimestamp: new Date().toISOString(),
            };

            evidenceDetails.push(detail);
            result.downloaded = downloadResult.success;
            result.localPath = downloadResult.localPath;
          } finally {
            running--;
          }
        })();
        downloadPromises.push(downloadPromise);
      }

      await Promise.all(downloadPromises);
    }

    // Write evidence detail files
    let evidenceDetailPath = '';
    if (executive && (evidenceDetails.length > 0 || allResults.length > 0)) {
      const allEvidence: EvidenceDetail[] = allResults.map(r => ({
        url: r.url,
        sourceDomain: extractDomain(r.url),
        discoveredAt: new Date().toISOString(),
        title: r.title,
        fileType: r.fileType || extractFileType(r.url),
        fileName: r.downloaded ? path.basename(r.localPath || '') : '',
        downloadStatus: r.downloaded ? 'success' : (r.isDownloadable ? 'failed' : 'skipped'),
        localPath: r.localPath || '',
        fileSize: 0,
        captureTimestamp: new Date().toISOString(),
      }));

      evidenceDetailPath = writeEvidenceDetail(executive.fullName, baseDir, allEvidence, aiAnalysis, queryGroups, engineStats);
    }

    // =========================================================================
    // UPDATE EXECUTIVE RECORD
    // =========================================================================
    if (executive) {
      const resultsSummary = allResults.slice(0, 50).map(r => ({
        title: r.title,
        url: r.url,
        snippet: r.snippet.substring(0, 200),
        source: r.source,
        fileType: r.fileType,
        isDownloadable: r.isDownloadable,
        downloaded: r.downloaded,
        localPath: r.localPath,
      }));

      await db.executive.update({
        where: { id: executive.id },
        data: {
          lastMetasearch: new Date(),
          lastMetasearchResults: JSON.stringify(resultsSummary),
        },
      });
    }

    // =========================================================================
    // RETURN RESPONSE
    // =========================================================================
    return NextResponse.json({
      success: true,
      searchEngine,
      enginesUsed,
      engineStats,
      queryGroups: queryGroups.map(g => ({ label: g.label, queryCount: g.queries.length, blockType: g.blockType })),
      resultCount: allResults.length,
      downloadableCount: downloadableResults.length,
      downloadedCount: evidenceDetails.filter(e => e.downloadStatus === 'success').length,
      results: allResults.slice(0, 150),
      aiAnalysis,
      evidence: evidenceDetails,
      evidenceDetailPath,
      executive: executive ? {
        id: executive.id,
        fullName: executive.fullName,
        identificationNum: executive.identificationNum,
        email: executive.email,
      } : null,
      timestamp: new Date().toISOString(),
      elapsedSeconds: parseFloat(elapsed),
      extensionsMonitored: ALL_EXTENSIONS,
    });
  } catch (error) {
    console.error('Metasearch error:', error);
    return NextResponse.json(
      { error: 'Error al ejecutar metabusqueda' },
      { status: 500 }
    );
  }
}
