import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import * as cheerio from 'cheerio';
import * as fs from 'fs';
import * as path from 'path';

export const maxDuration = 300;

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
// DYNAMIC ANTI-BLOCK SYSTEM
// Rotating user agents, enterprise headers, session simulation, random delays
// ============================================================================

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.142 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
];

const ACCEPT_LANGUAGES = [
  'es-CO,es;q=0.9,en;q=0.8',
  'es-ES,es;q=0.9,en;q=0.8',
  'es;q=0.9,en-US;q=0.8,en;q=0.7',
  'es-CO,es-419;q=0.9,en;q=0.8',
  'en-US,en;q=0.9,es;q=0.8',
];

const ACCEPT_ENCODINGS = [
  'gzip, deflate, br',
  'gzip, deflate',
  'identity',
  'br, gzip, deflate',
];

// Session cookie store for each engine
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
  const lang = getRandomElement(AcCEPT_LANGUAGES);
  const enc = getRandomElement(ACCEPT_ENCODINGS);

  const headers: Record<string, string> = {
    'User-Agent': ua,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': lang,
    'Accept-Encoding': enc,
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'Dnt': '1',
  };

  // Add session cookies if available
  if (sessionCookies[engine]) {
    headers['Cookie'] = sessionCookies[engine];
  }

  return headers;
}

function extractAndStoreCookies(response: Response, engine: string): void {
  const setCookies = response.headers.getSetCookie?.() || [];
  if (setCookies.length > 0) {
    const existing = sessionCookies[engine] || '';
    const newCookies = setCookies.map(c => c.split(';')[0]).join('; ');
    sessionCookies[engine] = existing ? `${existing}; ${newCookies}` : newCookies;
  }
}

// ============================================================================
// FLEXIBLE SEMANTIC HTML PARSER
// Instead of relying on rigid CSS selectors, this parser extracts all links
// with meaningful text content and uses heuristics to identify search results
// ============================================================================

function flexibleHtmlParse(html: string, engineSource: string, query: string): MetasearchResult[] {
  const results: MetasearchResult[] = [];
  const $ = cheerio.load(html);
  const seenInPage = new Set<string>();

  // Strategy 1: Try engine-specific selectors first (fast path)
  const engineSelectors: Record<string, { container: string; link: string; title: string; snippet: string }> = {
    Google: { container: 'div.g, div[data-hveid], div[data-ved]', link: 'a[href^="http"]', title: 'h3, [data-header-feature] h3', snippet: '.VwiC3b, .st, [data-sncf], .IsZvec, .kb0PBd' },
    Bing: { container: 'li.b_algo, li.b_vlhit', link: 'h2 a, a[href^="http"]', title: 'h2, .b_promotionText', snippet: '.b_caption p, .b_lineclamp2, p, .b_factrow' },
    Yandex: { container: 'li.serp-item, div.serp-item, .Organic, .organic__url', link: 'a[href^="http"]', title: '.organic__title, h2, .Typs-heading, span.OrganicTextContentSpan', snippet: '.organic__content-wrapper, .text-container, .Typs-text, .organic__text' },
    DuckDuckGo: { container: 'div.result, div.web-result', link: 'a.result__a, a[href^="http"]', title: 'a.result__a, h2 a', snippet: '.result__snippet, a.result__snippet, .result__body' },
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

  // Strategy 2: If engine-specific selectors found nothing, use semantic extraction
  if (results.length === 0) {
    console.log(`[METASEARCH] ${engineSource}: Specific selectors failed, using semantic extraction...`);

    // Look for all anchor tags with href and meaningful text
    $('a[href]').each((_, el) => {
      if (results.length >= 20) return false;
      const linkEl = $(el);
      let href = linkEl.attr('href') || '';
      const title = linkEl.text().trim();

      href = cleanRedirectUrl(href, engineSource);
      if (!href.startsWith('http')) href = normalizeUrl(href);

      const urlKey = href.toLowerCase().split('?')[0].split('#')[0];

      // Filter: must have meaningful title, not be a nav/footer link, not a search engine self-link
      if (
        title.length > 8 &&
        href.startsWith('http') &&
        !isSearchEngineUrl(href, engineSource) &&
        !seenInPage.has(urlKey) &&
        !isNavOrFooterLink(title)
      ) {
        seenInPage.add(urlKey);

        // Try to find snippet near the link
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

  // Strategy 3: Last resort - extract from raw text with URL patterns
  if (results.length === 0) {
    console.log(`[METASEARCH] ${engineSource}: Semantic extraction also failed, trying URL pattern matching...`);
    const urlPattern = /https?:\/\/[^\s"'<>\]\)]+/g;
    const foundUrls = html.match(urlPattern) || [];
    const cleanUrls = [...new Set(foundUrls.map(u => u.split(/[<>"'\]\)]/)[0]))];

    for (const url of cleanUrls) {
      if (results.length >= 15) break;
      const urlKey = url.toLowerCase().split('?')[0].split('#')[0];
      if (!isSearchEngineUrl(url, engineSource) && !seenInPage.has(urlKey) && isDocumentUrl(url)) {
        seenInPage.add(urlKey);
        const urlObj = new URL(url);
        results.push({
          title: urlObj.pathname.split('/').pop() || urlObj.hostname,
          url,
          snippet: '',
          source: engineSource,
          position: results.length + 1,
          isDownloadable: true,
          querySource: query.substring(0, 80),
        });
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
  if (href.startsWith('/')) return ''; // relative URLs can't be resolved without base
  return href;
}

function isSearchEngineUrl(url: string, engine: string): boolean {
  const engineDomains: Record<string, string[]> = {
    Google: ['google.com', 'google.co', 'gstatic.com', 'googleapis.com'],
    Bing: ['bing.com', 'microsoft.com', 'msn.com'],
    Yandex: ['yandex.com', 'yandex.ru', 'yandex.net'],
    DuckDuckGo: ['duckduckgo.com'],
  };
  const domains = engineDomains[engine] || [];
  return domains.some(d => url.includes(d));
}

function isNavOrFooterLink(text: string): boolean {
  const navPatterns = /^(login|sign|register|home|about|contact|privacy|terms|cookies|buscar|buscar|inicio|privacidad|mapa|images|videos|news|maps|translate|mail|signin|signup|log out|log in|cached|similar|more|next|previous|1|2|3|4|5)$/i;
  return navPatterns.test(text.trim()) || text.length < 5;
}

// ============================================================================
// EXPANDED OSINT DORKING MATRIX
// 3 Blocks: Name, Email, ID with 30+ file extensions
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

function buildOsintQueryMatrix(executive: {
  fullName: string;
  identificationNum: string;
  email: string | null;
}): SearchQueryGroup[] {
  const groups: SearchQueryGroup[] = [];
  const name = executive.fullName;
  const id = executive.identificationNum;
  const email = executive.email;

  // Build ext: operator string for primary extensions
  const primaryExtGroup = PRIMARY_EXTENSIONS.map(e => `ext:${e}`).join(' OR ');
  const secondaryExtGroup = SECONDARY_EXTENSIONS.map(e => `ext:${e}`).join(' OR ');

  // =========================================================================
  // BLOQUE 1: Por Nombre Completo
  // =========================================================================
  const nameQueries: string[] = [];

  // 1a: Name + all primary extensions (single powerful query)
  nameQueries.push(`"${name}" (${primaryExtGroup})`);

  // 1b: Name + secondary extensions
  nameQueries.push(`"${name}" (${secondaryExtGroup})`);

  // 1c: Name + specific high-value document types
  nameQueries.push(`"${name}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:pptx OR ext:sql OR ext:env OR ext:conf OR ext:bak)`);

  // 1d: Name + ID combined (cross-reference)
  nameQueries.push(`"${name}" "${id}"`);

  // 1e: Name variations (last name + first name)
  const nameParts = name.toLowerCase().split(' ');
  const lastName = nameParts[nameParts.length - 1] || '';
  const firstName = nameParts[0] || '';
  const secondLastName = nameParts.length > 2 ? nameParts[nameParts.length - 2] : '';

  if (secondLastName && lastName) {
    nameQueries.push(`"${firstName} ${secondLastName} ${lastName}" (ext:pdf OR ext:xlsx OR ext:doc)`);
  }

  // 1f: Name in URL paths (intitle/inurl dorking)
  const nameUrl = name.toLowerCase().replace(/\s+/g, '.');
  nameQueries.push(`inurl:"${nameUrl}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:csv)`);

  groups.push({ label: `Nombre: ${name}`, queries: nameQueries, blockType: 'name' });

  // =========================================================================
  // BLOQUE 2: Por Correo Electrónico
  // =========================================================================
  if (email) {
    const emailQueries: string[] = [];

    // 2a: Email + all primary extensions
    emailQueries.push(`"${email}" (${primaryExtGroup})`);

    // 2b: Email + secondary extensions
    emailQueries.push(`"${email}" (${secondaryExtGroup})`);

    // 2c: Email + high-value document types
    emailQueries.push(`"${email}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:sql OR ext:env OR ext:conf OR ext:bak OR ext:json)`);

    // 2d: Email username part (without domain)
    const emailUser = email.split('@')[0];
    if (emailUser && emailUser !== email) {
      emailQueries.push(`"${emailUser}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:csv OR ext:sql)`);
    }

    // 2e: Email in document metadata
    emailQueries.push(`"${email}" (ext:pdf OR ext:doc OR ext:xlsx OR ext:pptx)`);

    groups.push({ label: `Email: ${email}`, queries: emailQueries, blockType: 'email' });
  }

  // =========================================================================
  // BLOQUE 3: Por Identificación
  // =========================================================================
  const idQueries: string[] = [];

  // 3a: ID + all primary extensions
  idQueries.push(`"${id}" (${primaryExtGroup})`);

  // 3b: ID + secondary extensions
  idQueries.push(`"${id}" (${secondaryExtGroup})`);

  // 3c: ID + high-value document types
  idQueries.push(`"${id}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:csv OR ext:sql OR ext:env OR ext:conf OR ext:bak)`);

  // 3d: ID in URL paths
  idQueries.push(`inurl:"${id}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:html)`);

  groups.push({ label: `ID: ${id}`, queries: idQueries, blockType: 'id' });

  // =========================================================================
  // BLOQUE COMBINADO: Cross-reference queries
  // =========================================================================
  const combinedQueries: string[] = [];

  // 4a: Name + email
  if (email) {
    combinedQueries.push(`"${name}" "${email}" (ext:pdf OR ext:xlsx OR ext:doc OR ext:sql)`);
  }

  // 4b: Name + organization (if we can extract it from email domain)
  if (email) {
    const domain = email.split('@')[1];
    if (domain) {
      combinedQueries.push(`"${name}" site:${domain} (ext:pdf OR ext:xlsx OR ext:doc OR ext:html OR ext:conf)`);
    }
  }

  // 4c: ID + name parts
  if (lastName) {
    combinedQueries.push(`"${id}" "${lastName}" (ext:pdf OR ext:xlsx OR ext:doc)`);
  }

  groups.push({ label: 'Cruzamiento Multi-Campo', queries: combinedQueries, blockType: 'combined' });

  return groups;
}

// ============================================================================
// SEARCH ENGINE IMPLEMENTATIONS
// With dynamic headers, cookie management, and flexible parsing
// ============================================================================

// --- GOOGLE ---
async function searchGoogle(query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  try {
    await randomDelay(500, 1500); // Random pre-request delay
    const encodedQuery = encodeURIComponent(query);
    const url = `https://www.google.com/search?q=${encodedQuery}&num=20&hl=es-419&start=0`;
    const headers = buildDynamicHeaders('Google');

    const response = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(20000),
    });

    extractAndStoreCookies(response, 'Google');

    if (!response.ok) {
      console.log(`[METASEARCH] Google HTTP ${response.status}`);
      return results;
    }

    const html = await response.text();

    // Check if we got a CAPTCHA/consent page
    if (html.includes('captcha') || html.includes('unusual traffic') || html.includes('Sorry')) {
      console.log(`[METASEARCH] Google: CAPTCHA/block detected, trying Google Colombia...`);
      // Try Google Colombia as fallback
      const coUrl = `https://www.google.com.co/search?q=${encodedQuery}&num=20&hl=es`;
      const coResponse = await fetch(coUrl, {
        headers: buildDynamicHeaders('Google'),
        redirect: 'follow',
        signal: AbortSignal.timeout(20000),
      });
      if (coResponse.ok) {
        const coHtml = await coResponse.text();
        return flexibleHtmlParse(coHtml, 'Google', query);
      }
      return results;
    }

    return flexibleHtmlParse(html, 'Google', query);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Google error: ${msg.substring(0, 80)}`);
  }
  return results;
}

// --- BING ---
async function searchBing(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(400, 1200);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://www.bing.com/search?q=${encodedQuery}&count=20&setlang=es-419&cc=co`;
    const headers = buildDynamicHeaders('Bing');

    const response = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(20000),
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

// --- YANDEX ---
async function searchYandex(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(600, 1800);
    const encodedQuery = encodeURIComponent(query);

    // Try multiple Yandex endpoints for better results
    const endpoints = [
      `https://yandex.com/search/?text=${encodedQuery}&lr=10636&lang=es`,
      `https://yandex.com/search/?text=${encodedQuery}&lr=109670`,  // Colombia region
    ];

    for (const url of endpoints) {
      const headers = buildDynamicHeaders('Yandex');
      headers['Accept-Language'] = 'es,es-ES;q=0.9,en;q=0.8';

      const response = await fetch(url, {
        headers,
        redirect: 'follow',
        signal: AbortSignal.timeout(20000),
      });

      extractAndStoreCookies(response, 'Yandex');

      if (!response.ok) {
        console.log(`[METASEARCH] Yandex HTTP ${response.status} from ${url.substring(0, 50)}`);
        continue;
      }

      const html = await response.text();
      const results = flexibleHtmlParse(html, 'Yandex', query);

      if (results.length > 0) return results;
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Yandex error: ${msg.substring(0, 80)}`);
  }
  return [];
}

// --- DUCKDUCKGO ---
async function searchDuckDuckGo(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(400, 1000);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://html.duckduckgo.com/html/?q=${encodedQuery}`;
    const headers = buildDynamicHeaders('DuckDuckGo');

    const response = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(20000),
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

// --- BRAVE SEARCH (Additional engine for more coverage) ---
async function searchBrave(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(400, 1000);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://search.brave.com/search?q=${encodedQuery}&source=web`;
    const headers = buildDynamicHeaders('Brave');

    const response = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(20000),
    });

    if (!response.ok) return [];

    const html = await response.text();
    const $ = cheerio.load(html);
    const results: MetasearchResult[] = [];
    const seenInPage = new Set<string>();

    // Brave-specific selectors
    $('div.snippet').each((_, el) => {
      if (results.length >= 15) return false;
      const container = $(el);
      const linkEl = container.find('a.result-header').first();
      let href = linkEl.attr('href') || '';
      const title = linkEl.find('.snippet-title').text().trim() || linkEl.text().trim();
      const snippet = container.find('.snippet-description').text().trim();

      if (href.startsWith('//')) href = 'https:' + href;

      const urlKey = href.toLowerCase().split('?')[0].split('#')[0];
      if (title && href.startsWith('http') && !seenInPage.has(urlKey)) {
        seenInPage.add(urlKey);
        results.push({
          title: title.substring(0, 300),
          url: href,
          snippet: snippet.substring(0, 500),
          source: 'Brave',
          position: results.length + 1,
          isDownloadable: isDocumentUrl(href),
          querySource: query.substring(0, 80),
        });
      }
    });

    // Fallback with flexible parser if specific selectors failed
    if (results.length === 0) {
      return flexibleHtmlParse(html, 'DuckDuckGo', query).map(r => ({ ...r, source: 'Brave' }));
    }

    return results;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Brave error: ${msg.substring(0, 80)}`);
  }
  return [];
}

// ============================================================================
// ZAI WEB SEARCH (PRIMARY FALLBACK - Most Reliable)
// Always runs alongside scraping engines for maximum coverage
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
      return searchResult.map((item: any, index: number) => ({
        title: item.name || 'Sin título',
        url: item.url || '',
        snippet: item.snippet || '',
        source: 'Web Search',
        position: index + 1,
        isDownloadable: item.url ? isDocumentUrl(item.url) : false,
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
// When HTML parsing fails, use AI to extract structured data from raw HTML
// ============================================================================
async function aiExtractFromHtml(html: string, engineSource: string, query: string): Promise<MetasearchResult[]> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    // Take a sample of the HTML for AI analysis
    const htmlSample = html.substring(0, 12000);

    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a web scraping expert. Extract search results from the HTML of a ${engineSource} search results page. Return ONLY a JSON array of objects with: title, url, snippet. Maximum 15 results. If no results found, return empty array [].`
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
          title: (item.title || 'Sin título').substring(0, 300),
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
// AI ANALYSIS OF RESULTS - Enhanced
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

    const prompt = `Eres un analista de inteligencia OSINT especializado en protección ejecutiva. Analiza los siguientes resultados de metabúsqueda para el ejecutivo y genera un informe de amenazas/exposición digital.

EJECUTIVO:
- Nombre: ${executive.fullName}
- Identificación: ${executive.identificationNum}
- Email: ${executive.email || 'No disponible'}

RESULTADOS DE METABÚSQUEDA OSINT (${results.length} resultados de múltiples motores):
${resultsSummary}

INSTRUCCIONES:
1. Clasifica cada resultado según nivel de exposición: CRÍTICO, ALTO, MEDIO, BAJO
2. Identifica documentos que contengan datos personales del ejecutivo (PDFs con cédula, Excel con datos financieros, configs con credenciales, etc.)
3. Detecta posibles filtraciones de información sensible (archivos .env, .conf, .sql, .bak expuestos)
4. Identifica documentos académicos, laborales, financieros o regulatorios asociados
5. Presta especial atención a archivos de configuración (.env, .conf, .ini, .json, .yaml) que puedan contener credenciales
6. Genera recomendaciones de protección específicas y accionables
7. Identifica vectores de ataque potenciales basados en la información expuesta

FORMATO DE RESPUESTA:
- Resumen Ejecutivo (3-5 líneas con nivel de riesgo general)
- Hallazgos Críticos (exposición crítica/alta - documentos con datos personales)
- Hallazgos de Seguridad (archivos .env, .conf, .sql, .bak expuestos)
- Hallazgos Moderados (documentos públicos pero relevantes)
- Documentos Identificados por Tipo de Archivo
- Vectores de Ataque Potenciales
- Recomendaciones de Protección (inmediatas, corto plazo, largo plazo)`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista de inteligencia OSINT experto en protección ejecutiva, ciberseguridad y contrainteligencia. Respondes siempre en español de forma clara, detallada y profesional. Tu análisis debe ser profundo y accionable.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 3000,
    });

    return completion.choices?.[0]?.message?.content || 'Análisis no disponible';
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] AI analysis error: ${msg.substring(0, 200)}`);
    return 'Análisis IA no disponible en este momento.';
  }
}

// ============================================================================
// FILE DOWNLOAD AND STORAGE - Enhanced with metadata
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
      signal: AbortSignal.timeout(60000),
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
// EVIDENCE DETAIL FILE GENERATOR - Enhanced with full metadata
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
      generatorAgent: 'ActorTrace OSINT Metasearch v3.0',
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

  // Also write a human-readable TXT version
  const txtPath = path.join(execDir, 'detalle_identificado.txt');
  const txtContent = [
    `╔══════════════════════════════════════════════════════════════╗`,
    `║  ACTORTRACE - REPORTE DE EVIDENCIA DIGITAL OSINT           ║`,
    `╚══════════════════════════════════════════════════════════════╝`,
    ``,
    `Ejecutivo: ${executiveName}`,
    `Fecha de captura: ${new Date().toLocaleString('es-CO')}`,
    `Agente: ActorTrace OSINT Metasearch v3.0`,
    ``,
    `═══ ESTADÍSTICAS ═══`,
    `Total hallazgos: ${evidence.length}`,
    `Archivos descargados: ${evidence.filter(e => e.downloadStatus === 'success').length}`,
    `Descargas fallidas: ${evidence.filter(e => e.downloadStatus === 'failed').length}`,
    `Archivos omitidos: ${evidence.filter(e => e.downloadStatus === 'skipped').length}`,
    ``,
    `Motores consultados:`,
    ...Object.entries(engineStats).map(([engine, count]) => `  - ${engine}: ${count} resultados`),
    ``,
    `═══ MATRIZ DE CONSULTAS EJECUTADAS ═══`,
    ...queryGroups.map(g => `  [${g.blockType.toUpperCase()}] ${g.label} (${g.queries.length} consultas)`),
    ``,
    `═══ HALLAZGOS DETALLADOS ═══`,
    ...evidence.map((e, i) => [
      ``,
      `  Hallazgo #${i + 1}:`,
      `  URL: ${e.url}`,
      `  Dominio: ${e.sourceDomain}`,
      `  Fecha de captura: ${e.discoveredAt}`,
      `  Título: ${e.title}`,
      `  Tipo de archivo: ${e.fileType}`,
      `  Estado de descarga: ${e.downloadStatus}`,
      e.localPath ? `  Ruta local: ${e.localPath}` : '',
      e.fileSize ? `  Tamaño: ${(e.fileSize / 1024).toFixed(1)} KB` : '',
      e.error ? `  Error: ${e.error}` : '',
    ].filter(Boolean).join('\n')),
    ``,
    `═══ ANÁLISIS DE IA ═══`,
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
// MAIN POST HANDLER - 6 ENGINE METASEARCH v3.0
// Engines: Google + Bing + Yandex + DuckDuckGo + Brave (parallel scraping)
//          ZAI Web Search (always runs for maximum coverage)
//          AI Semantic Extraction (fallback when scraping fails)
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

    if (executiveId) {
      executive = await db.executive.findUnique({ where: { id: executiveId } });
      if (!executive) {
        return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
      }

      queryGroups = buildOsintQueryMatrix({
        fullName: executive.fullName,
        identificationNum: executive.identificationNum,
        email: executive.email,
      });

      console.log(`[METASEARCH] Built ${queryGroups.length} query groups with ${queryGroups.reduce((acc, g) => acc + g.queries.length, 0)} total queries`);
    } else {
      queryGroups = [{ label: 'Búsqueda personalizada', queries: [customQuery], blockType: 'custom' }];
    }

    // =========================================================================
    // COLLECT QUERIES - Execute ALL queries (up to 12 for comprehensive coverage)
    // =========================================================================
    const allQueries: string[] = [];
    for (const group of queryGroups) {
      allQueries.push(...group.queries);
    }
    // Take top query from each group first (diversity), then fill remaining
    const prioritizedQueries: string[] = [];
    const maxPerGroup = 2;
    const groupArrays = queryGroups.map(g => g.queries);
    for (let i = 0; i < Math.max(...groupArrays.map(g => g.length)); i++) {
      for (const groupArr of groupArrays) {
        if (i < groupArr.length && prioritizedQueries.length < 12) {
          prioritizedQueries.push(groupArr[i]);
        }
      }
    }
    const queriesToExecute = prioritizedQueries.slice(0, 12);
    console.log(`[METASEARCH] Executing ${queriesToExecute.length} prioritized queries across 6 engines`);

    const allResults: MetasearchResult[] = [];
    const seenUrls = new Set<string>();
    const enginesUsed: string[] = [];
    const engineStats: Record<string, number> = {
      google: 0, bing: 0, yandex: 0, duckduckgo: 0, brave: 0, webSearch: 0,
    };

    // =========================================================================
    // PHASE 1: SCRAPING ENGINES (Google + Bing + Yandex + DuckDuckGo + Brave)
    // For each query, hit all 5 engines in parallel with random delays
    // =========================================================================
    console.log('[METASEARCH] Phase 1: Scraping engines (Google + Bing + Yandex + DuckDuckGo + Brave)...');

    // Process queries in batches of 2 to avoid overwhelming engines
    const batchSize = 2;
    for (let i = 0; i < queriesToExecute.length; i += batchSize) {
      const batch = queriesToExecute.slice(i, i + batchSize);

      const batchPromises = batch.map(query =>
        Promise.all([
          searchGoogle(query).catch(() => [] as MetasearchResult[]),
          searchBing(query).catch(() => [] as MetasearchResult[]),
          searchYandex(query).catch(() => [] as MetasearchResult[]),
          searchDuckDuckGo(query).catch(() => [] as MetasearchResult[]),
          searchBrave(query).catch(() => [] as MetasearchResult[]),
        ]).then(([google, bing, yandex, ddg, brave]) => {
          engineStats.google += google.length;
          engineStats.bing += bing.length;
          engineStats.yandex += yandex.length;
          engineStats.duckduckgo += ddg.length;
          engineStats.brave += brave.length;

          addResults(google, allResults, seenUrls, enginesUsed, 'Google');
          addResults(bing, allResults, seenUrls, enginesUsed, 'Bing');
          addResults(yandex, allResults, seenUrls, enginesUsed, 'Yandex');
          addResults(ddg, allResults, seenUrls, enginesUsed, 'DuckDuckGo');
          addResults(brave, allResults, seenUrls, enginesUsed, 'Brave');
        })
      );

      await Promise.all(batchPromises);

      // Random delay between batches (1-3 seconds) to avoid rate limiting
      await randomDelay(1000, 3000);
    }

    console.log(`[METASEARCH] Scraping phase done: Google=${engineStats.google}, Bing=${engineStats.bing}, Yandex=${engineStats.yandex}, DDG=${engineStats.duckduckgo}, Brave=${engineStats.brave}, Total unique=${allResults.length}`);

    // =========================================================================
    // PHASE 2: ZAI WEB SEARCH (Always runs for maximum coverage)
    // =========================================================================
    console.log('[METASEARCH] Phase 2: ZAI Web Search (always-on for maximum coverage)...');
    const zaiQueries = queriesToExecute.slice(0, 6);
    const zaiPromises = zaiQueries.map(query =>
      searchZAI(query).catch(() => [] as MetasearchResult[])
    );
    const zaiResultsArray = await Promise.all(zaiPromises);

    for (const queryResults of zaiResultsArray) {
      engineStats.webSearch += queryResults.length;
      addResults(queryResults, allResults, seenUrls, enginesUsed, 'Web Search');
    }
    console.log(`[METASEARCH] ZAI phase: ${engineStats.webSearch} results, Total unique=${allResults.length}`);

    // =========================================================================
    // PHASE 3: AI SEMANTIC EXTRACTION (If scraping engines returned very few)
    // =========================================================================
    if (allResults.length < 5 && queriesToExecute.length > 0) {
      console.log('[METASEARCH] Phase 3: AI Semantic Extraction (scraping returned few results)...');
      try {
        // Re-fetch the most important query with a fresh request and extract with AI
        const primaryQuery = queriesToExecute[0];
        const enginesToRetry = [
          { fn: () => searchBing(primaryQuery), name: 'Bing' },
          { fn: () => searchDuckDuckGo(primaryQuery), name: 'DuckDuckGo' },
        ];

        for (const engine of enginesToRetry) {
          try {
            const response = await fetch(
              engine.name === 'Bing'
                ? `https://www.bing.com/search?q=${encodeURIComponent(primaryQuery)}&count=20`
                : `https://html.duckduckgo.com/html/?q=${encodeURIComponent(primaryQuery)}`,
              {
                headers: buildDynamicHeaders(engine.name),
                redirect: 'follow',
                signal: AbortSignal.timeout(15000),
              }
            );

            if (response.ok) {
              const html = await response.text();
              const aiResults = await aiExtractFromHtml(html, engine.name, primaryQuery);
              if (aiResults.length > 0) {
                addResults(aiResults, allResults, seenUrls, enginesUsed, `${engine.name} (AI)`);
                engineStats[engine.name.toLowerCase() as keyof typeof engineStats] += aiResults.length;
                console.log(`[METASEARCH] AI extraction from ${engine.name}: ${aiResults.length} results`);
              }
            }
          } catch {
            // Continue to next engine
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
      ? `OSINT Multi-Engine v3.0 [${enginesUsed.join(' + ')}]`
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

      for (const result of downloadableResults) {
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

    // Write evidence detail files (JSON + TXT)
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
      { error: 'Error al ejecutar metabúsqueda' },
      { status: 500 }
    );
  }
}
