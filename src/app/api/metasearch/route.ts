import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

// Lazy-load heavy modules to avoid issues in serverless
let cheerioInstance: typeof import('cheerio') | null = null;
async function getCheerio() {
  if (!cheerioInstance) {
    cheerioInstance = await import('cheerio');
  }
  return cheerioInstance;
}

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
// ============================================================================

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
];

const ACCEPT_LANGUAGES = [
  'es-CO,es;q=0.9,en;q=0.8',
  'es-ES,es;q=0.9,en;q=0.8',
  'es;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9,es;q=0.8',
];

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

  return {
    'User-Agent': ua,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': lang,
    'Accept-Encoding': 'gzip, deflate',
    'Cache-Control': 'no-cache',
    'Sec-Ch-Ua': '"Chromium";v="131", "Google Chrome";v="131"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
  };
}

// ============================================================================
// OSINT DORKING MATRIX v4.0 - Correct operators per engine
// Google/Bing: filetype: (NOT ext:)
// ZAI: plain queries (no operators)
// ============================================================================

const ALL_EXTENSIONS = [
  'pdf', 'xlsx', 'xls', 'ppt', 'pptx', 'doc', 'docx', 'txt',
  'rar', 'zip', '7z', 'htm', 'html', 'csv', 'rtf',
  'env', 'conf', 'config', 'ini', 'json', 'xml', 'yaml',
  'bak', 'old', 'sql', 'db',
  'odt', 'ods', 'odp', 'yml', 'tmp', 'sqlite',
  'tar.gz', 'tgz', 'png', 'jpg', 'jpeg', 'svg',
];

interface EngineQuerySet {
  google: string[];
  bing: string[];
  zai: string[];
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
  const emailUser = email ? email.split('@')[0] : '';
  const domain = email ? email.split('@')[1] : '';

  const groups: SearchQueryGroup[] = [];
  const googleQueries: string[] = [];
  const bingQueries: string[] = [];
  const zaiQueries: string[] = [];

  // =========================================================================
  // BLOQUE 1: Por Nombre Completo
  // =========================================================================
  const nameGroupQueries: string[] = [];

  // Simple name search
  googleQueries.push(`"${name}"`);
  bingQueries.push(`"${name}"`);
  zaiQueries.push(`"${name}"`);
  nameGroupQueries.push(`"${name}"`);

  // Name + filetype:pdf
  googleQueries.push(`"${name}" filetype:pdf`);
  bingQueries.push(`"${name}" filetype:pdf`);
  zaiQueries.push(`"${name}" PDF documento`);
  nameGroupQueries.push(`"${name}" filetype:pdf`);

  // Name + doc/excel
  googleQueries.push(`"${name}" filetype:xlsx OR filetype:doc`);
  bingQueries.push(`"${name}" filetype:xlsx OR filetype:doc`);
  zaiQueries.push(`"${name}" Excel Word documento`);
  nameGroupQueries.push(`"${name}" (filetype:xlsx OR filetype:doc)`);

  // Name + sensitive types
  googleQueries.push(`"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak`);
  bingQueries.push(`"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak`);
  zaiQueries.push(`"${name}" configuracion credenciales base datos`);
  nameGroupQueries.push(`"${name}" (filetype:env OR filetype:conf OR filetype:sql OR filetype:bak)`);

  // Name + ID
  googleQueries.push(`"${name}" "${id}"`);
  bingQueries.push(`"${name}" "${id}"`);
  zaiQueries.push(`"${name}" ${id}`);
  nameGroupQueries.push(`"${name}" "${id}"`);

  // Name + pptx/csv
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

    googleQueries.push(`"${email}"`);
    bingQueries.push(`"${email}"`);
    zaiQueries.push(`"${email}"`);
    emailGroupQueries.push(`"${email}"`);

    googleQueries.push(`"${email}" filetype:pdf`);
    bingQueries.push(`"${email}" filetype:pdf`);
    zaiQueries.push(`"${email}" PDF documento`);
    emailGroupQueries.push(`"${email}" filetype:pdf`);

    googleQueries.push(`"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`);
    bingQueries.push(`"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`);
    zaiQueries.push(`"${email}" Excel Word base datos`);
    emailGroupQueries.push(`"${email}" (filetype:xlsx OR filetype:doc OR filetype:sql)`);

    if (emailUser && emailUser !== email) {
      googleQueries.push(`"${emailUser}" filetype:pdf OR filetype:xlsx`);
      bingQueries.push(`"${emailUser}" filetype:pdf OR filetype:xlsx`);
      zaiQueries.push(`"${emailUser}" documento`);
      emailGroupQueries.push(`"${emailUser}" (filetype:pdf OR filetype:xlsx)`);
    }

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

  googleQueries.push(`"${id}"`);
  bingQueries.push(`"${id}"`);
  zaiQueries.push(`"${id}"`);
  idGroupQueries.push(`"${id}"`);

  googleQueries.push(`"${id}" filetype:pdf`);
  bingQueries.push(`"${id}" filetype:pdf`);
  zaiQueries.push(`"${id}" PDF documento`);
  idGroupQueries.push(`"${id}" filetype:pdf`);

  googleQueries.push(`"${id}" filetype:xlsx OR filetype:doc OR filetype:csv`);
  bingQueries.push(`"${id}" filetype:xlsx OR filetype:doc OR filetype:csv`);
  zaiQueries.push(`"${id}" Excel Word datos`);
  idGroupQueries.push(`"${id}" (filetype:xlsx OR filetype:doc OR filetype:csv)`);

  groups.push({ label: `ID: ${id}`, queries: idGroupQueries, blockType: 'id' });

  // =========================================================================
  // BLOQUE COMBINADO
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
// FLEXIBLE HTML PARSER
// ============================================================================

async function flexibleHtmlParse(html: string, engineSource: string, query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  const $ = (await getCheerio()).load(html);
  const seenInPage = new Set<string>();

  // Strategy 1: Engine-specific selectors
  const engineSelectors: Record<string, { container: string; link: string; title: string; snippet: string }> = {
    Google: { container: 'div.g, div[data-hveid], div[data-ved], div[data-sokoban-container]', link: 'a[href^="http"], a[href^="/url"]', title: 'h3, [data-header-feature] h3', snippet: '.VwiC3b, .st, [data-sncf], .IsZvec, .kb0PBd' },
    Bing: { container: 'li.b_algo, li.b_vlhit, .b_algo', link: 'h2 a, a[href^="http"]', title: 'h2, .b_promotionText', snippet: '.b_caption p, .b_lineclamp2, p, .b_factrow' },
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

  // Strategy 2: Semantic extraction
  if (results.length === 0) {
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
    const urlPattern = /https?:\/\/[^\s"'<>\]\)]+/g;
    const foundUrls = html.match(urlPattern) || [];
    const seen = new Set<string>();
    for (const rawUrl of foundUrls) {
      const cleanUrl = rawUrl.split(/[<>"'\]\)]/)[0];
      if (seen.has(cleanUrl)) continue;
      seen.add(cleanUrl);
      if (results.length >= 15) break;
      if (!isSearchEngineUrl(cleanUrl, engineSource) && (isDocumentUrl(cleanUrl) || cleanUrl.length > 30)) {
        try {
          const urlObj = new URL(cleanUrl);
          results.push({
            title: urlObj.pathname.split('/').pop() || urlObj.hostname,
            url: cleanUrl,
            snippet: '',
            source: engineSource,
            position: results.length + 1,
            isDownloadable: isDocumentUrl(cleanUrl),
            querySource: query.substring(0, 80),
          });
        } catch { /* skip */ }
      }
    }
  }

  return results;
}

function cleanRedirectUrl(href: string, engine: string): string {
  if (!href) return '';
  if (href.includes('google.com/url?') || href.includes('google.com/search?')) {
    const match = href.match(/[?&](?:q|url)=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }
  if (href.startsWith('/url?q=')) {
    const match = href.match(/[?&]q=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }
  if (href.includes('uddg=')) {
    const match = href.match(/uddg=([^&]+)/i);
    if (match) return decodeURIComponent(match[1]);
  }
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
    Google: ['google.com', 'google.co', 'gstatic.com', 'googleapis.com'],
    Bing: ['bing.com', 'microsoft.com', 'msn.com'],
    DuckDuckGo: ['duckduckgo.com'],
  };
  const domains = engineDomains[engine] || [];
  return domains.some(d => url.includes(d));
}

function isNavOrFooterLink(text: string): boolean {
  const navPatterns = /^(login|sign|register|home|about|contact|privacy|terms|cookies|buscar|inicio|images|videos|news|maps|mail|signin|signup|cached|similar|more|next)$/i;
  return navPatterns.test(text.trim()) || text.length < 5;
}

// ============================================================================
// SEARCH ENGINES
// ============================================================================

async function searchGoogle(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(800, 2000);
    const encodedQuery = encodeURIComponent(query);
    const endpoints = [
      `https://www.google.com/search?q=${encodedQuery}&num=15&hl=es-419`,
      `https://www.google.com.co/search?q=${encodedQuery}&num=15&hl=es`,
    ];

    for (const url of endpoints) {
      try {
        const response = await fetch(url, {
          headers: buildDynamicHeaders('Google'),
          redirect: 'follow',
          signal: AbortSignal.timeout(12000),
        });

        if (!response.ok) continue;

        const html = await response.text();
        if (html.includes('captcha') || html.includes('unusual traffic') || html.length < 500) continue;

        const parsed = await flexibleHtmlParse(html, 'Google', query);
        if (parsed.length > 0) return parsed;
      } catch { continue; }
    }
  } catch (e: unknown) {
    console.log(`[METASEARCH] Google error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
  }
  return [];
}

async function searchBing(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(600, 1500);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://www.bing.com/search?q=${encodedQuery}&count=15&setlang=es-419&cc=co`;

    const response = await fetch(url, {
      headers: buildDynamicHeaders('Bing'),
      redirect: 'follow',
      signal: AbortSignal.timeout(12000),
    });

    if (!response.ok) return [];

    const html = await response.text();
    return await flexibleHtmlParse(html, 'Bing', query);
  } catch (e: unknown) {
    console.log(`[METASEARCH] Bing error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
  }
  return [];
}

async function searchDuckDuckGo(query: string): Promise<MetasearchResult[]> {
  try {
    await randomDelay(500, 1200);
    const encodedQuery = encodeURIComponent(query);
    const url = `https://html.duckduckgo.com/html/?q=${encodedQuery}`;

    const response = await fetch(url, {
      headers: buildDynamicHeaders('DuckDuckGo'),
      redirect: 'follow',
      signal: AbortSignal.timeout(12000),
    });

    if (!response.ok) return [];

    const html = await response.text();
    return await flexibleHtmlParse(html, 'DuckDuckGo', query);
  } catch (e: unknown) {
    console.log(`[METASEARCH] DDG error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
  }
  return [];
}

// ============================================================================
// ZAI WEB SEARCH - PRIMARY ENGINE
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
    console.log(`[METASEARCH] ZAI error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
  }
  return [];
}

// ============================================================================
// AI EXTRACTION
// ============================================================================
async function aiExtractFromHtml(html: string, engineSource: string, query: string): Promise<MetasearchResult[]> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    const htmlSample = html.substring(0, 8000);
    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: `Extract search results from HTML of a ${engineSource} page. Return ONLY a JSON array of objects with: title, url, snippet. Max 15 results. If none, return [].` },
        { role: 'user', content: `Query: "${query}"\n\nHTML:\n${htmlSample}` },
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
    console.log(`[METASEARCH] AI extraction error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
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
  try { return new URL(url).hostname; } catch { return 'unknown'; }
}

// ============================================================================
// AI ANALYSIS
// ============================================================================
async function analyzeResultsWithAI(
  executive: { fullName: string; identificationNum: string; email: string | null },
  results: MetasearchResult[]
): Promise<string> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    const resultsSummary = results.slice(0, 40).map((r, i) =>
      `${i + 1}. [${r.fileType?.toUpperCase() || 'WEB'}] "${r.title}" - ${r.url} | ${r.source} | ${r.snippet.substring(0, 150)}`
    ).join('\n');

    const prompt = `Analiza los resultados de metabusqueda OSINT para:
EJECUTIVO: ${executive.fullName}, ID: ${executive.identificationNum}, Email: ${executive.email || 'N/A'}

RESULTADOS (${results.length} resultados):
${resultsSummary}

Genera: Resumen Ejecutivo, Hallazgos Criticos, Hallazgos de Seguridad, Vectores de Ataque, Recomendaciones.`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista OSINT experto en proteccion ejecutiva. Responde en espanol, detallado y profesional.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 3000,
    });

    return completion.choices?.[0]?.message?.content || 'Analisis no disponible';
  } catch (e: unknown) {
    console.log(`[METASEARCH] AI analysis error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
    return 'Analisis IA no disponible.';
  }
}

// ============================================================================
// SAFE FILE OPERATIONS - Wrapped for Vercel serverless
// ============================================================================

function safeWriteFile(filePath: string, data: string | Buffer): boolean {
  try {
    const fs = require('fs');
    const path = require('path');
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, data);
    return true;
  } catch (e) {
    console.log(`[METASEARCH] File write error: ${e instanceof Error ? e.message.substring(0, 80) : String(e).substring(0, 80)}`);
    return false;
  }
}

function safeDownloadFile(url: string, execName: string, baseDir: string): { success: boolean; localPath: string; fileName: string; fileSize: number; error?: string } {
  try {
    const fs = require('fs');
    const path = require('path');
    const execDir = path.join(baseDir, execName.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ_\- ]/g, '').replace(/\s+/g, '_').substring(0, 100));
    fs.mkdirSync(execDir, { recursive: true });

    let originalName: string;
    try {
      originalName = path.basename(new URL(url).pathname) || `document_${Date.now()}`;
    } catch { originalName = `document_${Date.now()}`; }

    const ext = path.extname(originalName) || '.bin';
    const baseName = path.basename(originalName, ext).substring(0, 50);
    const safeName = baseName.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ_\- ]/g, '').replace(/\s+/g, '_');
    const fileName = `${safeName}${ext}`;
    const localPath = path.join(execDir, fileName);

    if (fs.existsSync(localPath)) {
      const stats = fs.statSync(localPath);
      return { success: true, localPath, fileName, fileSize: stats.size };
    }

    // Note: downloads are synchronous here, which is fine for small files
    return { success: false, localPath: '', fileName, fileSize: 0, error: 'Download skipped (serverless)' };
  } catch (e) {
    return { success: false, localPath: '', fileName, fileSize: 0, error: e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100) };
  }
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
// MAIN POST HANDLER v4.1 - Bulletproof for Vercel serverless
// ============================================================================
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  try {
    // Auth check
    const user = await getAuthenticatedUser(request);
    if (!user) {
      return NextResponse.json({ error: 'No autorizado' }, { status: 401 });
    }

    const body = await request.json();
    const { executiveId, query: customQuery, downloadFiles = true } = body;

    if (!executiveId && !customQuery) {
      return NextResponse.json({ error: 'Se requiere executiveId o query' }, { status: 400 });
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

      console.log(`[METASEARCH] v4.1: ${queryGroups.length} groups, ZAI=${engineQueries.zai.length}, Google=${engineQueries.google.length}, Bing=${engineQueries.bing.length}`);
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
    // PHASE 1: ZAI WEB SEARCH (PRIMARY - Most reliable)
    // =========================================================================
    console.log(`[METASEARCH] Phase 1: ZAI Web Search (${engineQueries.zai.length} queries)...`);

    try {
      const zaiBatchSize = 3;
      for (let i = 0; i < engineQueries.zai.length; i += zaiBatchSize) {
        const batch = engineQueries.zai.slice(i, i + zaiBatchSize);
        const zaiPromises = batch.map(q => searchZAI(q).catch(() => []));
        const zaiResultsArray = await Promise.all(zaiPromises);

        for (const queryResults of zaiResultsArray) {
          engineStats.webSearch += queryResults.length;
          addResults(queryResults, allResults, seenUrls, enginesUsed, 'Web Search');
        }

        if (i + zaiBatchSize < engineQueries.zai.length) {
          await randomDelay(300, 800);
        }
      }
    } catch (e: unknown) {
      console.log(`[METASEARCH] ZAI phase error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
    }
    console.log(`[METASEARCH] ZAI done: ${engineStats.webSearch} results, Total=${allResults.length}`);

    // =========================================================================
    // PHASE 2: SCRAPING ENGINES (Google + Bing + DDG)
    // =========================================================================
    console.log('[METASEARCH] Phase 2: Scraping engines...');

    try {
      const maxScrapingQueries = 4;
      const gQueries = engineQueries.google.slice(0, maxScrapingQueries);
      const bQueries = engineQueries.bing.slice(0, maxScrapingQueries);
      const dQueries = engineQueries.zai.slice(0, maxScrapingQueries);

      for (let i = 0; i < Math.max(gQueries.length, bQueries.length, dQueries.length); i++) {
        const promises: Promise<void>[] = [];

        if (i < gQueries.length) {
          promises.push(
            searchGoogle(gQueries[i])
              .then(r => { engineStats.google += r.length; addResults(r, allResults, seenUrls, enginesUsed, 'Google'); })
              .catch(() => {})
          );
        }
        if (i < bQueries.length) {
          promises.push(
            searchBing(bQueries[i])
              .then(r => { engineStats.bing += r.length; addResults(r, allResults, seenUrls, enginesUsed, 'Bing'); })
              .catch(() => {})
          );
        }
        if (i < dQueries.length) {
          promises.push(
            searchDuckDuckGo(dQueries[i])
              .then(r => { engineStats.duckduckgo += r.length; addResults(r, allResults, seenUrls, enginesUsed, 'DuckDuckGo'); })
              .catch(() => {})
          );
        }

        await Promise.all(promises);
        await randomDelay(1500, 3000);
      }
    } catch (e: unknown) {
      console.log(`[METASEARCH] Scraping phase error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
    }
    console.log(`[METASEARCH] Scraping done: G=${engineStats.google} B=${engineStats.bing} DDG=${engineStats.duckduckgo}, Total=${allResults.length}`);

    // =========================================================================
    // PHASE 3: AI EXTRACTION (if few results)
    // =========================================================================
    if (allResults.length < 3) {
      console.log('[METASEARCH] Phase 3: AI extraction fallback...');
      try {
        const primaryQuery = engineQueries.bing[0] || engineQueries.zai[0];
        if (primaryQuery) {
          const bingUrl = `https://www.bing.com/search?q=${encodeURIComponent(primaryQuery)}&count=20`;
          const response = await fetch(bingUrl, {
            headers: buildDynamicHeaders('Bing'),
            redirect: 'follow',
            signal: AbortSignal.timeout(12000),
          });

          if (response.ok) {
            const html = await response.text();
            const aiResults = await aiExtractFromHtml(html, 'Bing', primaryQuery);
            if (aiResults.length > 0) {
              engineStats.bing += aiResults.length;
              addResults(aiResults, allResults, seenUrls, enginesUsed, 'Bing (AI)');
            }
          }
        }
      } catch (e: unknown) {
        console.log(`[METASEARCH] AI fallback error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
      }
    }

    // Sort and re-number
    allResults.sort((a, b) => {
      if (a.isDownloadable && !b.isDownloadable) return -1;
      if (!a.isDownloadable && b.isDownloadable) return 1;
      return a.position - b.position;
    });
    allResults.forEach((r, i) => { r.position = i + 1; });

    const searchEngine = enginesUsed.length > 0
      ? `OSINT v4.1 [${enginesUsed.join(' + ')}]`
      : 'Sin resultados';

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[METASEARCH] Final (${elapsed}s): ZAI=${engineStats.webSearch}, G=${engineStats.google}, B=${engineStats.bing}, DDG=${engineStats.duckduckgo}, Total=${allResults.length}`);

    // =========================================================================
    // AI ANALYSIS
    // =========================================================================
    let aiAnalysis = '';
    if (executive && allResults.length > 0) {
      try {
        aiAnalysis = await analyzeResultsWithAI(
          { fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email },
          allResults
        );
      } catch (e: unknown) {
        console.log(`[METASEARCH] AI analysis error: ${e instanceof Error ? e.message.substring(0, 80) : String(e).substring(0, 80)}`);
        aiAnalysis = 'Analisis IA no disponible.';
      }
    }

    // =========================================================================
    // EVIDENCE FILES (Safe - won't crash on Vercel)
    // =========================================================================
    const evidenceDetails: EvidenceDetail[] = [];
    const downloadableResults = allResults.filter(r => r.isDownloadable);
    let evidenceDetailPath = '';

    // Only attempt file operations if we have results and an executive
    if (executive && allResults.length > 0) {
      try {
        const baseDir = '/tmp/Evidencias_Ejecutivos';

        // Build evidence details for ALL results
        const allEvidence: EvidenceDetail[] = allResults.map(r => ({
          url: r.url,
          sourceDomain: extractDomain(r.url),
          discoveredAt: new Date().toISOString(),
          title: r.title,
          fileType: r.fileType || extractFileType(r.url),
          fileName: '',
          downloadStatus: (r.isDownloadable ? 'skipped' : 'skipped') as EvidenceDetail['downloadStatus'],
          localPath: '',
          fileSize: 0,
          captureTimestamp: new Date().toISOString(),
        }));

        // Try to write evidence JSON (safe)
        const execDirName = executive.fullName.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ_\- ]/g, '').replace(/\s+/g, '_').substring(0, 100);
        const detailDir = `${baseDir}/${execDirName}`;

        const detailData = {
          caseInfo: {
            executiveName: executive.fullName,
            generatedAt: new Date().toISOString(),
            captureTimestamp: new Date().toISOString(),
            generatorAgent: 'ActorTrace OSINT v4.1',
            queryMatrixUsed: queryGroups.map(g => ({ block: g.blockType, label: g.label, queriesExecuted: g.queries.length })),
          },
          statistics: {
            totalFindings: allResults.length,
            engineStats,
          },
          aiAnalysis,
          findings: allEvidence,
        };

        const written = safeWriteFile(`${detailDir}/detalle_identificado.json`, JSON.stringify(detailData, null, 2));
        if (written) {
          evidenceDetailPath = `${detailDir}/detalle_identificado.json`;
        }
      } catch (e: unknown) {
        console.log(`[METASEARCH] Evidence write error: ${e instanceof Error ? e.message.substring(0, 80) : String(e).substring(0, 80)}`);
      }
    }

    // =========================================================================
    // UPDATE EXECUTIVE RECORD
    // =========================================================================
    if (executive) {
      try {
        const resultsSummary = allResults.slice(0, 50).map(r => ({
          title: r.title,
          url: r.url,
          snippet: r.snippet.substring(0, 200),
          source: r.source,
          fileType: r.fileType,
          isDownloadable: r.isDownloadable,
        }));

        await db.executive.update({
          where: { id: executive.id },
          data: {
            lastMetasearch: new Date(),
            lastMetasearchResults: JSON.stringify(resultsSummary),
          },
        });
      } catch (e: unknown) {
        console.log(`[METASEARCH] DB update error: ${e instanceof Error ? e.message.substring(0, 80) : String(e).substring(0, 80)}`);
      }
    }

    // =========================================================================
    // RETURN
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
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.error(`[METASEARCH] FATAL: ${errorMsg}`);
    return NextResponse.json(
      { error: 'Error al ejecutar metabusqueda', detail: errorMsg.substring(0, 200) },
      { status: 500 }
    );
  }
}
