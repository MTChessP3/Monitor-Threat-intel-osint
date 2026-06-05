import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

// Lazy-load cheerio
let cheerioInstance: typeof import('cheerio') | null = null;
async function getCheerio() {
  if (!cheerioInstance) cheerioInstance = await import('cheerio');
  return cheerioInstance;
}

// AUTH
async function getAuthenticatedUser(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload as { id: string; email: string; role: string };
}

// TYPES
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
  sourceDomain?: string;
  actors?: string;
  publicationDate?: string;
  matchedIdentifiers?: string[];
  classification?: 'validated' | 'potential' | 'discarded';
  classificationReason?: string;
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

// ANTI-BLOCK SYSTEM
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
];

const ACCEPT_LANGUAGES = [
  'es-CO,es;q=0.9,en;q=0.8',
  'es-ES,es;q=0.9,en;q=0.8',
  'en-US,en;q=0.9,es;q=0.8',
];

function getRandomElement<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomDelay(minMs: number, maxMs: number): Promise<void> {
  return new Promise(r => setTimeout(r, minMs + Math.random() * (maxMs - minMs)));
}

function buildDynamicHeaders(): Record<string, string> {
  return {
    'User-Agent': getRandomElement(USER_AGENTS),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': getRandomElement(ACCEPT_LANGUAGES),
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

// OSINT DORKING MATRIX
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

  // BLOQUE 1: Nombre
  const nameGroupQueries: string[] = [];
  googleQueries.push(`"${name}"`); bingQueries.push(`"${name}"`); zaiQueries.push(`"${name}"`); nameGroupQueries.push(`"${name}"`);
  googleQueries.push(`"${name}" filetype:pdf`); bingQueries.push(`"${name}" filetype:pdf`); zaiQueries.push(`"${name}" PDF documento`); nameGroupQueries.push(`"${name}" filetype:pdf`);
  googleQueries.push(`"${name}" filetype:xlsx OR filetype:doc`); bingQueries.push(`"${name}" filetype:xlsx OR filetype:doc`); zaiQueries.push(`"${name}" Excel Word documento`); nameGroupQueries.push(`"${name}" (filetype:xlsx OR filetype:doc)`);
  googleQueries.push(`"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak`); bingQueries.push(`"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak`); zaiQueries.push(`"${name}" configuracion credenciales base datos`); nameGroupQueries.push(`"${name}" (filetype:env OR filetype:conf OR filetype:sql OR filetype:bak)`);
  googleQueries.push(`"${name}" "${id}"`); bingQueries.push(`"${name}" "${id}"`); zaiQueries.push(`"${name}" ${id}`); nameGroupQueries.push(`"${name}" "${id}"`);
  googleQueries.push(`"${name}" filetype:pptx OR filetype:csv`); bingQueries.push(`"${name}" filetype:pptx OR filetype:csv`); zaiQueries.push(`"${name}" presentacion datos`); nameGroupQueries.push(`"${name}" (filetype:pptx OR filetype:csv)`);
  groups.push({ label: `Nombre: ${name}`, queries: nameGroupQueries, blockType: 'name' });

  // BLOQUE 2: Email
  if (email) {
    const emailGroupQueries: string[] = [];
    googleQueries.push(`"${email}"`); bingQueries.push(`"${email}"`); zaiQueries.push(`"${email}"`); emailGroupQueries.push(`"${email}"`);
    googleQueries.push(`"${email}" filetype:pdf`); bingQueries.push(`"${email}" filetype:pdf`); zaiQueries.push(`"${email}" PDF documento`); emailGroupQueries.push(`"${email}" filetype:pdf`);
    googleQueries.push(`"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`); bingQueries.push(`"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`); zaiQueries.push(`"${email}" Excel Word base datos`); emailGroupQueries.push(`"${email}" (filetype:xlsx OR filetype:doc OR filetype:sql)`);
    if (emailUser && emailUser !== email) {
      googleQueries.push(`"${emailUser}" filetype:pdf OR filetype:xlsx`); bingQueries.push(`"${emailUser}" filetype:pdf OR filetype:xlsx`); zaiQueries.push(`"${emailUser}" documento`); emailGroupQueries.push(`"${emailUser}" (filetype:pdf OR filetype:xlsx)`);
    }
    if (domain) {
      googleQueries.push(`"${name}" site:${domain}`); bingQueries.push(`"${name}" site:${domain}`); zaiQueries.push(`"${name}" ${domain}`); emailGroupQueries.push(`"${name}" site:${domain}`);
    }
    groups.push({ label: `Email: ${email}`, queries: emailGroupQueries, blockType: 'email' });
  }

  // BLOQUE 3: ID
  const idGroupQueries: string[] = [];
  googleQueries.push(`"${id}"`); bingQueries.push(`"${id}"`); zaiQueries.push(`"${id}"`); idGroupQueries.push(`"${id}"`);
  googleQueries.push(`"${id}" filetype:pdf`); bingQueries.push(`"${id}" filetype:pdf`); zaiQueries.push(`"${id}" PDF documento`); idGroupQueries.push(`"${id}" filetype:pdf`);
  googleQueries.push(`"${id}" filetype:xlsx OR filetype:doc OR filetype:csv`); bingQueries.push(`"${id}" filetype:xlsx OR filetype:doc OR filetype:csv`); zaiQueries.push(`"${id}" Excel Word datos`); idGroupQueries.push(`"${id}" (filetype:xlsx OR filetype:doc OR filetype:csv)`);
  groups.push({ label: `ID: ${id}`, queries: idGroupQueries, blockType: 'id' });

  // BLOQUE COMBINADO
  const combinedGroupQueries: string[] = [];
  if (email) {
    googleQueries.push(`"${name}" "${email}"`); bingQueries.push(`"${name}" "${email}"`); zaiQueries.push(`"${name}" "${email}"`); combinedGroupQueries.push(`"${name}" "${email}"`);
  }
  if (lastName) {
    googleQueries.push(`"${id}" "${lastName}"`); bingQueries.push(`"${id}" "${lastName}"`); zaiQueries.push(`"${id}" "${lastName}"`); combinedGroupQueries.push(`"${id}" "${lastName}"`);
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

// URL HELPERS (must be defined before search engines that use them)
function isDocumentUrl(url: string): boolean {
  const urlLower = url.toLowerCase().split('?')[0].split('#')[0];
  return ALL_EXTENSIONS.some(ext => {
    if (ext.includes('.')) return urlLower.endsWith(`.${ext}`) || urlLower.endsWith(`.${ext.replace('.', '_')}`);
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

function cleanRedirectUrl(href: string): string {
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

// HTML PARSING
async function flexibleHtmlParse(html: string, engineSource: string, query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  const $ = (await getCheerio()).load(html);
  const seenInPage = new Set<string>();

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
      href = cleanRedirectUrl(href);
      if (!href.startsWith('http')) href = normalizeUrl(href);
      const urlKey = href.toLowerCase().split('?')[0].split('#')[0];
      if (title && href.startsWith('http') && !isSearchEngineUrl(href, engineSource) && !seenInPage.has(urlKey)) {
        seenInPage.add(urlKey);
        results.push({ title: title.substring(0, 300), url: href, snippet: snippet.substring(0, 500), source: engineSource, position: results.length + 1, isDownloadable: isDocumentUrl(href), querySource: query.substring(0, 80) });
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
      href = cleanRedirectUrl(href);
      if (!href.startsWith('http')) href = normalizeUrl(href);
      const urlKey = href.toLowerCase().split('?')[0].split('#')[0];
      if (title.length > 8 && href.startsWith('http') && !isSearchEngineUrl(href, engineSource) && !seenInPage.has(urlKey) && !isNavOrFooterLink(title)) {
        seenInPage.add(urlKey);
        const parent = linkEl.closest('div, li, article, section');
        const parentText = parent.text().trim();
        const snippetRaw = parentText.replace(title, '').trim().substring(0, 500);
        results.push({ title: title.substring(0, 300), url: href, snippet: snippetRaw, source: engineSource, position: results.length + 1, isDownloadable: isDocumentUrl(href), querySource: query.substring(0, 80) });
      }
    });
  }

  // Strategy 3: URL pattern
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
          results.push({ title: urlObj.pathname.split('/').pop() || urlObj.hostname, url: cleanUrl, snippet: '', source: engineSource, position: results.length + 1, isDownloadable: isDocumentUrl(cleanUrl), querySource: query.substring(0, 80) });
        } catch { /* skip */ }
      }
    }
  }

  return results;
}

// SEARCH ENGINES
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
        const response = await fetch(url, { headers: buildDynamicHeaders(), redirect: 'follow', signal: AbortSignal.timeout(12000) });
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
    const response = await fetch(url, { headers: buildDynamicHeaders(), redirect: 'follow', signal: AbortSignal.timeout(12000) });
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
    const response = await fetch(url, { headers: buildDynamicHeaders(), redirect: 'follow', signal: AbortSignal.timeout(12000) });
    if (!response.ok) return [];
    const html = await response.text();
    return await flexibleHtmlParse(html, 'DuckDuckGo', query);
  } catch (e: unknown) {
    console.log(`[METASEARCH] DDG error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
  }
  return [];
}

// ZAI WEB SEARCH - PRIMARY
async function searchZAI(query: string): Promise<MetasearchResult[]> {
  try {
    const ZAIModule = await import('z-ai-web-dev-sdk');
    const ZAI = ZAIModule.default;
    const zai = await ZAI.create();
    const searchResult = await zai.functions.invoke('web_search', { query, num: 20 });
    console.log(`[METASEARCH] ZAI raw response type: ${typeof searchResult}, isArray: ${Array.isArray(searchResult)}, length: ${Array.isArray(searchResult) ? searchResult.length : 'N/A'}`);
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
    console.log(`[METASEARCH] ZAI error: ${e instanceof Error ? e.message.substring(0, 200) : String(e).substring(0, 200)}`);
  }
  return [];
}

// AI EXTRACTION
async function aiExtractFromHtml(html: string, engineSource: string, query: string): Promise<MetasearchResult[]> {
  try {
    const ZAIModule = await import('z-ai-web-dev-sdk');
    const ZAI = ZAIModule.default;
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

// AI ANALYSIS
async function analyzeResultsWithAI(
  executive: { fullName: string; identificationNum: string; email: string | null },
  results: MetasearchResult[]
): Promise<string> {
  try {
    const ZAIModule = await import('z-ai-web-dev-sdk');
    const ZAI = ZAIModule.default;
    const zai = await ZAI.create();
    const resultsSummary = results.slice(0, 40).map((r, i) =>
      `${i + 1}. [${r.classification?.toUpperCase() || 'N/A'}] [${r.fileType?.toUpperCase() || 'WEB'}] "${r.title}" - ${r.url} | ${r.source} | ${r.snippet.substring(0, 150)}`
    ).join('\n');
    const prompt = `Analiza ESTRICTAMENTE los resultados de metabusqueda OSINT para:
EJECUTIVO: ${executive.fullName}, ID: ${executive.identificationNum}, Email: ${executive.email || 'N/A'}

RESULTADOS (${results.length} resultados):
${resultsSummary}

INSTRUCCIONES:
- Los resultados marcados VALIDATED tienen coincidencia directa con identificadores del ejecutivo.
- Los marcados POTENTIAL vienen de busquedas dirigidas pero no muestran el identificador en el snippet - podrian ser relevantes.
- Clasifica la exposicion como ALTA si aparecen documentos sensibles.
- Clasifica como MEDIA si solo hay menciones web.
- Clasifica como BAJA si las menciones son indirectas.
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

// SAFE FILE OPS
function safeWriteFile(filePath: string, data: string | Buffer): boolean {
  try {
    const fs = require('fs');
    const path = require('path');
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, data);
    return true;
  } catch (e) {
    console.log(`[METASEARCH] File write error: ${e instanceof Error ? e.message.substring(0, 80) : String(e).substring(0, 80)}`);
    return false;
  }
}

// DEDUP
function addResults(
  newResults: MetasearchResult[],
  allResults: MetasearchResult[],
  seenUrls: Set<string>,
  enginesUsed: string[],
  engineName: string,
): number {
  let added = 0;
  if (newResults.length > 0 && !enginesUsed.includes(engineName)) enginesUsed.push(engineName);
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
// THREE-TIER CLASSIFICATION v6.0
// ============================================================================
function classifyResults(
  results: MetasearchResult[],
  executive: { fullName: string; identificationNum: string; email: string | null },
  targetedQueries: string[],
): {
  validated: MetasearchResult[];
  potential: MetasearchResult[];
  discarded: MetasearchResult[];
} {
  const name = executive.fullName;
  const id = executive.identificationNum;
  const email = executive.email;

  // Build identifier patterns
  const identifiers: Array<{ label: string; patterns: RegExp[] }> = [];

  // Name patterns
  const nameParts = name.toLowerCase().split(/\s+/).filter(p => p.length > 2);
  identifiers.push({
    label: 'Nombre',
    patterns: [
      new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
      ...nameParts.map(part => new RegExp(`\\b${part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i')),
    ],
  });

  // ID patterns
  const idClean = id.replace(/[^a-zA-Z0-9]/g, '');
  const idNum = id.replace(/\D/g, '');
  identifiers.push({
    label: 'ID',
    patterns: [
      new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
      ...(idNum.length > 4 ? [new RegExp(`\\b${idNum}\\b`, 'i')] : []),
      ...(idClean.length > 4 ? [new RegExp(`\\b${idClean}\\b`, 'i')] : []),
    ],
  });

  // Email patterns
  if (email) {
    const emailUser = email.split('@')[0];
    identifiers.push({
      label: 'Email',
      patterns: [
        new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
        ...(emailUser.length > 3 ? [new RegExp(`\\b${emailUser.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i')] : []),
      ],
    });
  }

  // Build lowercase set of targeted queries for checking
  const targetedQuerySet = new Set(targetedQueries.map(q => q.toLowerCase()));

  const validated: MetasearchResult[] = [];
  const potential: MetasearchResult[] = [];
  const discarded: MetasearchResult[] = [];

  for (const result of results) {
    const searchableText = `${result.title} ${result.snippet} ${result.url}`.toLowerCase();
    const matchedIds: string[] = [];
    let hasDirectMatch = false;

    for (const identifier of identifiers) {
      for (const pattern of identifier.patterns) {
        if (pattern.test(searchableText)) {
          hasDirectMatch = true;
          if (!matchedIds.includes(identifier.label)) matchedIds.push(identifier.label);
          break;
        }
      }
    }

    if (hasDirectMatch) {
      // TIER 1: VALIDATED - Direct identifier match in snippet/title/URL
      result.classification = 'validated';
      result.matchedIdentifiers = matchedIds;
      result.classificationReason = `Coincidencia directa: ${matchedIds.join(', ')}`;
      validated.push(result);
    } else {
      // Check if this result came from a targeted query
      const queryLower = (result.querySource || '').toLowerCase();
      const isFromTargetedQuery = targetedQuerySet.has(queryLower) ||
        targetedQueries.some(tq => {
          const tqLower = tq.toLowerCase();
          return queryLower.includes(tqLower.substring(0, 20)) || tqLower.includes(queryLower.substring(0, 20));
        });

      // Also check if ANY identifier appears in the query that produced this result
      const identifierInQuery = identifiers.some(idGroup =>
        idGroup.patterns.some(pattern => pattern.test(result.querySource || ''))
      );

      if (isFromTargetedQuery || identifierInQuery) {
        // TIER 2: POTENTIAL - From targeted query but no direct match in snippet
        result.classification = 'potential';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Resultado de busqueda dirigida - posible relevancia no visible en snippet';
        potential.push(result);
      } else {
        // TIER 3: DISCARDED - No match at all
        result.classification = 'discarded';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Sin coincidencia con identificadores del ejecutivo';
        discarded.push(result);
      }
    }
  }

  console.log(`[METASEARCH] Classification: ${results.length} total → ${validated.length} validated, ${potential.length} potential, ${discarded.length} discarded`);
  return { validated, potential, discarded };
}

// METADATA ENRICHMENT
function enrichResultsWithMetadata(results: MetasearchResult[]): MetasearchResult[] {
  for (const result of results) {
    try { result.sourceDomain = new URL(result.url).hostname; } catch { result.sourceDomain = 'unknown'; }
    const actors: string[] = [];
    const byPatterns = [
      /(?:by|por|author|autor|uploaded|subido)\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})/g,
      /@([\w.-]+)/g,
      /(?:user|usuario)\s*:?\s*([\w.-]+)/gi,
    ];
    const textToSearch = `${result.title} ${result.snippet}`;
    for (const pattern of byPatterns) {
      let match;
      while ((match = pattern.exec(textToSearch)) !== null) {
        const actor = match[1].trim();
        if (actor.length > 1 && actor.length < 60 && !actors.includes(actor)) actors.push(actor);
      }
    }
    result.actors = actors.length > 0 ? actors.join(', ') : 'No identificado';
    const datePatterns = [
      /(\d{1,2}\s+(?:ene|feb|mar|abr|may|jun|jul|ago|sep|oct|nov|dic|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\w*\s+\d{2,4})/i,
      /(\d{4}-\d{2}-\d{2})/,
      /((?:ene|feb|mar|abr|may|jun|jul|ago|sep|oct|nov|dic|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\w*\s+\d{1,2},?\s+\d{4})/i,
      /(\d{1,2}\/\d{1,2}\/\d{2,4})/,
    ];
    let foundDate = '';
    for (const pattern of datePatterns) {
      const match = textToSearch.match(pattern);
      if (match) { foundDate = match[1]; break; }
    }
    result.publicationDate = foundDate || 'No disponible';
  }
  return results;
}

// ============================================================================
// MAIN POST HANDLER v6.0
// ============================================================================
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  try {
    const user = await getAuthenticatedUser(request);
    if (!user) return NextResponse.json({ error: 'No autorizado' }, { status: 401 });

    const body = await request.json();
    const { executiveId, query: customQuery, downloadFiles = true } = body;
    if (!executiveId && !customQuery) return NextResponse.json({ error: 'Se requiere executiveId o query' }, { status: 400 });

    let executive: { id: string; fullName: string; identificationNum: string; email: string | null; [key: string]: any } | null = null;
    let queryGroups: SearchQueryGroup[] = [];
    let engineQueries: EngineQuerySet = { google: [], bing: [], zai: [] };

    if (executiveId) {
      executive = await db.executive.findUnique({ where: { id: executiveId } });
      if (!executive) return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
      const matrix = buildOsintQueryMatrix({ fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email });
      queryGroups = matrix.groups;
      engineQueries = matrix.engineQueries;
      console.log(`[METASEARCH] v6.0: ${queryGroups.length} groups, ZAI=${engineQueries.zai.length}, Google=${engineQueries.google.length}, Bing=${engineQueries.bing.length}`);
    } else {
      queryGroups = [{ label: 'Busqueda personalizada', queries: [customQuery], blockType: 'custom' }];
      engineQueries = { google: [customQuery], bing: [customQuery], zai: [customQuery] };
    }

    const allResults: MetasearchResult[] = [];
    const seenUrls = new Set<string>();
    const enginesUsed: string[] = [];
    const engineStats: Record<string, number> = { google: 0, bing: 0, yandex: 0, duckduckgo: 0, brave: 0, webSearch: 0 };

    // PHASE 1: ZAI WEB SEARCH (PRIMARY)
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
        if (i + zaiBatchSize < engineQueries.zai.length) await randomDelay(300, 800);
      }
    } catch (e: unknown) {
      console.log(`[METASEARCH] ZAI phase error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
    }
    console.log(`[METASEARCH] ZAI done: ${engineStats.webSearch} results, Total=${allResults.length}`);

    // PHASE 2: SCRAPING (Google + Bing + DDG)
    console.log('[METASEARCH] Phase 2: Scraping engines...');
    try {
      const maxScrapingQueries = 4;
      const gQueries = engineQueries.google.slice(0, maxScrapingQueries);
      const bQueries = engineQueries.bing.slice(0, maxScrapingQueries);
      const dQueries = engineQueries.bing.slice(0, maxScrapingQueries);

      for (let i = 0; i < Math.max(gQueries.length, bQueries.length, dQueries.length); i++) {
        const promises: Promise<void>[] = [];
        if (i < gQueries.length) promises.push(searchGoogle(gQueries[i]).then(r => { engineStats.google += r.length; addResults(r, allResults, seenUrls, enginesUsed, 'Google'); }).catch(() => {}));
        if (i < bQueries.length) promises.push(searchBing(bQueries[i]).then(r => { engineStats.bing += r.length; addResults(r, allResults, seenUrls, enginesUsed, 'Bing'); }).catch(() => {}));
        if (i < dQueries.length) promises.push(searchDuckDuckGo(dQueries[i]).then(r => { engineStats.duckduckgo += r.length; addResults(r, allResults, seenUrls, enginesUsed, 'DuckDuckGo'); }).catch(() => {}));
        await Promise.all(promises);
        await randomDelay(1500, 3000);
      }
    } catch (e: unknown) {
      console.log(`[METASEARCH] Scraping phase error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
    }
    console.log(`[METASEARCH] Scraping done: G=${engineStats.google} B=${engineStats.bing} DDG=${engineStats.duckduckgo}, Total=${allResults.length}`);

    // PHASE 3: AI EXTRACTION FALLBACK
    if (allResults.length < 3) {
      console.log('[METASEARCH] Phase 3: AI extraction fallback...');
      try {
        const primaryQuery = engineQueries.bing[0] || engineQueries.zai[0];
        if (primaryQuery) {
          const bingUrl = `https://www.bing.com/search?q=${encodeURIComponent(primaryQuery)}&count=20`;
          const response = await fetch(bingUrl, { headers: buildDynamicHeaders(), redirect: 'follow', signal: AbortSignal.timeout(12000) });
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

    // PHASE 4: THREE-TIER CLASSIFICATION
    const allTargetedQueries = [...engineQueries.zai, ...engineQueries.google, ...engineQueries.bing];
    const { validated, potential, discarded } = executive
      ? classifyResults(allResults, { fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email }, allTargetedQueries)
      : { validated: allResults, potential: [] as MetasearchResult[], discarded: [] as MetasearchResult[] };

    // Enrich all tiers with metadata
    enrichResultsWithMetadata(validated);
    enrichResultsWithMetadata(potential);
    enrichResultsWithMetadata(discarded);

    // Combine validated + potential for "active" results
    const activeResults = [...validated, ...potential];

    // Sort and re-number
    activeResults.sort((a, b) => {
      if (a.classification === 'validated' && b.classification !== 'validated') return -1;
      if (a.classification !== 'validated' && b.classification === 'validated') return 1;
      if (a.isDownloadable && !b.isDownloadable) return -1;
      if (!a.isDownloadable && b.isDownloadable) return 1;
      return 0;
    });
    activeResults.forEach((r, i) => { r.position = i + 1; });
    discarded.forEach((r, i) => { r.position = activeResults.length + i + 1; });

    const searchEngine = enginesUsed.length > 0 ? `OSINT v6.0 [${enginesUsed.join(' + ')}]` : 'Sin resultados';
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[METASEARCH] Final (${elapsed}s): Raw=${allResults.length}, Validated=${validated.length}, Potential=${potential.length}, Discarded=${discarded.length}`);

    // AI ANALYSIS on validated + potential
    let aiAnalysis = '';
    if (executive && activeResults.length > 0) {
      try {
        aiAnalysis = await analyzeResultsWithAI(
          { fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email },
          activeResults
        );
      } catch (e: unknown) {
        aiAnalysis = 'Analisis IA no disponible.';
      }
    }

    // EVIDENCE
    const downloadableResults = activeResults.filter(r => r.isDownloadable);
    const evidenceDetails: EvidenceDetail[] = [];
    let evidenceDetailPath = '';
    if (executive && activeResults.length > 0) {
      try {
        const baseDir = '/tmp/Evidencias_Ejecutivos';
        const execDirName = executive.fullName.replace(/[^a-zA-Z0-9áéíóúñÁÉÍÓÚÑ_\- ]/g, '').replace(/\s+/g, '_').substring(0, 100);
        const detailDir = `${baseDir}/${execDirName}`;
        const detailData = {
          caseInfo: { executiveName: executive.fullName, generatedAt: new Date().toISOString(), generatorAgent: 'ActorTrace OSINT v6.0' },
          statistics: { totalRaw: allResults.length, validated: validated.length, potential: potential.length, discarded: discarded.length, engineStats },
          aiAnalysis,
          validated: validated.map(r => ({ ...r })),
          potential: potential.map(r => ({ ...r })),
          discarded: discarded.map(r => ({ ...r })),
        };
        if (safeWriteFile(`${detailDir}/detalle_identificado.json`, JSON.stringify(detailData, null, 2))) {
          evidenceDetailPath = `${detailDir}/detalle_identificado.json`;
        }
      } catch { /* ignore */ }
    }

    // UPDATE DB
    if (executive) {
      try {
        await db.executive.update({
          where: { id: executive.id },
          data: {
            lastMetasearch: new Date(),
            lastMetasearchResults: JSON.stringify({
              validated: validated.length,
              potential: potential.length,
              discarded: discarded.length,
              topResults: activeResults.slice(0, 20).map(r => ({ title: r.title, url: r.url, source: r.source, classification: r.classification, matchedIdentifiers: r.matchedIdentifiers })),
            }),
          },
        });
      } catch { /* ignore */ }
    }

    // RETURN
    return NextResponse.json({
      success: true,
      searchEngine,
      enginesUsed,
      engineStats,
      queryGroups: queryGroups.map(g => ({ label: g.label, queryCount: g.queries.length, blockType: g.blockType })),
      resultCount: activeResults.length,
      rawResultCount: allResults.length,
      filteredOutCount: discarded.length,
      classificationStats: { validated: validated.length, potential: potential.length, discarded: discarded.length },
      downloadableCount: downloadableResults.length,
      downloadedCount: 0,
      results: activeResults.slice(0, 150),
      validatedResults: validated.slice(0, 150),
      potentialResults: potential.slice(0, 150),
      discardedResults: discarded.slice(0, 150),
      aiAnalysis,
      evidence: evidenceDetails,
      evidenceDetailPath,
      executive: executive ? { id: executive.id, fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email } : null,
      timestamp: new Date().toISOString(),
      elapsedSeconds: parseFloat(elapsed),
      extensionsMonitored: ALL_EXTENSIONS,
    });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.error(`[METASEARCH] FATAL: ${errorMsg}`);
    return NextResponse.json({ error: 'Error al ejecutar metabusqueda', detail: errorMsg.substring(0, 200) }, { status: 500 });
  }
}
