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
}

interface SearchQueryGroup {
  label: string;
  queries: string[];
}

// ============================================================================
// OSINT QUERY MATRIX BUILDER
// ============================================================================
const FILETYPE_EXTENSIONS = ['pdf', 'xlsx', 'xls', 'ppt', 'doc', 'docx', 'txt', 'rar', 'zip'];

function buildOsintQueryMatrix(executive: {
  fullName: string;
  identificationNum: string;
  email: string | null;
}): SearchQueryGroup[] {
  const groups: SearchQueryGroup[] = [];

  // GROUP 1: Full Name
  const nameQueries: string[] = [];
  nameQueries.push(`"${executive.fullName}"`);
  nameQueries.push(`"${executive.fullName}" filetype:pdf`);
  nameQueries.push(`"${executive.fullName}" filetype:xlsx OR filetype:xls`);
  nameQueries.push(`"${executive.fullName}" filetype:doc OR filetype:docx`);
  nameQueries.push(`"${executive.fullName}" "${executive.identificationNum}"`);
  groups.push({ label: `Nombre: ${executive.fullName}`, queries: nameQueries });

  // GROUP 2: ID Number
  const idQueries: string[] = [];
  idQueries.push(`"${executive.identificationNum}"`);
  idQueries.push(`"${executive.identificationNum}" filetype:pdf OR filetype:xlsx`);
  groups.push({ label: `ID: ${executive.identificationNum}`, queries: idQueries });

  // GROUP 3: Email
  if (executive.email) {
    const emailQueries: string[] = [];
    emailQueries.push(`"${executive.email}"`);
    emailQueries.push(`"${executive.email}" filetype:pdf OR filetype:xlsx`);
    groups.push({ label: `Email: ${executive.email}`, queries: emailQueries });
  }

  // GROUP 4: Direct file patterns
  const nameParts = executive.fullName.toLowerCase().split(' ');
  const lastName = nameParts[nameParts.length - 1] || '';
  const firstName = nameParts[0] || '';
  if (firstName && lastName) {
    const directQueries: string[] = [];
    directQueries.push(`${firstName} ${lastName} filetype:xlsx`);
    directQueries.push(`${lastName} ${firstName} filetype:pdf`);
    groups.push({ label: `Archivos Directos`, queries: directQueries });
  }

  return groups;
}

// ============================================================================
// COMMON BROWSER HEADERS
// ============================================================================
const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
  'Accept-Encoding': 'identity',
};

// ============================================================================
// GOOGLE SEARCH ENGINE
// ============================================================================
async function searchGoogle(query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  try {
    const encodedQuery = encodeURIComponent(query);
    const url = `https://www.google.com/search?q=${encodedQuery}&num=15&hl=es`;

    const response = await fetch(url, {
      headers: {
        ...BROWSER_HEADERS,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      console.log(`[METASEARCH] Google HTTP ${response.status}`);
      return results;
    }

    const html = await response.text();
    const $ = cheerio.load(html);

    // Google search result selectors
    $('div.g').each((idx, el) => {
      if (results.length >= 15) return false;
      const container = $(el);
      const linkEl = container.find('a[href^="http"]').first();
      let href = linkEl.attr('href') || '';
      const titleEl = container.find('h3').first();
      const title = titleEl.text().trim();
      const snippetEl = container.find('.VwiC3b, .st, [data-sncf], .IsZvec').first();
      const snippet = snippetEl.text().trim();

      // Clean Google redirect URLs
      if (href.includes('google.com/url?')) {
        const match = href.match(/[?&]q=([^&]+)/i) || href.match(/[?&]url=([^&]+)/i);
        if (match) href = decodeURIComponent(match[1]);
      }

      if (title && href.startsWith('http') && !href.includes('google.com')) {
        results.push({
          title: title.substring(0, 300),
          url: href,
          snippet: snippet.substring(0, 500) || '',
          source: 'Google',
          position: results.length + 1,
          isDownloadable: isDocumentUrl(href),
          querySource: query.substring(0, 80),
        });
      }
    });

    console.log(`[METASEARCH] Google: ${results.length} results for "${query.substring(0, 50)}"`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Google error: ${msg.substring(0, 80)}`);
  }
  return results;
}

// ============================================================================
// BING SEARCH ENGINE
// ============================================================================
async function searchBing(query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  try {
    const encodedQuery = encodeURIComponent(query);
    const url = `https://www.bing.com/search?q=${encodedQuery}&count=15&setlang=es`;

    const response = await fetch(url, {
      headers: BROWSER_HEADERS,
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) return results;

    const html = await response.text();
    const $ = cheerio.load(html);

    $('li.b_algo').each((idx, el) => {
      if (results.length >= 15) return false;
      const container = $(el);
      const linkEl = container.find('h2 a').first();
      let href = linkEl.attr('href') || '';
      const title = linkEl.text().trim();
      const snippetEl = container.find('.b_caption p, .b_lineclamp2, p').first();
      const snippet = snippetEl.text().trim();

      if (title && href.startsWith('http')) {
        results.push({
          title: title.substring(0, 300),
          url: href,
          snippet: snippet.substring(0, 500) || '',
          source: 'Bing',
          position: results.length + 1,
          isDownloadable: isDocumentUrl(href),
          querySource: query.substring(0, 80),
        });
      }
    });

    console.log(`[METASEARCH] Bing: ${results.length} results for "${query.substring(0, 50)}"`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Bing error: ${msg.substring(0, 80)}`);
  }
  return results;
}

// ============================================================================
// YANDEX SEARCH ENGINE
// ============================================================================
async function searchYandex(query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  try {
    const encodedQuery = encodeURIComponent(query);
    const url = `https://yandex.com/search/?text=${encodedQuery}&lr=10636&lang=es`;

    const response = await fetch(url, {
      headers: {
        ...BROWSER_HEADERS,
        'Accept-Language': 'es,es-ES;q=0.9,en;q=0.8',
        'Cookie': 'yandex_gid=10636; spravka=dZ0A; yp=1',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      console.log(`[METASEARCH] Yandex HTTP ${response.status}`);
      return results;
    }

    const html = await response.text();
    const $ = cheerio.load(html);

    // Yandex result selectors
    const yandexSelectors = [
      'li.serp-item',
      'div.serp-item',
      '.organic__url',
      'div.Typs',
    ];

    for (const selector of yandexSelectors) {
      $(selector).each((idx, el) => {
        if (results.length >= 15) return false;
        const container = $(el);
        const linkEl = container.find('a[href^="http"]').first();
        const href = linkEl.attr('href') || '';
        const titleEl = container.find('.organic__title, h2, .Typs-heading').first();
        const title = titleEl.text().trim() || linkEl.text().trim();
        const snippetEl = container.find('.organic__content-wrapper, .text-container, .Typs-text').first();
        const snippet = snippetEl.text().trim();

        if (title && href.startsWith('http') && !href.includes('yandex.com/search')) {
          results.push({
            title: title.substring(0, 300),
            url: href,
            snippet: snippet.substring(0, 500) || '',
            source: 'Yandex',
            position: results.length + 1,
            isDownloadable: isDocumentUrl(href),
            querySource: query.substring(0, 80),
          });
        }
      });
      if (results.length > 0) break;
    }

    // Fallback: grab any links with meaningful text
    if (results.length === 0) {
      $('a[href^="http"]').each((idx, el) => {
        if (results.length >= 10) return false;
        const href = $(el).attr('href') || '';
        const title = $(el).text().trim();
        if (title.length > 10 && !href.includes('yandex.') && !href.includes('javascript')) {
          results.push({
            title: title.substring(0, 300),
            url: href,
            snippet: '',
            source: 'Yandex',
            position: results.length + 1,
            isDownloadable: isDocumentUrl(href),
            querySource: query.substring(0, 80),
          });
        }
      });
    }

    console.log(`[METASEARCH] Yandex: ${results.length} results for "${query.substring(0, 50)}"`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] Yandex error: ${msg.substring(0, 80)}`);
  }
  return results;
}

// ============================================================================
// DUCKDUCKGO SEARCH ENGINE
// ============================================================================
async function searchDuckDuckGo(query: string): Promise<MetasearchResult[]> {
  const results: MetasearchResult[] = [];
  try {
    const encodedQuery = encodeURIComponent(query);
    const url = `https://html.duckduckgo.com/html/?q=${encodedQuery}`;

    const response = await fetch(url, {
      headers: BROWSER_HEADERS,
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) return results;

    const html = await response.text();
    const $ = cheerio.load(html);

    $('div.result').each((idx, el) => {
      if (results.length >= 15) return false;
      const container = $(el);
      const linkEl = container.find('a.result__a').first();
      let href = linkEl.attr('href') || '';
      const title = linkEl.text().trim();
      const snippetEl = container.find('.result__snippet, a.result__snippet').first();
      const snippet = snippetEl.text().trim();

      // DDG uses redirect URLs
      if (href.startsWith('//duckduckgo.com/l/')) {
        const match = href.match(/uddg=([^&]+)/i);
        if (match) href = decodeURIComponent(match[1]);
      }
      // Handle protocol-relative URLs
      if (href.startsWith('//')) href = 'https:' + href;

      if (title && href.startsWith('http')) {
        results.push({
          title: title.substring(0, 300),
          url: href,
          snippet: snippet.substring(0, 500) || '',
          source: 'DuckDuckGo',
          position: results.length + 1,
          isDownloadable: isDocumentUrl(href),
          querySource: query.substring(0, 80),
        });
      }
    });

    console.log(`[METASEARCH] DuckDuckGo: ${results.length} results for "${query.substring(0, 50)}"`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] DuckDuckGo error: ${msg.substring(0, 80)}`);
  }
  return results;
}

// ============================================================================
// ZAI WEB SEARCH (FALLBACK - Most Reliable)
// ============================================================================
async function searchZAI(query: string): Promise<MetasearchResult[]> {
  try {
    const ZAI = (await import('z-ai-web-dev-sdk')).default;
    const zai = await ZAI.create();

    const searchResult = await zai.functions.invoke('web_search', {
      query,
      num: 15,
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
// URL HELPERS
// ============================================================================
function isDocumentUrl(url: string): boolean {
  const docExtensions = ['.pdf', '.xlsx', '.xls', '.ppt', '.pptx', '.doc', '.docx', '.txt', '.rar', '.zip'];
  const urlLower = url.toLowerCase().split('?')[0];
  return docExtensions.some(ext => urlLower.endsWith(ext));
}

function extractFileType(url: string): string {
  const docExtensions = ['pdf', 'xlsx', 'xls', 'ppt', 'pptx', 'doc', 'docx', 'txt', 'rar', 'zip'];
  const urlPath = url.toLowerCase().split('?')[0].split('#')[0];
  for (const ext of docExtensions) {
    if (urlPath.endsWith(`.${ext}`)) return ext;
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

    const resultsSummary = results.slice(0, 30).map((r, i) =>
      `${i + 1}. [${r.fileType?.toUpperCase() || 'WEB'}] "${r.title}" - ${r.url} | Fuente: ${r.source} | Snippet: ${r.snippet.substring(0, 150)}`
    ).join('\n');

    const prompt = `Eres un analista de inteligencia OSINT especializado en protección ejecutiva. Analiza los siguientes resultados de metabúsqueda para el ejecutivo y genera un informe de amenazas/exposición digital.

EJECUTIVO:
- Nombre: ${executive.fullName}
- Identificación: ${executive.identificationNum}
- Email: ${executive.email || 'No disponible'}

RESULTADOS DE METABÚSQUEDA OSINT (${results.length} resultados):
${resultsSummary}

INSTRUCCIONES:
1. Clasifica cada resultado según nivel de exposición: ALTO, MEDIO, BAJO
2. Identifica documentos que contengan datos personales del ejecutivo
3. Detecta posibles filtraciones de información sensible
4. Identifica documentos académicos, laborales o financieros asociados
5. Genera recomendaciones de protección específicas

FORMATO DE RESPUESTA:
- Resumen Ejecutivo (2-3 líneas)
- Hallazgos Críticos (exposición alta)
- Hallazgos Moderados
- Documentos Identificados por Tipo
- Recomendaciones de Protección`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista de inteligencia OSINT experto en protección ejecutiva y ciberseguridad. Respondes siempre en español de forma clara y profesional.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 2000,
    });

    return completion.choices?.[0]?.message?.content || 'Análisis no disponible';
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[METASEARCH] AI analysis error: ${msg.substring(0, 200)}`);
    return 'Análisis IA no disponible en este momento.';
  }
}

// ============================================================================
// FILE DOWNLOAD AND STORAGE
// ============================================================================
async function downloadAndStoreFile(
  url: string,
  executiveName: string,
  baseDir: string
): Promise<{ success: boolean; localPath: string; fileName: string; fileSize: number; error?: string }> {
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
    console.log(`[METASEARCH] Downloading: ${url.substring(0, 80)}`);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'identity',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      return { success: false, localPath: '', fileName, fileSize: 0, error: `HTTP ${response.status}` };
    }

    const contentLength = parseInt(response.headers.get('content-length') || '0');
    if (contentLength > 50 * 1024 * 1024) {
      return { success: false, localPath: '', fileName, fileSize: contentLength, error: 'File too large (>50MB)' };
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(localPath, buffer);
    console.log(`[METASEARCH] Saved: ${localPath} (${buffer.length} bytes)`);

    return { success: true, localPath, fileName, fileSize: buffer.length };
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
): string {
  const execDir = path.join(baseDir, sanitizeFileName(executiveName));

  try {
    fs.mkdirSync(execDir, { recursive: true });
  } catch { /* ignore */ }

  const detailPath = path.join(execDir, 'detalle_identificado.json');

  const detailData = {
    executiveName,
    generatedAt: new Date().toISOString(),
    totalFindings: evidence.length,
    downloadedFiles: evidence.filter(e => e.downloadStatus === 'success').length,
    failedDownloads: evidence.filter(e => e.downloadStatus === 'failed').length,
    aiAnalysis,
    findings: evidence,
  };

  fs.writeFileSync(detailPath, JSON.stringify(detailData, null, 2), 'utf-8');
  console.log(`[METASEARCH] Evidence detail written: ${detailPath}`);

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
// MAIN POST HANDLER - 5 ENGINE METASEARCH
// Engines: Google + Bing + Yandex + DuckDuckGo (parallel scraping)
//          ZAI Web Search (fallback if scraping engines return few results)
// ============================================================================
export async function POST(request: NextRequest) {
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
      queryGroups = [{ label: 'Búsqueda personalizada', queries: [customQuery] }];
    }

    // =========================================================================
    // COLLECT QUERIES
    // =========================================================================
    const allQueries: string[] = [];
    for (const group of queryGroups) {
      allQueries.push(...group.queries);
    }
    // Limit to top 6 queries to avoid timeout
    const queriesToExecute = allQueries.slice(0, 6);
    console.log(`[METASEARCH] Executing ${queriesToExecute.length} queries across 5 engines`);

    const allResults: MetasearchResult[] = [];
    const seenUrls = new Set<string>();
    const enginesUsed: string[] = [];
    let googleCount = 0, bingCount = 0, yandexCount = 0, ddgCount = 0, zaiCount = 0;

    // =========================================================================
    // PHASE 1: SCRAPING ENGINES (Google + Bing + Yandex + DuckDuckGo)
    // For each query, hit all 4 engines in parallel
    // =========================================================================
    console.log('[METASEARCH] Phase 1: Scraping engines (Google + Bing + Yandex + DuckDuckGo)...');

    for (const query of queriesToExecute) {
      // Run all 4 engines for this query IN PARALLEL
      const [googleResults, bingResults, yandexResults, ddgResults] = await Promise.all([
        searchGoogle(query).catch(() => [] as MetasearchResult[]),
        searchBing(query).catch(() => [] as MetasearchResult[]),
        searchYandex(query).catch(() => [] as MetasearchResult[]),
        searchDuckDuckGo(query).catch(() => [] as MetasearchResult[]),
      ]);

      googleCount += googleResults.length;
      bingCount += bingResults.length;
      yandexCount += yandexResults.length;
      ddgCount += ddgResults.length;

      addResults(googleResults, allResults, seenUrls, enginesUsed, 'Google');
      addResults(bingResults, allResults, seenUrls, enginesUsed, 'Bing');
      addResults(yandexResults, allResults, seenUrls, enginesUsed, 'Yandex');
      addResults(ddgResults, allResults, seenUrls, enginesUsed, 'DuckDuckGo');

      // Small delay between query batches to be respectful
      await new Promise(r => setTimeout(r, 800));
    }

    console.log(`[METASEARCH] Scraping phase done: Google=${googleCount}, Bing=${bingCount}, Yandex=${yandexCount}, DDG=${ddgCount}, Total unique=${allResults.length}`);

    // =========================================================================
    // PHASE 2: ZAI Web Search (FALLBACK - only if scraping returned < 10)
    // =========================================================================
    if (allResults.length < 10) {
      console.log('[METASEARCH] Phase 2: ZAI Web Search fallback (scraping returned few results)...');
      const zaiPromises = queriesToExecute.slice(0, 3).map(query =>
        searchZAI(query).catch(() => [] as MetasearchResult[])
      );
      const zaiResultsArray = await Promise.all(zaiPromises);

      for (const queryResults of zaiResultsArray) {
        zaiCount += queryResults.length;
        addResults(queryResults, allResults, seenUrls, enginesUsed, 'Web Search');
      }
      console.log(`[METASEARCH] ZAI fallback: ${zaiCount} results, Total unique=${allResults.length}`);
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
      ? `OSINT Multi-Engine [${enginesUsed.join(' + ')}]`
      : 'Sin resultados';

    console.log(`[METASEARCH] Final: Google=${googleCount}, Bing=${bingCount}, Yandex=${yandexCount}, DDG=${ddgCount}, ZAI=${zaiCount}, Total unique=${allResults.length}`);

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

    // Write evidence detail file
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
      }));

      evidenceDetailPath = writeEvidenceDetail(executive.fullName, baseDir, allEvidence, aiAnalysis);
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
      engineStats: {
        google: googleCount,
        bing: bingCount,
        yandex: yandexCount,
        duckduckgo: ddgCount,
        webSearch: zaiCount,
      },
      queryGroups: queryGroups.map(g => ({ label: g.label, queryCount: g.queries.length })),
      resultCount: allResults.length,
      downloadableCount: downloadableResults.length,
      downloadedCount: evidenceDetails.filter(e => e.downloadStatus === 'success').length,
      results: allResults.slice(0, 100),
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
    });
  } catch (error) {
    console.error('Metasearch error:', error);
    return NextResponse.json(
      { error: 'Error al ejecutar metabúsqueda' },
      { status: 500 }
    );
  }
}
