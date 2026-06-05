import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import ZAI from 'z-ai-web-dev-sdk';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

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
  querySource?: string;
  queryBlock?: string;
  sourceDomain?: string;
  actors?: string;
  publicationDate?: string;
  matchedIdentifiers?: string[];
  classification?: 'validated' | 'potential' | 'discarded';
  classificationReason?: string;
  fromTargetedQuery?: boolean;
}

interface SearchQueryGroup {
  label: string;
  queries: string[];
  blockType: 'name' | 'email' | 'id' | 'combined' | 'filetype' | 'custom';
  resultsFound: number;
}

interface EngineDetail {
  name: string;
  queriesRun: number;
  resultsFound: number;
  status: 'active' | 'failed' | 'skipped';
  details: string;
}

// EXTENSIONS
const ALL_EXTENSIONS = [
  'pdf', 'xlsx', 'xls', 'ppt', 'pptx', 'doc', 'docx', 'txt',
  'rar', 'zip', '7z', 'htm', 'html', 'csv', 'rtf',
  'env', 'conf', 'config', 'ini', 'json', 'xml', 'yaml',
  'bak', 'old', 'sql', 'db',
  'odt', 'ods', 'odp', 'yml', 'tmp', 'sqlite',
  'tar.gz', 'tgz', 'png', 'jpg', 'jpeg', 'svg',
];

const EXTENSION_GROUPS = [
  { label: 'Documentos', exts: ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'], icon: 'doc' },
  { label: 'Hojas de calculo', exts: ['xlsx', 'xls', 'csv', 'ods'], icon: 'sheet' },
  { label: 'Presentaciones', exts: ['ppt', 'pptx', 'odp'], icon: 'pres' },
  { label: 'Archivos comprimidos', exts: ['zip', 'rar', '7z', 'tar.gz', 'tgz'], icon: 'zip' },
  { label: 'Configuracion/Sensibles', exts: ['env', 'conf', 'config', 'ini', 'json', 'xml', 'yaml', 'yml', 'bak', 'old'], icon: 'sensitive' },
  { label: 'Base de datos', exts: ['sql', 'db', 'sqlite'], icon: 'db' },
  { label: 'Web', exts: ['htm', 'html'], icon: 'web' },
  { label: 'Imagenes', exts: ['png', 'jpg', 'jpeg', 'svg'], icon: 'img' },
  { label: 'Temp/Logs', exts: ['tmp'], icon: 'temp' },
];

function isDocumentUrl(url: string): boolean {
  const urlLower = url.toLowerCase().split('?')[0].split('#')[0];
  return ALL_EXTENSIONS.some(ext => {
    if (ext.includes('.')) return urlLower.endsWith(`.${ext}`);
    return urlLower.endsWith(`.${ext}`);
  });
}

function extractFileType(url: string): string {
  const urlPath = url.toLowerCase().split('?')[0].split('#')[0];
  for (const ext of ALL_EXTENSIONS) {
    if (ext.includes('.')) {
      if (urlPath.endsWith(`.${ext}`)) return ext;
    } else {
      if (urlPath.endsWith(`.${ext}`)) return ext;
    }
  }
  return 'html';
}

// ============================================================================
// OSINT QUERY MATRIX v7.0 - Uses ZAI Web Search filetype: operators
// ============================================================================
function buildOsintQueryMatrix(executive: {
  fullName: string;
  identificationNum: string;
  email: string | null;
}): { groups: SearchQueryGroup[]; allQueries: string[] } {
  const name = executive.fullName;
  const id = executive.identificationNum;
  const email = executive.email;
  const nameParts = name.toLowerCase().split(' ');
  const lastName = nameParts[nameParts.length - 1] || '';
  const emailUser = email ? email.split('@')[0] : '';
  const domain = email ? email.split('@')[1] : '';

  const groups: SearchQueryGroup[] = [];
  const allQueries: string[] = [];

  // BLOQUE 1: Nombre exacto
  const nameQueries: string[] = [];
  const q1 = `"${name}"`;
  nameQueries.push(q1); allQueries.push(q1);
  groups.push({ label: `Nombre: ${name}`, queries: nameQueries, blockType: 'name', resultsFound: 0 });

  // BLOQUE 2: Nombre + Documentos (filetype: operators)
  const docQueries: string[] = [];
  // PDF documents
  const q2 = `"${name}" filetype:pdf`;
  docQueries.push(q2); allQueries.push(q2);
  // Office documents
  const q3 = `"${name}" filetype:doc OR filetype:docx`;
  docQueries.push(q3); allQueries.push(q3);
  // Spreadsheets
  const q4 = `"${name}" filetype:xlsx OR filetype:xls OR filetype:csv`;
  docQueries.push(q4); allQueries.push(q4);
  // Presentations
  const q5 = `"${name}" filetype:ppt OR filetype:pptx`;
  docQueries.push(q5); allQueries.push(q5);
  // Sensitive files
  const q6 = `"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak OR filetype:ini`;
  docQueries.push(q6); allQueries.push(q6);
  // Compressed
  const q7 = `"${name}" filetype:zip OR filetype:rar OR filetype:7z`;
  docQueries.push(q7); allQueries.push(q7);
  // Web pages
  const q8 = `"${name}" filetype:htm OR filetype:html`;
  docQueries.push(q8); allQueries.push(q8);
  // Databases
  const q9 = `"${name}" filetype:json OR filetype:xml OR filetype:yaml OR filetype:yml`;
  docQueries.push(q9); allQueries.push(q9);
  groups.push({ label: `Documentos por extension`, queries: docQueries, blockType: 'filetype', resultsFound: 0 });

  // BLOQUE 3: ID
  const idQueries: string[] = [];
  const q10 = `"${id}"`;
  idQueries.push(q10); allQueries.push(q10);
  const q11 = `"${id}" filetype:pdf`;
  idQueries.push(q11); allQueries.push(q11);
  const q12 = `"${id}" filetype:xlsx OR filetype:doc`;
  idQueries.push(q12); allQueries.push(q12);
  groups.push({ label: `ID: ${id}`, queries: idQueries, blockType: 'id', resultsFound: 0 });

  // BLOQUE 4: Email
  if (email) {
    const emailQueries: string[] = [];
    const q13 = `"${email}"`;
    emailQueries.push(q13); allQueries.push(q13);
    const q14 = `"${email}" filetype:pdf`;
    emailQueries.push(q14); allQueries.push(q14);
    const q15 = `"${email}" filetype:xlsx OR filetype:doc OR filetype:sql`;
    emailQueries.push(q15); allQueries.push(q15);
    if (domain) {
      const q16 = `"${name}" site:${domain}`;
      emailQueries.push(q16); allQueries.push(q16);
    }
    if (emailUser && emailUser.length > 3) {
      const q17 = `"${emailUser}" filetype:pdf OR filetype:xlsx`;
      emailQueries.push(q17); allQueries.push(q17);
    }
    groups.push({ label: `Email: ${email}`, queries: emailQueries, blockType: 'email', resultsFound: 0 });
  }

  // BLOQUE 5: Combinaciones
  const combinedQueries: string[] = [];
  const q18 = `"${name}" "${id}"`;
  combinedQueries.push(q18); allQueries.push(q18);
  if (email) {
    const q19 = `"${name}" "${email}"`;
    combinedQueries.push(q19); allQueries.push(q19);
  }
  if (lastName) {
    const q20 = `"${id}" "${lastName}"`;
    combinedQueries.push(q20); allQueries.push(q20);
  }
  groups.push({ label: 'Cruzamiento Multi-Campo', queries: combinedQueries, blockType: 'combined', resultsFound: 0 });

  return { groups, allQueries: [...new Set(allQueries)] };
}

// ============================================================================
// ZAI SDK SEARCH ENGINE
// ============================================================================
let zaiInstance: any = null;
async function getZAI() {
  if (!zaiInstance) {
    try {
      zaiInstance = await ZAI.create();
      console.log('[METASEARCH v7] ZAI SDK initialized successfully');
    } catch (e: unknown) {
      console.error(`[METASEARCH v7] ZAI SDK init FAILED: ${e instanceof Error ? e.message : String(e)}`);
      throw e;
    }
  }
  return zaiInstance;
}

async function searchZAI(query: string): Promise<MetasearchResult[]> {
  try {
    const zai = await getZAI();
    console.log(`[METASEARCH v7] ZAI searching: "${query.substring(0, 80)}"`);
    const searchResult = await zai.functions.invoke('web_search', { query, num: 15 });

    if (searchResult && Array.isArray(searchResult)) {
      const mapped = searchResult
        .filter((item: any) => item.url && item.url.startsWith('http'))
        .map((item: any, index: number) => ({
          title: (item.name || 'Sin titulo').substring(0, 300),
          url: item.url,
          snippet: (item.snippet || '').substring(0, 500),
          source: 'Web Search',
          position: index + 1,
          isDownloadable: isDocumentUrl(item.url),
          fileType: extractFileType(item.url),
          querySource: query.substring(0, 120),
        }));
      console.log(`[METASEARCH v7] ZAI returned ${mapped.length} results for: "${query.substring(0, 50)}"`);
      return mapped;
    }
    console.log(`[METASEARCH v7] ZAI returned empty for: "${query.substring(0, 50)}"`);
  } catch (e: unknown) {
    console.error(`[METASEARCH v7] ZAI search error: ${e instanceof Error ? e.message.substring(0, 200) : String(e).substring(0, 200)}`);
  }
  return [];
}

// ============================================================================
// AI ANALYSIS
// ============================================================================
async function analyzeResultsWithAI(
  executive: { fullName: string; identificationNum: string; email: string | null },
  results: MetasearchResult[]
): Promise<string> {
  try {
    const zai = await getZAI();
    const resultsSummary = results.slice(0, 40).map((r, i) =>
      `${i + 1}. [${r.classification?.toUpperCase() || 'N/A'}] [${r.fileType?.toUpperCase() || 'WEB'}] "${r.title}" - ${r.url} | ${r.source} | ${r.snippet.substring(0, 150)}`
    ).join('\n');

    const prompt = `Analiza los resultados de metabusqueda OSINT para:
EJECUTIVO: ${executive.fullName}, ID: ${executive.identificationNum}, Email: ${executive.email || 'N/A'}

RESULTADOS (${results.length} resultados):
${resultsSummary}

INSTRUCCIONES:
- Los resultados VALIDATED tienen coincidencia directa con identificadores del ejecutivo.
- Los POTENTIAL provienen de busquedas dirigidas pero no muestran el identificador en el snippet.
- Clasifica la exposicion como ALTA si aparecen documentos sensibles (.env, .sql, .bak, .conf, .xlsx con datos).
- Clasifica como MEDIA si solo hay menciones web o PDFs publicos.
- Clasifica como BAJA si las menciones son indirectas o genericas.
- Identifica vectores de ataque potenciales basandote en la informacion encontrada.
- Genera recomendaciones de proteccion ejecutiva especificas.

Genera: Resumen Ejecutivo, Nivel de Exposicion, Hallazgos Criticos, Vectores de Ataque, Recomendaciones.`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista OSINT experto en proteccion ejecutiva. Responde en espanol, detallado y profesional.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 3000,
    });
    const analysis = completion.choices?.[0]?.message?.content || 'Analisis no disponible';
    console.log(`[METASEARCH v7] AI analysis generated: ${analysis.length} chars`);
    return analysis;
  } catch (e: unknown) {
    console.log(`[METASEARCH v7] AI analysis error: ${e instanceof Error ? e.message.substring(0, 100) : String(e).substring(0, 100)}`);
    return 'Analisis IA no disponible en este momento. Los resultados de busqueda fueron capturados exitosamente.';
  }
}

// ============================================================================
// THREE-TIER CLASSIFICATION v7.0
// ============================================================================
function classifyResults(
  results: MetasearchResult[],
  executive: { fullName: string; identificationNum: string; email: string | null },
): {
  validated: MetasearchResult[];
  potential: MetasearchResult[];
  discarded: MetasearchResult[];
} {
  const name = executive.fullName;
  const id = executive.identificationNum;
  const email = executive.email;

  const identifiers: Array<{ label: string; patterns: RegExp[] }> = [];

  // Name patterns - check for full name and significant parts
  const nameParts = name.toLowerCase().split(/\s+/).filter(p => p.length > 2);
  identifiers.push({
    label: 'Nombre',
    patterns: [
      new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
      ...nameParts.filter(p => p.length > 3).map(part => new RegExp(`\\b${part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i')),
    ],
  });

  // ID patterns
  const idNum = id.replace(/\D/g, '');
  identifiers.push({
    label: 'ID',
    patterns: [
      new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
      ...(idNum.length > 4 ? [new RegExp(`\\b${idNum}\\b`, 'i')] : []),
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
      result.classification = 'validated';
      result.matchedIdentifiers = matchedIds;
      result.classificationReason = `Coincidencia directa: ${matchedIds.join(', ')}`;
      validated.push(result);
    } else {
      // Check if query source contains executive identifiers (targeted query result)
      const queryText = (result.querySource || '').toLowerCase();
      const isFromTargetedQuery = identifiers.some(idGroup =>
        idGroup.patterns.some(pattern => pattern.test(queryText))
      );

      // Also check if the result comes from a filetype dorking query
      const isFiletypeQuery = queryText.includes('filetype:');

      // Mark the result with fromTargetedQuery flag
      result.fromTargetedQuery = isFromTargetedQuery || isFiletypeQuery;

      if (isFromTargetedQuery) {
        // Results from queries containing the executive's identifiers
        // are automatically at least 'potential' - they were found because
        // the search specifically targeted the executive
        result.classification = 'potential';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Resultado de busqueda dirigida con identificador del ejecutivo';
        potential.push(result);
      } else if (isFiletypeQuery) {
        // Results from filetype dorking queries are also at least 'potential'
        // because the filetype operator was used specifically to find documents
        // related to the executive
        result.classification = 'potential';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Resultado de busqueda con operador filetype dirigido al ejecutivo';
        potential.push(result);
      } else {
        result.classification = 'discarded';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Sin coincidencia con identificadores del ejecutivo';
        discarded.push(result);
      }
    }
  }

  console.log(`[METASEARCH v7] Classification: ${results.length} total -> ${validated.length} validated, ${potential.length} potential, ${discarded.length} discarded`);
  return { validated, potential, discarded };
}

// ============================================================================
// METADATA ENRICHMENT
// ============================================================================
function enrichResultsWithMetadata(results: MetasearchResult[], executiveIdNum?: string): MetasearchResult[] {
  for (const result of results) {
    try { result.sourceDomain = new URL(result.url).hostname; } catch { result.sourceDomain = 'unknown'; }

    // Extract actors from snippet/title
    const actors: string[] = [];
    const byPatterns = [
      /(?:by|por|author|autor|uploaded|subido)\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})/g,
      /@([\w.-]+)/g,
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

    // Extract publication date
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

    // Determine query block from querySource
    const queryLower = (result.querySource || '').toLowerCase();
    if (queryLower.includes('filetype:')) {
      result.queryBlock = 'Documentos por extension';
    } else if (queryLower.includes('@') || queryLower.includes('site:')) {
      result.queryBlock = 'Email';
    } else if (executiveIdNum && queryLower.includes(executiveIdNum.toLowerCase())) {
      result.queryBlock = 'ID';
    } else {
      result.queryBlock = 'Nombre';
    }
  }
  return results;
}

// ============================================================================
// DEDUP
// ============================================================================
function addResults(
  newResults: MetasearchResult[],
  allResults: MetasearchResult[],
  seenUrls: Set<string>,
): number {
  let added = 0;
  for (const result of newResults) {
    const urlKey = result.url.toLowerCase().split('?')[0].split('#')[0];
    if (!seenUrls.has(urlKey) && result.url.startsWith('http')) {
      seenUrls.add(urlKey);
      if (!result.fileType) result.fileType = extractFileType(result.url);
      allResults.push(result);
      added++;
    }
  }
  return added;
}

// ============================================================================
// MAIN POST HANDLER v7.0
// ============================================================================
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  try {
    const user = await getAuthenticatedUser(request);
    if (!user) return NextResponse.json({ error: 'No autorizado' }, { status: 401 });

    const body = await request.json();
    const { executiveId, query: customQuery } = body;
    if (!executiveId && !customQuery) return NextResponse.json({ error: 'Se requiere executiveId o query' }, { status: 400 });

    let executive: { id: string; fullName: string; identificationNum: string; email: string | null; [key: string]: any } | null = null;
    let queryGroups: SearchQueryGroup[] = [];

    if (executiveId) {
      executive = await db.executive.findUnique({ where: { id: executiveId } });
      if (!executive) return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
      const matrix = buildOsintQueryMatrix({ fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email });
      queryGroups = matrix.groups;
      console.log(`[METASEARCH v7] Built ${matrix.groups.length} query groups with ${matrix.allQueries.length} unique queries for: ${executive.fullName}`);
    } else {
      queryGroups = [{ label: 'Busqueda personalizada', queries: [customQuery], blockType: 'custom' as const, resultsFound: 0 }];
    }

    const allResults: MetasearchResult[] = [];
    const seenUrls = new Set<string>();
    const engineDetails: EngineDetail[] = [];
    let totalQueriesRun = 0;

    // ============================================================================
    // PHASE 1: Execute ALL queries via ZAI Web Search
    // ============================================================================
    console.log(`[METASEARCH v7] Phase 1: Executing ZAI Web Search queries...`);

    for (const group of queryGroups) {
      let groupResults = 0;
      for (const query of group.queries) {
        try {
          totalQueriesRun++;
          const results = await searchZAI(query);
          const added = addResults(results, allResults, seenUrls);
          groupResults += added;

          // Small delay between queries to be respectful
          await new Promise(r => setTimeout(r, 200 + Math.random() * 300));
        } catch (e: unknown) {
          console.log(`[METASEARCH v7] Query error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
        }
      }
      group.resultsFound = groupResults;
    }

    engineDetails.push({
      name: 'ZAI Web Search',
      queriesRun: totalQueriesRun,
      resultsFound: allResults.length,
      status: allResults.length > 0 ? 'active' : 'failed',
      details: allResults.length > 0
        ? `${totalQueriesRun} consultas ejecutadas, ${allResults.length} resultados unicos encontrados`
        : 'No se obtuvieron resultados de las consultas ejecutadas',
    });

    console.log(`[METASEARCH v7] Phase 1 complete: ${allResults.length} unique results from ${totalQueriesRun} queries`);

    // ============================================================================
    // PHASE 2: THREE-TIER CLASSIFICATION
    // ============================================================================
    const { validated, potential, discarded } = executive
      ? classifyResults(allResults, { fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email })
      : { validated: allResults, potential: [] as MetasearchResult[], discarded: [] as MetasearchResult[] };

    // Enrich all tiers with metadata
    const execIdNum = executive?.identificationNum;
    enrichResultsWithMetadata(validated, execIdNum);
    enrichResultsWithMetadata(potential, execIdNum);
    enrichResultsWithMetadata(discarded, execIdNum);

    // Combine validated + potential for "active" results
    const activeResults = [...validated, ...potential];

    // Sort: validated first, then downloadable docs, then by position
    activeResults.sort((a, b) => {
      if (a.classification === 'validated' && b.classification !== 'validated') return -1;
      if (a.classification !== 'validated' && b.classification === 'validated') return 1;
      if (a.isDownloadable && !b.isDownloadable) return -1;
      if (!a.isDownloadable && b.isDownloadable) return 1;
      return 0;
    });
    activeResults.forEach((r, i) => { r.position = i + 1; });
    discarded.forEach((r, i) => { r.position = activeResults.length + i + 1; });

    const downloadableResults = activeResults.filter(r => r.isDownloadable);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    console.log(`[METASEARCH v7] Classification complete (${elapsed}s): Raw=${allResults.length}, Validated=${validated.length}, Potential=${potential.length}, Discarded=${discarded.length}`);

    // ============================================================================
    // PHASE 3: AI ANALYSIS
    // ============================================================================
    let aiAnalysis = '';
    if (activeResults.length > 0) {
      try {
        aiAnalysis = await analyzeResultsWithAI(
          { fullName: executive?.fullName || 'Custom', identificationNum: executive?.identificationNum || '', email: executive?.email || null },
          activeResults
        );
      } catch (e: unknown) {
        aiAnalysis = 'Analisis IA no disponible en este momento.';
      }
    } else {
      aiAnalysis = 'No se encontraron resultados relevantes para analizar. Se recomienda verificar los datos del ejecutivo y realizar una nueva busqueda.';
    }

    // ============================================================================
    // UPDATE DB
    // ============================================================================
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
              topResults: activeResults.slice(0, 20).map(r => ({ title: r.title, url: r.url, source: r.source, classification: r.classification, fileType: r.fileType })),
            }),
          },
        });
      } catch { /* ignore */ }
    }

    // ============================================================================
    // RETURN
    // ============================================================================
    return NextResponse.json({
      success: true,
      searchEngine: `OSINT v7.0 [ZAI Web Search]`,
      enginesUsed: ['ZAI Web Search'],
      engineDetails,
      queryGroups: queryGroups.map(g => ({
        label: g.label,
        queryCount: g.queries.length,
        blockType: g.blockType,
        resultsFound: g.resultsFound,
        sampleQueries: g.queries.slice(0, 3),
      })),
      resultCount: activeResults.length,
      rawResultCount: allResults.length,
      filteredOutCount: discarded.length,
      classificationStats: { validated: validated.length, potential: potential.length, discarded: discarded.length },
      downloadableCount: downloadableResults.length,
      downloadedCount: 0,
      results: activeResults.slice(0, 200),
      validatedResults: validated.slice(0, 200),
      potentialResults: potential.slice(0, 200),
      discardedResults: discarded.slice(0, 200),
      aiAnalysis,
      evidence: [],
      evidenceDetailPath: '',
      executive: executive ? { id: executive.id, fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email } : null,
      timestamp: new Date().toISOString(),
      extensionsMonitored: ALL_EXTENSIONS,
      extensionGroups: EXTENSION_GROUPS,
      elapsedSeconds: parseFloat(elapsed),
    });
  } catch (e: unknown) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.error(`[METASEARCH v7] Fatal error (${elapsed}s): ${e instanceof Error ? e.message : String(e)}`);
    return NextResponse.json({
      success: false,
      error: e instanceof Error ? e.message : 'Error desconocido en metabusqueda',
      elapsedSeconds: parseFloat(elapsed),
    }, { status: 500 });
  }
}
