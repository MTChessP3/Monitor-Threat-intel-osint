import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { isZAIConfigured, zaiChatCompletion, zaiWebSearch } from '@/lib/zai';
import type { ZAIWebSearchDiagnostics } from '@/lib/zai';

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
// OSINT QUERY MATRIX v8.0 - Uses DuckDuckGo filetype: operators
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
  const q2 = `"${name}" filetype:pdf`;
  docQueries.push(q2); allQueries.push(q2);
  const q3 = `"${name}" filetype:doc OR filetype:docx`;
  docQueries.push(q3); allQueries.push(q3);
  const q4 = `"${name}" filetype:xlsx OR filetype:xls OR filetype:csv`;
  docQueries.push(q4); allQueries.push(q4);
  const q5 = `"${name}" filetype:ppt OR filetype:pptx`;
  docQueries.push(q5); allQueries.push(q5);
  const q6 = `"${name}" filetype:env OR filetype:conf OR filetype:sql OR filetype:bak OR filetype:ini`;
  docQueries.push(q6); allQueries.push(q6);
  const q7 = `"${name}" filetype:zip OR filetype:rar OR filetype:7z`;
  docQueries.push(q7); allQueries.push(q7);
  const q8 = `"${name}" filetype:htm OR filetype:html`;
  docQueries.push(q8); allQueries.push(q8);
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
// WEB SEARCH ENGINE (free: DuckDuckGo + Bing, via lib/zai.ts)
// ============================================================================
// The free scrapers (especially Bing RSS) often ignore `filetype:` operators,
// returning generic web pages. Enforce the operator client-side so a query
// like `"Name" filetype:pdf` only yields actual PDFs.
function enforceQueryOperators(query: string, results: MetasearchResult[]): MetasearchResult[] {
  const filetypes = [...query.matchAll(/filetype:([a-z0-9]+)/gi)].map(m => m[1].toLowerCase());
  if (filetypes.length === 0) return results;
  return results.filter(r => {
    const ft = (r.fileType || '').toLowerCase();
    const urlPath = (r.url || '').toLowerCase().split('?')[0].split('#')[0];
    return filetypes.some(req => ft === req || urlPath.endsWith('.' + req));
  });
}

async function searchZAI(query: string, diagnostics: ZAIWebSearchDiagnostics[]): Promise<MetasearchResult[]> {
  try {
    const searchResult = await zaiWebSearch(query, {
      num: 15,
      maxRetries: 1,
      timeoutMs: 8000,
      onDiagnostics: (d) => diagnostics.push(d),
    });

    if (searchResult && searchResult.length > 0) {
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
      const filtered = enforceQueryOperators(query, mapped);
      console.log(`[METASEARCH v8] ZAI returned ${mapped.length} results for: "${query.substring(0, 50)}" -> ${filtered.length} after filetype filter`);
      return filtered;
    }
    console.log(`[METASEARCH v8] ZAI returned empty for: "${query.substring(0, 50)}"`);
  } catch (e: unknown) {
    console.error(`[METASEARCH v8] ZAI search error: ${e instanceof Error ? e.message.substring(0, 200) : String(e).substring(0, 200)}`);
  }
  return [];
}

// ============================================================================
// AI ANALYSIS (using unified lib/zai.ts)
// ============================================================================
async function analyzeResultsWithAI(
  executive: { fullName: string; identificationNum: string; email: string | null },
  results: MetasearchResult[]
): Promise<string> {
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

  const analysis = await zaiChatCompletion(
    [
      { role: 'system', content: 'Eres un analista OSINT experto en proteccion ejecutiva. Responde en espanol, detallado y profesional.' },
      { role: 'user', content: prompt },
    ],
    { temperature: 0.3, max_tokens: 3000, maxRetries: 3 }
  );

  if (analysis) {
    console.log(`[METASEARCH v8] AI analysis generated: ${analysis.length} chars`);
    return analysis;
  }

  // Intelligent fallback when AI is truly unavailable - generate from the data we have
  console.log('[METASEARCH v8] AI unavailable, generating analysis from classification data');
  const validated = results.filter(r => r.classification === 'validated');
  const potential = results.filter(r => r.classification === 'potential');
  const sensitive = results.filter(r => ['env', 'sql', 'bak', 'conf', 'ini', 'db', 'sqlite'].includes(r.fileType || ''));

  let exposureLevel = 'BAJA';
  let exposureReason = 'Las menciones son indirectas o genericas.';
  if (sensitive.length > 0) {
    exposureLevel = 'ALTA';
    exposureReason = `Se encontraron ${sensitive.length} archivo(s) con extensiones sensibles (${sensitive.map(s => '.' + s.fileType).join(', ')}). Esto representa un riesgo critico de exposicion de datos.`;
  } else if (validated.length > 3) {
    exposureLevel = 'MEDIA';
    exposureReason = `Se encontraron ${validated.length} resultados validados con coincidencia directa de identificadores del ejecutivo.`;
  } else if (validated.length > 0 || potential.length > 0) {
    exposureLevel = 'MEDIA';
    exposureReason = `Se encontraron ${validated.length} resultados validados y ${potential.length} potenciales.`;
  }

  return `RESUMEN EJECUTIVO - ANALISIS OSINT
========================================

Ejecutivo: ${executive.fullName}
ID: ${executive.identificationNum}
Email: ${executive.email || 'N/A'}

NIVEL DE EXPOSICION: ${exposureLevel}
Razon: ${exposureReason}

HALLAZGOS CRITICOS:
- Total de resultados analizados: ${results.length}
- Resultados Validados (coincidencia directa): ${validated.length}
- Resultados Potenciales (busqueda dirigida): ${potential.length}
- Archivos sensibles detectados: ${sensitive.length}
${sensitive.length > 0 ? `\nArchivos sensibles encontrados:\n${sensitive.map(s => `  - ${s.title} (${s.fileType}) - ${s.url}`).join('\n')}` : ''}

VECTORES DE ATAQUE IDENTIFICADOS:
${validated.length > 0 ? `- Ingenieria Social: La informacion publica permite perfilar al ejecutivo para ataques de ingenieria social.` : ''}
${potential.length > 0 ? `- Exposicion de datos: Se encontraron ${potential.length} resultados de busquedas dirigidas que pueden contener informacion relevante.` : ''}
${sensitive.length > 0 ? `- Filtracion de datos: Se detectaron archivos con extensiones sensibles que podrian contener informacion confidencial.` : ''}
- Suplantacion de identidad: Los datos publicos pueden ser utilizados para crear perfiles falsos.

RECOMENDACIONES:
1. Monitoreo continuo de las fuentes identificadas
2. Evaluar la necesidad de solicitar eliminacion de datos sensibles
3. Implementar alertas automatizadas para nuevas menciones
4. Revision periodica de la huella digital del ejecutivo
5. Capacitacion en seguridad digital y concientizacion sobre ingenieria social

NOTA: Este analisis fue generado automaticamente basado en la clasificacion de los resultados de busqueda. Se recomienda una revision detallada por un analista de inteligencia.`;
}

// ============================================================================
// THREE-TIER CLASSIFICATION v8.0
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

  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const nameParts = name.toLowerCase().split(/\s+/).filter(p => p.length > 2);
  const firstName = nameParts[0] || '';
  const lastName = nameParts[nameParts.length - 1] || '';

  // Full name (contiguous) is the strongest name signal.
  const fullNamePattern = new RegExp(esc(name), 'i');
  // Individual parts only count toward a partial match.
  const firstNameRe = firstName.length > 3 ? new RegExp(`\\b${esc(firstName)}\\b`, 'i') : null;
  const lastNameRe = lastName.length > 3 ? new RegExp(`\\b${esc(lastName)}\\b`, 'i') : null;

  const idNum = id.replace(/\D/g, '');
  const idPattern = new RegExp(esc(id), 'i');
  const idNumPattern = idNum.length > 4 ? new RegExp(`\\b${idNum}\\b`, 'i') : null;

  const emailPattern = email ? new RegExp(esc(email), 'i') : null;
  const emailUser = email ? email.split('@')[0] : '';
  const emailUserPattern = email && emailUser.length > 3 ? new RegExp(`\\b${esc(emailUser)}\\b`, 'i') : null;

  const validated: MetasearchResult[] = [];
  const potential: MetasearchResult[] = [];
  const discarded: MetasearchResult[] = [];

  for (const result of results) {
    const searchableText = `${result.title} ${result.snippet} ${result.url}`.toLowerCase();
    const matchedIds: string[] = [];
    let hasDirectMatch = false;

    // Strong name match: full name contiguous, or first+last name together.
    if (fullNamePattern.test(searchableText)) {
      hasDirectMatch = true;
      matchedIds.push('Nombre completo');
    } else if (
      (firstNameRe && lastNameRe && firstName !== lastName && firstNameRe.test(searchableText) && lastNameRe.test(searchableText)) ||
      (firstName === lastName && firstNameRe && firstNameRe.test(searchableText))
    ) {
      hasDirectMatch = true;
      matchedIds.push('Nombre');
    }

    if (idPattern.test(searchableText) || (idNumPattern && idNumPattern.test(searchableText))) {
      hasDirectMatch = true;
      if (!matchedIds.includes('ID')) matchedIds.push('ID');
    }

    if (emailPattern && (emailPattern.test(searchableText) || (emailUserPattern && emailUserPattern.test(searchableText)))) {
      hasDirectMatch = true;
      if (!matchedIds.includes('Email')) matchedIds.push('Email');
    }

    if (hasDirectMatch) {
      result.classification = 'validated';
      result.matchedIdentifiers = matchedIds;
      result.classificationReason = `Coincidencia directa: ${matchedIds.join(', ')}`;
      validated.push(result);
    } else {
      const queryText = (result.querySource || '').toLowerCase();
      const isFromTargetedQuery = queryText.includes('filetype:') || queryText.includes('site:') ||
        idPattern.test(queryText) || (emailPattern && emailPattern.test(queryText)) || fullNamePattern.test(queryText);
      const hasPartialName = (firstNameRe && firstNameRe.test(searchableText)) || (lastNameRe && lastNameRe.test(searchableText));

      result.fromTargetedQuery = isFromTargetedQuery;

      if (hasPartialName) {
        result.classification = 'potential';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Coincidencia parcial de nombre (posible homonimo)';
        potential.push(result);
      } else if (isFromTargetedQuery) {
        result.classification = 'potential';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Resultado de busqueda dirigida con identificador del ejecutivo';
        potential.push(result);
      } else {
        result.classification = 'discarded';
        result.matchedIdentifiers = [];
        result.classificationReason = 'Sin coincidencia con identificadores del ejecutivo';
        discarded.push(result);
      }
    }
  }

  console.log(`[METASEARCH v8] Classification: ${results.length} total -> ${validated.length} validated, ${potential.length} potential, ${discarded.length} discarded`);
  return { validated, potential, discarded };
}

// ============================================================================
// METADATA ENRICHMENT
// ============================================================================
function enrichResultsWithMetadata(results: MetasearchResult[], executiveIdNum?: string): MetasearchResult[] {
  for (const result of results) {
    try { result.sourceDomain = new URL(result.url).hostname; } catch { result.sourceDomain = 'unknown'; }

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
// MAIN POST HANDLER v8.0
// ============================================================================
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  try {
    await ensureDatabaseInitialized();
    const user = await getAuthenticatedUser(request);
    if (!user) return NextResponse.json({ error: 'No autorizado' }, { status: 401 });

    const body = await request.json();
    const { 
      executiveId, 
      query: customQuery, 
      targetType = 'executive',
      targetName,
      targetEmail,
      targetPhone,
      targetOrg,
    } = body;
    if (!executiveId && !customQuery) return NextResponse.json({ error: 'Se requiere executiveId o query' }, { status: 400 });

    let executive: { id: string; fullName: string; identificationNum: string; email: string | null; phone: string | null; organization: string | null; [key: string]: any } | null = null;
    let queryGroups: SearchQueryGroup[] = [];

    if (executiveId) {
      if (targetType === 'family') {
        // For family members, we need to find the executive first, then the family member
        executive = await db.executive.findUnique({ where: { id: executiveId } });
        if (!executive) return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
        
        // Find family member
        const familyMember = await db.familyMember.findFirst({ 
          where: { executiveId: executive.id, fullName: targetName }
        });
        
        if (familyMember) {
          // Use family member data for search, but include executive context
          const matrix = buildOsintQueryMatrix({ 
            fullName: familyMember.fullName, 
            identificationNum: familyMember.identificationNum || executive.identificationNum, 
            email: familyMember.email 
          });
          queryGroups = matrix.groups;
          console.log(`[METASEARCH v8] Built ${matrix.groups.length} query groups with ${matrix.allQueries.length} unique queries for family member: ${familyMember.fullName} (of ${executive.fullName})`);
        } else {
          // Fallback to targetName from request body
          const matrix = buildOsintQueryMatrix({ 
            fullName: targetName, 
            identificationNum: executive.identificationNum, 
            email: targetEmail 
          });
          queryGroups = matrix.groups;
          console.log(`[METASEARCH v8] Built ${matrix.groups.length} query groups with ${matrix.allQueries.length} unique queries for family member: ${targetName} (of ${executive.fullName})`);
        }
      } else {
        executive = await db.executive.findUnique({ where: { id: executiveId } });
        if (!executive) return NextResponse.json({ error: 'Ejecutivo no encontrado' }, { status: 404 });
        const matrix = buildOsintQueryMatrix({ fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email });
        queryGroups = matrix.groups;
        console.log(`[METASEARCH v8] Built ${matrix.groups.length} query groups with ${matrix.allQueries.length} unique queries for: ${executive.fullName}`);
      }
    } else {
      queryGroups = [{ label: 'Busqueda personalizada', queries: [customQuery], blockType: 'custom' as const, resultsFound: 0 }];
    }

    const allResults: MetasearchResult[] = [];
    const seenUrls = new Set<string>();
    const engineDetails: EngineDetail[] = [];
    let totalQueriesRun = 0;

    // ============================================================================
    // PHASE 1: Execute ALL queries via DuckDuckGo
    // Bounded: limited concurrency + global deadline + per-query timeout so the
    // whole request completes well under the serverless/proxy limits.
    // ============================================================================
    console.log(`[METASEARCH v8] Phase 1: Executing DuckDuckGo search queries...`);

    interface QueryTask { query: string; groupIndex: number; }
    const tasks: QueryTask[] = [];
    queryGroups.forEach((g, gi) => {
      for (const query of g.queries) tasks.push({ query, groupIndex: gi });
    });

    const SEARCH_DEADLINE_MS = 50000;
    const SEARCH_CONCURRENCY = 5;
    const searchStart = Date.now();
    const groupFound = queryGroups.map(() => 0);
    const searchDiagnostics: ZAIWebSearchDiagnostics[] = [];

    let nextTask = 0;
    async function searchWorker() {
      while (nextTask < tasks.length) {
        const remaining = SEARCH_DEADLINE_MS - (Date.now() - searchStart);
        if (remaining <= 0) break;
        const idx = nextTask++;
        const task = tasks[idx];
        try {
          totalQueriesRun++;
          const results = await searchZAI(task.query, searchDiagnostics);
          const added = addResults(results, allResults, seenUrls);
          groupFound[task.groupIndex] += added;
        } catch (e: unknown) {
          console.log(`[METASEARCH v8] Query error: ${e instanceof Error ? e.message.substring(0, 60) : String(e).substring(0, 60)}`);
        }
        // Small stagger between queries to reduce anti-bot triggering (DDG rate-limits server IPs).
        await new Promise(r => setTimeout(r, 500));
      }
    }
    await Promise.all(Array.from({ length: SEARCH_CONCURRENCY }, () => searchWorker()));
    queryGroups.forEach((g, i) => { g.resultsFound = groupFound[i]; });

    engineDetails.push({
      name: 'Free Web Search (SearXNG + Mojeek + Ecosia + DDG + Bing)',
      queriesRun: totalQueriesRun,
      resultsFound: allResults.length,
      status: allResults.length > 0 ? 'active' : 'failed',
      details: allResults.length > 0
        ? `${totalQueriesRun} consultas ejecutadas, ${allResults.length} resultados unicos encontrados`
        : 'No se obtuvieron resultados de las consultas ejecutadas',
    });

    console.log(`[METASEARCH v8] Phase 1 complete: ${allResults.length} unique results from ${totalQueriesRun} queries`);

    // ============================================================================
    // PHASE 2: THREE-TIER CLASSIFICATION
    // ============================================================================
    const { validated, potential, discarded } = executive
      ? classifyResults(allResults, { fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email })
      : { validated: allResults, potential: [] as MetasearchResult[], discarded: [] as MetasearchResult[] };

    const execIdNum = executive?.identificationNum;
    enrichResultsWithMetadata(validated, execIdNum);
    enrichResultsWithMetadata(potential, execIdNum);
    enrichResultsWithMetadata(discarded, execIdNum);

    const activeResults = [...validated, ...potential];

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

    console.log(`[METASEARCH v8] Classification complete (${elapsed}s): Raw=${allResults.length}, Validated=${validated.length}, Potential=${potential.length}, Discarded=${discarded.length}`);

    // ============================================================================
    // PHASE 3: AI ANALYSIS (always produces result, never shows "AI unavailable")
    // ============================================================================
    let aiAnalysis = '';
    if (activeResults.length > 0) {
      aiAnalysis = await analyzeResultsWithAI(
        { fullName: executive?.fullName || 'Custom', identificationNum: executive?.identificationNum || '', email: executive?.email || null },
        activeResults
      );
    } else {
      aiAnalysis = 'No se encontraron resultados relevantes para analizar. Se recomienda verificar los datos del ejecutivo y realizar una nueva busqueda.';
    }

    // ============================================================================
    // UPDATE DB
    // ============================================================================
    if (executive && targetType === 'executive') {
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
    const winnerCounts: Record<string, number> = {};
    for (const d of searchDiagnostics) {
      if (d.engine) winnerCounts[d.engine] = (winnerCounts[d.engine] || 0) + 1;
    }
    const winningEngines = Object.entries(winnerCounts).sort((a, b) => b[1] - a[1]);
    const primaryEngine = winningEngines[0]?.[0] || 'Bing RSS';

    return NextResponse.json({
      success: true,
      searchEngine: `OSINT v8.1 [${primaryEngine}]`,
      enginesUsed: winningEngines.map(([name]) => name),
      engineDetails,
      zaiDebug: {
        configured: isZAIConfigured(),
        baseUrl: (process.env.ZAI_BASE_URL || '').split('/').slice(0, 3).join('/') || '',
        env: {
          apiKey: !!process.env.ZAI_API_KEY,
          chatId: !!process.env.ZAI_CHAT_ID,
          token: !!process.env.ZAI_TOKEN,
          userId: !!process.env.ZAI_USER_ID,
        },
      },
      zaiDiagnostics: searchDiagnostics.slice(0, 60),
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
      executive: executive ? { id: executive.id, fullName: executive.fullName, identificationNum: executive.identificationNum, email: executive.email, phone: executive.phone, organization: executive.organization } : null,
      targetType,
      targetName: targetName || executive?.fullName,
      timestamp: new Date().toISOString(),
      extensionsMonitored: ALL_EXTENSIONS,
      extensionGroups: EXTENSION_GROUPS,
      elapsedSeconds: parseFloat(elapsed),
    });
  } catch (e: unknown) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.error(`[METASEARCH v8] Fatal error (${elapsed}s): ${e instanceof Error ? e.message : String(e)}`);
    return NextResponse.json({
      success: false,
      error: e instanceof Error ? e.message : 'Error desconocido en metabusqueda',
      elapsedSeconds: parseFloat(elapsed),
    }, { status: 500 });
  }
}
