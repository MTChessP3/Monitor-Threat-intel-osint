import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import ZAI from 'z-ai-web-dev-sdk';

export const maxDuration = 120;

async function createZAI(): Promise<InstanceType<typeof ZAI>> {
  if (process.env.ZAI_BASE_URL && process.env.ZAI_API_KEY) {
    return new ZAI({
      baseUrl: process.env.ZAI_BASE_URL,
      apiKey: process.env.ZAI_API_KEY,
      chatId: process.env.ZAI_CHAT_ID || '',
      token: process.env.ZAI_TOKEN || '',
      userId: process.env.ZAI_USER_ID || '',
    });
  }
  return ZAI.create();
}

// Helper: strip HTML to plain text
function htmlToPlainText(html: string): string {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

// Helper: detect if page_reader returned garbage (CSS, XML viewer, etc.)
function isGarbageContent(text: string): boolean {
  if (!text || text.length < 30) return true;
  const garbageSignals = [
    'webkit-xml-viewer',
    'Copyright 2014 The Chromium Authors',
    'color-scheme:',
    'border-bottom:',
    'font-family: monospace',
    'pretty-print',
    'folder-button',
    'user-select: none',
    '.opened {',
    'div.header',
    'div.folder',
  ];
  const matchCount = garbageSignals.filter(s => text.includes(s)).length;
  return matchCount >= 2;
}

// Helper: analyze URL metadata to extract context
function analyzeUrlMetadata(url: string): {
  domain: string;
  path: string;
  siteType: string;
  context: string;
} {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;

    let siteType = 'Sitio web general';
    let context = '';

    // Detect SEC/EDGAR filings
    if (domain.includes('sec.gov') && path.includes('edgar')) {
      siteType = 'Registro regulatorio SEC/EDGAR';
      const cikMatch = path.match(/data\/(\d+)/);
      const filingMatch = path.match(/(\d{10})/);
      context = `Filing regulatorio ante la SEC (U.S. Securities and Exchange Commission). CIK: ${cikMatch?.[1] || 'desconocido'}. Filing: ${filingMatch?.[1] || 'desconocido'}. Los filings SEC contienen información financiera detallada de compañías públicas incluyendo compensación de ejecutivos, participaciones accionarias, y datos de gobernanza corporativa. Esta información es PÚBLICA y requerida por ley, pero puede ser explotada por actores maliciosos para perfilar ejecutivos.`;
    }
    // Detect LinkedIn
    else if (domain.includes('linkedin.com')) {
      siteType = 'Red social profesional (LinkedIn)';
      context = 'Perfil profesional en LinkedIn. Puede contener nombre, cargo, historial laboral, educación, conexiones y recomendaciones. La información es semi-pública pero puede ser explotada para ingeniería social.';
    }
    // Detect social media
    else if (domain.includes('twitter.com') || domain.includes('x.com')) {
      siteType = 'Red social (X/Twitter)';
      context = 'Perfil o publicación en X/Twitter. Puede contener opiniones, ubicación, fotos y conexiones del VIP.';
    }
    // Detect news
    else if (domain.includes('news') || domain.includes('elpais') || domain.includes('eltiempo') || domain.includes('reuters') || domain.includes('bloomberg')) {
      siteType = 'Medio de comunicación';
      context = 'Artículo de noticias o reportaje que menciona al VIP. Puede contener información sobre su cargo, declaraciones, actividades y ubicaciones.';
    }
    // Generic
    else {
      context = `Sitio web en ${domain}. La URL y su path pueden revelar información sobre el tipo de contenido publicado.`;
    }

    return { domain, path, siteType, context };
  } catch {
    return { domain: url, path: '', siteType: 'URL inválida', context: 'No se pudo analizar la estructura de la URL.' };
  }
}

// ============================================================================
// MODE A: AUTOMATIC - AI-Driven Intelligence Report Generation
// ============================================================================
async function handleAutomaticGeneration(data: {
  urls: string[];
  writtenData: string;
  fileNames?: string[];
  templateId?: string;
  title?: string;
}) {
  const { urls, writtenData, fileNames, templateId, title } = data;
  const zai = await createZAI();

  // =========================================================================
  // PHASE 1: INTELLIGENT URL CONTENT RETRIEVAL
  // Strategy: Try page_reader first. If it fails or returns garbage,
  // fall back to web_search with the URL. Also analyze URL metadata.
  // =========================================================================
  const urlIntelligence: Array<{
    url: string;
    source: 'page_reader' | 'web_search' | 'metadata_only';
    title: string;
    textContent: string;
    siteType: string;
    urlMetadata: string;
    searchSnippets: string[];
    publishedTime: string;
    success: boolean;
  }> = [];

  for (const url of urls.slice(0, 8)) {
    const metadata = analyzeUrlMetadata(url);
    let pageContent = '';
    let pageTitle = '';
    let publishedTime = '';
    let source: 'page_reader' | 'web_search' | 'metadata_only' = 'metadata_only';
    let searchSnippets: string[] = [];
    let success = false;

    // --- ATTEMPT 1: Try page_reader ---
    try {
      console.log(`[INTEL-REPORT] Phase 1 - Attempting page_reader: ${url.substring(0, 80)}`);
      const pageResult = await (zai as any).functions.invoke('page_reader', { url });

      if (pageResult && pageResult.data) {
        const rawText = htmlToPlainText(pageResult.data.html || '');
        const titleFromPage = pageResult.data.title || '';

        // Validate content - reject garbage (CSS, XML viewer, etc.)
        if (!isGarbageContent(rawText) && rawText.length > 100) {
          pageContent = rawText.substring(0, 15000);
          pageTitle = titleFromPage || url;
          publishedTime = pageResult.data.publishedTime || '';
          source = 'page_reader';
          success = true;
          console.log(`[INTEL-REPORT] page_reader SUCCESS: ${rawText.length} chars of valid content`);
        } else {
          console.log(`[INTEL-REPORT] page_reader returned garbage/empty for ${url.substring(0, 50)}`);
        }
      }
      await new Promise(r => setTimeout(r, 1500));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`[INTEL-REPORT] page_reader error: ${msg.substring(0, 80)}`);
    }

    // --- ATTEMPT 2: If page_reader failed, use web_search with the exact URL ---
    if (!success) {
      try {
        console.log(`[INTEL-REPORT] Phase 1 - Falling back to web_search for URL context`);
        // Search for the exact URL to get snippets about what's on it
        const searchResult = await (zai as any).functions.invoke('web_search', {
          query: url.substring(0, 200),
          num: 5,
        });

        if (searchResult && Array.isArray(searchResult) && searchResult.length > 0) {
          searchSnippets = searchResult.map((item: any) =>
            `[${item.name || 'Fuente'}] ${item.snippet || ''}`
          ).filter((s: string) => s.length > 20);

          if (searchSnippets.length > 0) {
            source = 'web_search';
            success = true;
            console.log(`[INTEL-REPORT] web_search found ${searchSnippets.length} snippets for URL`);
          }
        }
        await new Promise(r => setTimeout(r, 2000));
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        console.log(`[INTEL-REPORT] web_search fallback error: ${msg.substring(0, 80)}`);
      }
    }

    // --- ATTEMPT 3: If both failed, do a broader search about the URL's domain/entity ---
    if (!success) {
      try {
        const domainQuery = `${metadata.domain} filing executive information`;
        console.log(`[INTEL-REPORT] Phase 1 - Last resort search: ${domainQuery}`);
        const broadResult = await (zai as any).functions.invoke('web_search', {
          query: domainQuery,
          num: 5,
        });

        if (broadResult && Array.isArray(broadResult) && broadResult.length > 0) {
          searchSnippets = broadResult.map((item: any) =>
            `[${item.name || 'Fuente'}] ${item.snippet || ''}`
          ).filter((s: string) => s.length > 20);

          if (searchSnippets.length > 0) {
            source = 'web_search';
            success = true;
          }
        }
        await new Promise(r => setTimeout(r, 2000));
      } catch (e: unknown) {
        console.log(`[INTEL-REPORT] Last resort search failed`);
      }
    }

    urlIntelligence.push({
      url,
      source,
      title: pageTitle || metadata.siteType,
      textContent: pageContent,
      siteType: metadata.siteType,
      urlMetadata: metadata.context,
      searchSnippets,
      publishedTime,
      success,
    });
  }

  // =========================================================================
  // PHASE 2: TARGETED OSINT WEB SEARCHES
  // First search for each URL specifically, then search based on
  // any entities we can identify from written data and URL metadata
  // =========================================================================
  const osintResults: Array<{
    sourceName: string;
    sourceUrl: string;
    snippet: string;
    hostname: string;
    date: string;
    searchQuery: string;
  }> = [];

  const searchQueries: string[] = [];

  // Search for context about each URL's domain
  for (const url of urls.slice(0, 3)) {
    try {
      const urlObj = new URL(url);
      // Extract CIK/entity number from SEC URLs
      const cikMatch = urlObj.pathname.match(/data\/(\d+)/);
      if (cikMatch) {
        searchQueries.push(`SEC CIK ${cikMatch[1]} company executive officers compensation`);
        searchQueries.push(`SEC filing ${cikMatch[1]} 20-F annual report executives`);
      }
      searchQueries.push(`${urlObj.hostname} ${urlObj.pathname.split('/').filter(Boolean).slice(0, 3).join(' ')} executive data`);
    } catch {
      // skip
    }
  }

  // Search based on written data entities
  if (writtenData.trim()) {
    try {
      const extractCompletion = await zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: `Eres un analista OSINT. Extrae las 3 búsquedas web más efectivas para investigar la amenaza descrita. Responde SOLO con JSON array de strings: ["búsqueda 1", "búsqueda 2", "búsqueda 3"]`,
          },
          { role: 'user', content: writtenData.substring(0, 3000) },
        ],
        temperature: 0.1,
        max_tokens: 300,
      });

      const extractText = extractCompletion.choices?.[0]?.message?.content || '';
      const extractMatch = extractText.match(/\[[\s\S]*\]/);
      if (extractMatch) {
        const extracted = JSON.parse(extractMatch[0]);
        if (Array.isArray(extracted)) {
          searchQueries.push(...extracted.filter((q: string) => typeof q === 'string').slice(0, 3));
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`[INTEL-REPORT] Entity extraction search error: ${msg.substring(0, 80)}`);
    }
  }

  // Default queries if none generated
  if (searchQueries.length === 0) {
    searchQueries.push(
      'exposición datos personales ejecutivos VIP riesgo seguridad 2025 2026',
      'protección ejecutiva datos expuestos web ingeniería social amenaza',
    );
  }

  // Execute OSINT searches (max 5)
  const queriesToExecute = searchQueries.slice(0, 5);
  console.log(`[INTEL-REPORT] Phase 2: Executing ${queriesToExecute.length} OSINT searches`);

  for (const query of queriesToExecute) {
    try {
      const result = await (zai as any).functions.invoke('web_search', { query, num: 5 });
      if (result && Array.isArray(result)) {
        for (const item of result) {
          osintResults.push({
            sourceName: item.name || 'Desconocido',
            sourceUrl: item.url || '',
            snippet: item.snippet || '',
            hostname: item.host_name || '',
            date: item.date || '',
            searchQuery: query,
          });
        }
      }
      await new Promise(r => setTimeout(r, 3000));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`[INTEL-REPORT] OSINT search error: ${msg.substring(0, 80)}`);
      if (msg.includes('429')) break;
    }
  }

  // Deduplicate
  const seenUrls = new Set<string>();
  const uniqueOsint = osintResults.filter(item => {
    if (seenUrls.has(item.sourceUrl)) return false;
    seenUrls.add(item.sourceUrl);
    return true;
  });

  // =========================================================================
  // PHASE 3: ENTITY EXTRACTION FROM ALL COLLECTED DATA
  // Use AI to identify the VIP, organization, and key facts
  // =========================================================================
  const allAvailableText = [
    ...urlIntelligence.map(ui => {
      let section = `--- URL: ${ui.url} ---\n`;
      section += `Tipo de sitio: ${ui.siteType}\n`;
      section += `Metadata: ${ui.urlMetadata}\n`;
      if (ui.textContent) {
        section += `Contenido leído:\n${ui.textContent.substring(0, 8000)}\n`;
      }
      if (ui.searchSnippets.length > 0) {
        section += `Contexto de búsqueda:\n${ui.searchSnippets.join('\n')}\n`;
      }
      return section;
    }),
    writtenData ? `--- Datos proporcionados por el analista ---\n${writtenData.substring(0, 12000)}` : '',
  ].filter(Boolean).join('\n\n');

  let extractedEntities: {
    vipName: string;
    vipTitle: string;
    organization: string;
    keyFacts: string[];
    dataTypesExposed: string[];
    urlsAnalyzed: number;
    urlsReadSuccessfully: number;
  } = {
    vipName: '',
    vipTitle: '',
    organization: '',
    keyFacts: [],
    dataTypesExposed: [],
    urlsAnalyzed: urlIntelligence.length,
    urlsReadSuccessfully: urlIntelligence.filter(ui => ui.source === 'page_reader').length,
  };

  try {
    console.log('[INTEL-REPORT] Phase 3: Extracting key entities...');
    const entityCompletion = await zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `Eres un analista de inteligencia OSINT experto en protección ejecutiva VIP. Analiza la información proporcionada sobre la EXPOSICIÓN de datos de un alto ejecutivo en sitios web.

Extrae:
1. Nombre del VIP o ejecutivo expuesto
2. Cargo del VIP
3. Organización o empresa
4. Hechos clave (lista de strings)
5. Tipos de datos expuestos (ej: nombre completo, cargo, compensación financiera, participaciones accionarias, dirección, teléfono, correo, información familiar, ubicación, agenda, etc.)

IMPORTANTE: Si la información proviene de filings SEC (reportes regulatorios), identifica QUÉ datos del ejecutivo están expuestos en esos filings (compensación, acciones, opciones, etc.).

Responde SOLO con JSON:
{
  "vipName": "nombre completo o vacío",
  "vipTitle": "cargo o vacío",
  "organization": "organización o vacío",
  "keyFacts": ["hecho 1", "hecho 2"],
  "dataTypesExposed": ["tipo1", "tipo2"]
}`,
        },
        { role: 'user', content: allAvailableText.substring(0, 25000) },
      ],
      temperature: 0.05,
      max_tokens: 2000,
    });

    const entityText = entityCompletion.choices?.[0]?.message?.content || '';
    const entityMatch = entityText.match(/\{[\s\S]*\}/);
    if (entityMatch) {
      const parsed = JSON.parse(entityMatch[0]);
      extractedEntities = { ...extractedEntities, ...parsed };
    }
    console.log(`[INTEL-REPORT] Extracted VIP: ${extractedEntities.vipName}, Org: ${extractedEntities.organization}`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[INTEL-REPORT] Entity extraction error: ${msg.substring(0, 100)}`);
  }

  // =========================================================================
  // PHASE 4: DEEP AI ANALYSIS
  // Produce a comprehensive, analytical intelligence report
  // =========================================================================

  // Build URL intelligence section for the AI
  const urlIntelligenceSection = urlIntelligence.map((ui, idx) => {
    let section = `=== URL ${idx + 1}: ${ui.url} ===
Tipo de sitio: ${ui.siteType}
Fuente de datos: ${ui.source}
Metadata contextual: ${ui.urlMetadata}`;

    if (ui.textContent && ui.source === 'page_reader') {
      section += `\n\nCONTENIDO LEÍDO DIRECTAMENTE DE LA PÁGINA:\n${ui.textContent.substring(0, 12000)}`;
    }

    if (ui.searchSnippets.length > 0) {
      section += `\n\nCONTEXTO OBTENIDO VÍA BÚSQUEDA WEB (el contenido directo no pudo ser leído, pero se obtuvo contexto relevante):\n${ui.searchSnippets.join('\n')}`;
    }

    return section;
  }).join('\n\n');

  const osintContextSection = uniqueOsint.length > 0
    ? uniqueOsint.slice(0, 15).map((item, idx) =>
        `[OSINT-${idx + 1}] Fuente: ${item.sourceName}\nURL: ${item.sourceUrl}\nFecha: ${item.date || 'N/A'}\nBúsqueda: ${item.searchQuery.substring(0, 60)}\nResumen: ${item.snippet}`
      ).join('\n\n')
    : '';

  const writtenDataSection = writtenData.trim()
    ? `=== DATOS Y CONTENIDO PROPORCIONADO POR EL ANALISTA ===\n${writtenData.substring(0, 18000)}`
    : '';

  const fileListSection = fileNames && fileNames.length > 0
    ? `Archivos cargados por el analista (contenido incluido arriba): ${fileNames.join(', ')}`
    : '';

  const systemPrompt = `Eres un ANALISTA DE INTELIGENCIA SUPERIOR con 25+ años de experiencia en protección ejecutiva VIP, contrainteligencia, ciberseguridad avanzada, OSINT y análisis de amenazas. Has trabajado con agencias gubernamentales, corporaciones Fortune 500 y organizaciones internacionales.

CONTEXTO CRÍTICO DE TU MISIÓN:
Se te ha entregado información sobre la EXPOSICIÓN de datos sensibles de un alto ejecutivo (VIP) en sitios web públicos. Esto NO es un ejercicio académico — es un caso REAL de seguridad ejecutiva. Tu análisis debe ser PROFUNDO, ESPECÍFICO y ACCIONABLE.

ENTIDADES IDENTIFICADAS PREVIAMENTE:
- VIP: ${extractedEntities.vipName || 'No identificado - DEBES identificarlo del contenido'}
- Cargo: ${extractedEntities.vipTitle || 'No identificado - DEBES identificarlo del contenido'}
- Organización: ${extractedEntities.organization || 'No identificada - DEBES identificarla del contenido'}
- Tipos de datos expuestos: ${extractedEntities.dataTypesExposed?.join(', ') || 'Por determinar'}
- URLs analizadas: ${extractedEntities.urlsAnalyzed}
- URLs con contenido directo leído: ${extractedEntities.urlsReadSuccessfully}

IMPORTANTE - SOBRE LAS FUENTES DE DATOS:
- Si el contenido de una URL fue leído directamente (page_reader), tienes el contenido REAL de la página
- Si no se pudo leer directamente, se obtuvo contexto vía web_search (snippets de búsqueda)
- SIEMPRE tienes metadata contextual de cada URL (tipo de sitio, dominio, path)
- Usa TODA la información disponible para tu análisis, no solo la que viene de page_reader
- Para filings SEC/EDGAR: estos son documentos regulatorios PÚBLICOS que contienen compensación ejecutiva, participaciones accionarias y datos de gobernanza. Analiza QUÉ información del VIP está expuesta ahí.

TU PROCESO DE ANÁLISIS:

PASO 1 - IDENTIFICACIÓN DEL ACTIVO:
- Identifica al VIP por nombre completo, cargo y organización
- Determina su nivel de exposición pública previa vs. la nueva exposición
- Evalúa su perfil de riesgo (¿es blanco de amenazas por su cargo/riqueza/visibilidad?)

PASO 2 - ANÁLISIS DE CADA FUENTE:
- Para CADA URL, analiza QUÉ información específica del VIP está expuesta
- Determina si la exposición es legítima (ej: reportes regulatorios SEC) o no autorizada
- Identifica qué datos son PÚBLICOS vs. PRIVADOS vs. SENSIBLES vs. CRÍTICOS
- Evalúa si los datos expuestos pueden ser explotados por actores maliciosos

PASO 3 - ANÁLISIS DE DATOS SENSIBLES:
- Cataloga TODOS los tipos de datos expuestos
- Para cada tipo de dato, evalúa el riesgo de explotación
- Cruza con los datos proporcionados manualmente por el analista

PASO 4 - EVALUACIÓN DE AMENAZAS:
- Identifica amenazas CONCRETAS y ESPECÍFICAS
- Cada amenaza debe estar basada en EVIDENCIA
- Considera: ingeniería social, suplantación de identidad, extorsión, ataque físico, fraude BEC, robo de identidad, acoso, secuestro

PASO 5 - EVALUACIÓN DE IMPACTO:
- Impacto en el VIP, la organización, la familia, reputación, finanzas, seguridad física

PASO 6 - LÍNEAS DE ACCIÓN por fases:
- Inmediatas (0-24h), Corto plazo (1-7d), Mediano plazo (1-4sem), Largo plazo (1-6m)

RESPUESTA - JSON con esta estructura EXACTA:
{
  "executiveProfile": {
    "name": "nombre completo",
    "title": "cargo",
    "organization": "organización",
    "publicProfile": "descripción del perfil público del VIP (mínimo 100 palabras)",
    "riskProfile": "evaluación del perfil de riesgo del VIP (mínimo 100 palabras)"
  },
  "dataExposureAnalysis": [
    {
      "dataType": "tipo de dato expuesto",
      "location": "dónde está expuesto (URL específica)",
      "sensitivityLevel": "publico|privado|sensible|critico",
      "exploitationRisk": "descripción detallada de cómo puede ser explotado",
      "currentExposure": "descripción del estado actual de exposición"
    }
  ],
  "urlAnalysis": [
    {
      "url": "URL analizada",
      "siteType": "tipo de sitio",
      "informationFound": "descripción DETALLADA de qué información del VIP se encontró (mínimo 100 palabras)",
      "isLegitimatePublication": true/false,
      "legitimacyDetail": "explicación de por qué es o no legítima la publicación",
      "riskAssessment": "evaluación del riesgo específico (mínimo 80 palabras)"
    }
  ],
  "threats": [
    {
      "title": "título descriptivo de la amenaza",
      "description": "descripción DETALLADA (mínimo 200 palabras): CÓMO se materializaría, QUIÉN podría ejecutarla, QUÉ datos la facilitan, CUÁL sería el impacto",
      "severity": "bajo|medio|alto|critico",
      "category": "ingenieria_social|suplantacion_identidad|fraude_financiero|amenaza_fisica|acoso|extorsion|robo_datos|ataque_cibernetico|exposicion_datos|cadena_suministro",
      "likelihood": "baja|media|alta|muy_alta",
      "impactDetail": "descripción detallada del impacto (mínimo 80 palabras)",
      "evidence": "evidencia específica del contenido que sustenta esta amenaza",
      "affectedParties": ["quién se vería afectado"]
    }
  ],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen EJECUTIVO COMPREHENSIVO (mínimo 600 palabras): QUÉ datos expuestos, de QUIÉN, DÓNDE, NIVEL DE RIESGO, amenazas críticas, acciones prioritarias",
  "immediateActions": ["acción INMEDIATA 1", ...],
  "shortTermActions": ["acción CORTO PLAZO 1", ...],
  "mediumTermActions": ["acción MEDIANO PLAZO 1", ...],
  "longTermActions": ["acción LARGO PLAZO 1", ...],
  "monitoringRecommendations": ["recomendación 1", ...],
  "sources": [
    {
      "title": "nombre fuente",
      "url": "URL",
      "relevance": "qué información ESPECÍFICA aportó",
      "reliability": "alta|media|baja"
    }
  ]
}

REGLAS ESTRICTAS:
1. NUNCA generes información genérica. Todo debe estar basado en los DATOS PROPORCIONADOS.
2. Si no puedes identificar algo, di "No identificado en los datos proporcionados" — NO inventes.
3. Cada amenaza debe tener EVIDENCIA concreta del contenido.
4. Las recomendaciones deben ser ESPECÍFICAS al caso.
5. El resumen ejecutivo debe ser COMPREHENSIVO (mínimo 600 palabras).
6. Para filings SEC: DOCUMENTA qué datos específicos del VIP están expuestos (compensación, acciones, etc.).
7. Mínimo 3 amenazas identificadas.
8. Cada amenaza con descripción de MÍNIMO 200 palabras.
9. Cada URL debe tener un análisis de mínimo 100 palabras sobre qué información se encontró.`;

  const userPrompt = `=== INFORMACIÓN SUMINISTRADA POR EL ANALISTA PARA ANÁLISIS DE INTELIGENCIA ===

--- INTELIGENCIA RECOLECTADA DE LAS URLs PROPORCIONADAS ---
A continuación se presenta la información recolectada de cada URL. Para cada una se indica la fuente de datos (lectura directa de la página, búsqueda web, o solo metadata).

${urlIntelligenceSection || 'No se proporcionaron URLs.'}

${writtenDataSection}

${fileListSection}

${osintContextSection ? `--- CONTEXTO OSINT ADICIONAL ---
${osintContextSection.substring(0, 8000)}` : ''}

=== ENTIDADES PREVIAMENTE IDENTIFICADAS ===
VIP: ${extractedEntities.vipName || 'Por identificar del contenido'}
Cargo: ${extractedEntities.vipTitle || 'Por identificar'}
Organización: ${extractedEntities.organization || 'Por identificar'}
Hechos clave: ${extractedEntities.keyFacts?.join('; ') || 'Por determinar'}
Tipos de datos expuestos: ${extractedEntities.dataTypesExposed?.join(', ') || 'Por determinar'}

=== INSTRUCCIÓN FINAL ===
Analiza EN PROFUNDIDAD toda la información proporcionada arriba. Produce un informe de inteligencia COMPLETO y PROFESIONAL. Cada sección debe tener sustancia analítica real, no texto de relleno. Recuerda: esto es un caso REAL de exposición de datos de un alto ejecutivo. Incluso si no tienes el contenido directo de una página, tienes contexto de búsqueda y metadata — ÚSALOS para tu análisis.`;

  try {
    console.log('[INTEL-REPORT] Phase 4: Deep AI analysis...');
    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.08,
      max_tokens: 16000,
    });

    const responseText = completion.choices?.[0]?.message?.content || '';
    console.log(`[INTEL-REPORT] AI response: ${responseText.length} chars`);
    const m = responseText.match(/\{[\s\S]*\}/);
    if (m) {
      const analysisResult = JSON.parse(m[0]);
      return { success: true, analysis: analysisResult };
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[INTEL-REPORT] Deep analysis error: ${msg.substring(0, 120)}`);
  }

  // Fallback
  return {
    success: true,
    analysis: {
      executiveProfile: {
        name: extractedEntities.vipName || 'No identificado',
        title: extractedEntities.vipTitle || 'No identificado',
        organization: extractedEntities.organization || 'No identificada',
        publicProfile: 'No se pudo determinar del análisis automatizado.',
        riskProfile: 'No se pudo determinar del análisis automatizado.',
      },
      dataExposureAnalysis: extractedEntities.dataTypesExposed?.map((dt: string) => ({
        dataType: dt,
        location: 'Ver URLs proporcionadas',
        sensitivityLevel: 'sensible',
        exploitationRisk: 'Los datos expuestos pueden ser utilizados para ingeniería social, suplantación de identidad u otros ataques dirigidos al VIP.',
        currentExposure: 'Expuesto en sitios web públicos según las fuentes proporcionadas.',
      })) || [],
      urlAnalysis: urlIntelligence.map(ui => ({
        url: ui.url,
        siteType: ui.siteType,
        informationFound: ui.textContent
          ? ui.textContent.substring(0, 500)
          : ui.searchSnippets.length > 0
            ? ui.searchSnippets.join(' ')
            : `Sitio tipo ${ui.siteType}. ${ui.urlMetadata}`,
        isLegitimatePublication: ui.siteType.includes('regulatorio'),
        legitimacyDetail: ui.siteType.includes('regulatorio')
          ? 'Publicación regulatoria requerida por ley (SEC/EDGAR). La publicación es legítima, pero la información del VIP expuesta puede ser explotada.'
          : 'No se pudo determinar la legitimidad de la publicación.',
        riskAssessment: 'Se requiere evaluación detallada del contenido expuesto.',
      })),
      threats: [{
        title: `Exposición de información del ejecutivo ${extractedEntities.vipName || ''} en ${urls.length} sitio(s) web`,
        description: `Se ha identificado que información del ejecutivo ${extractedEntities.vipName || 'no identificado'}${extractedEntities.vipTitle ? ` (${extractedEntities.vipTitle})` : ''} de ${extractedEntities.organization || 'organización no identificada'} aparece expuesta en ${urls.length} sitio(s) web. Los tipos de datos expuestos incluyen: ${extractedEntities.dataTypesExposed?.join(', ') || 'por determinar'}. ${urlIntelligence.map(ui => `En ${ui.siteType}: ${ui.urlMetadata}`).join('. ')}. Esta exposición representa un riesgo significativo de ingeniería social, suplantación de identidad y posibles ataques dirigidos al VIP. Los datos regulatorios públicos como filings SEC contienen compensación ejecutiva, participaciones accionarias y datos de gobernanza que pueden ser utilizados para perfilar al VIP. Se requiere evaluación inmediata del contenido expuesto y acciones de remediación. ${extractedEntities.keyFacts?.join('. ') || ''}`,
        severity: 'alto',
        category: 'exposicion_datos',
        likelihood: 'alta',
        impactDetail: 'El impacto potencial incluye riesgo de ingeniería social dirigida, suplantación de identidad, fraude BEC (Business Email Compromise), y amenazas físicas dependiendo del tipo de datos expuestos y la visibilidad del ejecutivo.',
        evidence: `Datos proporcionados por el analista. Fuentes: ${urlIntelligence.map(ui => ui.siteType).join(', ')}. ${extractedEntities.keyFacts?.join('; ') || ''}`,
        affectedParties: ['VIP', 'Organización', 'Familia del VIP'],
      }],
      overallRiskLevel: 'alto',
      summary: `Se detectó exposición de información sensible del ejecutivo ${extractedEntities.vipName || 'no identificado'} ${extractedEntities.vipTitle ? `(${extractedEntities.vipTitle})` : ''} ${extractedEntities.organization ? `de ${extractedEntities.organization}` : ''} en ${urls.length} sitio(s) web. Los tipos de datos expuestos incluyen: ${extractedEntities.dataTypesExposed?.join(', ') || 'tipos por determinar'}. Las fuentes incluyen: ${urlIntelligence.map(ui => ui.siteType).join(', ')}. ${urlIntelligence.map(ui => ui.urlMetadata).join('. ')}. Hechos clave: ${extractedEntities.keyFacts?.join('. ') || 'ver contenido proporcionado'}. Esta exposición representa un riesgo ALTO que requiere acción inmediata para evaluar el alcance completo, contener la diseminación de datos sensibles, y fortalecer los controles de seguridad del ejecutivo.`,
      immediateActions: [
        'Documentar toda la información expuesta en cada URL proporcionada',
        'Evaluar el riesgo de ingeniería social derivado de la información expuesta',
        'Notificar al VIP y al equipo de seguridad sobre la exposición',
        'Clasificar cada fuente como publicación legítima o no autorizada',
      ],
      shortTermActions: [
        'Implementar monitoreo continuo de los sitios identificados',
        'Evaluar necesidad de solicitar eliminación de datos sensibles no públicos',
        'Realizar barrido OSINT adicional para identificar otras fuentes de exposición',
      ],
      mediumTermActions: [
        'Implementar programa de reducción de huella digital del VIP',
        'Establecer protocolo de respuesta rápida para futuras exposiciones',
      ],
      longTermActions: [
        'Establecer monitoreo OSINT permanente',
        'Revisar políticas de privacidad corporativas',
      ],
      monitoringRecommendations: [
        'Monitoreo diario de las URLs identificadas',
        'Alertas automatizadas para nuevas menciones del VIP',
      ],
      sources: [
        ...urls.map(url => {
          const ui = urlIntelligence.find(u => u.url === url);
          return {
            title: ui?.siteType || url,
            url,
            relevance: ui?.urlMetadata || 'Sitio web donde aparece información del VIP',
            reliability: 'media' as const,
          };
        }),
        ...(fileNames || []).map(name => ({ title: name, url: '', relevance: 'Archivo del analista', reliability: 'alta' as const })),
      ],
    },
  };
}

// ============================================================================
// MODE B: MANUAL - Structured Classification Report
// ============================================================================
function handleManualGeneration(data: {
  urls: string[];
  writtenData: string;
  abuseTypes: string[];
  severity: string;
  tlpLevel: string;
  title?: string;
}) {
  const { urls, writtenData, abuseTypes, severity, tlpLevel } = data;

  const tlpDescriptions: Record<string, string> = {
    RED: 'TLP:RED - Solo para destinatarios específicos. No redistribuir bajo ninguna circunstancia.',
    AMBER: 'TLP:AMBER - Uso limitado dentro de la organización. Solo necesidad de conocer.',
    GREEN: 'TLP:GREEN - Uso limitado dentro de la comunidad de interés.',
    CLEAR: 'TLP:CLEAR - Información pública. Sin restricciones.',
  };

  const severityDescriptions: Record<string, string> = {
    bajo: 'BAJO - Impacto limitado, gestionable con controles existentes.',
    medio: 'MEDIO - Requiere atención y ajustes en controles.',
    alto: 'ALTO - Riesgo significativo, requiere acción prioritaria.',
    critico: 'CRÍTICO - Riesgo extremo, acción inmediata requerida.',
  };

  const abuseTypeLabels: Record<string, string> = {
    phishing: 'Phishing', identity_theft: 'Suplantación de Identidad',
    financial_fraud: 'Fraude Financiero', social_media_scam: 'Estafas en Redes Sociales',
    brand_abuse: 'Abuso de Marca', malware: 'Malware', ransomware: 'Ransomware',
    social_engineering: 'Ingeniería Social', data_breach: 'Fuga de Datos',
    insider_threat: 'Amenaza Interna', ddos: 'Ataque DDoS', supply_chain: 'Cadena de Suministro',
  };

  const urlList = urls.map((u, i) => `${i + 1}. ${u}`).join('\n');
  const abuseLabels = abuseTypes.map(t => abuseTypeLabels[t] || t).join(', ');
  const fechaStr = new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' });
  const refNumber = `VIP-RPT-${Date.now().toString(36).toUpperCase()}`;

  const manualReport = `# INFORME DE INTELIGENCIA - CLASIFICACIÓN MANUAL
## VIP_Protection Report | Executive Intelligence

---

**Fecha:** ${fechaStr}
**Número de Referencia:** ${refNumber}
**Clasificación TLP:** ${tlpLevel}
**Severidad:** ${severity.toUpperCase()}
**Modo de Generación:** Manual (Clasificación Estructurada)

---

## PROTOCOLO TLP

${tlpDescriptions[tlpLevel] || tlpDescriptions.GREEN}

---

## RESUMEN EJECUTIVO

Informe de inteligencia clasificado manualmente por el analista, con nivel de severidad **${severity.toUpperCase()}** y protocolo TLP **${tlpLevel}**. Tipos de amenaza identificados: ${abuseLabels}.

${writtenData ? `### Datos Proporcionados por el Analista\n\n${writtenData.substring(0, 5000)}` : ''}

---

## CLASIFICACIÓN DE AMENAZAS

${abuseTypes.map(type => {
  const label = abuseTypeLabels[type] || type;
  return `#### ${label}\n\nClasificado manualmente bajo la categoría de ${label}.`;
}).join('\n\n---\n\n')}

---

## EVALUACIÓN DE SEVERIDAD

${severityDescriptions[severity] || severityDescriptions.medio}

---

## FUENTES DE INFORMACIÓN

${urls.length > 0 ? `### URLs\n\n${urlList}` : 'No se proporcionaron URLs.'}

${writtenData ? `### Datos del Analista\n\n${writtenData.substring(0, 5000)}` : ''}

---

## RECOMENDACIONES

${severity === 'critico' ? `1. **ACTIVAR PROTOCOLO DE EMERGENCIA**\n2. **CONTENCIÓN INMEDIATA**\n3. **NOTIFICACIÓN TLP ${tlpLevel}**\n4. **INVESTIGACIÓN FORENSE**\n5. **MONITOREO 24/7**` : severity === 'alto' ? `1. **ACCIÓN PRIORITARIA** (24-48h)\n2. **EVALUACIÓN DE IMPACTO**\n3. **REFUERZO DE CONTROLES**\n4. **NOTIFICACIÓN TLP ${tlpLevel}**\n5. **SEGUIMIENTO 48h**` : severity === 'medio' ? `1. **MONITOREO CONTINUO**\n2. **ACTUALIZACIÓN DE CONTROLES**\n3. **DOCUMENTACIÓN**\n4. **REVISIÓN 1-2 SEMANAS**` : `1. **MONITOREO ESTÁNDAR**\n2. **REVISIÓN PERIÓDICA**\n3. **DOCUMENTACIÓN**`}

---

*Informe generado por VIP_Protection Report - Executive Intelligence System*
*Modo: Manual | TLP: ${tlpLevel} | Severidad: ${severity.toUpperCase()}*
*Fecha: ${fechaStr}*`;

  return {
    success: true,
    content: manualReport,
    analysis: {
      threats: abuseTypes.map(type => ({
        title: abuseTypeLabels[type] || type,
        description: `Clasificado manualmente bajo ${abuseTypeLabels[type] || type}.`,
        severity,
        category: 'seguridad',
      })),
      overallRiskLevel: severity,
      summary: `Informe manual: Severidad ${severity.toUpperCase()}, TLP ${tlpLevel}. Amenazas: ${abuseLabels}.`,
      recommendations: [],
      sources: urls.map(url => ({ title: url, url, relevance: 'Fuente del analista' })),
    },
  };
}

// ============================================================================
// MAIN HANDLER
// ============================================================================
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { mode, urls, writtenData, abuseTypes, severity, tlpLevel, templateId, title, fileNames } = body;

    if (!mode || !['automatic', 'manual'].includes(mode)) {
      return NextResponse.json({ error: 'Modo requerido: "automatic" o "manual"' }, { status: 400 });
    }

    const inputUrls = urls || [];
    const inputText = writtenData || '';

    if (mode === 'automatic') {
      const result = await handleAutomaticGeneration({
        urls: inputUrls,
        writtenData: inputText,
        fileNames: fileNames || [],
        templateId,
        title,
      });

      if (!result.success || !result.analysis) {
        return NextResponse.json({ error: 'Error en generación automática' }, { status: 500 });
      }

      const analysis = result.analysis;
      const fechaStr = new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' });
      const threats = analysis.threats || [];
      const immediateActions = analysis.immediateActions || [];
      const shortTermActions = analysis.shortTermActions || [];
      const mediumTermActions = analysis.mediumTermActions || [];
      const longTermActions = analysis.longTermActions || [];
      const monitoringRecs = analysis.monitoringRecommendations || [];
      const sources = analysis.sources || [];
      const riskLevel = analysis.overallRiskLevel || 'medio';
      const execProfile = analysis.executiveProfile || {};
      const dataExposure = analysis.dataExposureAnalysis || [];
      const urlAnalysis = analysis.urlAnalysis || [];

      const threatMatrix = threats.map((t: any, i: number) => {
        const sev = t.severity || 'medio';
        const prob = t.likelihood || (sev === 'critico' ? 'Muy Alta' : sev === 'alto' ? 'Alta' : sev === 'medio' ? 'Media' : 'Baja');
        const impact = sev === 'critico' ? 'Catastrófico' : sev === 'alto' ? 'Grave' : sev === 'medio' ? 'Moderado' : 'Menor';
        return `| ${i + 1} | ${t.title} | ${t.category || 'seguridad'} | ${sev.toUpperCase()} | ${prob} | ${impact} | ${t.affectedParties?.join(', ') || 'VIP, Organización'} |`;
      });

      const exposureTable = dataExposure.map((d: any, i: number) => {
        const sens = d.sensitivityLevel === 'critico' ? 'CRÍTICO' : d.sensitivityLevel === 'sensible' ? 'SENSIBLE' : d.sensitivityLevel === 'privado' ? 'PRIVADO' : 'PÚBLICO';
        return `| ${i + 1} | ${d.dataType} | ${sens} | ${d.location?.substring(0, 60) || 'N/A'} |`;
      });

      const urlAnalysisSection = urlAnalysis.map((u: any, i: number) => {
        const legitLabel = u.isLegitimatePublication
          ? `SÍ - Publicación legítima${u.legitimacyDetail ? `. ${u.legitimacyDetail}` : ''}`
          : `NO / VERIFICAR${u.legitimacyDetail ? `. ${u.legitimacyDetail}` : ''}`;
        return `### ${i + 1}. ${u.siteType || 'Sitio Web'}: ${u.url?.substring(0, 80) || 'URL'}

**Tipo de sitio:** ${u.siteType || 'No clasificado'}
**Publicación legítima:** ${legitLabel}

**Información encontrada del VIP:**

${u.informationFound || 'No se pudo determinar el contenido específico.'}

**Evaluación de riesgo:**

${u.riskAssessment || 'Se requiere evaluación manual.'}`;
      }).join('\n\n---\n\n');

      const reportContent = `# INFORME DE INTELIGENCIA - ANÁLISIS AUTOMÁTICO AVANZADO
## VIP_Protection Report | Executive Intelligence

---

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificación:** CONFIDENCIAL
**Modo de Generación:** Automático (Agente IA - Análisis Multi-Fase)
**Número de Referencia:** VIP-RPT-${Date.now().toString(36).toUpperCase()}
${inputUrls.length > 0 ? `**URLs Investigadas:** ${inputUrls.length}` : ''}
${fileNames && fileNames.length > 0 ? `**Archivos Analizados:** ${fileNames.length}` : ''}
${execProfile.name ? `**VIP Identificado:** ${execProfile.name}` : ''}
${execProfile.organization ? `**Organización:** ${execProfile.organization}` : ''}

---

## PROTOCOLO DE COMPARTICIÓN (TLP)

TLP:AMBER - Uso limitado dentro de la organización. Solo necesidad de conocer (need-to-know).

---

## 1. PERFIL DEL EJECUTIVO

${execProfile.name ? `**Nombre:** ${execProfile.name}` : '*No identificado*'}
${execProfile.title ? `**Cargo:** ${execProfile.title}` : ''}
${execProfile.organization ? `**Organización:** ${execProfile.organization}` : ''}

### Perfil Público

${execProfile.publicProfile || 'No determinado.'}

### Perfil de Riesgo

${execProfile.riskProfile || 'No determinado.'}

---

## 2. RESUMEN EJECUTIVO

${analysis.summary || 'No se pudo generar el resumen.'}

---

## 3. ANÁLISIS DE EXPOSICIÓN DE DATOS

| # | Tipo de Dato | Sensibilidad | Ubicación |
|---|-------------|-------------|-----------|
${exposureTable.length > 0 ? exposureTable.join('\n') : '| - | Sin datos específicos | - | - |'}

${dataExposure.map((d: any, i: number) => `#### ${i + 1}. ${d.dataType}

**Sensibilidad:** ${(d.sensitivityLevel || 'sensible').toUpperCase()}
**Ubicación:** ${d.location || 'Ver fuentes'}

**Riesgo de explotación:** ${d.exploitationRisk || 'No determinado.'}

**Estado actual:** ${d.currentExposure || 'No determinado.'}`).join('\n\n---\n\n')}

---

## 4. ANÁLISIS DE URLs INVESTIGADAS

${urlAnalysisSection || 'No se proporcionaron URLs.'}

---

## 5. MATRIZ DE AMENAZAS

| # | Amenaza | Categoría | Severidad | Probabilidad | Impacto | Afectados |
|---|---------|-----------|-----------|--------------|---------|-----------|
${threatMatrix.length > 0 ? threatMatrix.join('\n') : '| - | Sin amenazas específicas | - | - | - | - | - |'}

---

## 6. AMENAZAS IDENTIFICADAS

${threats.map((t: any, i: number) => `### ${i + 1}. ${t.title} [${(t.severity || 'medio').toUpperCase()}]

${t.description}

- **Categoría:** ${t.category || 'seguridad'}
- **Severidad:** ${(t.severity || 'medio').toUpperCase()}
- **Probabilidad:** ${t.likelihood || 'Media'}
- **Partes afectadas:** ${t.affectedParties?.join(', ') || 'VIP, Organización'}

**Impacto detallado:** ${t.impactDetail || 'No determinado.'}

**Evidencia:** ${t.evidence || 'Basado en la información proporcionada.'}`).join('\n\n---\n\n')}

---

## 7. LÍNEAS DE ACCIÓN

### 7.1 Acciones Inmediatas (0-24 horas)

${immediateActions.length > 0 ? immediateActions.map((a: string, i: number) => `${i + 1}. **[URGENTE]** ${a}`).join('\n') : '1. Evaluar alcance de exposición\n2. Notificar al VIP\n3. Documentar fuentes'}

### 7.2 Acciones a Corto Plazo (1-7 días)

${shortTermActions.length > 0 ? shortTermActions.map((a: string, i: number) => `${i + 1}. ${a}`).join('\n') : '1. Solicitar eliminación de datos\n2. Implementar monitoreo\n3. Evaluar controles'}

### 7.3 Acciones a Mediano Plazo (1-4 semanas)

${mediumTermActions.length > 0 ? mediumTermActions.map((a: string, i: number) => `${i + 1}. ${a}`).join('\n') : '1. Programa reducción huella digital\n2. Protocolo de respuesta'}

### 7.4 Acciones a Largo Plazo (1-6 meses)

${longTermActions.length > 0 ? longTermActions.map((a: string, i: number) => `${i + 1}. ${a}`).join('\n') : '1. Monitoreo OSINT permanente\n2. Revisar políticas privacidad'}

---

## 8. RECOMENDACIONES DE MONITOREO

${monitoringRecs.length > 0 ? monitoringRecs.map((r: string, i: number) => `${i + 1}. ${r}`).join('\n') : '1. Monitoreo diario de URLs\n2. Alertas para nuevas menciones'}

---

## 9. FUENTES CONSULTADAS

${sources.map((s: any) => `- **${s.title}**: ${s.relevance || 'Fuente de inteligencia'} ${s.url ? `([${s.url.substring(0, 60)}](${s.url}))` : ''} ${s.reliability ? `— Confiabilidad: ${s.reliability}` : ''}`).join('\n')}

---

*Informe generado por VIP_Protection Report - Executive Intelligence System*
*Agente IA: Análisis Multi-Fase (Lectura URLs + Búsqueda Web + Extracción Entidades + OSINT + Análisis Profundo)*
*Fecha: ${fechaStr} | TLP:AMBER | CONFIDENCIAL*`;

      const report = await db.report.create({
        data: {
          title: title || `Informe de Inteligencia - ${execProfile.name || 'VIP'} - ${fechaStr}`,
          summary: analysis.summary || '',
          threatLevel: riskLevel,
          content: reportContent,
          templateId: templateId || null,
          sourcesUsed: JSON.stringify(sources.map((s: any) => s.url || s.title)),
          generationMode: 'automatic',
          abuseTypes: '[]',
          severity: riskLevel,
          tlpLevel: 'AMBER',
          inputUrls: JSON.stringify(inputUrls),
          inputText: inputText.substring(0, 5000),
        },
      });

      return NextResponse.json({ report, analysis });

    } else {
      // MANUAL MODE
      if (!abuseTypes || !Array.isArray(abuseTypes) || abuseTypes.length === 0) {
        return NextResponse.json({ error: 'Seleccione al menos un tipo de amenaza' }, { status: 400 });
      }
      if (!severity) return NextResponse.json({ error: 'Seleccione severidad' }, { status: 400 });
      if (!tlpLevel) return NextResponse.json({ error: 'Seleccione protocolo TLP' }, { status: 400 });

      const result = handleManualGeneration({ urls: inputUrls, writtenData: inputText, abuseTypes, severity, tlpLevel, templateId, title });
      if (!result.success || !result.content) return NextResponse.json({ error: 'Error en generación manual' }, { status: 500 });

      const fechaStr = new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' });
      const report = await db.report.create({
        data: {
          title: title || `Informe Manual - ${fechaStr}`,
          summary: result.analysis.summary || '',
          threatLevel: severity,
          content: result.content,
          templateId: templateId || null,
          sourcesUsed: JSON.stringify(inputUrls),
          generationMode: 'manual',
          abuseTypes: JSON.stringify(abuseTypes),
          severity,
          tlpLevel,
          inputUrls: JSON.stringify(inputUrls),
          inputText: inputText.substring(0, 5000),
        },
      });

      return NextResponse.json({ report, analysis: result.analysis });
    }
  } catch (error) {
    console.error('Error generating intel report:', error);
    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 });
  }
}
