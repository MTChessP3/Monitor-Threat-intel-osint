import { NextRequest, NextResponse } from 'next/server';
import { db, ensureDatabaseInitialized } from '@/lib/db';
import * as cheerio from 'cheerio';
import { getZAI, zaiChatCompletion, zaiWebSearch } from '@/lib/zai';

export const maxDuration = 180; // 3 minutes

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

// Helper: detect if server fetch returned garbage
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

// Helper: analyze URL metadata
function analyzeUrlMetadata(url: string): {
  domain: string;
  path: string;
  siteType: string;
  context: string;
} {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const urlPath = urlObj.pathname;

    let siteType = 'Sitio web general';
    let context = '';

    if (domain.includes('sec.gov') && urlPath.includes('edgar')) {
      siteType = 'Registro regulatorio SEC/EDGAR';
      const cikMatch = urlPath.match(/data\/(\d+)/);
      const filingMatch = urlPath.match(/(\d{10})/);
      context = `Filing regulatorio ante la SEC (U.S. Securities and Exchange Commission). CIK: ${cikMatch?.[1] || 'desconocido'}. Filing: ${filingMatch?.[1] || 'desconocido'}. Los filings SEC contienen información financiera detallada de compañías públicas incluyendo compensación de ejecutivos, participaciones accionarias, y datos de gobernanza corporativa. Esta información es PÚBLICA y requerida por ley, pero puede ser explotada por actores maliciosos para perfilar ejecutivos.`;
    } else if (domain.includes('linkedin.com')) {
      siteType = 'Red social profesional (LinkedIn)';
      context = 'Perfil profesional en LinkedIn. Puede contener nombre, cargo, historial laboral, educación, conexiones y recomendaciones. La información es semi-pública pero puede ser explotada para ingeniería social.';
    } else if (domain.includes('twitter.com') || domain.includes('x.com')) {
      siteType = 'Red social (X/Twitter)';
      context = 'Perfil o publicación en X/Twitter. Puede contener opiniones, ubicación, fotos y conexiones del VIP.';
    } else if (domain.includes('news') || domain.includes('elpais') || domain.includes('eltiempo') || domain.includes('reuters') || domain.includes('bloomberg')) {
      siteType = 'Medio de comunicación';
      context = 'Artículo de noticias o reportaje que menciona al VIP. Puede contener información sobre su cargo, declaraciones, actividades y ubicaciones.';
    } else {
      context = `Sitio web en ${domain}. La URL y su path pueden revelar información sobre el tipo de contenido publicado.`;
    }

    return { domain, path: urlPath, siteType, context };
  } catch {
    return { domain: url, path: '', siteType: 'URL inválida', context: 'No se pudo analizar la estructura de la URL.' };
  }
}

// ============================================================================
// URL CONTENT FETCHER - Single URL processing
// ============================================================================
interface UrlIntelligence {
  url: string;
  source: 'server_fetch' | 'web_search' | 'metadata_only';
  title: string;
  textContent: string;
  siteType: string;
  urlMetadata: string;
  searchSnippets: string[];
  publishedTime: string;
  success: boolean;
}

async function fetchUrlContent(url: string, zai: any): Promise<UrlIntelligence> {
  const metadata = analyzeUrlMetadata(url);
  let pageContent = '';
  let pageTitle = '';
  let publishedTime = '';
  let source: 'server_fetch' | 'web_search' | 'metadata_only' = 'metadata_only';
  let searchSnippets: string[] = [];
  let success = false;

  // --- ATTEMPT 1: Server-side fetch + cheerio ---
  try {
    console.log(`[INTEL-REPORT] Fetching URL: ${url.substring(0, 80)}`);
    const fetchResponse = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });

    if (fetchResponse.ok) {
      const html = await fetchResponse.text();
      const $ = cheerio.load(html);

      const titleFromPage = $('title').first().text().trim() || $('h1').first().text().trim() || '';
      $('script, style, nav, footer, header, noscript, iframe, svg').remove();

      let mainContent = '';
      const contentSelectors = ['article', 'main', '.content', '.post-body', '.entry-content', '.article-body', '#content', '.main-content'];
      for (const selector of contentSelectors) {
        const el = $(selector);
        if (el.length > 0 && el.text().trim().length > 200) {
          mainContent = el.text().trim();
          break;
        }
      }

      if (!mainContent || mainContent.length < 200) {
        mainContent = $('body').text().trim();
      }

      const rawText = mainContent.replace(/\s+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();

      if (!isGarbageContent(rawText) && rawText.length > 100) {
        pageContent = rawText.substring(0, 15000);
        pageTitle = titleFromPage || url;
        source = 'server_fetch';
        success = true;
        console.log(`[INTEL-REPORT] Server fetch OK: ${rawText.length} chars from ${url.substring(0, 50)}`);
      }
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[INTEL-REPORT] Server fetch error: ${msg.substring(0, 80)}`);
  }

  // --- ATTEMPT 2: web_search fallback ---
  if (!success) {
    try {
      console.log(`[INTEL-REPORT] web_search fallback for: ${url.substring(0, 60)}`);
      const searchResult = await zaiWebSearch(url.substring(0, 200), { num: 5 });

      if (searchResult && searchResult.length > 0) {
        searchSnippets = searchResult.map((item: any) =>
          `[${item.name || 'Fuente'}] ${item.snippet || ''}`
        ).filter((s: string) => s.length > 20);

        if (searchSnippets.length > 0) {
          source = 'web_search';
          success = true;
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`[INTEL-REPORT] web_search fallback error: ${msg.substring(0, 80)}`);
    }
  }

  // --- ATTEMPT 3: Broader domain search ---
  if (!success) {
    try {
      const domainQuery = `${metadata.domain} filing executive information`;
      const broadResult = await zaiWebSearch(domainQuery, { num: 5 });

      if (broadResult && broadResult.length > 0) {
        searchSnippets = broadResult.map((item: any) =>
          `[${item.name || 'Fuente'}] ${item.snippet || ''}`
        ).filter((s: string) => s.length > 20);

        if (searchSnippets.length > 0) {
          source = 'web_search';
          success = true;
        }
      }
    } catch {
      console.log(`[INTEL-REPORT] Last resort search failed`);
    }
  }

  return {
    url,
    source,
    title: pageTitle || metadata.siteType,
    textContent: pageContent,
    siteType: metadata.siteType,
    urlMetadata: metadata.context,
    searchSnippets,
    publishedTime,
    success,
  };
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

  // Initialize ZAI SDK
  const zai = await getZAI();
  console.log('[INTEL-REPORT] ZAI SDK initialized successfully');

  // =========================================================================
  // PHASE 1: URL CONTENT RETRIEVAL (PARALLEL)
  // Fetch up to 6 URLs in parallel for speed
  // =========================================================================
  console.log(`[INTEL-REPORT] Phase 1: Fetching ${urls.slice(0, 6).length} URLs in parallel...`);
  const urlFetchPromises = urls.slice(0, 6).map(url =>
    fetchUrlContent(url, zai).catch((e) => {
      console.log(`[INTEL-REPORT] URL fetch failed for ${url.substring(0, 50)}: ${e}`);
      const metadata = analyzeUrlMetadata(url);
      return {
        url,
        source: 'metadata_only' as const,
        title: metadata.siteType,
        textContent: '',
        siteType: metadata.siteType,
        urlMetadata: metadata.context,
        searchSnippets: [],
        publishedTime: '',
        success: false,
      };
    })
  );
  const urlIntelligence = await Promise.all(urlFetchPromises);
  console.log(`[INTEL-REPORT] Phase 1 done: ${urlIntelligence.filter(ui => ui.success).length}/${urlIntelligence.length} URLs with content`);

  // =========================================================================
  // PHASE 2: OSINT WEB SEARCHES (PARALLEL)
  // =========================================================================
  const searchQueries: string[] = [];

  // URL-based queries
  for (const url of urls.slice(0, 3)) {
    try {
      const urlObj = new URL(url);
      const cikMatch = urlObj.pathname.match(/data\/(\d+)/);
      if (cikMatch) {
        searchQueries.push(`SEC CIK ${cikMatch[1]} company executive officers compensation`);
      }
      searchQueries.push(`${urlObj.hostname} executive data`);
    } catch { /* skip */ }
  }

  // Extract search queries from written data
  if (writtenData.trim()) {
    try {
      const extractText = await zaiChatCompletion([
          {
            role: 'system',
            content: `Eres un analista OSINT. Extrae las 3 busquedas web mas efectivas para investigar la amenaza descrita. Responde SOLO con JSON array de strings: ["busqueda 1", "busqueda 2", "busqueda 3"]`,
          },
          { role: 'user', content: writtenData.substring(0, 3000) },
        ], { temperature: 0.1, max_tokens: 300, maxRetries: 2 }) || '';
      const extractMatch = extractText.match(/\[[\s\S]*\]/);
      if (extractMatch) {
        const extracted = JSON.parse(extractMatch[0]);
        if (Array.isArray(extracted)) {
          searchQueries.push(...extracted.filter((q: string) => typeof q === 'string').slice(0, 3));
        }
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log(`[INTEL-REPORT] Entity extraction error: ${msg.substring(0, 80)}`);
    }
  }

  // Default queries
  if (searchQueries.length === 0) {
    searchQueries.push(
      'exposición datos personales ejecutivos VIP riesgo seguridad 2025 2026',
      'protección ejecutiva datos expuestos web ingeniería social amenaza',
    );
  }

  // Execute OSINT searches in parallel (max 4)
  console.log(`[INTEL-REPORT] Phase 2: ${searchQueries.slice(0, 4).length} OSINT searches in parallel...`);
  const osintSearchPromises = searchQueries.slice(0, 4).map(query =>
    zaiWebSearch(query, { num: 5 })
      .then((result: any[]) => {
        if (result && result.length > 0) {
          return result.map((item: any) => ({
            sourceName: item.name || 'Desconocido',
            sourceUrl: item.url || '',
            snippet: item.snippet || '',
            hostname: item.host_name || '',
            date: item.date || '',
            searchQuery: query,
          }));
        }
        return [];
      })
      .catch(() => [] as any[])
  );
  const osintResultsArrays = await Promise.all(osintSearchPromises);
  const osintResults = osintResultsArrays.flat();

  // Deduplicate
  const seenUrls = new Set<string>();
  const uniqueOsint = osintResults.filter((item: any) => {
    if (seenUrls.has(item.sourceUrl)) return false;
    seenUrls.add(item.sourceUrl);
    return true;
  });
  console.log(`[INTEL-REPORT] Phase 2 done: ${uniqueOsint.length} unique OSINT results`);

  // =========================================================================
  // PHASE 3: ENTITY EXTRACTION + DEEP ANALYSIS (Combined for speed)
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

  // Build the intelligence sections
  const urlIntelligenceSection = urlIntelligence.map((ui, idx) => {
    let section = `=== URL ${idx + 1}: ${ui.url} ===
Tipo de sitio: ${ui.siteType}
Fuente de datos: ${ui.source}
Metadata contextual: ${ui.urlMetadata}`;

    if (ui.textContent && ui.source === 'server_fetch') {
      section += `\n\nCONTENIDO LEÍDO DIRECTAMENTE DE LA PÁGINA:\n${ui.textContent.substring(0, 12000)}`;
    }
    if (ui.searchSnippets.length > 0) {
      section += `\n\nCONTEXTO OBTENIDO VÍA BÚSQUEDA WEB:\n${ui.searchSnippets.join('\n')}`;
    }
    return section;
  }).join('\n\n');

  const osintContextSection = uniqueOsint.length > 0
    ? uniqueOsint.slice(0, 15).map((item: any, idx: number) =>
        `[OSINT-${idx + 1}] Fuente: ${item.sourceName}\nURL: ${item.sourceUrl}\nFecha: ${item.date || 'N/A'}\nBúsqueda: ${item.searchQuery.substring(0, 60)}\nResumen: ${item.snippet}`
      ).join('\n\n')
    : '';

  const writtenDataSection = writtenData.trim()
    ? `=== DATOS Y CONTENIDO PROPORCIONADO POR EL ANALISTA ===\n${writtenData.substring(0, 18000)}`
    : '';

  const fileListSection = fileNames && fileNames.length > 0
    ? `Archivos cargados por el analista (contenido incluido arriba): ${fileNames.join(', ')}`
    : '';

  // =========================================================================
  // PHASE 4: DEEP AI ANALYSIS (Single comprehensive prompt)
  // =========================================================================
  const systemPrompt = `Eres un ANALISTA DE INTELIGENCIA SUPERIOR con 25+ años de experiencia en protección ejecutiva VIP, contrainteligencia, ciberseguridad avanzada, OSINT y análisis de amenazas. Has trabajado con agencias gubernamentales, corporaciones Fortune 500 y organizaciones internacionales.

CONTEXTO CRÍTICO DE TU MISIÓN:
Se te ha entregado información sobre la EXPOSICIÓN de datos sensibles de un alto ejecutivo (VIP) en sitios web públicos. Esto NO es un ejercicio académico — es un caso REAL de seguridad ejecutiva. Tu análisis debe ser PROFUNDO, ESPECÍFICO y ACCIONABLE.

IMPORTANTE - SOBRE LAS FUENTES DE DATOS:
- Si el contenido de una URL fue leído directamente (server_fetch), tienes el contenido REAL de la página
- Si no se pudo leer directamente, se obtuvo contexto vía web_search (snippets de búsqueda)
- SIEMPRE tienes metadata contextual de cada URL (tipo de sitio, dominio, path)
- Usa TODA la información disponible para tu análisis
- Para filings SEC/EDGAR: estos son documentos regulatorios PÚBLICOS que contienen compensación ejecutiva, participaciones accionarias y datos de gobernanza.

TU PROCESO DE ANÁLISIS:

PASO 1 - IDENTIFICACIÓN DEL ACTIVO:
- Identifica al VIP por nombre completo, cargo y organización
- Determina su nivel de exposición pública previa vs. la nueva exposición
- Evalúa su perfil de riesgo

PASO 2 - ANÁLISIS DE CADA FUENTE:
- Para CADA URL, analiza QUÉ información específica del VIP está expuesta
- Determina si la exposición es legítima o no autorizada
- Identifica qué datos son PÚBLICOS vs. PRIVADOS vs. SENSIBLES vs. CRÍTICOS

PASO 3 - EVALUACIÓN DE AMENAZAS:
- Identifica amenazas CONCRETAS y ESPECÍFICAS
- Considera: ingeniería social, suplantación de identidad, extorsión, ataque físico, fraude BEC, robo de identidad, acoso, secuestro

PASO 4 - LÍNEAS DE ACCIÓN por fases:
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
      "description": "descripción DETALLADA (mínimo 200 palabras)",
      "severity": "bajo|medio|alto|critico",
      "category": "ingenieria_social|suplantacion_identidad|fraude_financiero|amenaza_fisica|acoso|extorsion|robo_datos|ataque_cibernetico|exposicion_datos|cadena_suministro",
      "likelihood": "baja|media|alta|muy_alta",
      "impactDetail": "descripción detallada del impacto (mínimo 80 palabras)",
      "evidence": "evidencia específica del contenido que sustenta esta amenaza",
      "affectedParties": ["quién se vería afectado"]
    }
  ],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen EJECUTIVO COMPREHENSIVO (mínimo 600 palabras)",
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
4. Mínimo 3 amenazas identificadas.
5. El resumen ejecutivo debe ser COMPREHENSIVO (mínimo 600 palabras).
6. El overallRiskLevel debe basarse en los HALLAZGOS REALES, NO uses 'alto' como valor por defecto. Si los datos no muestran riesgo alto, asigna 'medio' o 'bajo' según corresponda.
7. NO incluyas secciones vacías o con contenido placeholder - solo secciones con datos reales.
8. Si el contenido de URLs fue leído exitosamente (server_fetch), enfatiza el análisis de URLs.
9. Si los resultados OSINT fueron la fuente principal, enfatiza el análisis OSINT.
10. Si solo se proporcionaron datos escritos, enfócate en analizar esos datos.
11. La estructura del informe debe ADAPTARSE a los datos disponibles, no ser siempre la misma plantilla.`;

  const userPrompt = `=== INFORMACIÓN SUMINISTRADA POR EL ANALISTA PARA ANÁLISIS DE INTELIGENCIA ===

--- INTELIGENCIA RECOLECTADA DE LAS URLs PROPORCIONADAS ---

${urlIntelligenceSection || 'No se proporcionaron URLs.'}

${writtenDataSection}

${fileListSection}

${osintContextSection ? `--- CONTEXTO OSINT ADICIONAL ---\n${osintContextSection.substring(0, 8000)}` : ''}

=== INSTRUCCIÓN FINAL ===
Analiza EN PROFUNDIDAD toda la información proporcionada arriba. Produce un informe de inteligencia COMPLETO y PROFESIONAL. Incluso si no tienes el contenido directo de una página, tienes contexto de búsqueda y metadata — ÚSALOS para tu análisis.`;

  try {
    console.log('[INTEL-REPORT] Phase 4: Deep AI analysis...');
    const responseText = await zaiChatCompletion([
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ], { temperature: 0.08, max_tokens: 16000, maxRetries: 3 }) || '';
    console.log(`[INTEL-REPORT] AI response: ${responseText.length} chars`);

    if (responseText) {
      const m = responseText.match(/\{[\s\S]*\}/);
      if (m) {
        const analysisResult = JSON.parse(m[0]);
        console.log('[INTEL-REPORT] AI analysis parsed successfully');
        return { success: true, analysis: analysisResult };
      }
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log(`[INTEL-REPORT] Deep analysis error: ${msg.substring(0, 200)}`);
  }

  // Fallback - return structured data even if AI fails
  console.log('[INTEL-REPORT] Using fallback analysis structure');
  return {
    success: true,
    analysis: {
      executiveProfile: {
        name: 'No identificado',
        title: 'No identificado',
        organization: 'No identificada',
        publicProfile: 'No se pudo determinar del análisis automatizado.',
        riskProfile: 'No se pudo determinar del análisis automatizado.',
      },
      dataExposureAnalysis: [],
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
          ? 'Publicación regulatoria requerida por ley.'
          : 'No se pudo determinar la legitimidad de la publicación.',
        riskAssessment: 'Se requiere evaluación detallada del contenido expuesto.',
      })),
      threats: urlIntelligence.filter(ui => ui.success).length > 0 ? [{
        title: `Exposición de información en ${urlIntelligence.filter(ui => ui.success).length} sitio(s) web`,
        description: `Se ha identificado exposición de información en ${urlIntelligence.filter(ui => ui.success).length} sitio(s) web con contenido accesible. Los datos pueden incluir información personal, profesional y financiera del ejecutivo. Esta exposición representa un riesgo de ingeniería social, suplantación de identidad y posibles ataques dirigidos al VIP. Se requiere evaluación del contenido expuesto y acciones de remediación.`,
        severity: 'medio',
        category: 'exposicion_datos',
        likelihood: 'media',
        impactDetail: 'El impacto potencial incluye riesgo de ingeniería social, suplantación de identidad y fraude BEC. Se requiere evaluación detallada del contenido para determinar la severidad real.',
        evidence: `Datos proporcionados por el analista. Fuentes: ${urlIntelligence.filter(ui => ui.success).map(ui => ui.siteType).join(', ')}.`,
        affectedParties: ['VIP', 'Organización'],
      }] : [],
      overallRiskLevel: urlIntelligence.filter(ui => ui.success).length > 0 ? 'medio' : 'bajo',
      summary: `Se detectó exposición de información en ${urlIntelligence.filter(ui => ui.success).length} de ${urls.length} sitio(s) web analizados. Las fuentes incluyen: ${urlIntelligence.filter(ui => ui.success).map(ui => ui.siteType).join(', ')}. ${urlIntelligence.map(ui => ui.urlMetadata).join('. ')}. El nivel de riesgo se determina como ${urlIntelligence.filter(ui => ui.success).length > 0 ? 'MEDIO' : 'BAJO'} basado en los datos disponibles. Se recomienda evaluación adicional con IA para un análisis más profundo.`,
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
    await ensureDatabaseInitialized();
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
*Agente IA: Análisis Multi-Fase (Lectura URLs + Búsqueda Web + OSINT + Análisis Profundo)*
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
    console.error('Intel report generation error:', error);
    return NextResponse.json(
      { error: 'Error al generar informe de inteligencia' },
      { status: 500 }
    );
  }
}
