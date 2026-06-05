import { NextResponse } from 'next/server';
import ZAI from 'z-ai-web-dev-sdk';

export const maxDuration = 60;

// ============================================================================
// ZAI SDK HELPER - Uses environment variables instead of .z-ai-config file
// This makes it compatible with Vercel's serverless environment
// ============================================================================
async function createZAI(): Promise<InstanceType<typeof ZAI>> {
  // Try environment variables first (for Vercel deployment)
  if (process.env.ZAI_BASE_URL && process.env.ZAI_API_KEY) {
    return new ZAI({
      baseUrl: process.env.ZAI_BASE_URL,
      apiKey: process.env.ZAI_API_KEY,
      chatId: process.env.ZAI_CHAT_ID || '',
      token: process.env.ZAI_TOKEN || '',
      userId: process.env.ZAI_USER_ID || '',
    });
  }
  // Fallback to ZAI.create() which reads from .z-ai-config file (local dev)
  return ZAI.create();
}

// ============================================================================
// Source metadata helpers
// ============================================================================
const hostnameCategoryMap: Record<string, string> = {
  'eltiempo.com': 'seguridad', 'elespectador.com': 'seguridad', 'semana.com': 'politica',
  'portafolio.co': 'economia', 'bluradio.com': 'seguridad', 'caracol.com.co': 'seguridad',
  'kaspersky.com': 'ciberseguridad', 'thehackernews.com': 'ciberseguridad',
  'bleepingcomputer.com': 'ciberseguridad', 'darkreading.com': 'ciberseguridad',
  'cnnespanol.cnn.com': 'politica', 'bbc.com': 'politica',
  'infosecurity-magazine.com': 'ciberseguridad', 'insightcrime.org': 'seguridad',
  'grupobancolombia.com': 'economia', 'redalert.col': 'seguridad'
};

const hostnameNameMap: Record<string, string> = {
  'eltiempo.com': 'El Tiempo', 'elespectador.com': 'El Espectador', 'semana.com': 'Semana',
  'portafolio.co': 'Portafolio', 'bluradio.com': 'Blu Radio', 'caracol.com.co': 'Caracol Radio',
  'kaspersky.com': 'Kaspersky', 'thehackernews.com': 'The Hacker News',
  'bleepingcomputer.com': 'BleepingComputer', 'darkreading.com': 'Dark Reading',
  'cnnespanol.cnn.com': 'CNN Espanol', 'bbc.com': 'BBC Mundo',
  'infosecurity-magazine.com': 'Infosecurity Magazine', 'insightcrime.org': 'InSight Crime',
  'grupobancolombia.com': 'Bancolombia', 'redalert.col': 'Red Alert Colombia'
};

const categoryTopicMap: Record<string, string> = {
  seguridad: 'seguridad amenazas ejecutivos secuestro extorsion grupos armados',
  ciberseguridad: 'ciberataques phishing malware ransomware hackeo seguridad digital',
  politica: 'politica conflictos protestas inestabilidad movilidad seguridad',
  economia: 'fraude financiero lavado activos estafa bancaria riesgo corporativo',
  fisica: 'vigilancia contravigilancia seguridad residencial proteccion fisica ejecutivos'
};

// ============================================================================
// FALLBACK REPORT GENERATOR (from scripts/generate-report.js)
// Kept for report generation, but NOT used for analysis fallback
// ============================================================================
function generateFallbackReport(
  analysis: {
    threats?: Array<{ title: string; description: string; severity: string; category: string }>;
    recommendations?: string[];
    sources?: Array<{ title: string; url: string; relevance: string }>;
    overallRiskLevel?: string;
    summary?: string;
    configuredSources?: Array<{ name: string; url: string; category: string }>;
    rawData?: Array<{ sourceName: string; sourceUrl: string; snippet: string; hostname: string; searchQuery: string; category: string; date: string }>;
    rawDataText?: string;
  },
  templateContent: string,
  hasTemplate: boolean,
  fechaStr: string
): string {
  const threats = analysis.threats || [];
  const recommendations = analysis.recommendations || [];
  const sources = analysis.sources || [];
  const riskLevel = analysis.overallRiskLevel || 'medio';
  const summary = analysis.summary || '';
  const configuredSources = analysis.configuredSources || [];
  const rawData = analysis.rawData || [];

  const riskDescriptions: Record<string, string> = {
    critico: 'CRITICO - Se requieren acciones inmediatas y controles reforzados de manera urgente. El nivel de amenaza actual exige la activacion de protocolos de emergencia y la implementacion de medidas extraordinarias de proteccion.',
    alto: 'ALTO - Es necesario intensificar las medidas de seguridad actuales de forma prioritaria. Se recomienda la revision inmediata de protocolos y la implementacion de medidas adicionales de proteccion.',
    medio: 'MEDIO - Se deben mantener y mejorar las medidas preventivas vigentes. Se recomienda monitoreo continuo y actualizacion periodica de las evaluaciones de riesgo.',
    bajo: 'BAJO - Las medidas actuales son adecuadas pero requieren monitoreo continuo para anticipar cambios en el panorama de amenazas.'
  };

  let sourcesSection = '';
  if (sources.length > 0) {
    sourcesSection = sources.map(s =>
      `- **${s.title || 'Fuente'}**: ${s.relevance || 'Fuente de inteligencia consultada'} ${s.url ? `([${s.url}](${s.url}))` : ''}`
    ).join('\n');
  } else if (configuredSources.length > 0) {
    sourcesSection = configuredSources.map(s =>
      `- **${s.name}** (${s.category}): Fuente de inteligencia OSINT configurada - [${s.url}](${s.url})`
    ).join('\n');
  } else {
    sourcesSection = 'Fuentes de inteligencia clasificadas - Consulte con la Direccion de Seguridad para acceso a las fuentes completas.';
  }

  let evidenceSection = '';
  if (rawData.length > 0) {
    evidenceSection = `### Evidencia Recopilada de Fuentes OSINT\n\n` +
      rawData.slice(0, 15).map((item, i) =>
        `${i + 1}. **${item.sourceName || 'Fuente'}** (${item.date || 'Sin fecha'}): ${item.snippet || 'Sin detalle'}\n   Fuente: ${item.sourceUrl || 'N/A'} | Consulta: "${item.searchQuery || 'N/A'}"`
      ).join('\n\n');
  } else if (analysis.rawDataText && analysis.rawDataText.length > 50) {
    evidenceSection = `### Evidencia de Fuentes OSINT\n\n${analysis.rawDataText.substring(0, 6000)}`;
  }

  const threatMatrix = threats.map((t, i) => {
    const sev = t.severity || 'medio';
    const prob = sev === 'critico' ? 'Muy Alta' : sev === 'alto' ? 'Alta' : sev === 'medio' ? 'Media' : 'Baja';
    const impact = sev === 'critico' ? 'Catastrofico' : sev === 'alto' ? 'Grave' : sev === 'medio' ? 'Moderado' : 'Menor';
    const urgency = sev === 'critico' ? 'INMEDIATA' : sev === 'alto' ? '24-48 horas' : sev === 'medio' ? '1-2 semanas' : '30 dias';
    return `| ${i + 1} | ${t.title} | ${t.category || 'seguridad'} | ${sev.toUpperCase()} | ${prob} | ${impact} | ${urgency} |`;
  });

  const detailedRecommendations = recommendations.length > 0 ? recommendations.map((r, i) => {
    const priority = i < 2 ? 'CRITICA' : i < 4 ? 'ALTA' : 'MEDIA';
    const deadline = i < 2 ? 'Inmediato (0-7 dias)' : i < 4 ? 'Corto plazo (7-30 dias)' : 'Mediano plazo (30-90 dias)';
    const responsible = r.toLowerCase().includes('ciber') || r.toLowerCase().includes('digital') || r.toLowerCase().includes('phishing') || r.toLowerCase().includes('informatic')
      ? 'CISO / Direccion de Ciberseguridad'
      : r.toLowerCase().includes('fisica') || r.toLowerCase().includes('escolta') || r.toLowerCase().includes('residencia') || r.toLowerCase().includes('vigilancia')
        ? 'Direccion de Seguridad Fisica'
        : r.toLowerCase().includes('financiero') || r.toLowerCase().includes('fraude') || r.toLowerCase().includes('transferencia')
          ? 'Oficial de Cumplimiento / Direccion Financiera'
          : 'Direccion de Seguridad / Comite de Crisis';
    return `### ${i + 1}. ${r}

- **Prioridad:** ${priority}
- **Plazo de implementacion:** ${deadline}
- **Responsable:** ${responsible}
- **Indicador de cumplimiento:** Documentacion de implementacion y verificacion por auditoria interna`;
  }).join('\n\n') : `### 1. Evaluaciones de riesgo periodicas
- **Prioridad:** CRITICA
- **Plazo:** Inmediato (0-7 dias)
- **Responsable:** Direccion de Seguridad

### 2. Medidas de seguridad integrales
- **Prioridad:** ALTA
- **Plazo:** 7-30 dias
- **Responsable:** Direccion de Seguridad / CISO

### 3. Planes de respuesta ante emergencias
- **Prioridad:** ALTA
- **Plazo:** 15 dias
- **Responsable:** Comite de Crisis`;

  if (hasTemplate) {
    return `# INFORME EJECUTIVO VIP
## VIP_Protection Report | Executive Intelligence
### Proteccion Digital y Fisica de Ejecutivos

---

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL
**Numero de Referencia:** VIP-RPT-${Date.now().toString(36).toUpperCase()}
**Elaborado por:** Sistema de Inteligencia Ejecutiva VIP_Protection Report
**Fuentes consultadas:** ${configuredSources.length > 0 ? configuredSources.length : sources.length} fuentes de inteligencia

---

## RESUMEN EJECUTIVO

${summary}

${riskDescriptions[riskLevel] || riskDescriptions.medio}

Se identificaron **${threats.length} amenazas activas** distribuidas en las categorias de ${[...new Set(threats.map(t => t.category))].join(', ')}. De estas, ${threats.filter(t => t.severity === 'critico').length} son de nivel critico, ${threats.filter(t => t.severity === 'alto').length} de nivel alto, ${threats.filter(t => t.severity === 'medio').length} de nivel medio y ${threats.filter(t => t.severity === 'bajo').length} de nivel bajo.

---

## MATRIZ DE AMENAZAS

| # | Amenaza | Categoria | Severidad | Probabilidad | Impacto | Urgencia |
|---|---------|-----------|-----------|--------------|---------|----------|
${threatMatrix.join('\n')}

---

## AMENAZAS IDENTIFICADAS - ANALISIS DETALLADO

${threats.length > 0 ? threats.map((t, i) => {
  const sev = t.severity || 'medio';
  const prob = sev === 'critico' ? 'Muy Alta (>80%)' : sev === 'alto' ? 'Alta (60-80%)' : sev === 'medio' ? 'Media (30-60%)' : 'Baja (<30%)';
  const impact = sev === 'critico' ? 'Catastrofico - Perdida de vida, secuestro, compromise total de operaciones' : sev === 'alto' ? 'Grave - Dano significativo a personas, activos o reputacion' : sev === 'medio' ? 'Moderado - Impacto manejable pero requiere atencion' : 'Menor - Impacto limitado';
  const vector = t.category === 'ciberseguridad' ? 'Ataque cibernetico (phishing, malware, ransomware, ingenieria social)' : t.category === 'seguridad' ? 'Amenaza fisica (grupos armados, criminalidad organizada)' : t.category === 'politica' ? 'Factor politico-social (inestabilidad, protestas, cambios regulatorios)' : t.category === 'economia' ? 'Riesgo financiero (fraude, lavado, estafa corporativa)' : 'Amenaza fisica avanzada (vigilancia, intrusion, contravigilancia)';
  const mitigation = t.category === 'ciberseguridad' ? 'Implementar MFA hardware, formacion anti-phishing, monitoreo de credenciales en dark web, segmentacion de redes y planes de respuesta a ransomware' : t.category === 'seguridad' ? 'Escoltas especializados, vehiculos blindados, rutas alternas, protocolos de comunicacion segura, coordinacion con autoridades' : t.category === 'politica' ? 'Monitoreo de coyuntura politica, planes de contingencia de movilidad, protocolos de neutralidad corporativa' : t.category === 'economia' ? 'Controles internos rigurosos, verificacion dual de transferencias, due diligence reforzada, monitoreo transaccional con IA' : 'Programa integral de contravigilancia, auditorias residenciales, geolocalizacion seguro, protocolos de desplazamiento';

  return `### ${i + 1}. ${t.title} [${sev.toUpperCase()}]

${t.description}

**Analisis de Riesgo:**
- **Categoria:** ${t.category || 'seguridad'}
- **Severidad:** ${sev.toUpperCase()}
- **Probabilidad:** ${prob}
- **Impacto Potencial:** ${impact}
- **Vector de Amenaza:** ${vector}
- **Medidas de Mitigacion:** ${mitigation}`;
}).join('\n\n---\n\n') : 'No se identificaron amenazas especificas en el periodo analizado.'}

---

${evidenceSection ? `## EVIDENCIA DE FUENTES DE INTELIGENCIA

${evidenceSection}

---` : ''}

## RECOMENDACIONES

${detailedRecommendations}

---

## CONCLUSIONES

### Evaluacion General

El panorama de amenazas para la proteccion VIP de ejecutivos en Colombia presenta un nivel de riesgo **${riskLevel.toUpperCase()}**, sustentado en el analisis de ${configuredSources.length > 0 ? configuredSources.length : sources.length} fuentes de inteligencia y la identificacion de ${threats.length} amenazas activas.

### Acciones Prioritarias

${threats.filter(t => t.severity === 'critico' || t.severity === 'alto').length > 0 ? `Se requiere accion INMEDIATA sobre las ${threats.filter(t => t.severity === 'critico' || t.severity === 'alto').length} amenazas de severidad critica/alta identificadas en este informe. Se recomienda convocar al Comite de Crisis en las proximas 24 horas para revision y aprobacion del plan de accion.` : 'Las amenazas identificadas requieren monitoreo continuo y la implementacion gradual de las medidas recomendadas.'}

---

## FUENTES CONSULTADAS

${sourcesSection}

---

*Documento generado por VIP_Protection Report - Executive Intelligence System*
*Fecha de generacion: ${fechaStr}*
*Clasificacion: CONFIDENCIAL - Uso restringido*`;
  } else {
    return `# INFORME EJECUTIVO VIP - Proteccion Digital de Ejecutivos
## VIP_Protection Report | Executive Intelligence

---

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL
**Numero de Referencia:** VIP-RPT-${Date.now().toString(36).toUpperCase()}

---

## RESUMEN EJECUTIVO

${summary}

${riskDescriptions[riskLevel] || riskDescriptions.medio}

---

## MATRIZ DE AMENAZAS

| # | Amenaza | Categoria | Severidad | Probabilidad | Impacto | Urgencia |
|---|---------|-----------|-----------|--------------|---------|----------|
${threatMatrix.join('\n')}

---

## AMENAZAS IDENTIFICADAS

${threats.length > 0 ? threats.map((t, i) => `### ${i + 1}. ${t.title} [${(t.severity || 'medio').toUpperCase()}]

${t.description}

- **Categoria:** ${t.category || 'seguridad'}
- **Severidad:** ${(t.severity || 'medio').toUpperCase()}
- **Probabilidad:** ${t.severity === 'critico' ? 'Muy Alta' : t.severity === 'alto' ? 'Alta' : 'Media'}
- **Impacto:** ${t.severity === 'critico' ? 'Catastrofico' : t.severity === 'alto' ? 'Grave' : 'Moderado'}`).join('\n\n---\n\n') : 'No se identificaron amenazas especificas.'}

---

## RECOMENDACIONES

${detailedRecommendations}

---

## FUENTES CONSULTADAS

${sourcesSection}

---

*Documento generado por VIP_Protection Report - Executive Intelligence System*
*Clasificacion: CONFIDENCIAL*`;
  }
}

// ============================================================================
// UTILITY
// ============================================================================
function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================================
// ANALYZ OPERATION - Dynamic, source-aware analysis
// ============================================================================
async function handleAnalyze(data: {
    urls?: string[];
    searchQueries?: string[];
    selectedCategories?: string[];
    selectedSourceNames?: string[];
    sourceInfo?: Array<{ id: string; name: string; url: string; domain: string; type: string; category: string }>;
  }) {
  const urls = data.urls || [];
  const searchQueries = data.searchQueries || [];
  const selectedCategories = data.selectedCategories || [];
  const selectedSourceNames = data.selectedSourceNames || [];
  const sourceInfo = data.sourceInfo || [];

  const zai = await createZAI();
  const allRawData: Array<{
    sourceName: string; sourceUrl: string; snippet: string;
    hostname: string; searchQuery: string; category: string; date: string;
  }> = [];

  // Build structured source info - use sourceInfo from frontend if available
  const sourceInfoList = sourceInfo.length > 0
    ? sourceInfo.map(si => ({
        url: si.url,
        hostname: si.domain || si.url,
        name: si.name,
        category: si.category || 'seguridad',
      }))
    : urls.map(url => {
      let hostname: string;
      try { hostname = new URL(url).hostname; } catch { hostname = url; }
      const name = hostnameNameMap[hostname] || hostname;
      const category = hostnameCategoryMap[hostname] || 'seguridad';
      return { url, hostname, name, category };
    });

  const sourceList = sourceInfoList.map(s => `- ${s.name} (${s.category}): ${s.url}`).join('\n');

  // Determine active categories - prioritize USER SELECTED categories over hostname-derived
  const activeCategories = new Set<string>();
  if (selectedCategories.length > 0) {
    // User selected specific categories - use those
    for (const cat of selectedCategories) {
      const catLower = cat.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      // Map user-friendly category labels to internal keys
      if (catLower.includes('seguridad digital') || catLower.includes('ciberseguridad') || catLower.includes('digital')) {
        activeCategories.add('ciberseguridad');
      } else if (catLower.includes('proteccion de datos') || catLower.includes('datos') || catLower.includes('privacidad')) {
        activeCategories.add('ciberseguridad');
        activeCategories.add('economia');
      } else if (catLower.includes('viajes') || catLower.includes('viaje') || catLower.includes('movilidad') || catLower.includes('fisica')) {
        activeCategories.add('fisica');
        activeCategories.add('seguridad');
      } else if (catLower.includes('economia') || catLower.includes('financiero') || catLower.includes('fraude')) {
        activeCategories.add('economia');
      } else if (catLower.includes('politica') || catLower.includes('conflicto')) {
        activeCategories.add('politica');
      } else if (catLower.includes('seguridad') && !catLower.includes('digital')) {
        activeCategories.add('seguridad');
      } else {
        activeCategories.add(cat.toLowerCase());
      }
    }
  }
  // Also add categories from source URLs
  for (const s of sourceInfoList) {
    activeCategories.add(s.category);
  }

  // If no categories detected, default to seguridad (minimum viable)
  if (activeCategories.size === 0) {
    activeCategories.add('seguridad');
  }

  const categoryNamesList = [...activeCategories].join(', ');

  // === PHASE 1: Build SOURCE-SPECIFIC search queries ===
  let webSearchWorked = false;

  const searchTasks: string[] = [];

  // Add user-provided search queries first (highest priority)
  for (const q of searchQueries.slice(0, 3)) {
    searchTasks.push(q);
  }

  // Build source-specific queries: for each source, search for content
  // relevant to the selected categories on that specific source
  for (const s of sourceInfoList.slice(0, 5)) {
    const topicKeywords = categoryTopicMap[s.category] || 'seguridad amenazas ejecutivos';
    // Site-specific search combining the source domain with its category topic
    searchTasks.push(`site:${s.hostname} ${topicKeywords} 2025 2026`);
  }

  // Add broader queries that combine ALL active categories with source names
  const sourceNames = sourceInfoList.filter(src => src.name !== src.hostname).map(src => src.name);
  if (sourceNames.length > 0) {
    for (const cat of activeCategories) {
      const topicKeywords = categoryTopicMap[cat] || 'seguridad amenazas';
      // Reference the actual source names in the query
      searchTasks.push(`${topicKeywords} Colombia ${sourceNames.slice(0, 3).join(' OR ')} 2025 2026`);
    }
  }

  // Only add a generic query if no source-specific queries exist yet
  if (searchTasks.length === 0) {
    for (const cat of activeCategories) {
      const topicKeywords = categoryTopicMap[cat] || 'seguridad amenazas ejecutivos';
      searchTasks.push(`${topicKeywords} Colombia 2025 2026`);
    }
  }

  const limitedSearches = [...new Set(searchTasks)].slice(0, 8);

  for (let i = 0; i < limitedSearches.length; i++) {
    const query = limitedSearches[i];
    try {
      console.log(`[ANALYZ] Search ${i+1}/${limitedSearches.length}: "${query.substring(0, 80)}"`);
      const result = await (zai as any).functions.invoke('web_search', { query, num: 8 });

      if (result && Array.isArray(result) && result.length > 0) {
        for (const item of result) {
          allRawData.push({
            sourceName: item.name || 'Desconocido',
            sourceUrl: item.url || '',
            snippet: item.snippet || '',
            hostname: item.host_name || '',
            searchQuery: query,
            category: 'general',
            date: item.date || ''
          });
        }
        console.log(`  -> Found ${result.length} results`);
        webSearchWorked = true;
      }

      if (i < limitedSearches.length - 1) await sleep(500);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`  -> Rate limited (429). Stopping web searches.`);
      } else {
        console.log(`  -> Error: ${msg.substring(0, 80)}`);
      }
      break;
    }
  }

  // Deduplicate
  const seenUrls = new Set<string>();
  const uniqueData = allRawData.filter(item => {
    if (seenUrls.has(item.sourceUrl)) return false;
    seenUrls.add(item.sourceUrl);
    return true;
  });

  console.log(`[ANALYZ] Web search: ${webSearchWorked ? 'OK' : 'UNAVAILABLE'}, ${uniqueData.length} results`);

  // === PHASE 2: Build data for AI ===
  let rawDataText = '';
  if (uniqueData.length > 0) {
    rawDataText = uniqueData.map((item, idx) =>
      `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  // === PHASE 3: AI Analysis ===
  let analysisResult: Record<string, unknown> | null = null;
  let aiWorked = false;
  const maxRetries = 1;
  const retryDelays = [5000];

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      console.log(`[ANALYZ] AI retry ${attempt}/${maxRetries} (waiting ${retryDelays[attempt-1]/1000}s)`);
      await sleep(retryDelays[attempt - 1]);
    }

    try {
      let analysisPrompt: string;

      if (uniqueData.length > 0) {
        analysisPrompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con 20 anos de experiencia en proteccion VIP y contrainteligencia en Colombia.

FUENTES CONFIGURADAS POR EL USUARIO (estas son las fuentes que el usuario selecciono para monitorear):
${sourceList}

CATEGORIAS SELECCIONADAS: ${categoryNamesList}

INFORMACION RECOPILADA DE BUSQUEDAS OSINT (basada en las fuentes y categorias seleccionadas):
${rawDataText.substring(0, 10000)}

INSTRUCCIONES CRITICAS:
1. Analiza cada fragmento de informacion individualmente
2. Identifica amenazas ESPECIFICAS con datos concretos extraidos de los resultados de busqueda
3. Para cada amenaza: probabilidad, impacto, vector, mitigacion
4. Clasifica severidad basandote en EVIDENCIA REAL de los resultados de busqueda
5. Identifica patrones entre fuentes
6. Recomendaciones ACCIONABLES especificas para las categorias seleccionadas (${categoryNamesList})
7. Atribuye cada dato a su fuente por nombre
8. Tu analisis DEBE diferir significativamente segun las fuentes y categorias seleccionadas
9. Si las fuentes son principalmente de ciberseguridad, enfocate en amenazas ciberneticas
10. Si las fuentes son de seguridad, enfocate en amenazas fisicas y criminales
11. NO generes amenazas genericas que no esten respaldadas por la informacion recopilada

Responde SOLO con JSON valido:
{
  "threats": [{"title": "titulo especifico basado en datos reales", "description": "minimo 100 palabras con datos de fuentes recopiladas", "severity": "bajo|medio|alto|critico", "category": "${[...activeCategories].join('|')}"}],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen DETALLADO minimo 300 palabras citando las fuentes recopiladas por nombre",
  "recommendations": ["recomendacion especifica para las categorias ${categoryNamesList}", "recomendacion 2"],
  "sources": [{"title": "nombre de la fuente", "url": "url", "relevance": "que informacion especifica aporto esta fuente"}]
}`;
      } else {
        analysisPrompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con 20 anos de experiencia en proteccion VIP y contrainteligencia en Colombia.

FUENTES CONFIGURADAS POR EL USUARIO:
${sourceList || 'No se configuraron fuentes especificas'}

CATEGORIAS SELECCIONADAS: ${categoryNamesList}

No se pudo obtener informacion de busquedas web. Realiza un analisis basado en tu conocimiento experto, pero enfocado EXCLUSIVAMENTE en las categorias seleccionadas (${categoryNamesList}) y las fuentes configuradas.

INSTRUCCIONES:
1. Enfocate SOLO en las categorias que el usuario selecciono: ${categoryNamesList}
2. Si solo se selecciono economia, NO hables de ciberseguridad o seguridad fisica
3. Si solo se selecciono ciberseguridad, NO hables de economia o politica
4. Menciona las fuentes configuradas por nombre como referencia
5. No generes amenazas para categorias que no fueron seleccionadas

Responde SOLO con JSON valido:
{
  "threats": [{"title": "titulo especifico para la categoria", "description": "minimo 100 palabras con datos especificos", "severity": "bajo|medio|alto|critico", "category": "${[...activeCategories].join('|')}"}],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen DETALLADO minimo 300 palabras enfocado en ${categoryNamesList}",
  "recommendations": ["recomendacion especifica", "recomendacion 2"],
  "sources": [{"title": "nombre fuente", "url": "url", "relevance": "que aporto"}]
}`;
      }

      const analysisCompletion = await zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Eres un analista de inteligencia senior experto en proteccion VIP en Colombia. Respondes SOLO con JSON valido. Tu analisis siempre refleja las fuentes y categorias especificas proporcionadas, NUNCA generas el mismo analisis generico.'
          },
          { role: 'user', content: analysisPrompt }
        ],
        temperature: 0.15,
        max_tokens: 8000,
      });

      const analysisText = analysisCompletion.choices?.[0]?.message?.content || '';

      try {
        const m = analysisText.match(/\{[\s\S]*\}/);
        if (m) analysisResult = JSON.parse(m[0]);
      } catch { /* ignore parse error */ }

      if (analysisResult && Array.isArray((analysisResult as Record<string, unknown>).threats) && ((analysisResult as Record<string, unknown>).threats as unknown[]).length > 0) {
        aiWorked = true;
        console.log(`[ANALYZ] AI analysis successful on attempt ${attempt + 1}`);
        break;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`[ANALYZ] AI rate limited (429) on attempt ${attempt + 1}`);
      } else {
        console.log(`[ANALYZ] AI error on attempt ${attempt + 1}: ${msg.substring(0, 80)}`);
      }
    }
  }

  // === PHASE 4: No static fallback - return error if AI is unavailable ===
  if (!aiWorked) {
    console.log(`[ANALYZ] AI unavailable. Returning error instead of static data.`);

    // Return a structured error instead of fake static data
    const errorResult: Record<string, unknown> = {
      error: 'AI_UNAVAILABLE',
      errorMessage: 'El servicio de inteligencia artificial no esta disponible en este momento. No se puede generar un analisis confiable sin IA. Por favor intente nuevamente en unos minutos.',
      threats: [],
      overallRiskLevel: 'indeterminado',
      summary: 'No fue posible completar el analisis de inteligencia debido a que el servicio de IA no se encuentra disponible. Los resultados de busqueda web si fueron recopilados y pueden ser revisados manualmente.',
      recommendations: ['Reintentar el analisis en unos minutos cuando el servicio de IA este disponible', 'Revisar manualmente los resultados de busqueda OSINT recopilados'],
      sources: sourceInfoList.slice(0, 16).map(s => ({
        title: s.name,
        url: s.url,
        relevance: `Fuente configurada - Categoria: ${s.category}`
      })),
      rawData: uniqueData.slice(0, 30),
      rawDataText: rawDataText.substring(0, 12000),
      configuredSources: sourceInfoList.map(s => ({ name: s.name, url: s.url, category: s.category })),
      webSearchResults: uniqueData.length,
      categoriesAnalyzed: categoryNamesList,
    };

    return errorResult;
  }

  // Attach data for report generation
  (analysisResult as Record<string, unknown>).rawData = uniqueData.slice(0, 30);
  (analysisResult as Record<string, unknown>).rawDataText = rawDataText.substring(0, 12000);
  (analysisResult as Record<string, unknown>).configuredSources = sourceInfoList.map(s => ({
    name: s.name, url: s.url, category: s.category
  }));

  console.log(`[ANALYZ] Complete. Threats: ${(analysisResult as Record<string, unknown>).threats ? ((analysisResult as Record<string, unknown>).threats as unknown[]).length : 0}, Risk: ${(analysisResult as Record<string, unknown>).overallRiskLevel}, AI: YES`);

  return analysisResult;
}

// ============================================================================
// GENERATE-REPORT OPERATION (from scripts/generate-report.js)
// ============================================================================
async function handleGenerateReport(data: { templateContent?: string; analysis: Record<string, unknown>; reportContext?: { selectedCategories?: string[]; selectedSources?: string[]; threatCount?: number; riskLevel?: string; summary?: string; topThreats?: Array<{ title: string; severity: string; category: string }>; sourcesUsed?: string[] } }) {
  const { templateContent = '', analysis } = data;
  const reportContext = data.reportContext || {};
  const selectedCategories = reportContext.selectedCategories || [];
  const selectedSources = reportContext.selectedSources || [];

  const zai = await createZAI();

  const threatsDetail = ((analysis.threats || []) as Array<{ title: string; description: string; severity: string; category: string }>).map((t, i) =>
    `AMENAZA ${i + 1} [${(t.severity || 'medio').toUpperCase()}] - ${t.title}:\n${t.description}\nCategoria: ${t.category || 'seguridad'}\nSeveridad: ${t.severity || 'medio'}`
  ).join('\n\n');

  const recommendations = ((analysis.recommendations || []) as string[]).map((r, i) => `${i + 1}. ${r}`).join('\n');

  const sourcesList = ((analysis.sources || []) as Array<{ title: string; url: string; relevance: string }>).map(s =>
    `- ${s.title || s.url}: ${s.relevance || 'Fuente consultada'}`
  ).join('\n');

  let rawDataSummary = '';
  const rawDataText = analysis.rawDataText as string | undefined;
  const rawData = analysis.rawData as Array<{ sourceName: string; sourceUrl: string; snippet: string; category: string; date: string; searchQuery: string }> | undefined;
  if (rawDataText && rawDataText.length > 100) {
    rawDataSummary = rawDataText.substring(0, 10000);
  } else if (rawData && rawData.length > 0) {
    rawDataSummary = rawData.slice(0, 20).map((item, i) =>
      `[${i + 1}] Fuente: ${item.sourceName} | Categoria: ${item.category || 'N/A'}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  let configuredSourcesInfo = '';
  const configuredSources = analysis.configuredSources as Array<{ name: string; category: string; url: string }> | undefined;
  if (configuredSources && configuredSources.length > 0) {
    configuredSourcesInfo = configuredSources.map(s =>
      `- ${s.name} (${s.category}): ${s.url}`
    ).join('\n');
  }

  const hasTemplate = templateContent && templateContent.trim().length > 50;

  const now = new Date();
  const fechaStr = now.toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  // Determine data composition for adaptive report structure
  const hasUrlContent = (rawData && rawData.length > 0) || (rawDataText && rawDataText.length > 100);
  const hasThreats = (analysis.threats as unknown[]) && (analysis.threats as unknown[]).length > 0;
  const hasRecommendations = (analysis.recommendations as string[]) && (analysis.recommendations as string[]).length > 0;
  const dataComposition = [
    hasUrlContent ? 'RESULTADOS_OSINT' : '',
    hasThreats ? 'AMENAZAS_IDENTIFICADAS' : '',
    hasRecommendations ? 'RECOMENDACIONES' : '',
  ].filter(Boolean).join(', ') || 'DATOS_LIMITADOS';

  const systemPrompt = `Eres el REDACTOR JEFE de informes de inteligencia ejecutiva de una agencia de proteccion VIP de alto nivel. Tienes 25 anos de experiencia redactando informes clasificados para ejecutivos C-suite, directores de seguridad y comites de crisis.

CARACTERISTICAS:
- Lenguaje tecnico y preciso pero accesible para ejecutivos
- CADA dato se atribuye a su fuente especifica con nombre y URL
- Analisis profundo: causas, actores, metodos, impactos, probabilidades
- Recomendaciones accionables con prioridad, responsable y plazo
- Formato Markdown profesional con jerarquia clara
- NUNCA inventas informacion
- Minimo 3000 palabras de contenido sustancial
- COMPOSICION DE DATOS DISPONIBLES: ${dataComposition}

CONTEXTO DEL INFORME (CRITICO - LA ESTRUCTURA DEBE ADAPTARSE):
${selectedCategories.length > 0 ? `- Clasificaciones de industria seleccionadas: ${selectedCategories.join(', ')}` : '- No se seleccionaron clasificaciones especificas'}
${selectedSources.length > 0 ? `- Fuentes seleccionadas: ${selectedSources.join(', ')}` : '- No se seleccionaron fuentes especificas'}
${selectedCategories.includes('Seguridad Digital') || selectedCategories.includes('Ciberseguridad') ? '- INCLUYE seccion detallada de "Seguridad Digital y Ciberamenazas" con analisis de phishing, malware, ransomware, filtracion de datos, ingenieria social' : ''}
${selectedCategories.includes('Proteccion de Datos') ? '- INCLUYE seccion detallada de "Proteccion de Datos y Privacidad" con analisis de exposicion de datos personales, brechas, compliance, derechos ARCO' : ''}
${selectedCategories.includes('Seguridad en Viajes') ? '- INCLUYE seccion detallada de "Seguridad en Viajes y Movilidad" con analisis de riesgos de desplazamiento, rutas criticas, protocolos de viaje seguro' : ''}
${selectedCategories.includes('Economia') || selectedCategories.includes('Fraude Financiero') ? '- INCLUYE seccion detallada de "Riesgo Financiero y Fraude" con analisis de fraude BEC, lavado de activos, estafa corporativa' : ''}

REGLAS DE ESTRUCTURA ADAPTATIVA:
${hasUrlContent ? '- Se encontraron resultados OSINT: INCLUYE una seccion detallada de "Evidencia de Fuentes OSINT" con cada fuente citada' : '- No hay resultados OSINT: NO incluyas seccion de evidencia OSINT'}
${hasThreats ? '- Se identificaron amenazas: INCLUYE seccion de "Amenazas Identificadas" con analisis detallado de cada una' : '- No se identificaron amenazas: NO incluyas seccion de amenazas, en su lugar enfatiza el bajo riesgo detectado'}
${hasRecommendations ? '- Hay recomendaciones del analisis: INCLUYE seccion "Recomendaciones" con cada una detallada' : '- No hay recomendaciones especificas: ofrece recomendaciones generales basadas en las fuentes configuradas'}
- NO incluyas secciones vacias o con placeholder - solo secciones con datos reales
- El nivel de riesgo debe basarse en los HALLAZGOS REALES, no en un valor por defecto
- LA ESTRUCTURA DEL INFORME DEBE SER DIFERENTE segun las clasificaciones y fuentes seleccionadas. No siempre la misma plantilla.`;

  let userPrompt: string;

  if (hasTemplate) {
    userPrompt = `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA completo usando EXACTAMENTE la estructura de la plantilla.

== PLANTILLA OFICIAL (USA ESTA ESTRUCTURA EXACTA) ==
---
${templateContent}
---

== FECHA == ${fechaStr}
== NIVEL DE RIESGO == ${analysis.overallRiskLevel || 'medio'}
== RESUMEN DEL ANALISIS == ${analysis.summary || 'Sin resumen'}
== AMENAZAS DETECTADAS ==
${threatsDetail || 'No se detectaron amenazas'}
== INFORMACION DE FUENTES OSINT ==
${rawDataSummary || 'Informacion limitada'}
== RECOMENDACIONES == ${recommendations || 'Monitoreo continuo'}
== FUENTES CONSULTADAS == ${sourcesList || 'Fuentes clasificadas'}
== FUENTES CONFIGURADAS == ${configuredSourcesInfo || 'No especificadas'}
== COMPOSICION DE DATOS == ${dataComposition}

INSTRUCCIONES:
1. USA LA ESTRUCTURA EXACTA DE LA PLANTILLA
2. REMPLAZA marcadores [Fecha actual], [Nivel] con datos reales
3. LLENA cada seccion con informacion REAL de las fuentes
4. Menciona de que fuente viene cada dato
5. Minimo 3000 palabras
6. Formato Markdown profesional
7. NO inventes informacion
8. Solo incluye secciones que tengan datos reales, omite secciones vacias
9. El nivel de riesgo debe ser coherente con los hallazgos reales, no un valor por defecto

REDACTA EL INFORME:`;
  } else {
    userPrompt = `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA profesional.

== FECHA == ${fechaStr}
== NIVEL DE RIESGO == ${analysis.overallRiskLevel || 'medio'}
== RESUMEN == ${analysis.summary || 'Sin resumen'}
== AMENAZAS == ${threatsDetail || 'No detectadas'}
== FUENTES OSINT == ${rawDataSummary?.substring(0, 8000) || 'Limitada'}
== RECOMENDACIONES == ${recommendations || 'Monitoreo'}
== FUENTES == ${sourcesList || 'Clasificadas'}
== FUENTES CONFIGURADAS == ${configuredSourcesInfo || 'No especificadas'}
== COMPOSICION DE DATOS == ${dataComposition}

ESTRUCTURA ADAPTATIVA: Construye la estructura del informe segun los datos disponibles.
${hasUrlContent ? '- INCLUYE seccion de Evidencia OSINT con detalles de cada fuente' : '- NO incluyas seccion de evidencia OSINT (no hay datos)'}
${hasThreats ? '- INCLUYE seccion de Amenazas con analisis detallado' : '- Enfatiza que no se detectaron amenazas significativas'}
- INCLUYE siempre: Resumen Ejecutivo, Conclusiones, Referencias
- Solo incluye secciones con contenido real, NO dejes secciones vacias ni con placeholders
- El nivel de riesgo debe reflejar los hallazgos reales, NO uses 'alto' como valor por defecto
Minimo 3000 palabras. Markdown. Citar fuentes.`;
  }

  console.log('[GENERATE] Starting report generation...');
  console.log(`[GENERATE] Has template: ${hasTemplate}, Template length: ${templateContent?.length || 0}`);
  console.log(`[GENERATE] Analysis threats: ${(analysis.threats as unknown[])?.length || 0}, Sources: ${(analysis.sources as unknown[])?.length || 0}`);
  console.log(`[GENERATE] Data composition: ${dataComposition}`);

  let content = '';
  let aiSuccess = false;
  const maxRetries = 1;
  const retryDelays = [5000];

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      console.log(`[GENERATE] Retry ${attempt}/${maxRetries} (waiting ${retryDelays[attempt-1]/1000}s)`);
      await sleep(retryDelays[attempt - 1]);
    }

    try {
      const completion = await zai.chat.completions.create({
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ],
        temperature: 0.2,
        max_tokens: 8000,
      });

      content = completion.choices?.[0]?.message?.content || '';
      if (content.length > 100) {
        aiSuccess = true;
        console.log(`[GENERATE] AI report generated successfully on attempt ${attempt + 1}`);
        break;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`[GENERATE] Rate limited (429). Attempt ${attempt + 1}/${maxRetries + 1}`);
      } else {
        console.log(`[GENERATE] AI error: ${msg.substring(0, 100)}`);
        break;
      }
    }
  }

  if (!aiSuccess || content.length < 100) {
    console.log('[GENERATE] AI unavailable. Generating professional report from analysis data directly.');
    content = generateFallbackReport(
      analysis as Parameters<typeof generateFallbackReport>[0],
      templateContent,
      !!hasTemplate,
      fechaStr
    );
  }

  console.log(`[GENERATE] Report generated. Length: ${content.length} characters, AI: ${aiSuccess ? 'YES' : 'FALLBACK'}`);
  return { content };
}

// ============================================================================
// UPDATE-REPORT OPERATION (from scripts/update-report.js)
// ============================================================================
async function handleUpdateReport(data: {
  existingContent: string;
  additionalUrls?: string[];
  additionalNews?: string;
  additionalContext?: string;
  templateContent?: string;
}) {
  const { existingContent, additionalUrls = [], additionalNews = '', additionalContext = '', templateContent = '' } = data;

  const zai = await createZAI();
  const collectedData: Array<{ sourceName: string; sourceUrl: string; snippet: string; date: string }> = [];

  // Search additional URLs with source-specific queries
  if (additionalUrls && additionalUrls.length > 0) {
    for (let i = 0; i < Math.min(additionalUrls.length, 5); i++) {
      try {
        const url = additionalUrls[i];
        let query: string;
        try {
          const hostname = new URL(url).hostname;
          const name = hostnameNameMap[hostname] || hostname;
          query = `site:${hostname} seguridad amenazas proteccion ejecutivos Colombia ${name} 2025 2026`;
        } catch {
          query = url.substring(0, 100);
        }
        const r = await (zai as any).functions.invoke('web_search', { query, num: 10 });
        if (r && Array.isArray(r)) {
          for (const item of r) {
            collectedData.push({
              sourceName: item.name || 'Desconocido',
              sourceUrl: item.url || '',
              snippet: item.snippet || '',
              date: item.date || ''
            });
          }
        }
        if (i < additionalUrls.length - 1) await sleep(500);
      } catch { /* ignore search errors */ }
    }
  }

  if (additionalNews?.trim()) {
    collectedData.push({
      sourceName: 'Noticias proporcionadas manualmente',
      sourceUrl: '',
      snippet: additionalNews.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  if (additionalContext?.trim()) {
    collectedData.push({
      sourceName: 'Contexto adicional proporcionado',
      sourceUrl: '',
      snippet: additionalContext.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  if (collectedData.length === 0) {
    return { content: existingContent };
  }

  const newDataText = collectedData.map((item, idx) =>
    `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date}\n    Contenido: ${item.snippet}`
  ).join('\n\n');

  const templateInstruction = templateContent
    ? `\n\nPLANTILLA ORIGINAL (manten esta estructura):\n---\n${templateContent.substring(0, 4000)}\n---`
    : '';

  const prompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva VIP con 20 anos de experiencia. Actualiza el informe existente con nueva informacion recopilada de fuentes.

INFORME ACTUAL:
${existingContent.substring(0, 12000)}
${templateInstruction}

NUEVA INFORMACION RECOPILADA:
${newDataText}

INSTRUCCIONES:
1. Integra la nueva informacion en las secciones correspondientes del informe existente
2. Menciona EXPLICITAMENTE de que fuente viene cada nuevo dato
3. Si cambia el nivel de riesgo, actualizalo y justifica el cambio
4. Anade nuevas amenazas si se detectan en la nueva informacion
5. Manten el formato Markdown y la estructura del informe original
6. Anade una seccion "ACTUALIZACION" al final con fecha y resumen de cambios
7. NO elimines informacion existente - solo anade o actualiza
8. NO inventes informacion que no este en las fuentes
9. Se detallado y profesional - el informe actualizado debe ser mas completo que el original
10. Manten la estructura de la plantilla si existe

Genera el informe actualizado COMPLETO en Markdown.`;

  try {
    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: 'Eres un analista senior de inteligencia ejecutiva VIP experto en proteccion de ejecutivos en Colombia. Actualizas informes con datos reales de fuentes. Mantienes el formato y estructura existente. Formato Markdown en espanol. NUNCA inventas datos. Cada dato se atribuye a su fuente.'
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.2,
      max_tokens: 8000,
    });

    const content = completion.choices?.[0]?.message?.content || existingContent;
    return { content };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('429')) {
      // Rate limited - return existing content with a note
      return {
        content: existingContent + `\n\n---\n\n**NOTA:** La actualizacion con IA no pudo completarse debido a limitaciones del servicio. La informacion nueva no fue integrada. Por favor reintente en unos minutos.\n\n*Fecha del intento: ${new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}*`
      };
    }
    throw e;
  }
}

// ============================================================================
// MAIN ROUTE HANDLER
// ============================================================================
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { operation, data } = body as { operation: string; data: Record<string, unknown> };

    if (operation === 'analyze') {
      const result = await handleAnalyze(data as Parameters<typeof handleAnalyze>[0]);
      return NextResponse.json(result);
    } else if (operation === 'generate-report') {
      const result = await handleGenerateReport(data as Parameters<typeof handleGenerateReport>[0]);
      return NextResponse.json(result);
    } else if (operation === 'update-report') {
      const result = await handleUpdateReport(data as {
        existingContent: string;
        additionalUrls?: string[];
        additionalNews?: string;
        additionalContext?: string;
        templateContent?: string;
      });
      return NextResponse.json(result);
    } else {
      return NextResponse.json({ error: 'Operacion invalida' }, { status: 400 });
    }
  } catch (error: unknown) {
    console.error('AI operation error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error en la operacion de IA';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
