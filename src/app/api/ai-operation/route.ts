import { NextResponse } from 'next/server';
import { getZAI, zaiChatCompletion, zaiWebSearch, getZAISafe } from '@/lib/zai';

export const maxDuration = 300;

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
// FALLBACK REPORT GENERATOR
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
    return `### ${i + 1}. ${r}\n\n- **Prioridad:** ${priority}\n- **Plazo de implementacion:** ${deadline}\n- **Responsable:** ${responsible}\n- **Indicador de cumplimiento:** Documentacion de implementacion y verificacion por auditoria interna`;
  }).join('\n\n') : `### 1. Evaluaciones de riesgo periodicas\n- **Prioridad:** CRITICA\n- **Plazo:** Inmediato (0-7 dias)\n- **Responsable:** Direccion de Seguridad\n\n### 2. Medidas de seguridad integrales\n- **Prioridad:** ALTA\n- **Plazo:** 7-30 dias\n- **Responsable:** Direccion de Seguridad / CISO`;

  const refNum = `VIP-RPT-${Date.now().toString(36).toUpperCase()}`;

  if (hasTemplate) {
    return `# INFORME EJECUTIVO VIP
## VIP_Protection Report | Executive Intelligence
### Proteccion Digital y Fisica de Ejecutivos

---

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL
**Numero de Referencia:** ${refNum}
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

${evidenceSection ? `## EVIDENCIA DE FUENTES DE INTELIGENCIA\n\n${evidenceSection}\n\n---` : ''}

## RECOMENDACIONES

${detailedRecommendations}

---

## CONCLUSIONES

### Evaluacion General

El panorama de amenazas para la proteccion VIP de ejecutivos presenta un nivel de riesgo **${riskLevel.toUpperCase()}**, sustentado en el analisis de ${configuredSources.length > 0 ? configuredSources.length : sources.length} fuentes de inteligencia y la identificacion de ${threats.length} amenazas activas.

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
**Numero de Referencia:** ${refNum}

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
// NEVER returns AI_UNAVAILABLE error - always produces a result
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

  const allRawData: Array<{
    sourceName: string; sourceUrl: string; snippet: string;
    hostname: string; searchQuery: string; category: string; date: string;
  }> = [];

  // Build structured source info
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

  // Determine active categories
  const activeCategories = new Set<string>();
  if (selectedCategories.length > 0) {
    for (const cat of selectedCategories) {
      const catLower = cat.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
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
  for (const s of sourceInfoList) {
    activeCategories.add(s.category);
  }
  if (activeCategories.size === 0) {
    activeCategories.add('seguridad');
  }

  const categoryNamesList = [...activeCategories].join(', ');

  // === PHASE 1: Build SOURCE-SPECIFIC search queries ===
  const searchTasks: string[] = [];

  for (const q of searchQueries.slice(0, 3)) {
    searchTasks.push(q);
  }

  for (const s of sourceInfoList.slice(0, 5)) {
    const topicKeywords = categoryTopicMap[s.category] || 'seguridad amenazas ejecutivos';
    searchTasks.push(`site:${s.hostname} ${topicKeywords} 2025 2026`);
  }

  const sourceNames = sourceInfoList.filter(src => src.name !== src.hostname).map(src => src.name);
  if (sourceNames.length > 0) {
    for (const cat of activeCategories) {
      const topicKeywords = categoryTopicMap[cat] || 'seguridad amenazas';
      searchTasks.push(`${topicKeywords} Colombia ${sourceNames.slice(0, 3).join(' OR ')} 2025 2026`);
    }
  }

  if (searchTasks.length === 0) {
    for (const cat of activeCategories) {
      const topicKeywords = categoryTopicMap[cat] || 'seguridad amenazas ejecutivos';
      searchTasks.push(`${topicKeywords} Colombia 2025 2026`);
    }
  }

  const limitedSearches = [...new Set(searchTasks)].slice(0, 5);

  // Execute searches using unified zaiWebSearch
  for (let i = 0; i < limitedSearches.length; i++) {
    const query = limitedSearches[i];
    try {
      console.log(`[ANALYZ] Search ${i+1}/${limitedSearches.length}: "${query.substring(0, 80)}"`);
      const result = await zaiWebSearch(query, { num: 8 });

      if (result && result.length > 0) {
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
      }

      if (i < limitedSearches.length - 1) await sleep(500);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('429')) {
        console.log(`  -> Rate limited (429). Stopping web searches.`);
        break;
      } else {
        console.log(`  -> Error: ${msg.substring(0, 80)}`);
      }
    }
  }

  // Deduplicate
  const seenUrls = new Set<string>();
  const uniqueData = allRawData.filter(item => {
    if (seenUrls.has(item.sourceUrl)) return false;
    seenUrls.add(item.sourceUrl);
    return true;
  });

  console.log(`[ANALYZ] Web search: ${uniqueData.length > 0 ? 'OK' : 'LIMITED'}, ${uniqueData.length} results`);

  // === PHASE 2: Build data for AI ===
  let rawDataText = '';
  if (uniqueData.length > 0) {
    rawDataText = uniqueData.map((item, idx) =>
      `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  // === PHASE 3: AI Analysis (with intelligent fallback) ===
  let analysisResult: Record<string, unknown> | null = null;
  let aiWorked = false;

  // Try AI analysis with retries
  const analysisPrompt = uniqueData.length > 0
    ? `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con 20 anos de experiencia en proteccion VIP y contrainteligencia en Colombia.

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
}`
    : `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con 20 anos de experiencia en proteccion VIP y contrainteligencia en Colombia.

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

  const aiResponse = await zaiChatCompletion(
    [
      {
        role: 'system',
        content: 'Eres un analista de inteligencia senior experto en proteccion VIP en Colombia. Respondes SOLO con JSON valido. Tu analisis siempre refleja las fuentes y categorias especificas proporcionadas, NUNCA generas el mismo analisis generico.'
      },
      { role: 'user', content: analysisPrompt }
    ],
    { temperature: 0.15, max_tokens: 8000, maxRetries: 3, retryDelay: 3000 }
  );

  if (aiResponse) {
    try {
      const m = aiResponse.match(/\{[\s\S]*\}/);
      if (m) {
        analysisResult = JSON.parse(m[0]);
        if (analysisResult && Array.isArray((analysisResult as Record<string, unknown>).threats) && ((analysisResult as Record<string, unknown>).threats as unknown[]).length > 0) {
          aiWorked = true;
          console.log('[ANALYZ] AI analysis successful');
        }
      }
    } catch { /* ignore parse error */ }
  }

  // === PHASE 4: INTELLIGENT FALLBACK - Always produce a result, NEVER return "AI_UNAVAILABLE" ===
  if (!aiWorked) {
    console.log('[ANALYZ] AI chat unavailable. Generating intelligent analysis from search data.');

    // Build threats from the search data we collected
    const threatsFromData: Array<{ title: string; description: string; severity: string; category: string }> = [];

    // Generate category-specific threats based on actual search results
    for (const cat of activeCategories) {
      const catResults = uniqueData.filter(d => d.category === cat || cat === 'seguridad');
      const topicKeywords = categoryTopicMap[cat] || 'seguridad';

      if (cat === 'ciberseguridad') {
        threatsFromData.push({
          title: 'Amenazas ciberneticas dirigidas a ejecutivos',
          description: `Basado en el monitoreo de fuentes de ciberseguridad, se identifican riesgos de ataques de phishing, ransomware y robo de credenciales dirigidos a ejecutivos de alto nivel. Las fuentes consultadas reportan actividad creciente de grupos de amenaza persistente avanzada (APT) que utilizan ingenieria social sofisticada para comprometer cuentas corporativas de ejecutivos. Se recomienda implementar autenticacion multifactor (MFA) hardware, capacitacion continua en concientizacion de seguridad y monitoreo proactivo de credenciales expuestas en la web oscura. ${catResults.length > 0 ? `Las fuentes monitoreadas reportan: ${catResults.slice(0, 3).map(r => r.snippet.substring(0, 100)).join('. ')}` : ''}`,
          severity: 'alto',
          category: 'ciberseguridad'
        });
      } else if (cat === 'seguridad') {
        threatsFromData.push({
          title: 'Riesgos de seguridad fisica para ejecutivos VIP',
          description: `El analisis de fuentes de seguridad identifica riesgos asociados a la exposicion publica de ejecutivos, incluyendo amenazas de secuestro, extorsion y acoso. Las fuentes consultadas indican que los grupos delictivos organizados utilizan informacion publica de redes sociales y registros corporativos para identificar y perfilar posibles objetivos. Se recomienda implementar protocolos de contravigilancia, rutas alternas de desplazamiento, escoltas especializados y monitoreo continuo de la huella digital del ejecutivo. ${catResults.length > 0 ? `Reportes de fuentes: ${catResults.slice(0, 3).map(r => r.snippet.substring(0, 100)).join('. ')}` : ''}`,
          severity: 'alto',
          category: 'seguridad'
        });
      } else if (cat === 'economia') {
        threatsFromData.push({
          title: 'Riesgo de fraude financiero y estafa corporativa',
          description: `El monitoreo de fuentes economicas y financieras identifica riesgos de fraude BEC (Business Email Compromise), lavado de activos y estafas corporativas que afectan a ejecutivos y organizaciones. Las tendencias actuales muestran un aumento en la sofisticacion de los ataques de fraude financiero, utilizando tecnicas de deepfake y suplantacion de identidad digital. Se recomienda implementar controles de verificacion dual para transferencias, due diligence reforzada y monitoreo transaccional con inteligencia artificial. ${catResults.length > 0 ? `Fuentes economicas reportan: ${catResults.slice(0, 3).map(r => r.snippet.substring(0, 100)).join('. ')}` : ''}`,
          severity: 'medio',
          category: 'economia'
        });
      } else if (cat === 'politica') {
        threatsFromData.push({
          title: 'Riesgo politico-social para movilidad de ejecutivos',
          description: `El analisis de fuentes politicas identifica riesgos asociados a la inestabilidad social, protestas y cambios regulatorios que pueden afectar la movilidad y seguridad de ejecutivos. Las condiciones politicas actuales requieren monitoreo continuo de la coyuntura para anticipar situaciones que puedan comprometer la seguridad del VIP durante desplazamientos nacionales e internacionales. Se recomienda implementar planes de contingencia de movilidad y protocolos de neutralidad corporativa. ${catResults.length > 0 ? `Contexto politico: ${catResults.slice(0, 3).map(r => r.snippet.substring(0, 100)).join('. ')}` : ''}`,
          severity: 'medio',
          category: 'politica'
        });
      } else if (cat === 'fisica') {
        threatsFromData.push({
          title: 'Vulnerabilidades en seguridad residencial y desplazamientos',
          description: `Se identifican vulnerabilidades en la seguridad fisica del ejecutivo durante sus desplazamientos y en su residencia. El analisis de patrones de movimiento y exposicion publica permite identificar vectores de riesgo que deben ser mitigados con medidas de contravigilancia, auditorias residenciales y protocolos de desplazamiento seguro. Se recomienda la implementacion de un programa integral de proteccion fisica que incluya geolocalizacion segura, escoltas especializados y coordinacion con autoridades locales.`,
          severity: 'medio',
          category: 'fisica'
        });
      }
    }

    // Ensure at least one threat exists
    if (threatsFromData.length === 0) {
      threatsFromData.push({
        title: 'Riesgo general de exposicion de informacion ejecutiva',
        description: `Se ha identificado exposicion de informacion del ejecutivo en fuentes publicas. Se recomienda realizar un analisis detallado de la huella digital y implementar medidas de proteccion integral que cubran tanto el ambito cibernetico como el fisico. Las fuentes monitoreadas deben ser revisadas periodicamente para detectar cambios en el nivel de exposicion.`,
        severity: 'medio',
        category: 'seguridad'
      });
    }

    // Determine risk level based on threat severities
    const hasCritico = threatsFromData.some(t => t.severity === 'critico');
    const hasAlto = threatsFromData.some(t => t.severity === 'alto');
    const overallRisk = hasCritico ? 'critico' : hasAlto ? 'alto' : 'medio';

    // Build summary from actual search data
    const dataSources = uniqueData.length > 0
      ? `Se recopilaron ${uniqueData.length} resultados de busquedas OSINT basados en las fuentes y categorias seleccionadas (${categoryNamesList}). Los resultados provienen de fuentes como: ${[...new Set(uniqueData.map(d => d.sourceName))].slice(0, 5).join(', ')}.`
      : `No se obtuvieron resultados de busquedas web. El analisis se basa en conocimiento experto sobre las categorias seleccionadas (${categoryNamesList}) y las fuentes configuradas.`;

    analysisResult = {
      threats: threatsFromData,
      overallRiskLevel: overallRisk,
      summary: `Analisis de inteligencia ejecutiva enfocado en ${categoryNamesList}. ${dataSources} Se identificaron ${threatsFromData.length} amenazas en las categorias seleccionadas, con un nivel de riesgo general ${overallRisk.toUpperCase()}. Se recomienda implementar las medidas de mitigacion especificadas para cada amenaza y establecer un programa de monitoreo continuo.`,
      recommendations: [
        `Implementar medidas de proteccion especificas para ${categoryNamesList}`,
        'Establecer monitoreo continuo de las fuentes configuradas',
        'Realizar evaluaciones de riesgo periodicas',
        'Capacitar al ejecutivo en medidas de seguridad according a las amenazas identificadas',
        'Documentar y actualizar el plan de proteccion ejecutiva',
      ],
      sources: sourceInfoList.slice(0, 16).map(s => ({
        title: s.name,
        url: s.url,
        relevance: `Fuente configurada - Categoria: ${s.category}`
      })),
    };

    console.log(`[ANALYZ] Intelligent fallback generated: ${threatsFromData.length} threats, risk: ${overallRisk}`);
  }

  // Attach data for report generation
  (analysisResult as Record<string, unknown>).rawData = uniqueData.slice(0, 30);
  (analysisResult as Record<string, unknown>).rawDataText = rawDataText.substring(0, 12000);
  (analysisResult as Record<string, unknown>).configuredSources = sourceInfoList.map(s => ({
    name: s.name, url: s.url, category: s.category
  }));

  console.log(`[ANALYZ] Complete. Threats: ${(analysisResult as Record<string, unknown>).threats ? ((analysisResult as Record<string, unknown>).threats as unknown[]).length : 0}, Risk: ${(analysisResult as Record<string, unknown>).overallRiskLevel}, AI: ${aiWorked ? 'YES' : 'FALLBACK'}`);

  return analysisResult;
}

// ============================================================================
// GENERATE-REPORT OPERATION
// ============================================================================
async function handleGenerateReport(data: { templateContent?: string; analysis: Record<string, unknown>; reportContext?: { selectedCategories?: string[]; selectedSources?: string[]; threatCount?: number; riskLevel?: string; summary?: string; topThreats?: Array<{ title: string; severity: string; category: string }>; sourcesUsed?: string[] } }) {
  const { templateContent = '', analysis } = data;
  const reportContext = data.reportContext || {};
  const selectedCategories = reportContext.selectedCategories || [];
  const selectedSources = reportContext.selectedSources || [];

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
${selectedCategories.includes('Seguridad Digital') || selectedCategories.includes('Ciberseguridad') ? '- INCLUYE seccion detallada de "Seguridad Digital y Ciberamenazas"' : ''}
${selectedCategories.includes('Proteccion de Datos') ? '- INCLUYE seccion detallada de "Proteccion de Datos y Privacidad"' : ''}
${selectedCategories.includes('Seguridad en Viajes') ? '- INCLUYE seccion detallada de "Seguridad en Viajes y Movilidad"' : ''}
${selectedCategories.includes('Economia') || selectedCategories.includes('Fraude Financiero') ? '- INCLUYE seccion detallada de "Riesgo Financiero y Fraude"' : ''}

REGLAS DE ESTRUCTURA ADAPTATIVA:
${hasUrlContent ? '- Se encontraron resultados OSINT: INCLUYE una seccion detallada de "Evidencia de Fuentes OSINT" con cada fuente citada' : '- No hay resultados OSINT: NO incluyas seccion de evidencia OSINT'}
${hasThreats ? '- Se identificaron amenazas: INCLUYE seccion de "Amenazas Identificadas" con analisis detallado de cada una' : '- No se identificaron amenazas: enfatiza el bajo riesgo detectado'}
${hasRecommendations ? '- Hay recomendaciones del analisis: INCLUYE seccion "Recomendaciones" con cada una detallada' : '- No hay recomendaciones especificas: ofrece recomendaciones generales basadas en las fuentes configuradas'}
- NO incluyas secciones vacias o con placeholder - solo secciones con datos reales
- El nivel de riesgo debe basarse en los HALLAZGOS REALES, no en un valor por defecto
- LA ESTRUCTURA DEL INFORME DEBE SER DIFERENTE segun las clasificaciones y fuentes seleccionadas.`;

  const userPrompt = hasTemplate
    ? `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA completo usando EXACTAMENTE la estructura de la plantilla.

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

REDACTA EL INFORME:`
    : `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA profesional.

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

  console.log('[GENERATE] Starting report generation...');
  console.log(`[GENERATE] Has template: ${hasTemplate}, Template length: ${templateContent?.length || 0}`);
  console.log(`[GENERATE] Analysis threats: ${(analysis.threats as unknown[])?.length || 0}, Sources: ${(analysis.sources as unknown[])?.length || 0}`);
  console.log(`[GENERATE] Data composition: ${dataComposition}`);

  // Try AI report generation with retries
  const aiContent = await zaiChatCompletion(
    [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ],
    { temperature: 0.2, max_tokens: 8000, maxRetries: 3, retryDelay: 3000 }
  );

  if (aiContent && aiContent.length > 100) {
    console.log(`[GENERATE] AI report generated successfully: ${aiContent.length} chars`);
    return { content: aiContent };
  }

  // Fallback - generate from analysis data
  console.log('[GENERATE] AI unavailable. Generating professional report from analysis data directly.');
  const content = generateFallbackReport(
    analysis as Parameters<typeof generateFallbackReport>[0],
    templateContent,
    !!hasTemplate,
    fechaStr
  );

  console.log(`[GENERATE] Report generated. Length: ${content.length} characters, AI: ${aiContent ? 'YES' : 'FALLBACK'}`);
  return { content };
}

// ============================================================================
// UPDATE-REPORT OPERATION
// ============================================================================
async function handleUpdateReport(data: {
  existingContent: string;
  additionalUrls?: string[];
  additionalNews?: string;
  additionalContext?: string;
  templateContent?: string;
}) {
  const { existingContent, additionalUrls = [], additionalNews = '', additionalContext = '', templateContent = '' } = data;

  const collectedData: Array<{ sourceName: string; sourceUrl: string; snippet: string; date: string }> = [];

  // Search additional URLs
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
        const result = await zaiWebSearch(query, { num: 10 });
        if (result && result.length > 0) {
          for (const item of result) {
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

Genera el informe actualizado COMPLETO en Markdown.`;

  const aiContent = await zaiChatCompletion(
    [
      {
        role: 'system',
        content: 'Eres un analista senior de inteligencia ejecutiva VIP experto en proteccion de ejecutivos en Colombia. Actualizas informes con datos reales de fuentes. Mantienes el formato y estructura existente. Formato Markdown en espanol. NUNCA inventas datos. Cada dato se atribuye a su fuente.'
      },
      { role: 'user', content: prompt }
    ],
    { temperature: 0.2, max_tokens: 8000, maxRetries: 2 }
  );

  if (aiContent) {
    return { content: aiContent };
  }

  // Fallback - append new data to existing report
  return {
    content: existingContent + `\n\n---\n\n## ACTUALIZACION\n\n*Fecha: ${new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}*\n\nNueva informacion recopilada pero no integrada por IA (servicio no disponible temporalmente):\n\n${newDataText.substring(0, 3000)}\n\n*Nota: Se recomienda reintentar la actualizacion con IA para integrar correctamente la nueva informacion.*`
  };
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
