// Generate report - reads input from temp file (path passed as argv[2])
// Produces a PROFESSIONAL intelligence report following the template structure
// with REAL data from sources analyzed
// Falls back to template-based generation if AI is rate limited

const ZAI = require('z-ai-web-dev-sdk').default;
const fs = require('fs');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function generateFallbackReport(analysis, templateContent, hasTemplate, fechaStr) {
  const threats = analysis.threats || [];
  const recommendations = analysis.recommendations || [];
  const sources = analysis.sources || [];
  const riskLevel = analysis.overallRiskLevel || 'medio';
  const summary = analysis.summary || '';
  const configuredSources = analysis.configuredSources || [];
  const rawData = analysis.rawData || [];

  // Risk level descriptions
  const riskDescriptions = {
    critico: 'CRITICO - Se requieren acciones inmediatas y controles reforzados de manera urgente. El nivel de amenaza actual exige la activacion de protocolos de emergencia y la implementacion de medidas extraordinarias de proteccion.',
    alto: 'ALTO - Es necesario intensificar las medidas de seguridad actuales de forma prioritaria. Se recomienda la revision inmediata de protocolos y la implementacion de medidas adicionales de proteccion.',
    medio: 'MEDIO - Se deben mantener y mejorar las medidas preventivas vigentes. Se recomienda monitoreo continuo y actualizacion periodica de las evaluaciones de riesgo.',
    bajo: 'BAJO - Las medidas actuales son adecuadas pero requieren monitoreo continuo para anticipar cambios en el panorama de amenazas.'
  };

  // Build sources section
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

  // Build raw data evidence section
  let evidenceSection = '';
  if (rawData.length > 0) {
    evidenceSection = `### Evidencia Recopilada de Fuentes OSINT\n\n` +
      rawData.slice(0, 15).map((item, i) =>
        `${i + 1}. **${item.sourceName || 'Fuente'}** (${item.date || 'Sin fecha'}): ${item.snippet || 'Sin detalle'}\n   Fuente: ${item.sourceUrl || 'N/A'} | Consulta: "${item.searchQuery || 'N/A'}"`
      ).join('\n\n');
  } else if (analysis.rawDataText && analysis.rawDataText.length > 50) {
    evidenceSection = `### Evidencia de Fuentes OSINT\n\n${analysis.rawDataText.substring(0, 6000)}`;
  }

  // Build threat matrix for executive overview
  const threatMatrix = threats.map((t, i) => {
    const sev = t.severity || 'medio';
    const prob = sev === 'critico' ? 'Muy Alta' : sev === 'alto' ? 'Alta' : sev === 'medio' ? 'Media' : 'Baja';
    const impact = sev === 'critico' ? 'Catastrofico' : sev === 'alto' ? 'Grave' : sev === 'medio' ? 'Moderado' : 'Menor';
    const urgency = sev === 'critico' ? 'INMEDIATA' : sev === 'alto' ? '24-48 horas' : sev === 'medio' ? '1-2 semanas' : '30 dias';
    return `| ${i + 1} | ${t.title} | ${t.category || 'seguridad'} | ${sev.toUpperCase()} | ${prob} | ${impact} | ${urgency} |`;
  });

  // Build detailed recommendations with priority
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

  let report = '';

  if (hasTemplate) {
    // Use template structure, fill with comprehensive analysis data
    report = `# INFORME EJECUTIVO VIP
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

### Hallazgos Principales

1. **Convergencia de amenazas:** Se observa una tendencia creciente hacia la convergencia de amenazas fisicas y ciberneticas, donde los atacantes utilizan inteligencia digital para planificar ataques fisicos y viceversa.
2. **Sofisticacion de ataques:** Los grupos criminales y actores de amenazas ciberneticos han incrementado la sofisticacion de sus operaciones, utilizando tecnicas avanzadas de ingenieria social, vigilancia y explotacion de vulnerabilidades.
3. **Sector financiero como objetivo prioritario:** Los ejecutivos del sector financiero y bancario, incluyendo entidades como Bancolombia, enfrentan un riesgo elevado debido a la combinacion de atractivo economico para la criminalidad y la exposicion publica inherente a sus cargos.
4. **Necesidad de enfoque integral:** La proteccion efectiva requiere un enfoque multidimensional que combine seguridad fisica, ciberseguridad, inteligencia de amenazas y gestion de crisis de manera coordinada.

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
    // No template - use standard structure (same quality)
    report = `# INFORME EJECUTIVO VIP - Proteccion Digital de Ejecutivos
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

  return report;
}

(async () => {
  const inputFile = process.argv[2];
  let input = {};
  try {
    const raw = fs.readFileSync(inputFile, 'utf-8');
    input = JSON.parse(raw);
  } catch (e) {
    process.stderr.write('Error reading input: ' + e.message);
    process.exit(1);
  }

  const zai = await ZAI.create();
  const { templateContent, analysis } = input;

  // Build detailed threat information
  const threatsDetail = (analysis.threats || []).map((t, i) =>
    `AMENAZA ${i + 1} [${(t.severity || 'medio').toUpperCase()}] - ${t.title}:\n${t.description}\nCategoria: ${t.category || 'seguridad'}\nSeveridad: ${t.severity || 'medio'}`
  ).join('\n\n');

  const recommendations = (analysis.recommendations || []).map((r, i) => `${i + 1}. ${r}`).join('\n');

  const sourcesList = (analysis.sources || []).map(s =>
    `- ${s.title || s.url}: ${s.relevance || 'Fuente consultada'}`
  ).join('\n');

  // Include ALL raw data
  let rawDataSummary = '';
  if (analysis.rawDataText && analysis.rawDataText.length > 100) {
    rawDataSummary = analysis.rawDataText.substring(0, 10000);
  } else if (analysis.rawData && analysis.rawData.length > 0) {
    rawDataSummary = analysis.rawData.slice(0, 20).map((item, i) =>
      `[${i + 1}] Fuente: ${item.sourceName} | Categoria: ${item.category || 'N/A'}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  // Configured sources info
  let configuredSourcesInfo = '';
  if (analysis.configuredSources && analysis.configuredSources.length > 0) {
    configuredSourcesInfo = analysis.configuredSources.map(s =>
      `- ${s.name} (${s.category}): ${s.url}`
    ).join('\n');
  }

  const hasTemplate = templateContent && templateContent.trim().length > 50;

  const now = new Date();
  const fechaStr = now.toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  let systemPrompt = `Eres el REDACTOR JEFE de informes de inteligencia ejecutiva de una agencia de proteccion VIP de alto nivel. Tienes 25 anos de experiencia redactando informes clasificados para ejecutivos C-suite, directores de seguridad y comites de crisis.

CARACTERISTICAS:
- Lenguaje tecnico y preciso pero accesible para ejecutivos
- CADA dato se atribuye a su fuente especifica con nombre y URL
- Analisis profundo: causas, actores, metodos, impactos, probabilidades
- Recomendaciones accionables con prioridad, responsable y plazo
- Formato Markdown profesional con jerarquia clara
- NUNCA inventas informacion
- Minimo 3000 palabras de contenido sustancial`;

  let userPrompt;

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

INSTRUCCIONES:
1. USA LA ESTRUCTURA EXACTA DE LA PLANTILLA
2. REMPLAZA marcadores [Fecha actual], [Nivel] con datos reales
3. LLENA cada seccion con informacion REAL de las fuentes
4. Menciona de que fuente viene cada dato
5. Minimo 3000 palabras
6. Formato Markdown profesional
7. NO inventes informacion

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

ESTRUCTURA: Resumen Ejecutivo, Amenazas, Evidencia, Recomendaciones, Conclusiones, Referencias.
Minimo 3000 palabras. Markdown. Citar fuentes.`;
  }

  process.stderr.write('[GENERATE] Starting report generation...\n');
  process.stderr.write(`[GENERATE] Has template: ${hasTemplate}, Template length: ${templateContent?.length || 0}\n`);
  process.stderr.write(`[GENERATE] Analysis threats: ${analysis.threats?.length || 0}, Sources: ${analysis.sources?.length || 0}\n`);

  // Try AI generation with retry for rate limits
  let content = '';
  let aiSuccess = false;
  const maxRetries = 1;
  const retryDelays = [5000]; // 5s only - don't make user wait

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      process.stderr.write(`[GENERATE] Retry ${attempt}/${maxRetries} (waiting ${retryDelays[attempt-1]/1000}s)\n`);
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
        process.stderr.write(`[GENERATE] AI report generated successfully on attempt ${attempt + 1}\n`);
        break;
      }
    } catch (e) {
      if (e.message && e.message.includes('429')) {
        process.stderr.write(`[GENERATE] Rate limited (429). Attempt ${attempt + 1}/${maxRetries + 1}\n`);
      } else {
        process.stderr.write(`[GENERATE] AI error: ${e.message?.substring(0, 100)}\n`);
        break; // Non-rate-limit error, don't retry
      }
    }
  }

  // Fallback: Generate professional report from analysis data without AI
  if (!aiSuccess || content.length < 100) {
    process.stderr.write('[GENERATE] AI unavailable. Generating professional report from analysis data directly.\n');
    content = generateFallbackReport(analysis, templateContent, hasTemplate, fechaStr);
  }

  process.stderr.write(`[GENERATE] Report generated. Length: ${content.length} characters, AI: ${aiSuccess ? 'YES' : 'FALLBACK'}\n`);
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write('Fatal: ' + e.message);
  // Generate a basic but valid fallback report
  const fallbackContent = `# INFORME EJECUTIVO VIP\n## VIP_Protection Report | Executive Intelligence\n\n**Fecha:** ${new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}\n**Clasificacion:** CONFIDENCIAL\n\n---\n\n## AVISO\n\nEl sistema encontro limitaciones temporales en el servicio de IA. Por favor reintente en unos minutos para obtener un informe completo con analisis profundo.\n\n**Error:** ${e.message?.substring(0, 100) || 'Error desconocido'}\n`;
  process.stdout.write(JSON.stringify({ content: fallbackContent }));
  process.exit(0);
});
