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
  const summary = analysis.summary || 'Analisis de inteligencia completado.';
  const configuredSources = analysis.configuredSources || [];

  let report = '';

  if (hasTemplate) {
    // Use template structure, fill with analysis data
    report = `# INFORME EJECUTIVO VIP
## VIP_Protection Report | Executive Intelligence

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL

---

## RESUMEN EJECUTIVO

${summary}

El presente informe ha sido generado por el sistema de inteligencia ejecutiva VIP_Protection Report, el cual realizo un analisis automatizado de las fuentes de inteligencia configuradas. El nivel de riesgo general evaluado es **${riskLevel.toUpperCase()}**, basado en el analisis de ${threats.length} amenazas identificadas y la consulta de ${configuredSources.length} fuentes de inteligencia.

---

## AMENAZAS IDENTIFICADAS

${threats.length > 0 ? threats.map((t, i) => `### ${i + 1}. ${t.title} [${(t.severity || 'medio').toUpperCase()}]
${t.description}
- **Categoria:** ${t.category || 'seguridad'}
- **Severidad:** ${t.severity || 'medio'}
- **Probabilidad:** Alta
- **Impacto:** ${t.severity === 'critico' ? 'Critico - requiere accion inmediata' : t.severity === 'alto' ? 'Alto - requiere atencion prioritaria' : t.severity === 'medio' ? 'Medio - requiere monitoreo' : 'Bajo - mantener vigilancia'}
- **Medidas de mitigacion:** Implementar protocolos de seguridad especificos para esta amenaza, incluir capacitacion del personal y actualizacion de controles de seguridad.`).join('\n\n') : 'No se identificaron amenazas especificas en el periodo analizado.'}

---

## RECOMENDACIONES

${recommendations.length > 0 ? recommendations.map((r, i) => `### ${i + 1}. ${r}
**Prioridad:** ${i < 2 ? 'Alta' : 'Media'}
**Plazo:** ${i < 2 ? 'Inmediato (0-30 dias)' : 'Corto plazo (30-90 dias)'}
**Responsable:** Direccion de Seguridad / equipo de proteccion VIP`).join('\n\n') : `### 1. Evaluaciones de riesgo periodicas
Actualizar analisis de amenazas cada 3 meses o tras incidentes relevantes.
**Prioridad:** Alta | **Plazo:** Inmediato

### 2. Medidas de seguridad integrales
Reforzar seguridad fisica en residencias, vehiculos y lugares de trabajo. Implementar soluciones de cibercuidado.
**Prioridad:** Alta | **Plazo:** 30 dias

### 3. Planes de respuesta ante emergencias
Protocolos claros para secuestro, extorsion o ataques digitales.
**Prioridad:** Alta | **Plazo:** 15 dias

### 4. Equipos de escolta especializados
Formacion continua en tecnicas de proteccion y manejo de crisis.
**Prioridad:** Media | **Plazo:** 60 dias

### 5. Protocolos de comunicacion segura
Uso de encriptacion en dispositivos y canales. Redundancia de sistemas criticos.
**Prioridad:** Media | **Plazo:** 45 dias`}

---

## CONCLUSIONES

La proteccion VIP requiere un enfoque multidimensional que combine tecnologia, personal capacitado y planificacion estrategica. La implementacion oportuna de las medidas recomendadas reduce significativamente el riesgo y garantiza la seguridad del protegido. El nivel de riesgo evaluado de **${riskLevel.toUpperCase()}** indica que ${riskLevel === 'critico' ? 'se requieren acciones inmediatas y controles reforzados' : riskLevel === 'alto' ? 'es necesario intensificar las medidas de seguridad actuales' : riskLevel === 'medio' ? 'se deben mantener y mejorar las medidas preventivas' : 'las medidas actuales son adecuadas pero requieren monitoreo continuo'}.

---

## FUENTES CONSULTADAS

${sources.length > 0 ? sources.map(s => `- **${s.title || 'Fuente'}**: ${s.relevance || 'Fuente de inteligencia consultada'} ${s.url ? `([${s.url}](${s.url}))` : ''}`).join('\n') : configuredSources.length > 0 ? configuredSources.map(s => `- **${s.name}** (${s.category}): Fuente de inteligencia OSINT configurada - [${s.url}](${s.url})`).join('\n') : 'Fuentes de inteligencia clasificadas'}

---

*Documento generado por VIP_Protection Report - Executive Intelligence System*
*NOTA: Este informe fue generado en modo de respaldo debido a limitaciones temporales del servicio de IA. Para un informe con analisis mas profundo, reintentar en unos minutos.*`;
  } else {
    // No template - use standard structure
    report = `# INFORME EJECUTIVO VIP - Proteccion Digital de Ejecutivos
## VIP_Protection Report | Executive Intelligence

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${riskLevel.toUpperCase()}
**Clasificacion:** CONFIDENCIAL

---

## RESUMEN EJECUTIVO

${summary}

---

## AMENAZAS IDENTIFICADAS

${threats.length > 0 ? threats.map((t, i) => `### ${i + 1}. ${t.title} [${(t.severity || 'medio').toUpperCase()}]
${t.description}
- Categoria: ${t.category || 'seguridad'}`).join('\n\n') : 'No se identificaron amenazas especificas.'}

---

## RECOMENDACIONES

${recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n')}

---

## FUENTES

${configuredSources.map(s => `- ${s.name} (${s.category}): ${s.url}`).join('\n')}

---
*Documento generado por VIP_Protection Report - Executive Intelligence System*`;
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
  const maxRetries = 3;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      if (attempt > 0) {
        const waitMs = Math.min(15000 * Math.pow(2, attempt - 1), 60000);
        process.stderr.write(`[GENERATE] Retry ${attempt}/${maxRetries} (waiting ${waitMs/1000}s)\n`);
        await sleep(waitMs);
      }

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
        break;
      }
    } catch (e) {
      if (e.message && e.message.includes('429')) {
        process.stderr.write(`[GENERATE] Rate limited (429). Attempt ${attempt + 1}/${maxRetries}\n`);
      } else {
        process.stderr.write(`[GENERATE] AI error: ${e.message}\n`);
        break;
      }
    }
  }

  // Fallback: Generate report from analysis data without AI
  if (!aiSuccess || content.length < 100) {
    process.stderr.write('[GENERATE] AI unavailable. Generating report from analysis data directly.\n');
    content = generateFallbackReport(analysis, templateContent, hasTemplate, fechaStr);
  }

  process.stderr.write(`[GENERATE] Report generated. Length: ${content.length} characters\n`);
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write('Fatal: ' + e.message);
  const fallbackContent = `# INFORME EJECUTIVO VIP\n## VIP_Protection Report | Executive Intelligence\n\n**Fecha:** ${new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}\n**Clasificacion:** CONFIDENCIAL\n\n---\n\n## AVISO\n\nEl sistema encontro limitaciones temporales en el servicio de IA. Por favor reintente en unos minutos para obtener un informe completo con analisis profundo.\n\n**Error:** ${e.message?.substring(0, 100) || 'Error desconocido'}\n`;
  process.stdout.write(JSON.stringify({ content: fallbackContent }));
  process.exit(0);
});
