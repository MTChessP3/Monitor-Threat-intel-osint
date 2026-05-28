// Generate report - reads input from temp file (path passed as argv[2])
// Produces a PROFESSIONAL intelligence report following the template structure
// with REAL data from sources analyzed

const ZAI = require('z-ai-web-dev-sdk').default;
const fs = require('fs');

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

  // Include ALL raw data - this is the actual intelligence from sources
  let rawDataSummary = '';
  if (analysis.rawDataText && analysis.rawDataText.length > 100) {
    rawDataSummary = analysis.rawDataText.substring(0, 10000);
  } else if (analysis.rawData && analysis.rawData.length > 0) {
    rawDataSummary = analysis.rawData.slice(0, 20).map((item, i) =>
      `[${i + 1}] Fuente: ${item.sourceName} | Categoria: ${item.category || 'N/A'}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Consulta: ${item.searchQuery}\n    Contenido: ${item.snippet}`
    ).join('\n\n');
  }

  // Include configured sources info
  let configuredSourcesInfo = '';
  if (analysis.configuredSources && analysis.configuredSources.length > 0) {
    configuredSourcesInfo = analysis.configuredSources.map(s =>
      `- ${s.name} (${s.category}): ${s.url}`
    ).join('\n');
  }

  const hasTemplate = templateContent && templateContent.trim().length > 50;

  // Current date in Spanish format
  const now = new Date();
  const fechaStr = now.toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  let systemPrompt = `Eres el REDACTOR JEFE de informes de inteligencia ejecutiva de una agencia de proteccion VIP de alto nivel. Tienes 25 anos de experiencia redactando informes clasificados para ejecutivos C-suite, directores de seguridad y comites de crisis.

CARACTERISTICAS DE TUS INFORMES:
- Lenguaje tecnico y preciso pero accesible para ejecutivos no tecnicos
- CADA dato, cifra o afirmacion se atribuye a su fuente especifica con nombre y URL
- Analisis profundo: causas, actores, metodos, impactos, probabilidades
- Recomendaciones accionables con prioridad, responsable y plazo
- Formato Markdown profesional con jerarquia clara
- NUNCA inventas informacion - si no hay datos, lo indicas explicitamente
- Estilo formal de documento de inteligencia gubernamental/corporativo
- Minimo 3000 palabras de contenido sustancial
- Cada seccion debe ser exhaustiva y detallada`;

  let userPrompt;

  if (hasTemplate) {
    userPrompt = `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA completo y profesional usando EXACTAMENTE la estructura de la plantilla oficial proporcionada.

== PLANTILLA OFICIAL (USA ESTA ESTRUCTURA EXACTA - respeta secciones, numeros, orden) ==
---
${templateContent}
---

== FECHA DEL INFORME ==
${fechaStr}

== NIVEL DE RIESGO GENERAL ==
${analysis.overallRiskLevel || 'medio'}

== RESUMEN DEL ANALISIS DE INTELIGENCIA ==
${analysis.summary || 'Sin resumen disponible'}

== AMENAZAS DETECTADAS (analizadas por inteligencia artificial) ==
${threatsDetail || 'No se detectaron amenazas especificas'}

== INFORMACION CRUDA RECOPILADA DE FUENTES OSINT ==
${rawDataSummary || 'Informacion limitada - consulte fuentes directamente'}

== RECOMENDACIONES DEL ANALISTA ==
${recommendations || 'Monitoreo continuo de fuentes'}

== FUENTES CONSULTADAS ==
${sourcesList || 'Fuentes clasificadas'}

== FUENTES CONFIGURADAS EN EL SISTEMA ==
${configuredSourcesInfo || 'Fuentes no especificadas'}

INSTRUCCIONES CRITICAS:
1. USA LA ESTRUCTURA EXACTA DE LA PLANTILLA - cada seccion, cada numero, cada titulo
2. REMPLAZA los marcadores [Fecha actual], [Nivel], etc. con datos reales
3. LLENA cada seccion de la plantilla con informacion REAL y ESPECIFICA de las fuentes
4. Menciona EXPLICITAMENTE de que fuente viene cada dato: "Segun El Tiempo...", "De acuerdo con Kaspersky..."
5. Se EXTENSO: cada seccion debe tener minimo 200 palabras de contenido sustancial
6. El informe COMPLETO debe tener minimo 3000 palabras
7. Incluye datos especificos: numeros, porcentajes, fechas, ubicaciones, actores
8. Si la plantilla tiene 5 amenazas, analysisa y describe cada una con datos reales
9. Si la plantilla tiene 5 recomendaciones, desarrolla cada una extensamente
10. Formato Markdown con # ## ### headers, listas con -, negritas con **
11. NO inventes informacion que no este en las fuentes
12. Si hay poca informacion sobre un tema, indicalo como "Informacion limitada en fuentes" y sugiere fuentes adicionales

REDACTA EL INFORME COMPLETO AHORA:`;

  } else {
    userPrompt = `REDACTA un INFORME DE INTELIGENCIA EJECUTIVA profesional y exhaustivo para proteccion VIP.

== FECHA ==
${fechaStr}

== NIVEL DE RIESGO ==
${analysis.overallRiskLevel || 'medio'}

== RESUMEN DEL ANALISIS ==
${analysis.summary || 'Sin resumen'}

== AMENAZAS DETECTADAS ==
${threatsDetail || 'No detectadas'}

== INFORMACION DE FUENTES OSINT ==
${rawDataSummary.substring(0, 8000) || 'Limitada'}

== RECOMENDACIONES ==
${recommendations || 'Monitoreo continuo'}

== FUENTES ==
${sourcesList || 'Fuentes clasificadas'}

== FUENTES CONFIGURADAS EN EL SISTEMA ==
${configuredSourcesInfo || 'Fuentes no especificadas'}

ESTRUCTURA OBLIGATORIA:
# INFORME EJECUTIVO VIP - Proteccion Digital de Ejecutivos
## VIP_Protection Report | Executive Intelligence

**Fecha:** ${fechaStr}
**Nivel de Amenaza:** ${analysis.overallRiskLevel || 'medio'}
**Clasificacion:** CONFIDENCIAL

## RESUMEN EJECUTIVO
(Minimo 300 palabras con hallazgos clave, datos especificos y fuentes citadas)

## AMENAZAS IDENTIFICADAS
(Analisis detallado de CADA amenaza con: actores, metodos, probabilidad, impacto, fuentes)

## ANALISIS DE FUENTES
(Detalle de que informacion aporto cada fuente consultada)

## RECOMENDACIONES
(Recomendaciones accionables con prioridad, responsable y plazo estimado)

## CONCLUSIONES
(Sintesis del analisis con evaluacion final de riesgo)

## REFERENCIAS
(Lista completa de fuentes con URLs)

INSTRUCCIONES:
- Minimo 3000 palabras de contenido sustancial
- Cada dato atribuido a su fuente
- Formato Markdown profesional
- NO inventar informacion`;

  }

  process.stderr.write('[GENERATE] Starting report generation...\n');
  process.stderr.write(`[GENERATE] Has template: ${hasTemplate}, Template length: ${templateContent?.length || 0}\n`);
  process.stderr.write(`[GENERATE] Analysis threats: ${analysis.threats?.length || 0}, Sources: ${analysis.sources?.length || 0}\n`);

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ],
    temperature: 0.2,
    max_tokens: 8000,
  });

  const content = completion.choices?.[0]?.message?.content || 'Error al generar informe.';

  process.stderr.write(`[GENERATE] Report generated. Length: ${content.length} characters\n`);

  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write('Fatal: ' + e.message);
  process.exit(1);
});
