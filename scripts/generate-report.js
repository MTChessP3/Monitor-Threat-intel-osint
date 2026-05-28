// Generate report - reads input from temp file (path passed as argv[2])
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

  const threatsDetail = (analysis.threats || []).map(t =>
    `[${(t.severity || 'medio').toUpperCase()}] ${t.title}:\n${t.description}\nCategoria: ${t.category || 'seguridad'}`
  ).join('\n\n');

  const recommendations = (analysis.recommendations || []).map((r, i) => `${i + 1}. ${r}`).join('\n');

  const sourcesList = (analysis.sources || []).map(s =>
    `- ${s.title || s.url}: ${s.relevance || 'Fuente consultada'}`
  ).join('\n');

  let rawDataSummary = '';
  if (analysis.rawDataText) {
    rawDataSummary = analysis.rawDataText.substring(0, 5000);
  } else if (analysis.rawData && analysis.rawData.length > 0) {
    rawDataSummary = analysis.rawData.slice(0, 15).map((item, i) =>
      `[${i + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Contenido: ${item.snippet}\n    Busqueda: ${item.searchQuery}`
    ).join('\n\n');
  }

  const hasTemplate = templateContent && templateContent.trim().length > 50;

  let systemPrompt = `Eres el REDACTOR JEFE de informes de inteligencia ejecutiva de una agencia de proteccion VIP. Tienes experiencia redactando informes clasificados para ejecutivos C-suite y directores de seguridad.

CARACTERISTICAS:
- Lenguaje tecnico pero accesible para ejecutivos
- Cada dato se atribuye a su fuente especifica
- Analisis profundo y detallado
- Recomendaciones accionables con prioridad
- Formato Markdown profesional
- NUNCA inventas informacion
- Si hay poca informacion, indicas limitaciones`;

  let userPrompt;

  if (hasTemplate) {
    userPrompt = `Genera un INFORME DE INTELIGENCIA EJECUTIVA usando EXACTAMENTE la estructura de la plantilla.

PLANTILLA OFICIAL (USA ESTA ESTRUCTURA):
---
${templateContent.substring(0, 6000)}
---

NIVEL DE RIESGO: ${analysis.overallRiskLevel || 'medio'}

RESUMEN DEL ANALISIS:
${analysis.summary || 'Sin resumen'}

AMENAZAS DETECTADAS:
${threatsDetail || 'No se detectaron amenazas'}

INFORMACION DE FUENTES:
${rawDataSummary || 'Informacion limitada'}

RECOMENDACIONES:
${recommendations || 'Monitoreo continuo'}

FUENTES CONSULTADAS:
${sourcesList || 'Fuentes clasificadas'}

INSTRUCCIONES:
1. USA LA ESTRUCTURA EXACTA DE LA PLANTILLA
2. Manten secciones legales intactas
3. LLENA cada seccion con informacion REAL de las fuentes
4. Menciona de que fuente viene cada dato
5. Se EXTENSO y PROFESIONAL - minimo 2000 palabras
6. Formato Markdown con headers, listas y negritas
7. NO inventes informacion

REDACTA EL INFORME:`;

  } else {
    userPrompt = `Genera un INFORME DE INTELIGENCIA EJECUTIVA profesional para proteccion VIP.

NIVEL DE RIESGO: ${analysis.overallRiskLevel || 'medio'}

RESUMEN:
${analysis.summary || 'Sin resumen'}

AMENAZAS:
${threatsDetail || 'No detectadas'}

INFORMACION DE FUENTES:
${rawDataSummary.substring(0, 3000) || 'Limitada'}

RECOMENDACIONES:
${recommendations || 'Monitoreo continuo'}

FUENTES:
${sourcesList || 'Fuentes clasificadas'}

ESTRUCTURA: Resumen Ejecutivo, Amenazas Detalladas, Evidencia, Recomendaciones, Conclusiones, Referencias.
Se extenso y profesional. Formato Markdown. Menciona fuentes.`;
  }

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ],
    temperature: 0.25,
    max_tokens: 6000,
  });

  const content = completion.choices?.[0]?.message?.content || 'Error al generar informe.';
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
