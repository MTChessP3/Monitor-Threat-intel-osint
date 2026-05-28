// Generate report - runs as child process
const ZAI = require('z-ai-web-dev-sdk').default;

const input = JSON.parse(process.argv[2] || '{}');

(async () => {
  const zai = await ZAI.create();
  const { templateContent, analysis } = input;

  const threatsDetail = (analysis.threats || []).map(t =>
    `[${(t.severity || 'medio').toUpperCase()}] ${t.title}: ${t.description} (${t.category || 'seguridad'})`
  ).join('\n');

  const recommendations = (analysis.recommendations || []).slice(0, 8).join('; ');

  const sourcesList = (analysis.sources || []).map(s =>
    `${s.title || s.url}: ${s.relevance || ''}`
  ).join('; ');

  let rawDataSummary = '';
  if (analysis.rawDataText) {
    rawDataSummary = analysis.rawDataText.substring(0, 3000);
  } else if (analysis.rawData && analysis.rawData.length > 0) {
    rawDataSummary = analysis.rawData.slice(0, 12).map((item, i) =>
      `[${i+1}] ${item.sourceName}: ${item.snippet}`
    ).join('\n');
  }

  const hasTemplate = templateContent && templateContent.trim().length > 50;

  let prompt;

  if (hasTemplate) {
    prompt = `Genera un informe de inteligencia ejecutiva en Markdown espanol usando EXACTAMENTE esta plantilla:

---
${templateContent.substring(0, 4500)}
---

DATOS DE INTELIGENCIA RECOPILADOS DE FUENTES REALES:
- Nivel de Riesgo: ${analysis.overallRiskLevel || 'medio'}
- Resumen: ${analysis.summary || 'Sin resumen'}

AMENAZAS DETECTADAS (de fuentes reales):
${threatsDetail || 'No se detectaron amenazas especificas'}

INFORMACION ESPECIFICA DE FUENTES:
${rawDataSummary || 'Ver fuentes consultadas'}

RECOMENDACIONES:
${recommendations || 'Monitoreo continuo'}

FUENTES CONSULTADAS:
${sourcesList || 'Fuentes clasificadas'}

INSTRUCCIONES CRITICAS:
1. USA LA ESTRUCTURA EXACTA DE LA PLANTILLA - mismos titulos, mismas secciones, mismo orden
2. Manten intactas las secciones legales (Confidencialidad, Descargo)
3. LLENA cada seccion vacia con informacion REAL de las fuentes
4. En Hallazgos Clave: lista TODOS los hallazgos con referencias a fuentes
5. En Evidencia Tecnica: incluye datos especificos (URLs, fechas, cifras)
6. En Monitoreo de amenazas: diagnostico basado en datos reales
7. En Conclusiones: resumen con datos concretos y proximos pasos
8. En Referencias: TODAS las fuentes con URLs
9. Menciona de que fuente viene cada dato
10. NO inventes informacion - solo datos de las fuentes
11. Se EXTENSO y PROFESIONAL`;

  } else {
    prompt = `Genera informe de inteligencia ejecutiva profesional en Markdown.

Nivel de Riesgo: ${analysis.overallRiskLevel || 'medio'}
Resumen: ${analysis.summary || 'Sin resumen'}

AMENAZAS:
${threatsDetail || 'No detectadas'}

FUENTES:
${rawDataSummary.substring(0, 2000)}

RECOMENDACIONES:
${recommendations}

Menciona fuentes especificas. Extenso y profesional.`;
  }

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Eres un redactor senior de informes de inteligencia ejecutiva y ciberseguridad. Generas informes detallados y profesionales basados en datos reales. NUNCA inventas informacion. Siempre mencionas la fuente de cada dato. Formato Markdown en espanol.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.3,
    max_tokens: 3000,
  });

  const content = completion.choices?.[0]?.message?.content || 'Error al generar informe.';
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
