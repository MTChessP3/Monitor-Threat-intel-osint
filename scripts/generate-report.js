// Generate report - runs as child process (memory optimized)
const ZAI = require('z-ai-web-dev-sdk').default;

const input = JSON.parse(process.argv[2] || '{}');

(async () => {
  const zai = await ZAI.create();
  const { templateContent, analysis } = input;

  // Build detailed threats section
  const threatsDetail = (analysis.threats || []).map(t =>
    `- [${t.severity?.toUpperCase() || 'MEDIO'}] ${t.title}: ${t.description} (Categoría: ${t.category || 'seguridad'})`
  ).join('\n');

  // Build recommendations section
  const recommendations = (analysis.recommendations || []).map(r => `- ${r}`).join('\n');

  // Build sources section
  const sourcesList = (analysis.sources || []).map(s => `- ${s.title || s.url}: ${s.relevance || 'Fuente de inteligencia'}`).join('\n');

  // Template guidance
  const templateGuidance = templateContent && templateContent.trim().length > 10
    ? `PLANTILLA OFICIAL DEL USUARIO (DEBE SEGUIR esta estructura y llenar las secciones con la información de inteligencia recopilada):\n${templateContent.substring(0, 3000)}\n\nINSTRUCCIÓN CRÍTICA: Usa la estructura de la plantilla anterior y LLENA cada sección con la información de inteligencia real. Mantén los títulos y formato de la plantilla.`
    : 'Usa el formato estándar de informe de inteligencia ejecutiva VIP que se proporciona a continuación.';

  const prompt = `Genera un INFORME DE INTELIGENCIA EJECUTIVA VIP completo y profesional en formato Markdown en español.

${templateGuidance}

DATOS DEL ANÁLISIS DE INTELIGENCIA:
- Nivel de Riesgo General: ${analysis.overallRiskLevel || 'medio'}
- Resumen: ${analysis.summary || 'Sin resumen disponible'}

AMENAZAS DETECTADAS:
${threatsDetail || 'No se detectaron amenazas específicas'}

RECOMENDACIONES:
${recommendations || 'Monitoreo continuo recomendado'}

FUENTES DE INTELIGENCIA:
${sourcesList || 'Fuentes clasificadas'}

REQUISITOS DEL INFORME:
1. Encabezado con clasificación y fecha
2. Resumen ejecutivo detallado (mínimo 3 párrafos)
3. Evaluación del nivel de amenaza con justificación
4. Análisis detallado de cada amenaza detectada
5. Matriz de riesgos con probabilidad e impacto
6. Recomendaciones operativas específicas y accionables
7. Protocolos de seguridad sugeridos
8. Conclusiones y próximos pasos
9. Lista de fuentes consultadas

Genera el informe completo en Markdown con formato profesional. Sé extenso y detallado.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Eres un redactor senior de informes de inteligencia ejecutiva VIP. Generas informes profesionales, detallados y bien estructurados en formato Markdown en español. Los informes deben ser extensos, con análisis profundo y recomendaciones accionables.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.4,
    max_tokens: 4000,
  });

  const content = completion.choices?.[0]?.message?.content || 'Error al generar el informe. Por favor intente nuevamente.';
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
