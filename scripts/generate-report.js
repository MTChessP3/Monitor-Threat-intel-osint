// Generate report - runs as child process (memory optimized)
const ZAI = require('z-ai-web-dev-sdk').default;

const input = JSON.parse(process.argv[2] || '{}');

(async () => {
  const zai = await ZAI.create();
  const { templateContent, analysis } = input;

  // Keep prompt short to reduce memory usage
  const threatsSummary = (analysis.threats || []).slice(0, 5).map(t =>
    `[${t.severity}] ${t.title}: ${(t.description || '').substring(0, 100)}`
  ).join('; ');

  const prompt = `Genera informe ejecutivo VIP en Markdown español.
Riesgo: ${analysis.overallRiskLevel}. Resumen: ${(analysis.summary || '').substring(0, 200)}.
Amenazas: ${threatsSummary}
Rec: ${(analysis.recommendations || []).slice(0, 5).join('; ')}
Plantilla: ${(templateContent || 'Estándar').substring(0, 500)}
Informe completo Markdown.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Redactor informes VIP. Markdown español. Sé conciso.' },
      { role: 'user', content: prompt }
    ],
  });

  const content = completion.choices?.[0]?.message?.content || 'Error';
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
