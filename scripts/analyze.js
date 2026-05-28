// Analyze intelligence - runs as child process
const ZAI = require('z-ai-web-dev-sdk').default;

const urls = JSON.parse(process.argv[2] || '[]');
const searchQueries = JSON.parse(process.argv[3] || '[]');

(async () => {
  const zai = await ZAI.create();

  // Build search query
  let mainQuery = '';
  if (searchQueries.length > 0) mainQuery = searchQueries[0];
  else if (urls.length > 0) {
    try { mainQuery = 'site:' + new URL(urls[0]).hostname + ' seguridad VIP amenazas'; }
    catch { mainQuery = 'amenazas seguridad VIP protección'; }
  } else {
    mainQuery = 'amenazas seguridad VIP protección ejecutiva 2026';
  }

  // Search
  let searchData = '';
  try {
    const result = await zai.functions.invoke('web_search', { query: mainQuery, num: 8 });
    if (result && Array.isArray(result)) {
      searchData = result.map(r => `[${r.name || ''}] ${r.snippet || ''} (${r.url || ''})`).join('\n');
    }
  } catch (e) { searchData = 'Search error: ' + e.message; }

  if (!searchData) {
    process.stdout.write(JSON.stringify({ error: 'No data collected' }));
    return;
  }

  // AI Analysis
  const prompt = `Analiza info de inteligencia VIP. Responde SOLO JSON válido: {"threats":[{"title":"","description":"","severity":"bajo|medio|alto|critico","category":"seguridad|politica|economia|social"}],"overallRiskLevel":"bajo|medio|alto|critico","summary":"","recommendations":[],"sources":[{"title":"","url":"","relevance":""}]}\n\n${searchData}`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Analista inteligencia VIP. JSON válido.' },
      { role: 'user', content: prompt }
    ]
  });

  const text = completion.choices?.[0]?.message?.content || '';
  try {
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      process.stdout.write(JSON.stringify(JSON.parse(m[0])));
      return;
    }
  } catch {}

  process.stdout.write(JSON.stringify({
    threats: [{ title: 'Análisis', description: text.substring(0, 500), severity: 'medio', category: 'seguridad' }],
    overallRiskLevel: 'medio',
    summary: text.substring(0, 300),
    recommendations: ['Monitoreo'],
    sources: []
  }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
