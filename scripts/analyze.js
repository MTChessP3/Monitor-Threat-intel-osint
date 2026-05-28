// Analyze intelligence - runs as child process
// This script searches EACH source individually and collects real information
const ZAI = require('z-ai-web-dev-sdk').default;

const urls = JSON.parse(process.argv[2] || '[]');
const searchQueries = JSON.parse(process.argv[3] || '[]');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  const zai = await ZAI.create();
  const allRawData = []; // Store ALL raw collected data

  // === PHASE 1: Collect information from EACH source ===
  
  // Build queries - one per source URL plus user queries
  const searchTasks = [];
  
  // Add user-provided search queries
  for (const q of searchQueries) {
    searchTasks.push({ type: 'query', value: q });
  }
  
  // Add source-specific searches - search for content ON each source
  for (const url of urls) {
    try {
      const hostname = new URL(url).hostname;
      searchTasks.push({ type: 'source', value: url, hostname });
    } catch {
      searchTasks.push({ type: 'source', value: url, hostname: url });
    }
  }
  
  // Default if nothing provided
  if (searchTasks.length === 0) {
    searchTasks.push({ type: 'query', value: 'proteccion digital ejecutivos amenazas ciberseguridad 2026' });
    searchTasks.push({ type: 'query', value: 'seguridad VIP amenazas inteligencia OSINT' });
    searchTasks.push({ type: 'query', value: 'phishing ejecutivos fraude digital Colombia 2026' });
  }

  // Execute searches with delays to avoid rate limiting
  for (let i = 0; i < searchTasks.length; i++) {
    const task = searchTasks[i];
    let query;
    
    if (task.type === 'source') {
      // Search specifically for content from this source
      query = `site:${task.hostname} seguridad amenazas proteccion digital ejecutivos`;
    } else {
      query = task.value;
    }
    
    try {
      const result = await zai.functions.invoke('web_search', { query, num: 8 });
      if (result && Array.isArray(result) && result.length > 0) {
        for (const item of result) {
          allRawData.push({
            sourceName: item.name || 'Unknown',
            sourceUrl: item.url || '',
            snippet: item.snippet || '',
            hostname: item.host_name || task.hostname || '',
            searchType: task.type,
            searchQuery: query
          });
        }
      }
    } catch (e) {
      // Continue with what we have
    }
    
    // Rate limiting delay between searches
    if (i < searchTasks.length - 1) {
      await sleep(2500);
    }
  }

  if (allRawData.length === 0) {
    process.stdout.write(JSON.stringify({
      threats: [],
      overallRiskLevel: 'bajo',
      summary: 'No se pudo recopilar informacion de las fuentes. Intente con diferentes terminos de busqueda o verifique que las fuentes esten accesibles.',
      recommendations: ['Reintentar con terminos mas especificos', 'Verificar accesibilidad de las fuentes'],
      sources: [],
      rawData: []
    }));
    return;
  }

  // === PHASE 2: Deep AI analysis of ALL collected data ===
  
  // Build comprehensive text of all collected data
  const rawDataText = allRawData.map((item, idx) => {
    return `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Contenido: ${item.snippet}\n    Busqueda: ${item.searchQuery}`;
  }).join('\n\n');

  const analysisPrompt = `Eres un analista SENIOR de inteligencia ejecutiva y ciberseguridad. Analiza DETALLADAMENTE la siguiente informacion recopilada de multiples fuentes de inteligencia.

INFORMACION RECOPILADA DE FUENTES (OSINT):
${rawDataText}

INSTRUCCIONES CRITICAS:
1. Analiza CADA fragmento de informacion individualmente
2. Identifica amenazas ESPECIFICAS mencionadas en las fuentes (no genericas)
3. Extrae datos concretos: nombres, fechas, cifras, ubicaciones, actores
4. Clasifica por severidad real basada en la evidencia encontrada
5. Proporciona un resumen ejecutivo DETALLADO con hallazgos especificos
6. Genera recomendaciones ESPECIFICAS basadas en la informacion recopilada
7. Lista TODAS las fuentes consultadas con su relevancia

Responde SOLO con JSON valido:
{
  "threats": [
    {"title": "titulo especifico de la amenaza detectada", "description": "descripcion detallada con datos especificos de las fuentes, menciona que fuente lo reporto", "severity": "bajo|medio|alto|critico", "category": "seguridad|politica|economia|social"}
  ],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen ejecutivo DETALLADO con hallazgos especificos, mencionando fuentes concretas y datos reales",
  "recommendations": ["recomendacion especifica 1 basada en hallazgos", "recomendacion especifica 2", "..."],
  "sources": [{"title": "nombre de la fuente", "url": "url", "relevance": "que informacion relevante aporto"}]
}`;

  const analysisCompletion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Eres un analista de inteligencia de alto nivel. Respondes SOLO con JSON valido. Tu analisis debe ser especifico, detallado y basado en los datos proporcionados. No inventes informacion.' },
      { role: 'user', content: analysisPrompt }
    ],
    temperature: 0.2,
    max_tokens: 4000,
  });

  const analysisText = analysisCompletion.choices?.[0]?.message?.content || '';
  
  let analysisResult;
  try {
    const m = analysisText.match(/\{[\s\S]*\}/);
    if (m) {
      analysisResult = JSON.parse(m[0]);
    }
  } catch {}

  if (!analysisResult || !analysisResult.threats) {
    analysisResult = {
      threats: [{ title: 'Analisis de seguridad', description: analysisText.substring(0, 1000), severity: 'medio', category: 'seguridad' }],
      overallRiskLevel: 'medio',
      summary: analysisText.substring(0, 800),
      recommendations: ['Monitoreo continuo de fuentes'],
      sources: allRawData.map(d => ({ title: d.sourceName, url: d.sourceUrl, relevance: d.snippet.substring(0, 200) }))
    };
  }

  // Include raw data for report generation - but limit size to avoid command line overflow
  // Keep only top 15 most relevant items
  analysisResult.rawData = allRawData.slice(0, 15);
  analysisResult.rawDataText = rawDataText.substring(0, 4000);

  process.stdout.write(JSON.stringify(analysisResult));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
