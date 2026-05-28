// Analyze intelligence - runs as child process
const ZAI = require('z-ai-web-dev-sdk').default;

const urls = JSON.parse(process.argv[2] || '[]');
const searchQueries = JSON.parse(process.argv[3] || '[]');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  const zai = await ZAI.create();
  const allSearchData = [];

  // Build search queries - combine user queries with source-based queries
  const queries = [];
  
  // Add user search queries
  if (searchQueries.length > 0) {
    queries.push(...searchQueries);
  }
  
  // Add source-based queries
  if (urls.length > 0) {
    for (const url of urls.slice(0, 3)) {
      try {
        const hostname = new URL(url).hostname;
        queries.push(`site:${hostname} seguridad amenazas`);
      } catch {
        // skip invalid URLs
      }
    }
  }
  
  // Default queries if none provided
  if (queries.length === 0) {
    queries.push('amenazas seguridad VIP protección ejecutiva 2026');
    queries.push('inteligencia seguridad ejecutiva riesgos');
    queries.push('seguridad personal altos ejecutivos alertas');
  }

  // Perform searches with delay between each to avoid rate limiting
  for (let i = 0; i < Math.min(queries.length, 4); i++) {
    try {
      const result = await zai.functions.invoke('web_search', { query: queries[i], num: 6 });
      if (result && Array.isArray(result)) {
        const items = result.map(r => {
          const name = r.name || '';
          const snippet = r.snippet || '';
          const url = r.url || '';
          return `Fuente: ${name}\nURL: ${url}\nContenido: ${snippet}`;
        });
        allSearchData.push(...items);
      }
    } catch (e) {
      // Continue with what we have
    }
    
    // Delay between searches to avoid 429
    if (i < queries.length - 1) {
      await sleep(2000);
    }
  }

  if (allSearchData.length === 0) {
    process.stdout.write(JSON.stringify({
      threats: [{ title: 'Sin datos disponibles', description: 'No se pudo recopilar información de las fuentes. Intente con diferentes consultas o fuentes.', severity: 'bajo', category: 'seguridad' }],
      overallRiskLevel: 'bajo',
      summary: 'No se pudo recopilar información de las fuentes en este momento. Se recomienda intentar nuevamente.',
      recommendations: ['Reintentar la búsqueda con diferentes términos', 'Verificar que las fuentes estén accesibles', 'Agregar más fuentes de información'],
      sources: []
    }));
    return;
  }

  // AI Analysis with detailed professional prompt
  const searchDataText = allSearchData.join('\n\n');
  
  const prompt = `Eres un analista senior de inteligencia ejecutiva VIP. Analiza la siguiente información recopilada de múltiples fuentes de noticias e inteligencia.

INFORMACIÓN RECOPILADA:
${searchDataText}

INSTRUCCIONES:
1. Identifica TODAS las amenazas relevantes para la protección de ejecutivos/VIPs
2. Clasifica cada amenaza por severidad: "bajo", "medio", "alto", o "critico"
3. Categoriza cada amenaza: "seguridad", "politica", "economia", o "social"
4. Proporciona un resumen ejecutivo detallado
5. Genera recomendaciones específicas y accionables
6. Evalúa el nivel de riesgo general

Responde SOLO con JSON válido en este formato exacto:
{
  "threats": [
    {"title": "título de la amenaza", "description": "descripción detallada de la amenaza y su impacto potencial", "severity": "bajo|medio|alto|critico", "category": "seguridad|politica|economia|social"}
  ],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen ejecutivo detallado de la situación de seguridad actual basado en la información recopilada",
  "recommendations": ["recomendación específica 1", "recomendación específica 2", "recomendación específica 3"],
  "sources": [{"title": "nombre de la fuente", "url": "url de la fuente", "relevance": "relevancia de la fuente para el análisis"}]
}`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Eres un analista de inteligencia ejecutiva de alto nivel. Respondes SOLO con JSON válido, sin texto adicional antes o después del JSON.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.3,
    max_tokens: 3000,
  });

  const text = completion.choices?.[0]?.message?.content || '';
  
  try {
    // Try to extract JSON from the response
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      const parsed = JSON.parse(m[0]);
      // Validate required fields
      if (parsed.threats && Array.isArray(parsed.threats) && parsed.overallRiskLevel) {
        process.stdout.write(JSON.stringify(parsed));
        return;
      }
    }
  } catch (e) {
    // Fallback below
  }

  // Fallback: create structured response from raw text
  process.stdout.write(JSON.stringify({
    threats: [{ title: 'Análisis de seguridad', description: text.substring(0, 800), severity: 'medio', category: 'seguridad' }],
    overallRiskLevel: 'medio',
    summary: text.substring(0, 500),
    recommendations: ['Monitorear la situación de manera continua', 'Actualizar protocolos de seguridad según la información disponible', 'Mantener comunicación con equipos de inteligencia'],
    sources: urls.map(u => ({ title: u, url: u, relevance: 'Fuente proporcionada por el usuario' }))
  }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
