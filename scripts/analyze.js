// Analyze intelligence - reads input from temp file (path passed as argv[2])
const ZAI = require('z-ai-web-dev-sdk').default;
const fs = require('fs');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

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

  const urls = input.urls || [];
  const searchQueries = input.searchQueries || [];

  const zai = await ZAI.create();
  const allRawData = [];

  // === PHASE 1: Collect information from EACH source ===
  const searchTasks = [];

  for (const q of searchQueries) {
    searchTasks.push({ type: 'query', value: q });
  }

  for (const url of urls) {
    try {
      const hostname = new URL(url).hostname;
      searchTasks.push({ type: 'source', value: url, hostname });
    } catch {
      searchTasks.push({ type: 'source', value: url, hostname: url });
    }
  }

  if (searchTasks.length === 0) {
    searchTasks.push({ type: 'query', value: 'proteccion digital ejecutivos amenazas ciberseguridad Colombia 2026' });
    searchTasks.push({ type: 'query', value: 'seguridad VIP Colombia amenazas secuestro extorsion 2026' });
    searchTasks.push({ type: 'query', value: 'phishing ejecutivos fraude digital Colombia Bancolombia 2026' });
    searchTasks.push({ type: 'query', value: 'inteligencia OSINT amenazas empresariales Colombia 2026' });
    searchTasks.push({ type: 'query', value: 'ciberataques bancarios Colombia seguridad informatica 2026' });
  }

  for (let i = 0; i < searchTasks.length; i++) {
    const task = searchTasks[i];
    let query;

    if (task.type === 'source') {
      query = `site:${task.hostname} seguridad amenazas proteccion digital ejecutivos Colombia`;
    } else {
      query = task.value;
    }

    try {
      const result = await zai.functions.invoke('web_search', { query, num: 10 });
      if (result && Array.isArray(result) && result.length > 0) {
        for (const item of result) {
          allRawData.push({
            sourceName: item.name || 'Desconocido',
            sourceUrl: item.url || '',
            snippet: item.snippet || '',
            hostname: item.host_name || task.hostname || '',
            searchType: task.type,
            searchQuery: query,
            date: item.date || ''
          });
        }
      }
    } catch (e) {
      // Continue
    }

    if (i < searchTasks.length - 1) {
      await sleep(3000);
    }
  }

  if (allRawData.length === 0) {
    process.stdout.write(JSON.stringify({
      threats: [],
      overallRiskLevel: 'bajo',
      summary: 'No se pudo recopilar informacion de las fuentes configuradas. Verifique accesibilidad y terminos de busqueda.',
      recommendations: ['Reintentar con terminos mas especificos', 'Verificar fuentes', 'Anadir fuentes adicionales'],
      sources: [],
      rawData: [],
      rawDataText: ''
    }));
    return;
  }

  // === PHASE 2: Deep AI analysis ===
  const rawDataText = allRawData.map((item, idx) => {
    return `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date || 'N/A'}\n    Contenido: ${item.snippet}\n    Busqueda: ${item.searchQuery}`;
  }).join('\n\n');

  const analysisPrompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva y ciberseguridad con experiencia en proteccion VIP y contrainteligencia.

INFORMACION RECOPILADA DE FUENTES OSINT:
${rawDataText}

INSTRUCCIONES:
1. Analiza CADA fragmento individualmente
2. Identifica amenazas ESPECIFICAS con datos concretos: actores, fechas, ubicaciones, metodos, cifras
3. Para cada amenaza: probabilidad, impacto, vector de ataque, medidas de mitigacion
4. Clasifica severidad basada en EVIDENCIA REAL
5. Resumen ejecutivo DETALLADO (minimo 200 palabras) con hallazgos y fuentes
6. Recomendaciones ACCIONABLES y ESPECIFICAS
7. Lista TODAS las fuentes con su aporte
8. Identifica patrones y tendencias

Responde SOLO con JSON:
{
  "threats": [{"title": "titulo especifico", "description": "descripcion detallada minimo 80 palabras con datos de fuentes", "severity": "bajo|medio|alto|critico", "category": "seguridad|politica|economia|social|ciberseguridad|fisica"}],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "Resumen ejecutivo DETALLADO minimo 200 palabras con hallazgos especificos y fuentes concretas",
  "recommendations": ["recomendacion accionable 1", "recomendacion 2"],
  "sources": [{"title": "nombre fuente", "url": "url", "relevance": "que aporto"}]
}`;

  const analysisCompletion = await zai.chat.completions.create({
    messages: [
      {
        role: 'system',
        content: 'Eres un analista de inteligencia senior. Respondes SOLO con JSON valido. Tu analisis es especifico, detallado y basado en datos proporcionados. No inventas informacion.'
      },
      { role: 'user', content: analysisPrompt }
    ],
    temperature: 0.15,
    max_tokens: 6000,
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
      threats: allRawData.slice(0, 5).map(d => ({
        title: `Hallazgo: ${d.sourceName}`,
        description: d.snippet,
        severity: 'medio',
        category: 'seguridad'
      })),
      overallRiskLevel: 'medio',
      summary: analysisText.substring(0, 1500) || 'Analisis completado con informacion limitada.',
      recommendations: ['Monitoreo continuo', 'Implementar medidas proactivas', 'Actualizar evaluacion de riesgos'],
      sources: allRawData.map(d => ({ title: d.sourceName, url: d.sourceUrl, relevance: d.snippet.substring(0, 300) }))
    };
  }

  analysisResult.rawData = allRawData.slice(0, 20);
  analysisResult.rawDataText = rawDataText.substring(0, 6000);

  process.stdout.write(JSON.stringify(analysisResult));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
