/**
 * VIP Protection Report - Unified Server
 * Combines AI backend + Next.js custom server in one process.
 * This avoids process management issues in the container environment.
 */

const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const ZAI = require('z-ai-web-dev-sdk').default;

const dev = process.env.NODE_ENV !== 'production';
const hostname = '0.0.0.0';
const port = 3000;

let zai;

async function initAI() {
  zai = await ZAI.create();
  console.log('[Unified] ZAI SDK initialized');
}

// AI Functions
async function webSearch(query, num = 5) {
  return await zai.functions.invoke('web_search', { query, num });
}

async function chatCompletion(messages) {
  return await zai.chat.completions.create({ messages });
}

// Handle AI API requests
async function handleAIRequest(path, body) {
  if (path === '/api/ai/analyze') {
    return await handleAnalyze(body);
  } else if (path === '/api/ai/generate-report') {
    return await handleGenerateReport(body);
  } else if (path === '/api/ai/update-report') {
    return await handleUpdateReport(body);
  } else if (path === '/api/ai/search') {
    const result = await webSearch(body.query, body.num || 5);
    return { ok: true, results: result };
  } else if (path === '/api/ai/chat') {
    const completion = await chatCompletion(body.messages);
    return { ok: true, completion };
  }
  throw new Error('Unknown AI endpoint');
}

async function handleAnalyze({ urls, searchQueries }) {
  const collectedData = [];
  const errors = [];

  const allSearchQueries = [];
  if (searchQueries && searchQueries.length > 0) {
    allSearchQueries.push(...searchQueries.slice(0, 2));
  }
  if (urls && urls.length > 0) {
    for (let i = 0; i < Math.min(urls.length, 3); i++) {
      try {
        const urlObj = new URL(urls[i]);
        allSearchQueries.push(`site:${urlObj.hostname} seguridad amenazas protección`);
      } catch {
        allSearchQueries.push(urls[i]);
      }
    }
  }
  if (allSearchQueries.length === 0) {
    allSearchQueries.push('amenazas seguridad VIP protección ejecutiva 2026');
  }

  const limitedQueries = allSearchQueries.slice(0, 3);
  console.log(`[AI] Analysis with ${limitedQueries.length} queries`);

  for (let i = 0; i < limitedQueries.length; i++) {
    const query = limitedQueries[i];
    try {
      const searchResult = await webSearch(query, 5);
      if (searchResult && Array.isArray(searchResult)) {
        const content = searchResult.map(r =>
          `[${r.name || 'Sin título'}] ${r.snippet || ''} (${r.url || ''})`
        ).join('\n');
        collectedData.push(`Búsqueda: "${query}"\n${content}`);
      } else {
        collectedData.push(`Búsqueda: "${query}"\n${JSON.stringify(searchResult)}`);
      }
    } catch (err) {
      console.error(`[AI] Search failed: ${err.message}`);
      errors.push(`Búsqueda fallida: ${query}`);
    }
    if (i < limitedQueries.length - 1) {
      await new Promise(r => setTimeout(r, 1500));
    }
  }

  if (collectedData.length === 0) {
    throw new Error('No se pudo obtener información de ninguna fuente.');
  }
  if (errors.length > 0) {
    collectedData.push(`Notas: ${errors.join('; ')}`);
  }

  const analysisPrompt = `Eres un analista de inteligencia de protección VIP experto. Analiza la siguiente información y proporciona un informe estructurado.

INFORMACIÓN RECOPILADA:
${collectedData.join('\n\n---\n\n')}

Responde SOLO en JSON: {"threats":[{"title":"","description":"","severity":"bajo|medio|alto|critico","category":"seguridad|politica|economia|social"}],"overallRiskLevel":"bajo|medio|alto|critico","summary":"","recommendations":[],"sources":[{"title":"","url":"","relevance":""}]}`;

  const completion = await chatCompletion([
    { role: 'system', content: 'Responde en JSON válido. Eres analista de inteligencia VIP.' },
    { role: 'user', content: analysisPrompt }
  ]);

  const responseText = completion.choices?.[0]?.message?.content || '';
  try {
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch {}

  return {
    threats: [{ title: 'Análisis', description: responseText.substring(0, 500), severity: 'medio', category: 'seguridad' }],
    overallRiskLevel: 'medio',
    summary: responseText.substring(0, 300),
    recommendations: ['Continuar monitoreo'],
    sources: (urls || []).map(url => ({ title: url, url, relevance: 'Fuente' }))
  };
}

async function handleGenerateReport({ templateContent, analysis }) {
  const reportPrompt = `Genera un informe ejecutivo de protección VIP en Markdown.

PLANTILLA:
${templateContent || 'Usar estructura estándar: # Informe, ## Resumen, ## Amenazas, ## Recomendaciones, ## Conclusiones'}

ANÁLISIS:
- Riesgo: ${analysis.overallRiskLevel}
- Resumen: ${analysis.summary}
- Amenazas: ${analysis.threats.map(t => `[${t.severity}] ${t.title}: ${t.description}`).join('\n')}
- Recomendaciones: ${analysis.recommendations.join('\n')}
- Fuentes: ${analysis.sources.map(s => `${s.title}`).join(', ')}

Genera el informe completo en Markdown, profesional, en español.`;

  const completion = await chatCompletion([
    { role: 'system', content: 'Eres redactor de informes ejecutivos VIP. Responde en Markdown en español.' },
    { role: 'user', content: reportPrompt }
  ]);

  return { ok: true, content: completion.choices?.[0]?.message?.content || 'Error' };
}

async function handleUpdateReport({ existingContent, additionalUrls, additionalNews, additionalContext }) {
  const collectedData = [];

  if (additionalUrls && additionalUrls.length > 0) {
    for (const url of additionalUrls) {
      if (!url.trim()) continue;
      try {
        let sq;
        try { sq = `site:${new URL(url).hostname} seguridad`; } catch { sq = url; }
        const r = await webSearch(sq, 3);
        if (r && Array.isArray(r)) {
          collectedData.push(`Fuente: ${url}\n${r.map(x => `[${x.name||''}] ${x.snippet||''}`).join('\n')}`);
        }
      } catch { collectedData.push(`Error: ${url}`); }
      await new Promise(r => setTimeout(r, 1500));
    }
  }

  if (additionalNews?.trim()) collectedData.push(`Noticias:\n${additionalNews}`);
  if (additionalContext?.trim()) collectedData.push(`Contexto:\n${additionalContext}`);

  if (collectedData.length === 0) return { ok: true, content: existingContent };

  const prompt = `Actualiza este informe VIP con nueva información.

INFORME:
${existingContent}

NUEVA INFO:
${collectedData.join('\n---\n')}

Mantén formato original. Marca cambios con [ACTUALIZADO]. Markdown en español.`;

  const completion = await chatCompletion([
    { role: 'system', content: 'Actualizas informes VIP. Markdown en español.' },
    { role: 'user', content: prompt }
  ]);

  return { ok: true, content: completion.choices?.[0]?.message?.content || existingContent };
}

// Start server
async function start() {
  await initAI();

  const app = next({ dev: false, hostname, port });
  const handle = app.getRequestHandler();

  await app.prepare();
  console.log('[Unified] Next.js prepared');

  const server = createServer(async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true);
      const { pathname } = parsedUrl;

      // Handle AI API routes internally (no separate process needed)
      if (pathname.startsWith('/api/ai/')) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const parsed = JSON.parse(body);
            const result = await handleAIRequest(pathname, parsed);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err) {
            console.error(`[Unified] AI error at ${pathname}:`, err.message);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }

      // All other requests go to Next.js
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('[Unified] Error:', err);
      res.writeHead(500);
      res.end('Internal Server Error');
    }
  });

  server.listen(port, hostname, () => {
    console.log(`[Unified] Server running at http://${hostname}:${port}`);
  });
}

start().catch(err => {
  console.error('[Unified] Failed to start:', err);
  process.exit(1);
});
