/**
 * AI Worker - Persistent child process that handles all AI/SDK operations.
 * Communicates with parent via stdin/stdout JSON messages.
 * This avoids loading the SDK in the Next.js process.
 */

const ZAI = require('z-ai-web-dev-sdk').default;

let zai;

async function init() {
  zai = await ZAI.create();
  send({ type: 'ready' });
}

function send(data) {
  process.stdout.write(JSON.stringify(data) + '\n');
}

async function handleMessage(msg) {
  try {
    if (msg.type === 'search') {
      const result = await zai.functions.invoke('web_search', { query: msg.query, num: msg.num || 5 });
      send({ id: msg.id, type: 'search-result', result });
    }
    else if (msg.type === 'chat') {
      const completion = await zai.chat.completions.create({ messages: msg.messages });
      const content = completion.choices?.[0]?.message?.content || '';
      send({ id: msg.id, type: 'chat-result', content });
    }
    else if (msg.type === 'analyze') {
      const result = await handleAnalyze(msg);
      send({ id: msg.id, type: 'analyze-result', result });
    }
    else if (msg.type === 'generate-report') {
      const content = await handleGenerateReport(msg);
      send({ id: msg.id, type: 'generate-report-result', content });
    }
    else if (msg.type === 'update-report') {
      const content = await handleUpdateReport(msg);
      send({ id: msg.id, type: 'update-report-result', content });
    }
  } catch (err) {
    send({ id: msg.id, type: 'error', error: err.message });
  }
}

async function handleAnalyze(msg) {
  const { urls = [], searchQueries = [] } = msg;
  const collectedData = [];

  let mainQuery = '';
  if (searchQueries.length > 0) mainQuery = searchQueries[0];
  else if (urls.length > 0) {
    try { mainQuery = 'site:' + new URL(urls[0]).hostname + ' seguridad VIP amenazas'; }
    catch { mainQuery = 'amenazas seguridad VIP protección'; }
  } else {
    mainQuery = 'amenazas seguridad VIP protección ejecutiva 2026';
  }

  try {
    const searchResult = await zai.functions.invoke('web_search', { query: mainQuery, num: 8 });
    if (searchResult && Array.isArray(searchResult)) {
      const content = searchResult.map(r =>
        `[${r.name || ''}] ${r.snippet || ''} (${r.url || ''})`
      ).join('\n');
      collectedData.push(content);
    }
  } catch (err) {
    collectedData.push('Search error: ' + err.message);
  }

  if (collectedData.length === 0) {
    return { error: 'No data collected' };
  }

  const prompt = `Analiza info de inteligencia VIP. Responde SOLO JSON: {"threats":[{"title":"","description":"","severity":"bajo|medio|alto|critico","category":"seguridad|politica|economia|social"}],"overallRiskLevel":"bajo|medio|alto|critico","summary":"","recommendations":[],"sources":[{"title":"","url":"","relevance":""}]}

${collectedData.join('\n---\n')}`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Analista inteligencia VIP. JSON válido.' },
      { role: 'user', content: prompt }
    ]
  });

  const text = completion.choices?.[0]?.message?.content || '';
  try {
    const m = text.match(/\{[\s\S]*\}/);
    if (m) return JSON.parse(m[0]);
  } catch {}

  return {
    threats: [{ title: 'Análisis', description: text.substring(0, 500), severity: 'medio', category: 'seguridad' }],
    overallRiskLevel: 'medio',
    summary: text.substring(0, 300),
    recommendations: ['Monitoreo'],
    sources: []
  };
}

async function handleGenerateReport(msg) {
  const { templateContent, analysis } = msg;

  const prompt = `Genera informe ejecutivo VIP en Markdown.

PLANTILLA:
${templateContent || 'Estructura estándar'}

ANÁLISIS:
- Riesgo: ${analysis.overallRiskLevel}
- Resumen: ${analysis.summary}
- Amenazas: ${analysis.threats.map(t => `[${t.severity}] ${t.title}: ${t.description}`).join('\n')}
- Recomendaciones: ${analysis.recommendations.join('\n')}

Informe completo en Markdown, español, profesional.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Redactor informes VIP. Markdown español.' },
      { role: 'user', content: prompt }
    ]
  });

  return completion.choices?.[0]?.message?.content || 'Error';
}

async function handleUpdateReport(msg) {
  const { existingContent, additionalUrls, additionalNews, additionalContext } = msg;
  const collectedData = [];

  if (additionalUrls?.length) {
    try {
      const query = additionalUrls.map(u => {
        try { return 'site:' + new URL(u).hostname; } catch { return u; }
      }).join(' OR ');
      const r = await zai.functions.invoke('web_search', { query: query + ' seguridad', num: 3 });
      if (r && Array.isArray(r)) {
        collectedData.push(r.map(x => `[${x.name || ''}] ${x.snippet || ''}`).join('\n'));
      }
    } catch {}
  }

  if (additionalNews?.trim()) collectedData.push(additionalNews);
  if (additionalContext?.trim()) collectedData.push(additionalContext);

  if (collectedData.length === 0) return existingContent;

  const prompt = `Actualiza informe VIP con nueva info.

INFORME:
${existingContent}

NUEVA INFO:
${collectedData.join('\n---\n')}

Mantén formato. [ACTUALIZADO]. Markdown español.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Actualizas informes VIP. Markdown español.' },
      { role: 'user', content: prompt }
    ]
  });

  return completion.choices?.[0]?.message?.content || existingContent;
}

// Read messages from stdin
let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk.toString();
  const lines = buffer.split('\n');
  buffer = lines.pop() || '';
  for (const line of lines) {
    if (line.trim()) {
      try {
        const msg = JSON.parse(line);
        handleMessage(msg);
      } catch (e) {
        console.error('Invalid message:', line);
      }
    }
  }
});

process.stdin.on('end', () => {
  process.exit(0);
});

init().catch(e => {
  console.error('Init failed:', e);
  process.exit(1);
});
