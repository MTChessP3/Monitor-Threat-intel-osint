/**
 * VIP Protection Report - Backend Server
 * Handles AI SDK calls that crash Next.js runtime.
 * Runs on port 3001, Next.js proxies to this.
 */
const express = require('express');
const cors = require('cors');
const ZAI = require('z-ai-web-dev-sdk').default;

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

let zai;

async function initAI() {
  zai = await ZAI.create();
  console.log('[Backend] ZAI SDK initialized');
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Web search
app.post('/api/ai/search', async (req, res) => {
  try {
    const { query, num = 5 } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    console.log(`[Backend] Searching: "${query}"`);
    const result = await zai.functions.invoke('web_search', { query, num });
    res.json({ ok: true, results: result });
  } catch (err) {
    console.error('[Backend] Search error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Chat completion
app.post('/api/ai/chat', async (req, res) => {
  try {
    const { messages } = req.body;
    if (!messages) return res.status(400).json({ error: 'Messages are required' });

    console.log(`[Backend] Chat completion with ${messages.length} messages`);
    const completion = await zai.chat.completions.create({ messages });
    res.json({ ok: true, completion });
  } catch (err) {
    console.error('[Backend] Chat error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Full analysis - combines search + chat in one call
app.post('/api/ai/analyze', async (req, res) => {
  try {
    const { urls, searchQueries } = req.body;
    const collectedData = [];
    const errors = [];

    // Build search queries
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
    console.log(`[Backend] Analysis with ${limitedQueries.length} queries:`, limitedQueries);

    // Execute searches sequentially with delays
    for (let i = 0; i < limitedQueries.length; i++) {
      const query = limitedQueries[i];
      try {
        const searchResult = await zai.functions.invoke('web_search', { query, num: 5 });
        if (searchResult && Array.isArray(searchResult)) {
          const content = searchResult.map(r =>
            `[${r.name || 'Sin título'}] ${r.snippet || ''} (${r.url || ''}) ${r.date || ''}`
          ).join('\n');
          collectedData.push(`Búsqueda: "${query}"\n${content}`);
        } else {
          collectedData.push(`Búsqueda: "${query}"\n${JSON.stringify(searchResult)}`);
        }
      } catch (err) {
        console.error(`[Backend] Search failed for "${query}":`, err.message);
        errors.push(`Búsqueda fallida: ${query}`);
      }

      // Delay between searches
      if (i < limitedQueries.length - 1) {
        await new Promise(r => setTimeout(r, 1500));
      }
    }

    if (collectedData.length === 0) {
      return res.status(500).json({ error: 'No se pudo obtener información de ninguna fuente.' });
    }

    if (errors.length > 0) {
      collectedData.push(`Nota: Algunas fuentes no disponibles:\n${errors.join('\n')}`);
    }

    console.log(`[Backend] Collected data, sending to AI for analysis...`);

    // AI analysis
    const analysisPrompt = `Eres un analista de inteligencia de protección VIP experto. Analiza la siguiente información recopilada de múltiples fuentes y proporciona un informe estructurado de inteligencia.

INFORMACIÓN RECOPILADA:
${collectedData.join('\n\n---\n\n')}

INSTRUCCIONES:
1. Identifica todas las amenazas relevantes para la protección VIP
2. Clasifica cada amenaza por severidad: bajo, medio, alto, critico
3. Asigna una categoría a cada amenaza: seguridad, política, económica, social
4. Determina el nivel de riesgo general
5. Proporciona un resumen ejecutivo
6. Genera recomendaciones específicas de protección

RESPONDE ÚNICAMENTE en formato JSON válido con esta estructura exacta:
{
  "threats": [
    {
      "title": "título de la amenaza",
      "description": "descripción detallada",
      "severity": "bajo|medio|alto|critico",
      "category": "seguridad|politica|economia|social"
    }
  ],
  "overallRiskLevel": "bajo|medio|alto|critico",
  "summary": "resumen ejecutivo de la situación",
  "recommendations": ["recomendación 1", "recomendación 2"],
  "sources": [
    {
      "title": "título de la fuente",
      "url": "url de la fuente",
      "relevance": "relevancia para la protección VIP"
    }
  ]
}`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista de inteligencia de protección VIP. Siempre respondes en formato JSON válido.' },
        { role: 'user', content: analysisPrompt }
      ]
    });

    const responseText = completion.choices?.[0]?.message?.content || '';

    // Parse JSON from response
    try {
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        console.log(`[Backend] Analysis complete. Risk: ${parsed.overallRiskLevel}, Threats: ${parsed.threats?.length || 0}`);
        return res.json(parsed);
      }
    } catch (parseErr) {
      console.error('[Backend] JSON parse error:', parseErr.message);
    }

    // Fallback
    console.log('[Backend] Using fallback result');
    res.json({
      threats: [{ title: 'Análisis en proceso', description: responseText.substring(0, 500), severity: 'medio', category: 'seguridad' }],
      overallRiskLevel: 'medio',
      summary: responseText.substring(0, 300),
      recommendations: ['Continuar monitoreo', 'Revisar fuentes adicionales'],
      sources: (urls || []).map(url => ({ title: url, url, relevance: 'Fuente proporcionada' }))
    });

  } catch (err) {
    console.error('[Backend] Analysis error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Generate report
app.post('/api/ai/generate-report', async (req, res) => {
  try {
    const { templateContent, analysis } = req.body;

    const reportPrompt = `Eres un redactor de informes ejecutivos de protección VIP. Genera un informe ejecutivo profesional siguiendo la estructura de la plantilla proporcionada, utilizando la información del análisis de inteligencia.

PLANTILLA DEL INFORME:
${templateContent || 'Usar estructura estándar'}

DATOS DEL ANÁLISIS DE INTELIGENCIA:
- Nivel de Riesgo General: ${analysis.overallRiskLevel}
- Resumen: ${analysis.summary}
- Amenazas Detectadas: ${analysis.threats.map(t => `[${t.severity.toUpperCase()}] ${t.title}: ${t.description}`).join('\n')}
- Recomendaciones: ${analysis.recommendations.join('\n')}
- Fuentes: ${analysis.sources.map(s => `${s.title} (${s.url})`).join('\n')}

INSTRUCCIONES:
1. Sigue la estructura de la plantilla exactamente
2. Rellena cada sección con información del análisis
3. Usa un tono profesional y ejecutivo
4. Incluye evaluaciones específicas de riesgo
5. Proporciona recomendaciones accionables
6. El informe debe estar en español
7. Usa formato Markdown para estructurar el documento

Genera el informe completo en formato Markdown.`;

    console.log('[Backend] Generating report...');
    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un redactor profesional de informes ejecutivos de protección VIP. Generas informes en español con formato Markdown.' },
        { role: 'user', content: reportPrompt }
      ]
    });

    const content = completion.choices?.[0]?.message?.content || 'Error al generar el informe';
    console.log('[Backend] Report generated, length:', content.length);
    res.json({ ok: true, content });

  } catch (err) {
    console.error('[Backend] Report generation error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Update report
app.post('/api/ai/update-report', async (req, res) => {
  try {
    const { existingContent, additionalUrls, additionalNews, additionalContext } = req.body;
    const collectedData = [];

    // Search for additional URL content
    if (additionalUrls && additionalUrls.length > 0) {
      for (const url of additionalUrls) {
        if (!url.trim()) continue;
        try {
          let searchQuery;
          try {
            const urlObj = new URL(url);
            searchQuery = `site:${urlObj.hostname} seguridad amenazas`;
          } catch {
            searchQuery = url;
          }

          const searchResult = await zai.functions.invoke('web_search', { query: searchQuery, num: 3 });
          if (searchResult && Array.isArray(searchResult)) {
            const content = searchResult.map(r => `[${r.name || ''}] ${r.snippet || ''} (${r.url || ''})`).join('\n');
            collectedData.push(`Nueva fuente: ${url}\n${content}`);
          }
        } catch {
          collectedData.push(`Error al buscar: ${url}`);
        }
        await new Promise(r => setTimeout(r, 1500));
      }
    }

    if (additionalNews?.trim()) {
      collectedData.push(`Noticias adicionales:\n${additionalNews}`);
    }
    if (additionalContext?.trim()) {
      collectedData.push(`Contexto adicional:\n${additionalContext}`);
    }

    if (collectedData.length === 0) {
      return res.json({ ok: true, content: existingContent });
    }

    const updatePrompt = `Eres un analista de inteligencia VIP experto. Incorpora la nueva información al informe existente.

INFORME EXISTENTE:
${existingContent}

NUEVA INFORMACIÓN:
${collectedData.join('\n\n---\n\n')}

INSTRUCCIONES:
1. Integra la nueva información
2. Actualiza secciones relevantes
3. Añade nuevas amenazas si se identifican
4. Mantén estructura y formato original
5. Tono profesional y ejecutivo
6. En español con formato Markdown
7. Marca secciones actualizadas con [ACTUALIZADO]

Genera el informe completo actualizado en Markdown.`;

    console.log('[Backend] Updating report...');
    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: 'Eres un analista profesional de inteligencia de protección VIP. Actualizas informes en español con formato Markdown.' },
        { role: 'user', content: updatePrompt }
      ]
    });

    const content = completion.choices?.[0]?.message?.content || existingContent;
    console.log('[Backend] Report updated, length:', content.length);
    res.json({ ok: true, content });

  } catch (err) {
    console.error('[Backend] Update report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = 3001;
initAI().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Backend] AI Backend Server running on http://0.0.0.0:${PORT}`);
  });
}).catch(err => {
  console.error('[Backend] Failed to initialize AI:', err);
  process.exit(1);
});
