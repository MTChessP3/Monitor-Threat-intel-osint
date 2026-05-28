// Update report - reads input from temp file (path passed as argv[2])
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

  const zai = await ZAI.create();
  const { existingContent, additionalUrls, additionalNews, additionalContext, templateContent } = input;
  const collectedData = [];

  if (additionalUrls && additionalUrls.length > 0) {
    for (let i = 0; i < Math.min(additionalUrls.length, 5); i++) {
      try {
        const url = additionalUrls[i];
        let query;
        try {
          query = `site:${new URL(url).hostname} seguridad amenazas proteccion ejecutivos`;
        } catch {
          query = url.substring(0, 100);
        }
        const r = await zai.functions.invoke('web_search', { query, num: 8 });
        if (r && Array.isArray(r)) {
          for (const item of r) {
            collectedData.push({
              sourceName: item.name || 'Desconocido',
              sourceUrl: item.url || '',
              snippet: item.snippet || '',
              date: item.date || ''
            });
          }
        }
        if (i < additionalUrls.length - 1) await sleep(3000);
      } catch {}
    }
  }

  if (additionalNews?.trim()) {
    collectedData.push({
      sourceName: 'Noticias proporcionadas manualmente',
      sourceUrl: '',
      snippet: additionalNews.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  if (additionalContext?.trim()) {
    collectedData.push({
      sourceName: 'Contexto adicional proporcionado',
      sourceUrl: '',
      snippet: additionalContext.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  if (collectedData.length === 0) {
    process.stdout.write(JSON.stringify({ content: existingContent }));
    return;
  }

  const newDataText = collectedData.map((item, idx) =>
    `[${idx + 1}] Fuente: ${item.sourceName}\n    URL: ${item.sourceUrl}\n    Fecha: ${item.date}\n    Contenido: ${item.snippet}`
  ).join('\n\n');

  const templateInstruction = templateContent
    ? `\n\nPLANTILLA ORIGINAL (manten esta estructura):\n---\n${templateContent.substring(0, 3000)}\n---`
    : '';

  const prompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva VIP. Actualiza el informe con nueva informacion.

INFORME ACTUAL:
${existingContent.substring(0, 8000)}
${templateInstruction}

NUEVA INFORMACION:
${newDataText}

INSTRUCCIONES:
1. Integra la nueva informacion en las secciones correspondientes
2. Menciona de que fuente viene cada dato
3. Si cambia el nivel de riesgo, actualizalo
4. Anade nuevas amenazas si se detectan
5. Manten formato Markdown y estructura
6. Anade seccion "ACTUALIZACION" al final
7. NO elimines informacion existente
8. NO inventes informacion
9. Se detallado y profesional

Genera el informe actualizado COMPLETO en Markdown.`;

  const completion = await zai.chat.completions.create({
    messages: [
      {
        role: 'system',
        content: 'Eres un analista senior de inteligencia ejecutiva. Actualizas informes con datos reales. Mantienes formato existente. Markdown en espanol. NUNCA inventas datos.'
      },
      { role: 'user', content: prompt }
    ],
    temperature: 0.25,
    max_tokens: 6000,
  });

  const content = completion.choices?.[0]?.message?.content || existingContent;
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
