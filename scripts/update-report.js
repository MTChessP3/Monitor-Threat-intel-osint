// Update report - runs as child process (memory optimized)
const ZAI = require('z-ai-web-dev-sdk').default;

const input = JSON.parse(process.argv[2] || '{}');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  const zai = await ZAI.create();
  const { existingContent, additionalUrls, additionalNews, additionalContext } = input;
  const collectedData = [];

  // Search for URL-based information
  if (additionalUrls && additionalUrls.length > 0) {
    for (let i = 0; i < Math.min(additionalUrls.length, 2); i++) {
      try {
        const url = additionalUrls[i];
        let query;
        try {
          query = `site:${new URL(url).hostname} seguridad amenazas VIP`;
        } catch {
          query = url.substring(0, 100);
        }
        const r = await zai.functions.invoke('web_search', { query, num: 3 });
        if (r && Array.isArray(r)) {
          collectedData.push(...r.map(x => `${x.name || ''}: ${x.snippet || ''}`));
        }
        if (i < additionalUrls.length - 1) await sleep(2000);
      } catch {}
    }
  }

  if (additionalNews?.trim()) collectedData.push(`Noticias adicionales: ${additionalNews.substring(0, 800)}`);
  if (additionalContext?.trim()) collectedData.push(`Contexto adicional: ${additionalContext.substring(0, 800)}`);

  if (collectedData.length === 0) {
    process.stdout.write(JSON.stringify({ content: existingContent }));
    return;
  }

  const newDataText = collectedData.join('\n\n');

  const prompt = `Eres un analista de inteligencia ejecutiva VIP. Actualiza el siguiente informe con nueva información recopilada.

INFORME ACTUAL:
${existingContent.substring(0, 4000)}

NUEVA INFORMACIÓN RECOPILADA:
${newDataText}

INSTRUCCIONES:
1. Integra la nueva información en el informe existente
2. Actualiza las secciones relevantes (amenazas, recomendaciones, evaluación de riesgos)
3. Si la nueva información cambia el nivel de riesgo, actualízalo
4. Añade nuevas amenazas si se detectan
5. Mantén el formato Markdown y la estructura del informe
6. Añade una sección "ACTUALIZACIÓN" al final con fecha de hoy indicando los cambios realizados
7. No elimines información existente, solo enriquece y actualiza

Genera el informe actualizado completo en Markdown.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Eres un analista senior de inteligencia ejecutiva VIP que actualiza informes con nueva información. Mantienes el formato y la estructura existente mientras añades y actualizas contenido. Respondes en Markdown en español.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.3,
    max_tokens: 4000,
  });

  const content = completion.choices?.[0]?.message?.content || existingContent;
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
