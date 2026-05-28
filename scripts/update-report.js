// Update report - runs as child process
const ZAI = require('z-ai-web-dev-sdk').default;

const input = JSON.parse(process.argv[2] || '{}');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
  const zai = await ZAI.create();
  const { existingContent, additionalUrls, additionalNews, additionalContext } = input;
  const collectedData = [];

  // Search for URL-based information
  if (additionalUrls && additionalUrls.length > 0) {
    for (let i = 0; i < Math.min(additionalUrls.length, 3); i++) {
      try {
        const url = additionalUrls[i];
        let query;
        try {
          query = `site:${new URL(url).hostname} seguridad amenazas proteccion ejecutivos`;
        } catch {
          query = url.substring(0, 100);
        }
        const r = await zai.functions.invoke('web_search', { query, num: 5 });
        if (r && Array.isArray(r)) {
          collectedData.push(...r.map(x => `[${x.name || ''}] ${x.snippet || ''} (Fuente: ${x.url || ''})`));
        }
        if (i < additionalUrls.length - 1) await sleep(2500);
      } catch {}
    }
  }

  if (additionalNews?.trim()) collectedData.push(`Noticias adicionales proporcionadas: ${additionalNews.substring(0, 1000)}`);
  if (additionalContext?.trim()) collectedData.push(`Contexto adicional proporcionado: ${additionalContext.substring(0, 1000)}`);

  if (collectedData.length === 0) {
    process.stdout.write(JSON.stringify({ content: existingContent }));
    return;
  }

  const newDataText = collectedData.join('\n\n');

  const prompt = `Eres un analista de inteligencia ejecutiva VIP. Actualiza el siguiente informe con nueva informacion recopilada de fuentes reales.

INFORME ACTUAL:
${existingContent.substring(0, 6000)}

NUEVA INFORMACION RECOPILADA DE FUENTES:
${newDataText}

INSTRUCCIONES:
1. Integra la nueva informacion en las secciones correspondientes del informe
2. Menciona ESPECIFICAMENTE de que fuente viene cada nuevo dato
3. Si la nueva informacion cambia el nivel de riesgo, actualizalo
4. Añade nuevas amenazas si se detectan en las nuevas fuentes
5. Manten el formato Markdown y la estructura del informe existente
6. Añade una seccion "ACTUALIZACION" al final con fecha indicando los cambios
7. NO elimines informacion existente, solo enriquece y actualiza
8. NO inventes informacion - solo usa datos de las fuentes proporcionadas

Genera el informe actualizado completo en Markdown.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Eres un analista senior de inteligencia ejecutiva que actualiza informes con nueva informacion real de fuentes. Mantienes el formato y estructura existente. Respondes en Markdown en espanol. NUNCA inventas datos.' },
      { role: 'user', content: prompt }
    ],
    temperature: 0.3,
    max_tokens: 6000,
  });

  const content = completion.choices?.[0]?.message?.content || existingContent;
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
