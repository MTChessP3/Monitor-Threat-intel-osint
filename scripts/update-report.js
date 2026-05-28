// Update report - reads input from temp file (path passed as argv[2])
// Searches new URLs, integrates findings into existing report

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

  // Search additional URLs
  if (additionalUrls && additionalUrls.length > 0) {
    for (let i = 0; i < Math.min(additionalUrls.length, 5); i++) {
      try {
        const url = additionalUrls[i];
        let query;
        try {
          const hostname = new URL(url).hostname;
          query = `site:${hostname} seguridad amenazas proteccion ejecutivos Colombia 2025 2026`;
        } catch {
          query = url.substring(0, 100);
        }
        const r = await zai.functions.invoke('web_search', { query, num: 10 });
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

  // Add manually provided news
  if (additionalNews?.trim()) {
    collectedData.push({
      sourceName: 'Noticias proporcionadas manualmente',
      sourceUrl: '',
      snippet: additionalNews.substring(0, 2000),
      date: new Date().toISOString()
    });
  }

  // Add manually provided context
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
    ? `\n\nPLANTILLA ORIGINAL (manten esta estructura):\n---\n${templateContent.substring(0, 4000)}\n---`
    : '';

  const prompt = `Eres un ANALISTA SENIOR de inteligencia ejecutiva VIP con 20 anos de experiencia. Actualiza el informe existente con nueva informacion recopilada de fuentes.

INFORME ACTUAL:
${existingContent.substring(0, 12000)}
${templateInstruction}

NUEVA INFORMACION RECOPILADA:
${newDataText}

INSTRUCCIONES:
1. Integra la nueva informacion en las secciones correspondientes del informe existente
2. Menciona EXPLICITAMENTE de que fuente viene cada nuevo dato
3. Si cambia el nivel de riesgo, actualizalo y justifica el cambio
4. Anade nuevas amenazas si se detectan en la nueva informacion
5. Manten el formato Markdown y la estructura del informe original
6. Anade una seccion "ACTUALIZACION" al final con fecha y resumen de cambios
7. NO elimines informacion existente - solo anade o actualiza
8. NO inventes informacion que no este en las fuentes
9. Se detallado y profesional - el informe actualizado debe ser mas completo que el original
10. Manten la estructura de la plantilla si existe

Genera el informe actualizado COMPLETO en Markdown.`;

  const completion = await zai.chat.completions.create({
    messages: [
      {
        role: 'system',
        content: 'Eres un analista senior de inteligencia ejecutiva VIP experto en proteccion de ejecutivos en Colombia. Actualizas informes con datos reales de fuentes. Mantienes el formato y estructura existente. Formato Markdown en espanol. NUNCA inventas datos. Cada dato se atribuye a su fuente.'
      },
      { role: 'user', content: prompt }
    ],
    temperature: 0.2,
    max_tokens: 8000,
  });

  const content = completion.choices?.[0]?.message?.content || existingContent;
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write('Fatal: ' + e.message);
  process.exit(1);
});
