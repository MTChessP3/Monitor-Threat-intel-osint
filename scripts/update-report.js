// Update report - runs as child process (memory optimized)
const ZAI = require('z-ai-web-dev-sdk').default;

const input = JSON.parse(process.argv[2] || '{}');

(async () => {
  const zai = await ZAI.create();
  const { existingContent, additionalUrls, additionalNews, additionalContext } = input;
  const collectedData = [];

  // Simple search for URLs
  if (additionalUrls && additionalUrls.length > 0) {
    try {
      const query = additionalUrls.slice(0, 2).map(u => {
        try { return 'site:' + new URL(u).hostname; } catch { return u; }
      }).join(' ') + ' seguridad';
      const r = await zai.functions.invoke('web_search', { query, num: 3 });
      if (r && Array.isArray(r)) {
        collectedData.push(r.map(x => (x.snippet || '')).join('; '));
      }
    } catch {}
  }

  if (additionalNews?.trim()) collectedData.push(additionalNews.substring(0, 500));
  if (additionalContext?.trim()) collectedData.push(additionalContext.substring(0, 500));

  if (collectedData.length === 0) {
    process.stdout.write(JSON.stringify({ content: existingContent }));
    return;
  }

  const prompt = `Actualiza informe VIP. Nueva info: ${collectedData.join('; ')}
INFORME: ${existingContent.substring(0, 3000)}
Mantén formato. [ACTUALIZADO]. Markdown español.`;

  const completion = await zai.chat.completions.create({
    messages: [
      { role: 'system', content: 'Actualizas informes VIP. Markdown español.' },
      { role: 'user', content: prompt }
    ],
  });

  const content = completion.choices?.[0]?.message?.content || existingContent;
  process.stdout.write(JSON.stringify({ content }));
})().catch(e => {
  process.stderr.write(e.message);
  process.exit(1);
});
