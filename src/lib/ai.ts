import ZAI from 'z-ai-web-dev-sdk';

let zaiInstance: Awaited<ReturnType<typeof ZAI.create>> | null = null;

export async function getAI() {
  if (!zaiInstance) {
    zaiInstance = await ZAI.create();
  }
  return zaiInstance;
}

export async function webSearch(query: string, num: number = 10) {
  const zai = await getAI();
  const result = await zai.functions.invoke("web_search", { query, num });
  return result;
}

export async function webReader(url: string): Promise<string> {
  // Strategy 1: Try fetching the URL directly
  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; VIPProtectionBot/1.0)',
        'Accept': 'text/html,text/plain,application/json',
      },
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });
    if (response.ok) {
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('text/html') || contentType.includes('text/plain')) {
        const text = await response.text();
        // Strip HTML tags for a cleaner result
        const cleaned = text.replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/<style[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();
        if (cleaned.length > 100) {
          return cleaned.substring(0, 5000);
        }
      }
    }
  } catch (err) {
    console.error(`Direct fetch failed for ${url}:`, err);
  }

  // Strategy 2: Fallback to web_search
  try {
    const zai = await getAI();
    const searchResult = await zai.functions.invoke("web_search", { query: url, num: 3 });
    if (searchResult && Array.isArray(searchResult) && searchResult.length > 0) {
      return searchResult.map((r: { name?: string; snippet?: string; url?: string }) =>
        `${r.name || ''}: ${r.snippet || ''} (${r.url || ''})`
      ).join('\n');
    }
    return JSON.stringify(searchResult);
  } catch (searchErr) {
    console.error(`Web search fallback failed for ${url}:`, searchErr);
    throw new Error(`No se pudo leer la URL: ${url}`);
  }
}

export async function chatCompletion(messages: { role: string; content: string }[]) {
  const zai = await getAI();
  const completion = await zai.chat.completions.create({
    messages: messages as Array<{ role: 'system' | 'user' | 'assistant'; content: string }>,
  });
  return completion;
}

export interface AnalysisResult {
  threats: Array<{
    title: string;
    description: string;
    severity: 'bajo' | 'medio' | 'alto' | 'critico';
    category: string;
  }>;
  overallRiskLevel: 'bajo' | 'medio' | 'alto' | 'critico';
  summary: string;
  recommendations: string[];
  sources: Array<{
    title: string;
    url: string;
    relevance: string;
  }>;
}

// Helper to add delay between API calls to avoid rate limiting
function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function analyzeIntelligence(
  urls: string[],
  searchQueries: string[]
): Promise<AnalysisResult> {
  const collectedData: string[] = [];
  const errors: string[] = [];

  // Fetch content from URLs sequentially to avoid rate limiting
  for (const url of urls) {
    try {
      const readerResult = await webReader(url);
      collectedData.push(`Fuente URL: ${url}\n${readerResult.substring(0, 3000)}`);
    } catch (err) {
      errors.push(`URL no accesible: ${url}`);
    }
    // Small delay between URL fetches
    if (urls.indexOf(url) < urls.length - 1) {
      await delay(500);
    }
  }

  // Search for relevant news sequentially to avoid 429 rate limiting
  for (let i = 0; i < searchQueries.length; i++) {
    const query = searchQueries[i];
    try {
      const searchResult = await webSearch(query, 5);
      const content = typeof searchResult === 'string'
        ? searchResult
        : JSON.stringify(searchResult);
      collectedData.push(`Búsqueda: ${query}\n${content.substring(0, 3000)}`);
    } catch (err) {
      errors.push(`Búsqueda fallida: ${query}`);
    }
    // Delay between searches to avoid rate limiting
    if (i < searchQueries.length - 1) {
      await delay(1000);
    }
  }

  if (collectedData.length === 0) {
    throw new Error('No se pudo obtener información de ninguna fuente. Verifique las URLs y consultas de búsqueda.');
  }

  // Add error context if some sources failed
  if (errors.length > 0) {
    collectedData.push(`Nota: Algunas fuentes no estuvieron disponibles:\n${errors.join('\n')}`);
  }

  // Use AI to analyze collected data
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

  const completion = await chatCompletion([
    {
      role: 'system',
      content: 'Eres un analista de inteligencia de protección VIP. Siempre respondes en formato JSON válido.'
    },
    {
      role: 'user',
      content: analysisPrompt
    }
  ]);

  const responseText = completion.choices?.[0]?.message?.content || '';

  // Extract JSON from response
  try {
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]) as AnalysisResult;
    }
  } catch {
    // Fallback if JSON parsing fails
  }

  // Fallback result
  return {
    threats: [{
      title: 'Análisis en proceso',
      description: responseText.substring(0, 500),
      severity: 'medio',
      category: 'seguridad'
    }],
    overallRiskLevel: 'medio',
    summary: responseText.substring(0, 300),
    recommendations: ['Continuar monitoreo', 'Revisar fuentes adicionales'],
    sources: urls.map(url => ({ title: url, url, relevance: 'Fuente proporcionada' }))
  };
}

export async function generateReport(
  templateContent: string,
  analysis: AnalysisResult
): Promise<string> {
  const reportPrompt = `Eres un redactor de informes ejecutivos de protección VIP. Genera un informe ejecutivo profesional siguiendo la estructura de la plantilla proporcionada, utilizando la información del análisis de inteligencia.

PLANTILLA DEL INFORME:
${templateContent}

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

  const completion = await chatCompletion([
    {
      role: 'system',
      content: 'Eres un redactor profesional de informes ejecutivos de protección VIP. Generas informes en español con formato Markdown.'
    },
    {
      role: 'user',
      content: reportPrompt
    }
  ]);

  return completion.choices?.[0]?.message?.content || 'Error al generar el informe';
}

export async function updateReport(
  existingContent: string,
  existingTitle: string,
  additionalUrls: string[],
  additionalNews: string,
  additionalContext: string
): Promise<string> {
  const collectedData: string[] = [];

  // Fetch content from additional URLs sequentially
  for (const url of additionalUrls) {
    try {
      const readerResult = await webReader(url);
      collectedData.push(`Nueva fuente URL: ${url}\n${readerResult.substring(0, 3000)}`);
    } catch {
      collectedData.push(`Error al leer URL: ${url}`);
    }
    await delay(500);
  }

  // Add additional news text
  if (additionalNews.trim()) {
    collectedData.push(`Noticias adicionales:\n${additionalNews}`);
  }

  // Add additional context
  if (additionalContext.trim()) {
    collectedData.push(`Contexto adicional del analista:\n${additionalContext}`);
  }

  const updatePrompt = `Eres un analista de inteligencia de protección VIP experto. Se te proporciona un informe existente y nueva información que debe ser incorporada para mejorarlo.

INFORME EXISTENTE:
${existingContent}

NUEVA INFORMACIÓN RECOPILADA:
${collectedData.join('\n\n---\n\n')}

INSTRUCCIONES:
1. Integra la nueva información en el informe existente
2. Actualiza las secciones relevantes con los nuevos hallazgos
3. Si la nueva información cambia el nivel de amenaza, actualízalo
4. Añade nuevas amenazas si se identifican
5. Actualiza las recomendaciones si es necesario
6. Mantén la estructura y formato del informe original
7. Usa un tono profesional y ejecutivo
8. El informe debe estar en español
9. Usa formato Markdown para estructurar el documento
10. Marca las secciones actualizadas con [ACTUALIZADO] al inicio del título de la sección

Genera el informe completo actualizado en formato Markdown.`;

  const completion = await chatCompletion([
    {
      role: 'system',
      content: 'Eres un analista profesional de inteligencia de protección VIP. Actualizas informes incorporando nueva información de manera coherente. Generas informes en español con formato Markdown.'
    },
    {
      role: 'user',
      content: updatePrompt
    }
  ]);

  return completion.choices?.[0]?.message?.content || existingContent;
}
