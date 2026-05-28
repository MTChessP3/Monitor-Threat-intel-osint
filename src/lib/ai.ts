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
  const zai = await getAI();
  try {
    const result = await zai.functions.invoke("web_reader", { url });
    if (typeof result === 'string') return result;
    if (result && typeof result === 'object') {
      // Try to extract content from the reader result
      if (result.content) return typeof result.content === 'string' ? result.content : JSON.stringify(result.content);
      if (result.html) return typeof result.html === 'string' ? result.html : JSON.stringify(result.html);
      if (result.text) return typeof result.text === 'string' ? result.text : JSON.stringify(result.text);
      return JSON.stringify(result);
    }
    return JSON.stringify(result);
  } catch (error) {
    console.error(`web_reader failed for ${url}:`, error);
    // Fallback: try web search as alternative
    try {
      const searchResult = await zai.functions.invoke("web_search", { query: url, num: 3 });
      return JSON.stringify(searchResult);
    } catch {
      throw new Error(`No se pudo leer la URL: ${url}`);
    }
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

export async function analyzeIntelligence(
  urls: string[],
  searchQueries: string[]
): Promise<AnalysisResult> {
  const collectedData: string[] = [];
  const errors: string[] = [];

  // Fetch content from URLs (with parallel processing for speed)
  const urlPromises = urls.map(async (url) => {
    try {
      const readerResult = await webReader(url);
      return `Fuente URL: ${url}\n${readerResult.substring(0, 3000)}`;
    } catch (err) {
      errors.push(`URL no accesible: ${url}`);
      return null;
    }
  });

  const urlResults = await Promise.allSettled(urlPromises);
  for (const result of urlResults) {
    if (result.status === 'fulfilled' && result.value) {
      collectedData.push(result.value);
    }
  }

  // Search for relevant news (with parallel processing)
  const searchPromises = searchQueries.map(async (query) => {
    try {
      const searchResult = await webSearch(query, 5);
      const content = typeof searchResult === 'string'
        ? searchResult
        : JSON.stringify(searchResult);
      return `Búsqueda: ${query}\n${content.substring(0, 3000)}`;
    } catch (err) {
      errors.push(`Búsqueda fallida: ${query}`);
      return null;
    }
  });

  const searchResults = await Promise.allSettled(searchPromises);
  for (const result of searchResults) {
    if (result.status === 'fulfilled' && result.value) {
      collectedData.push(result.value);
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

  // Fetch content from additional URLs
  for (const url of additionalUrls) {
    try {
      const readerResult = await webReader(url);
      const content = typeof readerResult === 'string'
        ? readerResult
        : JSON.stringify(readerResult);
      collectedData.push(`Nueva fuente URL: ${url}\n${content.substring(0, 3000)}`);
    } catch {
      collectedData.push(`Error al leer URL: ${url}`);
    }
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
