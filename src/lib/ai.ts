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

export async function webReader(url: string) {
  const zai = await getAI();
  const result = await zai.functions.invoke("web_reader", { url });
  return result;
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

  // Fetch content from URLs
  for (const url of urls) {
    try {
      const readerResult = await webReader(url);
      const content = typeof readerResult === 'string'
        ? readerResult
        : JSON.stringify(readerResult);
      collectedData.push(`Fuente URL: ${url}\n${content.substring(0, 3000)}`);
    } catch {
      collectedData.push(`Error al leer URL: ${url}`);
    }
  }

  // Search for relevant news
  for (const query of searchQueries) {
    try {
      const searchResult = await webSearch(query, 5);
      const content = typeof searchResult === 'string'
        ? searchResult
        : JSON.stringify(searchResult);
      collectedData.push(`Búsqueda: ${query}\n${content.substring(0, 3000)}`);
    } catch {
      collectedData.push(`Error en búsqueda: ${query}`);
    }
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
