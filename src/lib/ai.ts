// AI provider client (OpenAI-compatible) for server-side use.
// Defaults to Groq (free, fast). Works with any OpenAI-compatible endpoint
// by overriding AI_BASE_URL, AI_MODEL and AI_API_KEY.
//
// When AI_API_KEY is not configured, isAIEnabled() returns false and
// aiComplete() returns { content: null, usedAI: false }, letting callers
// fall back to rule-based engines (clearly labeled).

export interface AIConfig {
  apiKey: string;
  baseURL: string;
  model: string;
  temperature: number;
  maxTokens: number;
}

export interface AIResult {
  content: string | null;
  usedAI: boolean;
  provider: string;
  model: string;
  raw?: unknown;
}

const DEFAULT_MODEL = process.env.AI_MODEL || 'llama-3.3-70b-versatile';
const DEFAULT_BASE_URL =
  process.env.AI_BASE_URL || 'https://api.groq.com/openai/v1';

export function getAIConfig(): AIConfig {
  return {
    apiKey: process.env.AI_API_KEY || process.env.GROQ_API_KEY || '',
    baseURL: DEFAULT_BASE_URL,
    model: DEFAULT_MODEL,
    temperature: parseFloat(process.env.AI_TEMPERATURE || '0.3'),
    maxTokens: parseInt(process.env.AI_MAX_TOKENS || '2000', 10),
  };
}

export function isAIEnabled(): boolean {
  return Boolean(getAIConfig().apiKey);
}

// Strip any <thinking> tags a model might emit, keeping only the final answer.
function stripReasoning(text: string): string {
  return text.replace(/<thinking>[\s\S]*?<\/thinking>/g, '').trim();
}

export async function aiComplete(
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>,
  options?: Partial<AIConfig>
): Promise<AIResult> {
  const config: AIConfig = { ...getAIConfig(), ...options };

  if (!config.apiKey) {
    return { content: null, usedAI: false, provider: 'not-configured', model: config.model };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 45000);

    const response = await fetch(`${config.baseURL.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        model: config.model,
        messages,
        temperature: config.temperature,
        max_tokens: config.maxTokens,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      throw new Error(`AI API HTTP ${response.status}: ${errText.slice(0, 300)}`);
    }

    const data = await response.json();
    const rawContent: string = data?.choices?.[0]?.message?.content || '';
    const content = stripReasoning(rawContent);

    if (!content) {
      throw new Error('AI returned empty content');
    }

    return {
      content,
      usedAI: true,
      provider: 'ai-provider',
      model: data?.model || config.model,
      raw: data,
    };
  } catch (error) {
    console.error('[AI] aiComplete failed:', error instanceof Error ? error.message : error);
    return { content: null, usedAI: false, provider: 'error', model: config.model };
  }
}

// Best-effort extraction of a JSON object from an LLM response.
export function extractJSON<T = Record<string, unknown>>(text: string): T | null {
  if (!text) return null;

  // Try direct parse first (trim code fences)
  const cleaned = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    /* fall through */
  }

  // Extract the largest balanced {...} block
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start !== -1 && end > start) {
    try {
      return JSON.parse(cleaned.slice(start, end + 1)) as T;
    } catch {
      /* fall through */
    }
  }

  return null;
}

export async function aiJSON<T = Record<string, unknown>>(
  systemPrompt: string,
  userPrompt: string,
  options?: { temperature?: number; maxTokens?: number }
): Promise<{ data: T | null; usedAI: boolean; raw: string }> {
  const result = await aiComplete(
    [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    options
  );

  if (!result.usedAI || !result.content) {
    return { data: null, usedAI: false, raw: '' };
  }

  const data = extractJSON<T>(result.content);
  return { data, usedAI: true, raw: result.content };
}
