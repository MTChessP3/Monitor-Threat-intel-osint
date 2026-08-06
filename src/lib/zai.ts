/**
 * ZAI SDK Unified Initialization Module
 *
 * This module provides a single, robust way to initialize the ZAI SDK
 * that works in ALL environments:
 * - Local development (reads from /etc/.z-ai-config)
 * - Vercel serverless (reads from environment variables)
 * - Any other cloud provider (reads from environment variables)
 *
 * CRITICAL: The .z-ai-config file only exists on the local dev machine.
 * On Vercel/cloud, we MUST use environment variables.
 */

import ZAI from 'z-ai-web-dev-sdk';

// ============================================================================
// ZAI Configuration from environment variables
// ============================================================================
const ZAI_BASE_URL = process.env.ZAI_BASE_URL || '';
const ZAI_API_KEY = process.env.ZAI_API_KEY || '';
const ZAI_CHAT_ID = process.env.ZAI_CHAT_ID || '';
const ZAI_TOKEN = process.env.ZAI_TOKEN || '';
const ZAI_USER_ID = process.env.ZAI_USER_ID || '';

// ============================================================================
// Singleton instance - reuse across invocations in same cold start
// ============================================================================
let zaiInstance: InstanceType<typeof ZAI> | null = null;
let zaiInitPromise: Promise<InstanceType<typeof ZAI>> | null = null;

/**
 * Get a ZAI SDK instance. Uses singleton pattern with double-checked locking.
 *
 * Priority:
 * 1. Environment variables (ZAI_BASE_URL + ZAI_API_KEY) - for Vercel/cloud
 * 2. ZAI.create() which reads .z-ai-config file - for local dev
 *
 * If both fail, throws an error with clear instructions.
 */
export async function getZAI(): Promise<InstanceType<typeof ZAI>> {
  if (zaiInstance) return zaiInstance;

  // Prevent concurrent initialization
  if (zaiInitPromise) return zaiInitPromise;

  zaiInitPromise = (async () => {
    try {
      // METHOD 1: Environment variables (for Vercel/cloud deployment)
      if (ZAI_BASE_URL && ZAI_API_KEY) {
        console.log('[ZAI] Initializing from environment variables...');
        const instance = new ZAI({
          baseUrl: ZAI_BASE_URL,
          apiKey: ZAI_API_KEY,
          chatId: ZAI_CHAT_ID,
          token: ZAI_TOKEN,
          userId: ZAI_USER_ID,
        });

        // Verify the instance works by doing a quick test
        zaiInstance = instance;
        console.log('[ZAI] Initialized from env vars successfully');
        return instance;
      }

      // METHOD 2: ZAI.create() reads .z-ai-config file (local dev)
      console.log('[ZAI] No env vars found, trying ZAI.create() (reads .z-ai-config)...');
      const instance = await ZAI.create();
      zaiInstance = instance;
      console.log('[ZAI] Initialized from .z-ai-config successfully');
      return instance;
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error(`[ZAI] ALL initialization methods failed: ${msg.substring(0, 200)}`);
      zaiInitPromise = null; // Allow retry on next call
      throw new Error(`ZAI SDK initialization failed: ${msg.substring(0, 100)}`);
    }
  })();

  return zaiInitPromise;
}

/**
 * Safe ZAI instance getter - never throws, returns null if unavailable
 */
export async function getZAISafe(): Promise<InstanceType<typeof ZAI> | null> {
  try {
    return await getZAI();
  } catch {
    console.error('[ZAI] SDK unavailable - all initialization methods failed');
    return null;
  }
}

/**
 * Check if ZAI is available without initializing it
 */
export function isZAIConfigured(): boolean {
  return !!(ZAI_BASE_URL && ZAI_API_KEY);
}

/**
 * Execute a ZAI chat completion with automatic retry logic
 * Never throws - returns null on failure after all retries
 */
export async function zaiChatCompletion(
  messages: Array<{ role: string; content: string }>,
  options: {
    temperature?: number;
    max_tokens?: number;
    maxRetries?: number;
    retryDelay?: number;
  } = {}
): Promise<string | null> {
  const { temperature = 0.2, max_tokens = 8000, maxRetries = 3, retryDelay = 2000 } = options;

  const zai = await getZAISafe();
  if (!zai) {
    console.error('[ZAI] Cannot execute chat completion - SDK not available');
    return null;
  }

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const completion = await zai.chat.completions.create({
        messages,
        temperature,
        max_tokens,
      } as any);

      const content = completion.choices?.[0]?.message?.content || '';
      if (content.length > 0) {
        console.log(`[ZAI] Chat completion succeeded on attempt ${attempt + 1}: ${content.length} chars`);
        return content;
      }

      console.log(`[ZAI] Chat completion returned empty on attempt ${attempt + 1}`);
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error(`[ZAI] Chat completion error (attempt ${attempt + 1}/${maxRetries}): ${msg.substring(0, 150)}`);

      // If rate limited, wait longer
      if (msg.includes('429')) {
        const waitTime = retryDelay * Math.pow(2, attempt);
        console.log(`[ZAI] Rate limited, waiting ${waitTime / 1000}s before retry...`);
        await new Promise(r => setTimeout(r, waitTime));
        continue;
      }

      // For other errors, shorter wait
      if (attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, retryDelay));
      }
    }
  }

  console.error(`[ZAI] Chat completion failed after ${maxRetries} attempts`);
  return null;
}

/**
 * Execute a ZAI web search with automatic retry logic.
 * Never throws - returns empty array on failure.
 *
 * An optional onDiagnostics callback receives the outcome of the whole call
 * (final status, attempts, elapsed time, error body) so callers can surface
 * the real ZAI behavior in their API response. This is the only way to debug
 * ZAI calls on serverless platforms without runtime-log access.
 */
export type ZAIWebSearchStatus = 'ok' | 'empty' | 'timeout' | 'error' | 'bad_shape';

export interface ZAIWebSearchDiagnostics {
  query: string;
  status: ZAIWebSearchStatus;
  attempts: number;
  elapsedMs: number;
  error?: string;
  raw?: string;
}

export async function zaiWebSearch(
  query: string,
  options: {
    num?: number;
    maxRetries?: number;
    timeoutMs?: number;
    onDiagnostics?: (diagnostics: ZAIWebSearchDiagnostics) => void;
  } = {}
): Promise<Array<{
  url: string;
  name: string;
  snippet: string;
  host_name: string;
  rank: number;
  date: string;
  favicon: string;
}>> {
  const { num = 10, maxRetries = 2, timeoutMs, onDiagnostics } = options;
  const startedAt = Date.now();

  const zai = await getZAISafe();
  if (!zai) {
    console.error('[ZAI] Cannot execute web search - SDK not available');
    onDiagnostics?.({ query, status: 'error', attempts: 0, elapsedMs: Date.now() - startedAt, error: 'SDK not available' });
    return [];
  }

  let status: ZAIWebSearchStatus = 'empty';
  let lastError = '';
  let rawShape = '';
  let attempts = 0;

  const finish = (finalStatus: ZAIWebSearchStatus, results: Array<any>): Array<any> => {
    const diagnostics: ZAIWebSearchDiagnostics = {
      query,
      status: finalStatus,
      attempts,
      elapsedMs: Date.now() - startedAt,
    };
    if (lastError) diagnostics.error = lastError;
    if (rawShape) diagnostics.raw = rawShape;
    onDiagnostics?.(diagnostics);
    return results;
  };

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    attempts++;
    try {
      const invoke = zai.functions.invoke('web_search', { query, num });
      let result: any;
      if (timeoutMs && timeoutMs > 0) {
        // Guard against the underlying fetch never settling: race with a timer.
        // The abandoned promise is guarded so it cannot become an unhandled rejection.
        const guarded = invoke.then(
          (v: any) => v,
          (e: unknown) => {
            const msg = e instanceof Error ? e.message : String(e);
            console.error(`[ZAI] Web search late error (${msg.substring(0, 100)})`);
            return [];
          }
        );
        try {
          result = await Promise.race([
            guarded,
            new Promise((_, reject) => setTimeout(() => reject(new Error('ZAI_WEB_SEARCH_TIMEOUT')), timeoutMs)),
          ]);
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          if (msg.includes('ZAI_WEB_SEARCH_TIMEOUT')) {
            status = 'timeout';
            continue;
          }
          throw e;
        }
      } else {
        result = await invoke;
      }

      if (Array.isArray(result)) {
        if (result.length > 0) {
          console.log(`[ZAI] Web search succeeded: "${query.substring(0, 60)}" -> ${result.length} results`);
          return finish('ok', result);
        }
        status = 'empty';
        console.log(`[ZAI] Web search returned empty array: "${query.substring(0, 60)}"`);
        continue;
      }

      // ZAI responded but the shape is not the documented array -> record it.
      status = 'bad_shape';
      try { rawShape = JSON.stringify(result).substring(0, 300); } catch { rawShape = String(result).substring(0, 300); }
      console.log(`[ZAI] Web search unexpected shape: "${query.substring(0, 50)}" -> ${rawShape}`);
      continue;
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      lastError = msg;
      status = 'error';
      console.error(`[ZAI] Web search error (attempt ${attempt + 1}/${maxRetries}): "${query.substring(0, 50)}" - ${msg.substring(0, 150)}`);

      if (msg.includes('429') && attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  }

  return finish(status, []);
}
