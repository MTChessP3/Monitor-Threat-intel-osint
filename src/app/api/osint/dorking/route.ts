/**
 * Google Dorking OSINT API Endpoint
 *
 * POST /api/osint/dorking
 *
 * Accepts target info, filters, and template IDs.
 * Returns Server-Sent Events (SSE) with progressive results
 * as each dork query is executed against multiple search engines.
 *
 * Flow:
 * 1. Frontend sends POST with search parameters
 * 2. Backend responds with SSE stream
 * 3. Each dork result is sent as an SSE event
 * 4. Final "complete" event signals end of search
 */

import { NextRequest } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { zaiWebSearch } from '@/lib/zai';
import {
  DORK_TEMPLATES,
  SEVERITY_COLORS,
  type SeverityLevel,
  type DorkCategory,
} from '@/lib/osint/dork-templates';
import {
  buildQueryFromTemplate,
  buildSearchUrl,
  getRandomUserAgent,
  type TargetInput,
  type SearchFilters,
  type DorkSearchResult,
  type DorkSearchResultItem,
} from '@/lib/osint/query-builder';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

// ============================================================================
// Auth
// ============================================================================
async function getAuthenticatedUser(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload as { id: string; email: string; role: string };
}

// ============================================================================
// SSE Helper
// ============================================================================
function sseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

// ============================================================================
// Search Engine Adapters
// ============================================================================
interface EngineAdapter {
  name: string;
  search: (query: string) => Promise<DorkSearchResultItem[]>;
}

function createZAIEngineAdapter(engineName: string): EngineAdapter {
  return {
    name: engineName,
    search: async (query: string): Promise<DorkSearchResultItem[]> => {
      try {
        const searchResult = await zaiWebSearch(query, { num: 15, maxRetries: 2 });

        if (searchResult && searchResult.length > 0) {
          return searchResult
            .filter((item: any) => item.url && item.url.startsWith('http'))
            .map((item: any, index: number) => ({
              title: (item.name || 'Sin titulo').substring(0, 300),
              url: item.url,
              snippet: (item.snippet || '').substring(0, 500),
              source: engineName,
              position: index + 1,
            }));
        }
        return [];
      } catch (e: unknown) {
        console.error(`[DORKING] ${engineName} search error: ${e instanceof Error ? e.message.substring(0, 150) : String(e).substring(0, 150)}`);
        return [];
      }
    },
  };
}

// We use ZAI Web Search as the unified search backend
// It aggregates results from multiple search engines
const ENGINES: EngineAdapter[] = [
  createZAIEngineAdapter('Google (via ZAI)'),
  createZAIEngineAdapter('Bing (via ZAI)'),
  createZAIEngineAdapter('DuckDuckGo (via ZAI)'),
  createZAIEngineAdapter('Yandex (via ZAI)'),
];

// ============================================================================
// POST Handler - SSE Stream
// ============================================================================
export async function POST(request: NextRequest) {
  // Auth check
  const user = await getAuthenticatedUser(request);
  if (!user) {
    return new Response(JSON.stringify({ error: 'No autorizado' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let body: {
    target: TargetInput;
    filters?: SearchFilters;
    templateIds: string[];
    engines?: string[];
  };

  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Cuerpo de la peticion invalido' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { target, filters = {}, templateIds } = body;

  if (!target || (!target.name && !target.email && !target.alias && !target.phone && !target.domain)) {
    return new Response(JSON.stringify({ error: 'Se requiere al menos un campo del objetivo (nombre, email, alias, telefono, dominio)' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (!templateIds || templateIds.length === 0) {
    return new Response(JSON.stringify({ error: 'Se debe seleccionar al menos una plantilla de dork' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Get selected templates
  const selectedTemplates = DORK_TEMPLATES.filter(t => templateIds.includes(t.id));
  if (selectedTemplates.length === 0) {
    return new Response(JSON.stringify({ error: 'Plantillas seleccionadas no encontradas' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const taskId = `dork-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  const startedAt = new Date().toISOString();

  // Create SSE stream
  const encoder = new TextEncoder();
  const stream = new TransformStream();
  const writer = stream.writable.getWriter();

  // Process dorks asynchronously and stream results
  (async () => {
    try {
      // Send initial event
      await writer.write(encoder.encode(sseEvent('start', {
        taskId,
        totalQueries: selectedTemplates.length,
        startedAt,
      })));

      let completedQueries = 0;
      let totalResults = 0;
      const allResults: DorkSearchResult[] = [];

      // Execute each dork template
      for (const template of selectedTemplates) {
        const query = buildQueryFromTemplate(template, target, filters);
        const searchUrl = buildSearchUrl(query, 'google');

        // Try multiple engines (use ZAI as primary, which aggregates)
        let bestResults: DorkSearchResultItem[] = [];
        let usedEngine = 'ZAI Web Search';
        let searchError: string | undefined;

        try {
          // Use the first engine adapter (ZAI aggregates multiple engines)
          const results = await ENGINES[0].search(query);
          if (results.length > 0) {
            bestResults = results;
            usedEngine = ENGINES[0].name;
          }
        } catch (e: unknown) {
          searchError = e instanceof Error ? e.message.substring(0, 200) : String(e).substring(0, 200);
        }

        // If no results from primary, try secondary
        if (bestResults.length === 0 && !searchError) {
          try {
            const results = await ENGINES[1].search(query);
            if (results.length > 0) {
              bestResults = results;
              usedEngine = ENGINES[1].name;
            }
          } catch (e: unknown) {
            searchError = e instanceof Error ? e.message.substring(0, 200) : String(e).substring(0, 200);
          }
        }

        completedQueries++;
        totalResults += bestResults.length;

        const dorkResult: DorkSearchResult = {
          templateId: template.id,
          templateName: template.name,
          query,
          severity: template.severity,
          category: template.category,
          engine: usedEngine,
          searchUrl,
          resultCount: bestResults.length,
          results: bestResults,
          completedAt: new Date().toISOString(),
          error: searchError,
        };

        allResults.push(dorkResult);

        // Send progressive result event
        await writer.write(encoder.encode(sseEvent('result', {
          dork: dorkResult,
          progress: {
            taskId,
            totalQueries: selectedTemplates.length,
            completedQueries,
            totalResults,
          },
        })));

        // Rate limiting delay between queries (anti-bot)
        const delay = 300 + Math.random() * 500;
        await new Promise(r => setTimeout(r, delay));
      }

      // Send completion event
      await writer.write(encoder.encode(sseEvent('complete', {
        taskId,
        totalQueries: selectedTemplates.length,
        completedQueries,
        totalResults,
        allResults: allResults.map(r => ({
          templateId: r.templateId,
          templateName: r.templateName,
          query: r.query,
          severity: r.severity,
          category: r.category,
          resultCount: r.resultCount,
          engine: r.engine,
        })),
        elapsedSeconds: ((Date.now() - new Date(startedAt).getTime()) / 1000).toFixed(1),
        target,
      })));

    } catch (e: unknown) {
      const errorMsg = e instanceof Error ? e.message : 'Error desconocido en la busqueda';
      console.error(`[DORKING] Fatal error: ${errorMsg}`);
      await writer.write(encoder.encode(sseEvent('error', {
        taskId,
        error: errorMsg,
      })));
    } finally {
      await writer.close();
    }
  })();

  return new Response(stream.readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}
