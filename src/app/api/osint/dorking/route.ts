/**
 * Google Dorking OSINT API Endpoint
 *
 * POST /api/osint/dorking
 *
 * Uses a Smart Search Strategy:
 * - For each target field (name, email, alias, phone, domain), generates
 *   2-5 targeted natural-language queries
 * - Queries are designed for generic web search engines (ZAI), NOT Google Dork syntax
 * - Total queries: ~10-25 (not 100+ like template×field approach)
 * - Results are grouped by target field for clear presentation
 *
 * The old approach (Google Dork templates) failed because:
 * 1. ZAI doesn't support Google operators (intitle:, filetype:, site:)
 * 2. Multiplying 27 templates × 4 fields = 108 API calls was excessive
 * 3. Many resulting queries were nonsensical for a generic search engine
 */

import { NextRequest } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { zaiWebSearch } from '@/lib/zai';
import {
  DORK_TEMPLATES,
  type DorkCategory,
} from '@/lib/osint/dork-templates';
import {
  type TargetInput,
  type SearchFilters,
  type DorkSearchResult,
  type DorkSearchResultItem,
} from '@/lib/osint/query-builder';
import {
  buildSmartQueries,
  buildGoogleUrl,
  deduplicateResults,
  type SmartQuery,
} from '@/lib/osint/smart-search-queries';

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
// ZAI Search Executor
// ============================================================================
async function executeZAIQuery(query: string): Promise<DorkSearchResultItem[]> {
  try {
    const searchResult = await zaiWebSearch(query, { num: 15, maxRetries: 2 });

    if (searchResult && searchResult.length > 0) {
      return searchResult
        .filter((item: any) => item.url && item.url.startsWith('http'))
        .map((item: any, index: number) => ({
          title: (item.name || 'Sin titulo').substring(0, 300),
          url: item.url,
          snippet: (item.snippet || '').substring(0, 500),
          source: 'Investigation Search',
          position: index + 1,
        }));
    }
    return [];
  } catch (e: unknown) {
    console.error(`[DORKING] ZAI search error for "${query.substring(0, 60)}": ${e instanceof Error ? e.message.substring(0, 150) : String(e).substring(0, 150)}`);
    return [];
  }
}

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

  // Determine which categories the user selected (from template IDs)
  const selectedCategories: DorkCategory[] = [];
  const selectedTemplates = DORK_TEMPLATES.filter(t => templateIds.includes(t.id));
  for (const t of selectedTemplates) {
    if (!selectedCategories.includes(t.category)) {
      selectedCategories.push(t.category);
    }
  }

  // Build smart queries — one per field + context combination
  const smartQueries = buildSmartQueries(target, selectedCategories, filters);

  if (smartQueries.length === 0) {
    return new Response(JSON.stringify({ error: 'No se pudieron generar consultas de búsqueda con los datos proporcionados' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const taskId = `dork-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  const startedAt = new Date().toISOString();
  const totalQueryCount = smartQueries.length;

  // Create SSE stream
  const encoder = new TextEncoder();
  const stream = new TransformStream();
  const writer = stream.writable.getWriter();

  // Process queries asynchronously and stream results
  (async () => {
    try {
      // Send initial event
      await writer.write(encoder.encode(sseEvent('start', {
        taskId,
        totalQueries: totalQueryCount,
        startedAt,
        targetFields: [...new Set(smartQueries.map(q => q.targetField))],
        queryPlan: smartQueries.map(q => ({
          id: q.id,
          label: q.label,
          field: q.targetField,
          category: q.category,
        })),
      })));

      let completedQueries = 0;
      let totalResults = 0;
      const allResults: DorkSearchResult[] = [];

      // Execute each smart query
      for (const sq of smartQueries) {
        // Execute the natural-language query on ZAI
        const searchItems = await executeZAIQuery(sq.query);

        // Build Google URL from dork equivalent for "Open in Google" link
        const searchUrl = buildGoogleUrl(sq.dorkEquivalent);

        completedQueries++;
        totalResults += searchItems.length;

        const dorkResult: DorkSearchResult = {
          templateId: sq.id,
          templateName: sq.label,
          query: sq.dorkEquivalent, // Show the dork-style query in UI
          severity: sq.severity,
          category: sq.category,
          engine: 'Investigation Search',
          searchUrl,
          resultCount: searchItems.length,
          results: searchItems,
          completedAt: new Date().toISOString(),
          error: undefined,
        };

        allResults.push(dorkResult);

        // Send progressive result event
        await writer.write(encoder.encode(sseEvent('result', {
          dork: dorkResult,
          progress: {
            taskId,
            totalQueries: totalQueryCount,
            completedQueries,
            totalResults,
          },
          smartQuery: {
            id: sq.id,
            targetField: sq.targetField,
            targetValue: sq.targetValue,
            naturalQuery: sq.query, // The actual query sent to ZAI
            dorkQuery: sq.dorkEquivalent, // The dork-style query for display
          },
        })));

        // Rate limiting delay between queries
        const delay = 400 + Math.random() * 600;
        await new Promise(r => setTimeout(r, delay));
      }

      // Send completion event
      await writer.write(encoder.encode(sseEvent('complete', {
        taskId,
        totalQueries: totalQueryCount,
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
        targetFields: [...new Set(smartQueries.map(q => q.targetField))],
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
