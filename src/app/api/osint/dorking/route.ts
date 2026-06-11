/**
 * Google Dorking OSINT API Endpoint
 *
 * POST /api/osint/dorking
 *
 * Accepts target info, filters, and template IDs.
 * Returns Server-Sent Events (SSE) with progressive results.
 *
 * KEY DESIGN DECISIONS:
 * 1. Templates use Google Dork syntax (intitle:, inurl:, filetype:, site:)
 *    but the backend uses ZAI Web Search which does NOT understand those operators.
 * 2. We convert dork queries to natural-language queries for ZAI execution,
 *    while preserving the original dork query for display / "Open in Google" link.
 * 3. For each template, we generate ONE query per target field (name, email,
 *    alias, phone, domain), so all provided fields are searched.
 * 4. Results from all field-specific queries are merged and deduplicated.
 */

import { NextRequest } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { zaiWebSearch } from '@/lib/zai';
import {
  DORK_TEMPLATES,
  type SeverityLevel,
  type DorkCategory,
} from '@/lib/osint/dork-templates';
import {
  buildQueryFromTemplate,
  buildSearchUrl,
  buildMultiFieldZAIQueries,
  deduplicateResults,
  type TargetInput,
  type SearchFilters,
  type DorkSearchResult,
  type DorkSearchResultItem,
  type MultiFieldQuery,
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
// ZAI Search Executor
// ============================================================================
/**
 * Execute a single natural-language query against ZAI Web Search.
 * Returns an array of search result items.
 */
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

/**
 * Execute all field-specific queries for a single template,
 * merge and deduplicate the results.
 */
async function executeTemplateQueries(
  multiQueries: MultiFieldQuery[],
): Promise<{ results: DorkSearchResultItem[]; error?: string }> {
  const allItems: DorkSearchResultItem[] = [];
  let lastError: string | undefined;

  for (const mq of multiQueries) {
    const items = await executeZAIQuery(mq.zaiQuery);
    allItems.push(...items);

    // Small delay between field queries to avoid rate limiting
    if (multiQueries.indexOf(mq) < multiQueries.length - 1) {
      await new Promise(r => setTimeout(r, 200));
    }
  }

  // Deduplicate by URL
  const deduped = deduplicateResults(allItems);

  return { results: deduped, error: lastError };
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

  // Build multi-field ZAI queries for all templates
  const allMultiQueries: MultiFieldQuery[] = [];
  for (const template of selectedTemplates) {
    const queries = buildMultiFieldZAIQueries(template, target, filters);
    allMultiQueries.push(...queries);
  }

  // Total queries = number of unique template+field combinations
  const totalQueryCount = selectedTemplates.length; // Report progress per template, not per field query

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
        totalQueries: totalQueryCount,
        startedAt,
        targetFields: [...new Set(allMultiQueries.map(q => q.targetField))],
        totalSubQueries: allMultiQueries.length,
      })));

      let completedQueries = 0;
      let totalResults = 0;
      const allResults: DorkSearchResult[] = [];

      // Execute each dork template (with multi-field queries)
      for (const template of selectedTemplates) {
        // Get the multi-field queries for this template
        const templateMultiQueries = allMultiQueries.filter(q => q.templateId === template.id);

        // Build the dork query (for display) using primary target
        const dorkQuery = buildQueryFromTemplate(template, target, filters);
        const searchUrl = buildSearchUrl(dorkQuery, 'google');

        // Execute all field-specific queries and merge results
        const { results: mergedResults, error: searchError } = await executeTemplateQueries(templateMultiQueries);

        completedQueries++;
        totalResults += mergedResults.length;

        const dorkResult: DorkSearchResult = {
          templateId: template.id,
          templateName: template.name,
          query: dorkQuery,
          severity: template.severity,
          category: template.category,
          engine: 'Investigation Search',
          searchUrl,
          resultCount: mergedResults.length,
          results: mergedResults,
          completedAt: new Date().toISOString(),
          error: searchError,
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
        })));

        // Rate limiting delay between templates (anti-bot)
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
        targetFields: [...new Set(allMultiQueries.map(q => q.targetField))],
        totalSubQueries: allMultiQueries.length,
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
