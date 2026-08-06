import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { getZAI, getZAISafe } from '@/lib/zai';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

async function getAuthenticatedUser(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload as { id: string; email: string; role: string };
}

interface ProbeResult {
  name: string;
  ok: boolean;
  elapsedMs: number;
  note?: string;
  body?: string;
}

async function timed(name: string, fn: () => Promise<any>): Promise<ProbeResult> {
  const t0 = Date.now();
  try {
    const res = await fn();
    return {
      name,
      ok: true,
      elapsedMs: Date.now() - t0,
      body: safeJson(res),
    };
  } catch (e: unknown) {
    return {
      name,
      ok: false,
      elapsedMs: Date.now() - t0,
      note: e instanceof Error ? e.message : String(e),
    };
  }
}

function safeJson(v: any): string {
  try {
    return JSON.stringify(v).substring(0, 1200);
  } catch {
    return String(v).substring(0, 1200);
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);
    if (!user) return NextResponse.json({ error: 'No autorizado' }, { status: 401 });

    const zai = await getZAI();
    const results: ProbeResult[] = [];

    const body = await request.json().catch(() => ({}));
    const tests: string[] = Array.isArray(body.tests) ? body.tests : ['all'];

    const want = (t: string) => tests.includes('all') || tests.includes(t);

    if (want('web_search_basic')) {
      results.push(await timed('web_search {query, num:5}', async () => zai.functions.invoke('web_search', { query: 'OpenAI', num: 5 } as any)));
    }
    if (want('web_search_no_num')) {
      results.push(await timed('web_search {query} (no num)', async () => zai.functions.invoke('web_search', { query: 'OpenAI' } as any)));
    }
    if (want('web_search_recency')) {
      results.push(await timed('web_search {query, num:10, recency_days:30}', async () => zai.functions.invoke('web_search', { query: 'OpenAI', num: 10, recency_days: 30 } as any)));
    }
    if (want('chat')) {
      results.push(await timed('chat.completions.create (control)', async () => zai.chat.completions.create({
        messages: [{ role: 'user', content: 'Responde solo: OK' }],
        max_tokens: 50,
      } as any)));
    }
    if (want('page_reader')) {
      results.push(await timed('page_reader example.com (control)', async () => zai.functions.invoke('page_reader', { url: 'https://example.com' } as any)));
    }
    if (want('image_search')) {
      results.push(await timed('images.search.create (control)', async () => zai.images.search.create({ query: 'OpenAI', count: 3 } as any)));
    }

    return NextResponse.json({ success: true, zaiConfigured: !!(process.env.ZAI_BASE_URL && process.env.ZAI_API_KEY), results });
  } catch (e: unknown) {
    return NextResponse.json({ success: false, error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}
