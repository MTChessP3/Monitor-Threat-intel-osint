import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, AUTH_COOKIE_NAME } from '@/lib/auth';
import { getZAI } from '@/lib/zai';

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
  ok: boolean;
  elapsedMs: number;
  note?: string;
  body?: string;
}

function safeJson(v: any): string {
  try {
    return JSON.stringify(v).substring(0, 2000);
  } catch {
    return String(v).substring(0, 2000);
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);
    if (!user) return NextResponse.json({ error: 'No autorizado' }, { status: 401 });

    const body = await request.json().catch(() => ({}));
    const test: string = body.test || 'raw_ws';
    const t0 = Date.now();

    if (test === 'raw_ws' || test === 'raw_ws_nonum' || test === 'raw_ws_recency') {
      const args: any = test === 'raw_ws_nonum' ? { query: 'OpenAI' } : test === 'raw_ws_recency'
        ? { query: 'OpenAI', num: 10, recency_days: 30 }
        : { query: 'OpenAI', num: 5 };
      const baseUrl = process.env.ZAI_BASE_URL || '';
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.ZAI_API_KEY || ''}`,
        'X-Z-AI-From': 'Z',
      };
      if (process.env.ZAI_CHAT_ID) headers['X-Chat-Id'] = process.env.ZAI_CHAT_ID;
      if (process.env.ZAI_USER_ID) headers['X-User-Id'] = process.env.ZAI_USER_ID;
      if (process.env.ZAI_TOKEN) headers['X-Token'] = process.env.ZAI_TOKEN;

      const res = await fetch(`${baseUrl}/functions/invoke`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ function_name: 'web_search', arguments: args }),
      });
      const text = await res.text();
      return NextResponse.json({
        success: true,
        test,
        httpStatus: res.status,
        headers: { 'content-type': res.headers.get('content-type') },
        rawBody: text.substring(0, 2000),
        elapsedMs: Date.now() - t0,
      });
    }

    const zai = await getZAI();
    let result: ProbeResult;

    if (test === 'chat') {
      try {
        const r = await zai.chat.completions.create({
          messages: [{ role: 'user', content: 'Responde solo: OK' }],
          max_tokens: 50,
        } as any);
        result = { ok: true, elapsedMs: Date.now() - t0, body: safeJson(r) };
      } catch (e: unknown) {
        result = { ok: false, elapsedMs: Date.now() - t0, note: e instanceof Error ? e.message : String(e) };
      }
    } else if (test === 'page') {
      try {
        const r = await zai.functions.invoke('page_reader', { url: 'https://example.com' } as any);
        result = { ok: true, elapsedMs: Date.now() - t0, body: safeJson(r) };
      } catch (e: unknown) {
        result = { ok: false, elapsedMs: Date.now() - t0, note: e instanceof Error ? e.message : String(e) };
      }
    } else if (test === 'image') {
      try {
        const r = await zai.images.search.create({ query: 'OpenAI', count: 3 } as any);
        result = { ok: true, elapsedMs: Date.now() - t0, body: safeJson(r) };
      } catch (e: unknown) {
        result = { ok: false, elapsedMs: Date.now() - t0, note: e instanceof Error ? e.message : String(e) };
      }
    } else {
      return NextResponse.json({ success: false, error: 'unknown test' }, { status: 400 });
    }

    return NextResponse.json({ success: true, test, result });
  } catch (e: unknown) {
    return NextResponse.json({ success: false, error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}
