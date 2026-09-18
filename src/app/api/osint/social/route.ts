import { NextRequest, NextResponse } from 'next/server';
import { generateId } from '@/lib/store';
import { kvPushList, kvGetList } from '@/lib/kv';
import { isAIEnabled } from '@/lib/ai';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

// Social channel monitoring (Telegram + Discord).
// Real integration via official Bot APIs when tokens are configured;
// otherwise runs in demo mode with seeded corpora so the UI is fully usable.

const MESSAGES_KEY = 'nexus:social:messages';
const CHANNELS_KEY = 'nexus:social:channels';
const KEYWORDS_KEY = 'nexus:social:keywords';

const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const DC_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const configured = !!(TG_TOKEN || DC_TOKEN);

interface Message {
  id: string;
  platform: 'telegram' | 'discord';
  channel: string;
  channelId: string;
  author: string;
  authorId: string;
  text: string;
  ts: string;
  keywords: string[];
  severity: string;
  objects?: string[];
  links?: string[];
}

// ---------- Real Telegram fetch via Bot API (getUpdates / getChat) ----------
async function fetchTelegramMessages(): Promise<Message[]> {
  const res = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/getUpdates`, { signal: AbortSignal.timeout(10000) });
  const data = await res.json();
  const msgs: Message[] = [];
  if (!data.ok) return msgs;
  (data.result || []).forEach((u: any) => {
    const m = u.message || u.edited_message;
    if (!m || !m.chat || !m.text) return;
    msgs.push({
      id: String(m.message_id),
      platform: 'telegram',
      channel: m.chat.title || m.chat.username || String(m.chat.id),
      channelId: String(m.chat.id),
      author: m.from?.first_name || m.from?.username || 'unknown',
      authorId: String(m.from?.id || 0),
      text: m.text,
      ts: new Date(m.date * 1000).toISOString(),
      keywords: [],
      severity: 'INFO',
      links: (m.text.match(/https?:\/\/[^\s]+/g) || []),
    });
  });
  return msgs;
}

// ---------- Real Discord fetch via REST (channels read) ----------
async function fetchDiscordMessages(): Promise<Message[]> {
  const headers = { Authorization: `Bot ${DC_TOKEN}` };
  const guilds = await fetch('https://discord.com/api/v10/users/@me/guilds', { headers, signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.json() : []));
  const msgs: Message[] = [];
  for (const g of (guilds as any[]).slice(0, 5)) {
    const channels: any[] = await fetch(`https://discord.com/api/v10/guilds/${g.id}/channels`, { headers, signal: AbortSignal.timeout(8000) }).then((r) => (r.ok ? r.json() : []));
    for (const ch of channels.filter((c: any) => c.type === 0).slice(0, 5)) {
      const raw: any[] = await fetch(`https://discord.com/api/v10/channels/${ch.id}/messages?limit=20`, { headers, signal: AbortSignal.timeout(8000) }).then((r) => (r.ok ? r.json() : []));
      (raw || []).forEach((m) => {
        msgs.push({
          id: m.id,
          platform: 'discord',
          channel: ch.name,
          channelId: ch.id,
          author: m.author?.username || 'unknown',
          authorId: m.author?.id || '0',
          text: m.content || '',
          ts: m.timestamp,
          keywords: [],
          severity: 'INFO',
          objects: (m.attachments || []).map((a: any) => a.filename),
          links: (m.content || '').match(/https?:\/\/[^\s]+/g) || [],
        });
      });
    }
  }
  return msgs;
}

// ---------- Demo corpus ----------
function seedMessages(): Message[] {
  const now = Date.now();
  const corpus: [string, string, string, string, string][] = [
    ['telegram', 'breach-sellers', 'dark_ledger', 'Selling fresh logs — paypal accounts with balance. DM me', 'CRITICAL'],
    ['telegram', 'leaks-watcher', 'anonym_01', 'New dump posted: 1.2M credentials from social platform', 'CRITICAL'],
    ['discord', 'malware-analysis', 'hexbyte', 'Anyone seen this phishing kit? target: banking brands', 'HIGH'],
    ['telegram', 'cve-alerts', 'vuln_bot', 'CVE-2026-11872 exploited in the wild, patch now', 'HIGH'],
    ['discord', 'threat-intel', 'osint_ghost', 'Tracking campaign: fake login pages for major e-commerce', 'MEDIUM'],
    ['telegram', 'marketplace', 'vendor_7', 'RAT builder v4.0 for sale, telegram @rat_builder_x', 'HIGH'],
    ['discord', 'incident-response', 'sec_ops', 'Phishing email with malicious .zip attachment reported', 'MEDIUM'],
    ['telegram', 'deep-web-index', 'index_bot', 'Indexed: carding forum, 5 new threads on payment fraud', 'MEDIUM'],
  ];
  const keywords = ['phishing', 'breach', 'malware', 'kit', 'login', 'credential', 'exploit', 'ransomware', 'banking', 'leak', 'dump', 'carding', 'botnet'];
  return corpus.map(([platform, channel, author, text, severity], i) => {
    const matched = keywords.filter((k) => text.toLowerCase().includes(k.toLowerCase()));
    return {
      id: generateId(),
      platform: platform as Message['platform'],
      channel,
      channelId: `demo-${channel}`,
      author,
      authorId: `demo-${author}`,
      text,
      ts: new Date(now - (i + 1) * 900000).toISOString(),
      keywords: matched,
      severity,
      links: (text.match(/https?:\/\/[^\s]+/g) || []) as any,
      objects: [],
    };
  });
}

// ---------- Keyword matching ----------
function matchKeywords(text: string, keywords: string[]): string[] {
  const t = text.toLowerCase();
  return keywords.filter((k) => t.includes(k.toLowerCase()));
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const q = searchParams.get('q') || '';
  const platform = searchParams.get('platform') || '';
  const channel = searchParams.get('channel') || '';
  const author = searchParams.get('author') || '';
  const from = searchParams.get('from') || '';

  const { module: socialModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }

  // Collect messages (real when tokens present, else demo)
  let messages = await kvGetList<Message>(MESSAGES_KEY);
  if (configured && action === 'refresh') {
    try {
      const [tg, dc] = await Promise.allSettled([fetchTelegramMessages(), fetchDiscordMessages()]);
      const fresh = [...(tg.status === 'fulfilled' ? tg.value : []), ...(dc.status === 'fulfilled' ? dc.value : [])];
      const keywords = (await kvGetList<string>(KEYWORDS_KEY)) || ['phishing', 'malware', 'breach', 'kit'];
      fresh.forEach((m) => { m.keywords = matchKeywords(m.text, keywords); });
      fresh.forEach((m) => kvPushList(MESSAGES_KEY, m, 500));
      messages = fresh;
    } catch (e) {
      console.error('Social refresh error:', e);
    }
  } else if (messages.length === 0) {
    messages = seedMessages();
    await Promise.all(messages.map((m) => kvPushList(MESSAGES_KEY, m, 500)));
  }

  // Filters
  const keywords = (await kvGetList<string>(KEYWORDS_KEY)) || ['phishing', 'malware', 'breach', 'kit', 'login', 'credential'];
  const filtered = messages.filter((m) => {
    if (q && !(m.text.toLowerCase().includes(q.toLowerCase()) || m.keywords.some((k) => k.toLowerCase().includes(q.toLowerCase())))) return false;
    if (platform && m.platform !== platform) return false;
    if (channel && m.channel !== channel) return false;
    if (author && m.author !== author) return false;
    if (from && new Date(m.ts) < new Date(from)) return false;
    return true;
  });

  const channels = [...new Set(messages.map((m) => m.channel))];
  const authors = [...new Set(messages.map((m) => m.author))];
  const stats = {
    total: messages.length,
    filtered: filtered.length,
    byPlatform: { telegram: messages.filter((m) => m.platform === 'telegram').length, discord: messages.filter((m) => m.platform === 'discord').length },
    critical: messages.filter((m) => m.severity === 'CRITICAL').length,
    high: messages.filter((m) => m.severity === 'HIGH').length,
    medium: messages.filter((m) => m.severity === 'MEDIUM').length,
    topKeywords: (() => {
      const count: Record<string, number> = {};
      messages.forEach((m) => m.keywords.forEach((k) => { count[k] = (count[k] || 0) + 1; }));
      return Object.entries(count).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => ({ keyword: k, count: v }));
    })(),
    activeChannels: channels.length,
    objectsCaptured: messages.filter((m) => (m.objects || []).length || (m.links || []).length).length,
  };

  return NextResponse.json({
    success: true,
    module: socialModule,
    source: configured ? 'Telegram/Discord live' : 'Telegram/Discord (demo mode)',
    timestamp: new Date().toISOString(),
    configured,
    aiEnabled: isAIEnabled(),
    filters: { q, platform, channel, author, from },
    stats,
    channels,
    authors,
    keywords,
    data: filtered.slice(0, 200),
    message: configured
      ? 'Live capture active — listening on configured bots'
      : 'Demo mode — set TELEGRAM_BOT_TOKEN / DISCORD_BOT_TOKEN for live capture',
  });
}

// ---------- POST: set keywords / refresh / ingest webhook ----------
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, keywords, message } = body;

    const { module: socialModule, error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }

    if (action === 'set-keywords') {
      if (!Array.isArray(keywords)) return NextResponse.json({ success: false, error: 'keywords must be an array' }, { status: 400 });
      const unique = [...new Set(keywords.map((k) => String(k).trim()).filter(Boolean))];
      for (const k of unique) await kvPushList(KEYWORDS_KEY, k, 100);
      return NextResponse.json({ success: true, module: socialModule, data: unique, message: `${unique.length} keyword(s) configured` });
    }

    if (action === 'ingest') {
      // Manual ingest (also used by future webhook endpoints)
      const m: Message = {
        id: generateId(),
        platform: message.platform || 'telegram',
        channel: message.channel || 'manual',
        channelId: message.channelId || 'manual',
        author: message.author || 'manual',
        authorId: message.authorId || 'manual',
        text: message.text || '',
        ts: message.ts || new Date().toISOString(),
        keywords: [],
        severity: message.severity || 'INFO',
        objects: message.objects || [],
        links: (message.text || '').match(/https?:\/\/[^\s]+/g) || [],
      };
      const keywords = (await kvGetList<string>(KEYWORDS_KEY)) || [];
      m.keywords = matchKeywords(m.text, keywords);
      await kvPushList(MESSAGES_KEY, m, 500);
      return NextResponse.json({ success: true, data: m, message: 'Message ingested' });
    }

    if (action === 'refresh') {
      const res = await fetch(new URL(request.url).origin + '/api/osint/social?action=refresh', { signal: AbortSignal.timeout(30000) }).then((r) => r.json());
      return NextResponse.json(res);
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (error) {
    console.error('Social module error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Social monitoring failed' },
      { status: 500 }
    );
  }
}
