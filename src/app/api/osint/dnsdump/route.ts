import { NextRequest, NextResponse } from 'next/server';
import { lookupDomain } from '@/lib/intel';
import { isAIEnabled } from '@/lib/ai';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'];

const TAKEOVER_SERVICES: [RegExp, string][] = [
  [/github\.io$/i, 'GitHub Pages'],
  [/herokuapp\.com$/i, 'Heroku'],
  [/herokudns\.com$/i, 'Heroku'],
  [/azurewebsites\.net$/i, 'Azure Web Apps'],
  [/\.cloudapp\.(net|azure\.com)$/i, 'Azure CloudApp'],
  [/trafficmanager\.net$/i, 'Azure Traffic Manager'],
  [/\.s3\.amazonaws\.com$/i, 'AWS S3'],
  [/\.s3-[a-z0-9-]+\.amazonaws\.com$/i, 'AWS S3'],
  [/\.cloudfront\.net$/i, 'AWS CloudFront'],
  [/\.elasticbeanstalk\.com$/i, 'AWS Elastic Beanstalk'],
  [/\.netlify\.app$/i, 'Netlify'],
  [/\.surge\.sh$/i, 'Surge.sh'],
  [/\.pantheonsite\.io$/i, 'Pantheon'],
  [/\.myshopify\.com$/i, 'Shopify'],
  [/\.shopify\.com$/i, 'Shopify'],
  [/\.bitbucket\.io$/i, 'Bitbucket'],
  [/\.readthedocs\.io$/i, 'ReadTheDocs'],
  [/\.ghost\.io$/i, 'Ghost'],
  [/\.wordpress\.com$/i, 'WordPress.com'],
  [/\.wpengine\.com$/i, 'WP Engine'],
  [/\.fastly\.net$/i, 'Fastly'],
  [/\.vercel-dns\.com$/i, 'Vercel'],
  [/^cname\.vercel-dns\.com$/i, 'Vercel'],
  [/\.zendesk\.com$/i, 'Zendesk'],
  [/\.freshdesk\.com$/i, 'Freshdesk'],
  [/\.statuspage\.io$/i, 'Atlassian Statuspage'],
  [/\.cargo\.site$/i, 'Cloudflare Pages'],
  [/\.pages\.dev$/i, 'Cloudflare Pages'],
  [/\.web\.app$/i, 'Firebase'],
  [/\.firebaseapp\.com$/i, 'Firebase'],
];

async function resolveRecord(domain: string, type: string): Promise<any> {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { type, status: res.status, Answer: [] };
    return { type, ...(await res.json()) };
  } catch {
    return { type, status: 'ERROR', Answer: [] };
  }
}

async function resolveHost(host: string): Promise<{ ips: string[]; cname: string | null }> {
  try {
    const [aRes, cRes] = await Promise.allSettled([
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(6000),
      }).then((r) => r.json()),
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=CNAME`, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(6000),
      }).then((r) => r.json()),
    ]);
    const a = aRes.status === 'fulfilled' ? aRes.value : null;
    const c = cRes.status === 'fulfilled' ? cRes.value : null;
    const ips = (a?.Answer || [])
      .filter((x: any) => x.type === 1 || /^\d+\.\d+\.\d+\.\d+$/.test(String(x.data || '')))
      .map((x: any) => String(x.data))
      .filter((d: string, i: number, arr: string[]) => arr.indexOf(d) === i)
      .slice(0, 5);
    const cname = (c?.Answer || []).find((x: any) => x.type === 5)?.data?.replace(/\.$/, '') || null;
    return { ips, cname };
  } catch {
    return { ips: [], cname: null };
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, Math.max(items.length, 1)) }, async () => {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

async function bruteForceSubdomains(domain: string): Promise<string[]> {
  const words = ['www', 'mail', 'api', 'dev', 'staging', 'blog', 'shop', 'app', 'admin', 'portal', 'vpn', 'cdn', 'mx', 'smtp', 'ns1', 'ns2', 'ftp', 'gateway', 'remote', 'cloud', 'webmail', 'owa', 'autodiscover', 'git', 'jira', 'jenkins', 'test', 'beta', 'secure', 'ssl', 'proxy', 'static', 'assets', 'img', 'media', 'mobile', 'm', 'old', 'new', 'backup', 'db', 'mysql', 'redis', 'status', 'support', 'help', 'kb', 'docs', 'docs2', 'staging2', 'prod', 'production', 'preprod', 'sandbox', 'demo', 'v2', 'v3', 'api2', 'api3', 'web', 'www2', 'edge', 'us', 'eu', 'asiapacific', 'auth', 'sso', 'login', 'register', 'checkout', 'payment', 'billing', 'crm', 'erp', 'hr', 'intranet', 'internal', 'corp', 'office', 'remote-desktop', 'rdp', 'plex', 'nas', 'mail2', 'pop', 'imap', 'exchange', 'owa2', 'cpanel', 'whm', 'plesk', 'webmail2', 'mailserver', 'mx2', 'mx3', 'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'ns', 'nameserver', 'registrar', 'bak', 'temp', 'tmp', 'cache', 'store', 'cart', 'catalog', 'surveys', 'forms', 'grafana', 'kibana', 'prometheus', 'zabbix', 'nagios', 'sentry', 'elastic', 'log', 'logs', 'logger', 'monitor', 'metrics', 'stats', 'tracking', 'analytics', 'matomo', 'piwik', 'ga', 'gtm', 'ads', 'adserver', 'tickets', 'support2', 'forum', 'discussion', 'community', 'news', 'newsletter', 'subscribe', 'unsubscribe', 'notify', 'push', 'events', 'event', 'calendar', 'booking', 'reserve', 'careers', 'jobs', 'recruit', 'hr2', 'payroll', 'finance', 'reporting', 'reports', 'export', 'import', 'bulk', 'sync', 'webhook', 'hooks', 'partner', 'partners', 'affiliate', 'affiliates', 'download', 'downloads', 'uploads', 'files', 'file', 'media2', 'images', 'img2', 'img3', 'video', 'videos', 'audio', 'cdn2', 'cdn3', 'static2', 'static3', 'assets2', 'js', 'css', 'fonts', 'favicon', 'icons', 'uploads2', 'public', 'private', 'secure2', 'ssl2', 'waf', 'dshield', 'honeypot', 'canary', 'decoy', 'fake', 'shadow', 'ghost2', 'dev2', 'dev3', 'qa', 'qa2', 'uat', 'sit', 'perf', 'load', 'stress', 'benchmark', 'bench', 'ci', 'cd', 'build', 'deploy', 'artifact', 'artifacts', 'registry', 'docker', 'k8s', 'kubernetes', 'cluster', 'node', 'nodes', 'worker', 'workers', 'broker', 'queue', 'rabbit', 'kafka', 'redis2', 'mongo', 'mongodb', 'postgres', 'pg', 'database', 'db2', 'db3', 'cassandra', 'elasticsearch', 'solr', 'search', 'search2', 'index', 'abuse', 'webmaster', 'dmarc', 'spf', 'dkim', 'key', 'keys', 'pgp', 'openpgp', 'gpg', 'sig', 'signature', 'verify', 'validate', 'antispam', 'spam', 'spamhaus', 'postmaster', 'abuse2', 'notifications', 'notification', 'alerts', 'alert', 'pager', 'pagerduty', 'ops', 'op', 'operations', 'sre', 'deployments', 'releases', 'release', 'changelog', 'faq', 'about', 'team', 'legal', 'privacy', 'terms', 'tos', 'cookies', 'gdpr', 'dsr', 'privacy2', 'press', 'media3', 'brand', 'branding', 'logo', 'logos', 'social', 'socials', 'instagram', 'facebook', 'twitter', 'youtube', 'linkedin', 'tiktok', 'whatsapp', 'telegram', 'discord', 'slack', 'teams', 'zoom', 'meet', 'meeting', 'conference', 'webinar', 'seminar', 'training', 'learn', 'academy', 'university', 'student', 'students', 'teacher', 'teachers', 'courses', 'course', 'lesson', 'lessons', 'quiz', 'quiz2', 'exam', 'exams', 'test2', 'tests', 'certificate', 'certificates', 'diploma', 'degree', 'transcript', 'library', 'books', 'book', 'reading', 'e-book', 'ebook', 'pdf', 'docs3', 'manual', 'manuals', 'guides', 'guide', 'tutorial', 'tutorials', 'howto', 'how-to', 'faq2', 'help2', 'support3', 'contact', 'contacts', 'contact-us', 'contactus', 'feedback', 'complaints', 'complaint', 'reviews', 'review', 'rating', 'ratings', 'review2', 'reviews2', 'testimonials', 'testimonial', 'case-studies', 'case-study', 'portfolio', 'portfolios', 'projects', 'project', 'work', 'works', 'clients', 'client', 'partners2', 'sponsors', 'sponsor', 'donate', 'donations', 'fundraising', 'fund', 'funds', 'grants', 'grant', 'scholarship', 'scholarships', 'fellowship', 'fellowships', 'internship', 'internships', 'volunteer', 'volunteers', 'career', 'careers2', 'job', 'jobs2', 'position', 'positions', 'opening', 'openings', 'recruiting', 'recruiter', 'hiring', 'hires', 'hire', 'talent', 'talents', 'people', 'personnel', 'staff', 'employee', 'employees', 'directory', 'directories', 'phonebook', 'phone', 'phone2', 'phones', 'fax', 'fax2', 'email', 'emails', 'mail3', 'mailing', 'mailinglist', 'mailinglists', 'listserv', 'lists', 'list', 'newsletter2', 'newsletters', 'digest', 'digests', 'bulletin', 'bulletin2', 'notifications2', 'notices', 'notice', 'announce', 'announcements', 'announcement', 'bulletin3', 'testimonial2', 'testimonials2', 'social-proof', 'socialproof', 'widget', 'widgets', 'embed', 'embedded', 'embeds', 'iframe', 'iframes', 'frame', 'frames', 'popup', 'popups', 'modal', 'modals', 'lightbox', 'slider', 'sliders', 'carousel', 'carousels', 'banner', 'banners', 'ad', 'ads2', 'advert', 'adverts', 'advertising', 'advertisement', 'advertisements', 'promo', 'promos', 'promotional', 'promotions', 'promotion', 'campaign', 'campaigns', 'marketing', 'marketing2', 'seo', 'sem', 'ppc', 'cpc', 'cpm', 'cpa', 'cpl', 'cps', 'roi', 'roas', 'analytics2', 'webdev', 'developer', 'developers', 'devrel', 'developer-relations', 'developerrelations', 'dev-relations', 'devrelations', 'engineering', 'engineering2', 'engineers', 'engineer', 'tech', 'technology', 'technology2', 'tech2', 'innovation', 'innovations', 'research', 'researches', 'rd', 'r&d', 'labs', 'lab', 'experiments', 'experiment', 'prototype', 'prototypes', 'pilot', 'pilots', 'mvp', 'proof', 'proof-of-concept', 'poc', 'concept', 'concepts', 'idea', 'ideas', 'innovation2', 'incubator', 'incubators', 'accelerator', 'accelerators', 'startup', 'startups', 'venture', 'ventures', 'vc', 'capital', 'capital2', 'funding', 'funding2', 'investor', 'investors', 'investment', 'investments', 'securities', 'stocks', 'bond', 'bonds', 'treasury', 'treasuries', 'dividend', 'dividends', 'interest', 'interests', 'mortgage', 'mortgages', 'loan', 'loans', 'credit', 'credits', 'debt', 'debts', 'liability', 'liabilities', 'asset', 'assets3', 'equity', 'equities', 'audit', 'audits', 'tax', 'taxes', 'legal2', 'law', 'laws', 'compliance', 'compliance2', 'regulatory', 'regulation', 'regulations', 'governance', 'governance2', 'board', 'boards', 'meetings', 'meeting2', 'agenda', 'agendas', 'minutes', 'minutes2', 'resolutions', 'resolution', 'policies', 'policy', 'procedures', 'procedure', 'guidelines', 'guideline', 'standards', 'standard', 'specifications', 'specification', 'specs', 'spec', 'requirements', 'requirement', 'documents', 'document', 'doc', 'docs4', 'documentation', 'documentation2', 'wikis', 'wiki', 'confluence', 'sharepoint', 'notion', 'notion2', 'basecamp', 'asana', 'trello', 'jira2', 'jira3', 'linear', 'monday', 'monday2', 'clickup', 'task', 'tasks', 'todo', 'todos', 'ticketing', 'ticket', 'tickets2', 'helpdesk', 'helpdesk2', 'supportdesk', 'desk', 'zendesk2', 'freshdesk2', 'intercom', 'intercom2', 'chat', 'chats', 'livechat', 'live-chat', 'livechat2', 'live-chat2', 'chatbot', 'chatbots', 'bot', 'bots', 'virtual-assistant', 'virtualassistant', 'assistant', 'assistants', 'agent', 'agents', 'customer-service', 'customerservice', 'service', 'services', 'service2', 'servicing', 'servicing2', 'client-services', 'clientservices', 'care2', 'careers3', 'hiring2', 'jobs3', 'positions2', 'job-postings', 'jobpostings', 'openings2', 'recruiting2', 'recruitment', 'recruitments', 'talent-acquisition', 'talentacquisition', 'hr3', 'human-resources', 'humanresources', 'peopleops', 'people-ops'];
  const seen = new Set<string>();
  const out: string[] = [];
  const results = await Promise.allSettled(
    words.map(async (w) => {
      try {
        const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(`${w}.${domain}`)}&type=A`, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(5000),
        }).then((r) => r.json());
        if (res.Answer?.length && !seen.has(w)) {
          seen.add(w);
          return `${w}.${domain}`;
        }
      } catch { /* ignore */ }
      return null;
    })
  );
  results.forEach((r) => {
    if (r.status === 'fulfilled' && r.value) out.push(r.value);
  });
  return out;
}

async function certificateTransparency(domain: string): Promise<{ name: string; firstSeen: string | null; lastSeen: string | null }[]> {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) return [];
    const rows = await res.json();
    const map = new Map<string, { firstSeen: string | null; lastSeen: string | null }>();
    for (const row of (rows || []).slice(0, 300)) {
      const names = String(row.name_value || '').split('\n');
      const nb = row.not_before ? String(row.not_before).slice(0, 10) : null;
      const na = row.not_after ? String(row.not_after).slice(0, 10) : null;
      for (const raw of names) {
        const n = raw.trim().toLowerCase().replace(/^\*\./, '');
        if (!n.endsWith(domain) || !n.includes('.') || n === domain) continue;
        const existing = map.get(n);
        if (!existing) map.set(n, { firstSeen: nb, lastSeen: na });
        else {
          if (nb && (!existing.firstSeen || nb < existing.firstSeen)) existing.firstSeen = nb;
          if (na && (!existing.lastSeen || na > existing.lastSeen)) existing.lastSeen = na;
        }
      }
    }
    return [...map.entries()].map(([name, d]) => ({ name, ...d })).slice(0, 150);
  } catch {
    return [];
  }
}

// Passive DNS via AlienVault OTX (free, sin clave, con reintento)
async function otxPassiveDns(domain: string): Promise<{ name: string; firstSeen: string | null; lastSeen: string | null; address: string }[]> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`, {
        headers: { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0 (compatible; NEXUS-OSINT)' },
        signal: AbortSignal.timeout(12000),
      });
      if (res.status === 429) {
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      if (!res.ok) return [];
      const data = await res.json();
      const out: { name: string; firstSeen: string | null; lastSeen: string | null; address: string }[] = [];
      for (const row of (data?.results || []).slice(0, 250)) {
        const raw = String(row.hostname || '').toLowerCase().replace(/\.$/, '');
        if (!raw.endsWith(domain) || raw === domain) continue;
        out.push({
          name: raw,
          firstSeen: row.first ? String(row.first).slice(0, 10) : null,
          lastSeen: row.last ? String(row.last).slice(0, 10) : null,
          address: String(row.address || ''),
        });
      }
      return out;
    } catch {
      if (attempt === 1) return [];
      await new Promise((r) => setTimeout(r, 800));
    }
  }
  return [];
}

// Subdominios via DNS BufferOver (free, JSON)
async function bufferoverSubdomains(domain: string): Promise<{ name: string; ip: string }[]> {
  try {
    const res = await fetch(`https://dns.bufferover.run/dns?q=.${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    const out: { name: string; ip: string }[] = [];
    const lines = (data?.FDNS_A || []).concat(data?.RDNS || []);
    for (const line of lines.slice(0, 250)) {
      const parts = String(line).split(',');
      if (parts.length < 2) continue;
      const ip = parts[0].trim();
      const raw = parts[1].trim().toLowerCase().replace(/\.$/, '');
      if (!raw.endsWith(domain) || raw === domain) continue;
      out.push({ name: raw, ip });
    }
    return out;
  } catch {
    return [];
  }
}

// Subdominios via HackerTarget hostsearch (free, texto plano)
async function hackertargetSubdomains(domain: string): Promise<{ name: string; ips: string[] }[]> {
  try {
    const res = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    const out: { name: string; ips: string[] }[] = [];
    for (const line of text.split('\n')) {
      const parts = line.trim().split(',');
      if (parts.length < 2) continue;
      const raw = parts[0].trim().toLowerCase().replace(/\.$/, '');
      if (!raw.endsWith(domain) || raw === domain) continue;
      const ip = parts[1].trim();
      const existing = out.find((o) => o.name === raw);
      if (existing) existing.ips.push(ip);
      else out.push({ name: raw, ips: [ip] });
    }
    return out;
  } catch {
    return [];
  }
}

async function ipProviderInfo(ip: string): Promise<{ asn: string; isp: string; org: string; country: string }> {
  try {
    const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { asn: '', isp: '', org: '', country: '' };
    const rd = await res.json();
    const vcards = (rd.entities || []).flatMap((e: any) => e.vcardArray?.[1] || []);
    const fn = vcards.find((l: any) => l?.[0]?.toLowerCase() === 'fn')?.[3] || '';
    const adr = vcards.find((l: any) => l?.[0]?.toLowerCase() === 'adr')?.[3];
    const adrCountry = adr && Array.isArray(adr) ? String(adr[adr.length - 1] || '') : '';
    const handle = (rd.entities || []).map((e: any) => e.handle || '').find((h: string) => /^(as\d+|autnum)/i.test(h));
    const asn = handle ? handle.toUpperCase().replace(/AUTNUM-?/i, 'AS') : '';
    return {
      asn,
      isp: String(fn || rd.name || ''),
      org: String(rd.name || fn || ''),
      country: String(rd.country || adrCountry || ''),
    };
  } catch {
    return { asn: '', isp: '', org: '', country: '' };
  }
}

function classifyTakeover(sub: string, cname: string | null, hasA: boolean): any | null {
  if (!cname) return null;
  if (hasA) return { subdomain: sub, cname, status: 'SAFE', service: '', reason: 'CNAME presente pero el subdominio resuelve correctamente (no vulnerable)' };
  for (const [re, svc] of TAKEOVER_SERVICES) {
    if (re.test(cname)) {
      return {
        subdomain: sub,
        cname,
        status: 'CANDIDATE',
        service: svc,
        reason: `CNAME apunta a ${cname} (${svc}) y el subdominio NO resuelve (NXDOMAIN / sin registro A) — candidato a takeover`,
      };
    }
  }
  return {
    subdomain: sub,
    cname,
    status: 'DANGLING',
    service: cname.split('.').slice(-2).join('.'),
    reason: `CNAME colgante (dangling) hacia ${cname} sin registro A propio — revisar manualmente`,
  };
}

// Reverse lookup a range around a seed IP (demo — best effort public sources)
function reverseRange(ip: string): string[] {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return [];
  const out: string[] = [];
  const [a, b, c] = parts;
  for (let d = 1; d <= 5; d++) {
    const candidate = `${a}.${b}.${c}.${d}`;
    out.push(`ptr-${d} (${candidate})`);
  }
  return out;
}

export async function GET(request: NextRequest) {
  const { module: dnsModule, error: moduleError } = resolveModuleScope(request);
  if (moduleError) {
    return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
  }
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');

  if (!domain) {
    return NextResponse.json(
      { success: false, error: 'Domain is required', example: '/api/osint/dnsdump?domain=example.com' },
      { status: 400 }
    );
  }

  try {
    const clean = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    const records = await Promise.all(TYPES.map((t) => resolveRecord(clean, t)));

    const allRecords: any[] = [];
    const byType: Record<string, any[]> = {};
    records.forEach((r) => {
      byType[r.type] = (r.Answer || []).map((a: any) => {
        const data = String(a.data ?? (a.type === 16 ? a.data : a.data ?? ''));
        const row = {
          name: a.name || clean,
          type: r.type,
          ttl: a.TTL ?? 0,
          data,
        };
        allRecords.push(row);
        return row;
      });
    });

    // --- Subdomain discovery: CT (crt.sh) + OTX passive DNS + bufferover + hackertarget + brute-force ---
    const [ctSubs, otxSubs, bufferSubs, htSubs, bruteSubs, enriched] = await Promise.all([
      certificateTransparency(clean),
      otxPassiveDns(clean),
      bufferoverSubdomains(clean),
      hackertargetSubdomains(clean),
      bruteForceSubdomains(clean),
      lookupDomain(clean),
    ]);

    const sourceLabel = (src: string) =>
      src === 'crt.sh' ? 'crt.sh' : src === 'otx' ? 'OTX passive DNS' : src === 'bufferover' ? 'bufferover' : src === 'hackertarget' ? 'hackertarget' : 'brute-force';

    const subInfo = new Map<string, { name: string; source: string; firstSeen: string | null; lastSeen: string | null; ips: string[]; cname: string | null }>();
    const addSub = (name: string, source: string, firstSeen: string | null, lastSeen: string | null, ips: string[] = []) => {
      const existing = subInfo.get(name);
      if (existing) {
        if (!existing.source.includes(sourceLabel(source))) existing.source = `${existing.source} + ${sourceLabel(source)}`;
        if (firstSeen && (!existing.firstSeen || firstSeen < existing.firstSeen)) existing.firstSeen = firstSeen;
        if (lastSeen && (!existing.lastSeen || lastSeen > existing.lastSeen)) existing.lastSeen = lastSeen;
        if (ips.length && !existing.ips.length) existing.ips = ips;
      } else {
        subInfo.set(name, { name, source: sourceLabel(source), firstSeen, lastSeen, ips, cname: null });
      }
    };
    ctSubs.forEach((s) => addSub(s.name, 'crt.sh', s.firstSeen, s.lastSeen));
    otxSubs.forEach((s) => addSub(s.name, 'otx', s.firstSeen, s.lastSeen, s.address ? [s.address] : []));
    bufferSubs.forEach((s) => addSub(s.name, 'bufferover', null, null, s.ip ? [s.ip] : []));
    htSubs.forEach((s) => addSub(s.name, 'hackertarget', null, null, s.ips));
    bruteSubs.forEach((s) => addSub(s, 'brute-force', null, null));

    const mergedSubs = [...subInfo.values()];

    // --- Resolve A + CNAME for each subdomain (concurrency 12) ---
    const resolved = await mapLimit(mergedSubs.slice(0, 80), 12, async (s) => {
      const r = await resolveHost(s.name);
      s.ips = r.ips;
      s.cname = r.cname;
      return s;
    });
    mergedSubs.length = 0;
    mergedSubs.push(...resolved);

    // --- Mapping domain -> IP -> hosting provider (RDAP) ---
    const uniqueIps = [...new Set(mergedSubs.flatMap((s) => s.ips))].slice(0, 30);
    const ipCache = new Map<string, any>();
    await mapLimit(uniqueIps, 8, async (ip) => {
      ipCache.set(ip, await ipProviderInfo(ip));
      return ip;
    });

    const ipMap = mergedSubs.flatMap((s) =>
      s.ips.map((ip) => {
        const prov = ipCache.get(ip) || {};
        return {
          host: s.name,
          ip,
          asn: prov.asn || '—',
          isp: prov.isp || '—',
          org: prov.org || '—',
          country: prov.country || '—',
          provider: prov.isp === '—' && prov.org !== '—' ? prov.org : prov.isp,
        };
      })
    );

    // --- Passive DNS timeline (from CT history) ---
    const passiveDns = mergedSubs
      .filter((s) => s.firstSeen || s.lastSeen)
      .map((s) => ({
        name: s.name,
        firstSeen: s.firstSeen || s.lastSeen,
        lastSeen: s.lastSeen || s.firstSeen,
        firstSeenTs: new Date(s.firstSeen || s.lastSeen || 0).getTime(),
        lastSeenTs: new Date(s.lastSeen || s.firstSeen || 0).getTime(),
        daysKnown: Math.max(1, Math.round((Date.now() - new Date(s.firstSeen || s.lastSeen || 0).getTime()) / 86400000)),
      }))
      .sort((a, b) => a.firstSeenTs - b.firstSeenTs)
      .slice(0, 80);

    // --- Subdomain takeover detection ---
    const takeovers = mergedSubs
      .map((s) => classifyTakeover(s.name, s.cname, s.ips.length > 0))
      .filter(Boolean)
      .sort((a: any, b: any) => (a.status === 'CANDIDATE' ? -1 : b.status === 'CANDIDATE' ? 1 : a.status === 'DANGLING' ? -1 : 1));

    const subdomainNames = mergedSubs.map((s) => s.name);

    const uniqueHosts = new Set<string>(subdomainNames);
    allRecords.forEach((a) => {
      if (String(a.data || '').includes('.')) uniqueHosts.add(String(a.data));
      if (a.name) uniqueHosts.add(String(a.name));
    });
    mergedSubs.forEach((s) => s.ips.forEach((ip) => uniqueHosts.add(ip)));

    const hosts = [...uniqueHosts].slice(0, 40);

    return NextResponse.json({
      success: true,
      module: dnsModule,
      source: 'Monitor-Threat DNS Dumpster (Google DoH + crt.sh + RDAP)',
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      aiEnabled: isAIEnabled(),
      data: {
        domain: clean,
        records: byType,
        allRecords,
        subdomains: subdomainNames,
        subdomainInfo: mergedSubs,
        ipMap,
        passiveDns,
        takeovers,
        relatedHosts: hosts,
        reverseLookup: reverseRange('8.8.8.8'),
        whois: enriched.whois,
        security: enriched.security,
        map: {
          nodes: hosts.map((h, i) => ({ id: i, host: h, group: i === 0 ? 'domain' : h.includes('.') && h.split('.').length === 2 ? 'host' : 'ip' })),
          edges: hosts.slice(1).map((_, i) => ({ from: 0, to: i + 1 })),
        },
        sourceBreakdown: {
          ct: ctSubs.length,
          otx: otxSubs.length,
          buffer: bufferSubs.length,
          hackertarget: htSubs.length,
          brute: bruteSubs.length,
          hosts,
        },
      },
      message: `DNS dump for ${clean}: ${allRecords.length} records, ${mergedSubs.length} subdomains (CT ${ctSubs.length} / OTX ${otxSubs.length} / bufferover ${bufferSubs.length} / hackertarget ${htSubs.length} / brute-force ${bruteSubs.length}), ${takeovers.filter((t: any) => t.status !== 'SAFE').length} takeover candidates`,
    });
  } catch (error) {
    console.error('DNS Dump error:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'DNS enumeration failed' },
      { status: 500 }
    );
  }
}