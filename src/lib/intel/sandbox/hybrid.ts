// External sandbox API integrations (Hybrid Analysis, Joe Sandbox, ANY.RUN).
// All require API keys via environment variables.
//
// Design: async two-phase flow. Detonations take 1-3 minutes, far beyond the
// Vercel serverless 60s limit, so `submitExternal` returns job IDs immediately
// and `pollExternal` is called separately to collect the normalized result.

import type {
  ContentIndicator, SandboxResult, SandboxVerdict, StaticFlag,
} from './types';

const HYBRID_ANALYSIS_API = 'https://hybrid-analysis.com/api/v2';
const JOE_SANDBOX_API = 'https://jbxcloud.joesecurity.org/api';
const ANY_RUN_API = 'https://api.any.run/v1';

export type ExternalSource = 'hybrid-analysis' | 'joe-sandbox' | 'any-run';

export interface ExternalJob {
  source: ExternalSource;
  jobId: string;
  status: 'submitted' | 'processing' | 'completed' | 'error';
  error?: string;
  result?: SandboxResult;
}

interface HybridConfig {
  hybridAnalysisKey?: string;
  joeSandboxKey?: string;
  anyRunKey?: string;
}

function getConfig(): HybridConfig {
  return {
    hybridAnalysisKey: process.env.HYBRID_ANALYSIS_API_KEY,
    joeSandboxKey: process.env.JOE_SANDBOX_API_KEY,
    anyRunKey: process.env.ANY_RUN_API_KEY,
  };
}

export function configuredExternalSources(): ExternalSource[] {
  const cfg = getConfig();
  const sources: ExternalSource[] = [];
  if (cfg.hybridAnalysisKey) sources.push('hybrid-analysis');
  if (cfg.joeSandboxKey) sources.push('joe-sandbox');
  if (cfg.anyRunKey) sources.push('any-run');
  return sources;
}

function mapSeverity(label: string): ContentIndicator['severity'] {
  const l = label.toLowerCase();
  if (l.includes('critical') || l.includes('malicious') || l.includes('ransomware') || l.includes('trojan')) return 'CRITICAL';
  if (l.includes('high') || l.includes('suspicious') || l.includes('phishing') || l.includes('c2') || l.includes('exfil') || l.includes('exploit')) return 'HIGH';
  if (l.includes('medium') || l.includes('moderate') || l.includes('potential') || l.includes('informative')) return 'MEDIUM';
  if (l.includes('low') || l.includes('info') || l.includes('benign')) return 'LOW';
  return 'MEDIUM';
}

// verdict values used by the external services
const MALICIOUS_VS = ['malicious', 'suspicious', 'no specific threat'];
function verdictToScore(verdict: string | undefined, sigScores: number[]): number {
  const v = (verdict || '').toLowerCase();
  const fromSig = sigScores.reduce((a, b) => a + b, 0);
  if (v.includes('malicious')) return Math.max(65, fromSig);
  if (v.includes('suspicious')) return Math.max(35, fromSig);
  if (v.includes('no specific threat') || v.includes('benign') || v.includes('clean')) return Math.min(fromSig, 10);
  return fromSig;
}

function buildResult(url: string, host: string, sourceLabel: string, indicators: ContentIndicator[], staticFlags: StaticFlag[], verdictLabel: string | undefined, score: number): SandboxResult {
  const level: SandboxVerdict['level'] = score >= 30 ? 'MALICIOUS' : score >= 12 ? 'SUSPICIOUS' : 'BENIGN';
  return {
    url,
    host,
    timestamp: new Date().toISOString(),
    source: sourceLabel,
    live: true,
    http: null,
    redirects: [],
    tls: null,
    content: {
      title: `${sourceLabel} Report`,
      description: null,
      lang: null,
      favicon: null,
      forms: [],
      iframes: [],
      metaRefresh: false,
      obfuscatedJs: false,
      inlineJsBytes: 0,
      scripts: [],
      emails: [],
      telegramTokens: [],
      telegramChatIds: [],
      indicators,
      finalHost: host,
    },
    resources: [],
    reputation: {
      ip: null, geo: null, asn: null, isp: null,
      dnsblListed: 0, dnsblBlocked: 0, torExit: false, urlhausCount: 0,
      hosting: false, proxy: false,
      whoisCreated: null, domainAgeDays: null, domainExpires: null,
    },
    staticFlags,
    verdict: {
      score: Math.min(score, 100),
      level,
      verdict: score >= 30 ? `${sourceLabel}: strong malicious signals.` : score >= 12 ? `${sourceLabel}: suspicious signals.` : `${sourceLabel}: no significant threats.`,
      reasons: verdictLabel ? [verdictLabel] : [],
    },
    screenshotUrl: null,
  };
}

// ---------------- Hybrid Analysis ----------------

interface HASubmitResponse {
  job_id?: string;
  sha256?: string;
}

interface HASignature {
  threat_level?: number;
  threat_level_human?: string;
  category?: string;
  name?: string;
  description?: string;
  attck_id?: string | null;
}

interface HAReport {
  verdict?: string;
  threat_score?: number;
  av_detect?: number;
  total_av?: number;
  tags?: string[];
  signatures?: HASignature[];
  mitre_attcks?: { tactic?: string; technique?: string; attck_id?: string }[];
  state?: string;
  hosts?: string[];
  domains?: string[];
}

export async function submitHybridAnalysis(url: string): Promise<ExternalJob | null> {
  const { hybridAnalysisKey } = getConfig();
  if (!hybridAnalysisKey) return null;
  try {
    const res = await fetch(`${HYBRID_ANALYSIS_API}/submit/url`, {
      method: 'POST',
      headers: {
        'api-key': hybridAnalysisKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({ url, environment_id: '160' }), // Windows 10 64 bit
    });
    if (!res.ok) return null;
    const data: HASubmitResponse = await res.json();
    if (!data.job_id) return null;
    return { source: 'hybrid-analysis', jobId: data.job_id, status: 'submitted' };
  } catch {
    return null;
  }
}

export async function pollHybridAnalysis(url: string, host: string, jobId: string): Promise<ExternalJob> {
  const { hybridAnalysisKey } = getConfig();
  const job: ExternalJob = { source: 'hybrid-analysis', jobId, status: 'processing' };
  if (!hybridAnalysisKey) return { ...job, status: 'error', error: 'No API key configured' };
  try {
    // The full report JSON requires 'default' privileges (full API key).
    // The summary endpoint is available to restricted keys and includes
    // signatures + MITRE + hosts + domains.
    const res = await fetch(`${HYBRID_ANALYSIS_API}/report/${jobId}/summary`, {
      headers: { 'api-key': hybridAnalysisKey, Accept: 'application/json' },
    });
    if (res.status === 404) return job; // not ready yet
    if (res.status === 403) return job; // no report yet for this key level
    if (!res.ok) return { ...job, status: 'error', error: `Hybrid Analysis HTTP ${res.status}` };
    const data: HAReport = await res.json();
    const state = (data.state || '').toLowerCase();
    if (state === 'in progress' || state === 'unknown' || state === '') return job;

    const indicators: ContentIndicator[] = [];
    const staticFlags: StaticFlag[] = [];

    for (const sig of data.signatures || []) {
      const tl = sig.threat_level || 0;
      if (tl <= 0) continue; // informative signals are noise
      const severity: ContentIndicator['severity'] =
        tl >= 3 ? 'CRITICAL' : tl === 2 ? 'HIGH' : 'MEDIUM';
      indicators.push({
        label: sig.name || 'Unknown signature',
        category: sig.category || 'hybrid-analysis',
        severity,
        detail: `${sig.description || ''}${sig.attck_id ? ` [MITRE ${sig.attck_id}]` : ''}`.trim(),
      });
    }

    for (const attack of data.mitre_attcks || []) {
      if (!attack.technique) continue;
      indicators.push({
        label: `MITRE ${attack.technique} (${attack.tactic || '?'})`,
        category: 'mitre-attack',
        severity: 'HIGH',
        detail: attack.attck_id || attack.technique,
      });
    }

    for (const d of data.domains || []) {
      if (!d || d === host) continue;
      staticFlags.push({ label: `Connected to ${d}`, weight: 2, category: 'network' });
    }

    if ((data.av_detect ?? 0) > 0) {
      staticFlags.push({ label: `AV detection ${data.av_detect}/${data.total_av ?? '?'}`, weight: 8, category: 'av' });
    }
    for (const tag of data.tags || []) {
      staticFlags.push({ label: tag, weight: 2, category: 'tag' });
    }

    const score = verdictToScore(data.verdict, indicators.map((i) => (i.severity === 'CRITICAL' ? 8 : i.severity === 'HIGH' ? 5 : i.severity === 'MEDIUM' ? 3 : 1)));
    const result = buildResult(url, host, 'Hybrid Analysis (dynamic detonation)', indicators, staticFlags, data.verdict, score);
    result.verdict.reasons = data.verdict ? [`Hybrid Analysis verdict: ${data.verdict}`, `report: https://www.hybrid-analysis.com/report/${jobId}`] : [];

    return { ...job, status: 'completed', result };
  } catch (e) {
    return { ...job, status: 'error', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

// ---------------- Joe Sandbox ----------------

interface JoeSubmitResponse {
  data?: { webids?: string[] };
}

interface JoeInfoResponse {
  data?: {
    status?: string;
    verdict?: string;
    score?: number;
    signaturedetections?: { strategy?: { score?: number }[] };
  };
}

export async function submitJoeSandbox(url: string): Promise<ExternalJob | null> {
  const { joeSandboxKey } = getConfig();
  if (!joeSandboxKey) return null;
  try {
    const res = await fetch(`${JOE_SANDBOX_API}/v2/analysis/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        apikey: joeSandboxKey,
        'accept-tac': '1',
        url,
        'internet-access': '1',
        'systems[]': 'w10x64',
        'comments': 'Submitted via NEXUS Intel',
      }),
    });
    if (!res.ok) return null;
    const data: JoeSubmitResponse = await res.json();
    const webid = data.data?.webids?.[0];
    if (!webid) return null;
    return { source: 'joe-sandbox', jobId: webid, status: 'submitted' };
  } catch {
    return null;
  }
}

export async function pollJoeSandbox(url: string, host: string, webid: string): Promise<ExternalJob> {
  const { joeSandboxKey } = getConfig();
  const job: ExternalJob = { source: 'joe-sandbox', jobId: webid, status: 'processing' };
  if (!joeSandboxKey) return { ...job, status: 'error', error: 'No API key configured' };
  try {
    const res = await fetch(`${JOE_SANDBOX_API}/v2/analysis/info`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ apikey: joeSandboxKey, webid }),
    });
    if (!res.ok) return { ...job, status: 'error', error: `Joe Sandbox HTTP ${res.status}` };
    const data: JoeInfoResponse = await res.json();
    const status = data.data?.status?.toLowerCase() || '';
    if (status !== 'finished') return job;

    const score = data.data?.score ?? data.data?.signaturedetections?.strategy?.[0]?.score ?? 0;
    const verdict = data.data?.verdict || '';
    const result = buildResult(
      url, host, 'Joe Sandbox (dynamic detonation)',
      [],
      score >= 30 ? [{ label: `Joe Sandbox score ${score}`, weight: 8, category: 'joe' }] : [],
      verdict,
      score,
    );
    result.verdict.reasons = [`Joe Sandbox verdict: ${verdict || 'n/a'}`, `score: ${score}`, `report: https://jbxcloud.joesecurity.org/analyses/${webid}`];
    return { ...job, status: 'completed', result };
  } catch (e) {
    return { ...job, status: 'error', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

// ---------------- ANY.RUN ----------------

interface AnyRunSubmitResponse {
  data?: { taskid?: string };
}

interface AnyRunReport {
  data?: {
    status?: string;
    verdict?: string;
    score?: number;
    processes?: { verdict?: string }[];
    signatures?: { title?: string; verdict?: string; severity?: string; category?: string }[];
    mitre?: { technique?: string; tactic?: string }[];
  };
}

export async function submitAnyRun(url: string): Promise<ExternalJob | null> {
  const { anyRunKey } = getConfig();
  if (!anyRunKey) return null;
  try {
    const form = new FormData();
    form.append('obj_type', 'url');
    form.append('obj_url', url);
    form.append('env_os', 'windows');
    form.append('env_version', '10');
    form.append('env_bitness', '64');
    form.append('env_type', 'complete');
    form.append('opt_network_connect', 'true');
    const res = await fetch(`${ANY_RUN_API}/analysis/`, {
      method: 'POST',
      headers: { Authorization: `API-Key ${anyRunKey}` },
      body: form,
    });
    if (!res.ok) return null;
    const data: AnyRunSubmitResponse = await res.json();
    const taskid = data.data?.taskid;
    if (!taskid) return null;
    return { source: 'any-run', jobId: taskid, status: 'submitted' };
  } catch {
    return null;
  }
}

export async function pollAnyRun(url: string, host: string, taskid: string): Promise<ExternalJob> {
  const { anyRunKey } = getConfig();
  const job: ExternalJob = { source: 'any-run', jobId: taskid, status: 'processing' };
  if (!anyRunKey) return { ...job, status: 'error', error: 'No API key configured' };
  try {
    const res = await fetch(`${ANY_RUN_API}/analysis/${taskid}`, {
      headers: { Authorization: `API-Key ${anyRunKey}` },
    });
    if (res.status === 404) return job;
    if (!res.ok) return { ...job, status: 'error', error: `ANY.RUN HTTP ${res.status}` };
    const data: AnyRunReport = await res.json();
    const status = data.data?.status?.toLowerCase() || '';
    if (status !== 'completed' && status !== 'finished') return job;

    const indicators: ContentIndicator[] = [];
    for (const sig of data.data?.signatures || []) {
      if (!sig.title) continue;
      indicators.push({
        label: sig.title,
        category: sig.category || 'anyrun',
        severity: sig.severity === 'critical' ? 'CRITICAL' : sig.severity === 'high' || sig.verdict === 'malicious' ? 'HIGH' : sig.severity === 'medium' ? 'MEDIUM' : 'LOW',
        detail: `ANY.RUN signature verdict: ${sig.verdict || 'n/a'}`,
      });
    }
    for (const attack of data.data?.mitre || []) {
      if (!attack.technique) continue;
      indicators.push({
        label: `MITRE ${attack.technique} (${attack.tactic || '?'})`,
        category: 'mitre-attack',
        severity: 'HIGH',
        detail: attack.technique,
      });
    }

    const score = data.data?.score ?? verdictToScore(data.data?.verdict, indicators.map((i) => (i.severity === 'CRITICAL' ? 8 : i.severity === 'HIGH' ? 5 : i.severity === 'MEDIUM' ? 3 : 1)));
    const result = buildResult(url, host, 'ANY.RUN (dynamic detonation)', indicators, [], data.data?.verdict, score);
    result.verdict.reasons = data.data?.verdict ? [`ANY.RUN verdict: ${data.data.verdict}`, `score: ${score}`, `report: https://app.any.run/tasks/${taskid}`] : [];
    return { ...job, status: 'completed', result };
  } catch (e) {
    return { ...job, status: 'error', error: e instanceof Error ? e.message : 'Unknown error' };
  }
}

// ---------------- dispatch ----------------

export function submitExternal(url: string): Promise<ExternalJob | null>[] {
  return [submitHybridAnalysis(url), submitJoeSandbox(url), submitAnyRun(url)];
}

export function pollExternal(job: ExternalJob, url: string, host: string): Promise<ExternalJob> {
  switch (job.source) {
    case 'hybrid-analysis':
      return pollHybridAnalysis(url, host, job.jobId);
    case 'joe-sandbox':
      return pollJoeSandbox(url, host, job.jobId);
    case 'any-run':
      return pollAnyRun(url, host, job.jobId);
  }
}
