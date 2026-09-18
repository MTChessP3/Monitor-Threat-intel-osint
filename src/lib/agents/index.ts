// Agent system for the OSINT platform.
// Agents orchestrate enrichment modules and synthesize results with an LLM
// (Groq by default). When AI is not configured, agents fall back to a
// rule-based engine that still uses real enrichment data.

import { aiJSON, isAIEnabled } from '@/lib/ai';
import {
  detectType,
  lookupIP,
  lookupDomain,
  lookupCVE,
  lookupHash,
  loadThreatFeeds,
  type TargetType,
} from '@/lib/intel';
import { getIOCs } from '@/lib/store';

export interface EnrichmentBundle {
  target: string;
  type: TargetType;
  ip?: any;
  domain?: any;
  cve?: any;
  hash?: any;
  threats?: any[];
  iocs?: any[];
  [key: string]: any;
}

// ---------- Enrichment Agent ----------
// Runs the relevant OSINT modules for a given target and bundles evidence.
export async function enrichmentAgent(target: string, type?: TargetType): Promise<EnrichmentBundle> {
  const resolvedType = type || detectType(target);
  const bundle: EnrichmentBundle = { target, type: resolvedType };

  if (resolvedType === 'ip') {
    bundle.ip = await lookupIP(target);
  }

  if (resolvedType === 'domain') {
    bundle.domain = await lookupDomain(target);
  }

  if (resolvedType === 'cve') {
    bundle.cve = await lookupCVE(target);
  }

  if (resolvedType === 'hash') {
    bundle.hash = await lookupHash(target);
  }

  if (resolvedType === 'url') {
    let hostname = target;
    try {
      hostname = new URL(target).hostname;
    } catch {
      hostname = target.replace(/^https?:\/\//, '').split('/')[0];
    }
    bundle.domain = await lookupDomain(hostname);
    bundle.urlHost = hostname;
  }

  return bundle;
}

// ---------- Analysis Agent ----------
// Synthesizes enrichment data into a structured threat assessment via LLM.
export interface AnalysisResult {
  summary: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  keyFindings: string[];
  indicators: Array<{ type: string; value: string; context?: string }>;
  recommendations: string[];
  sources: string[];
  usedAI: boolean;
}

const ANALYSIS_SYSTEM_PROMPT = `You are an expert OSINT and Cyber Threat Intelligence analyst.
Analyze the provided enrichment data and produce a structured JSON assessment with exactly these fields:
{
  "summary": "2-3 sentence executive summary of findings",
  "threatLevel": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": 0-100,
  "keyFindings": ["finding1", "finding2", "finding3"],
  "indicators": [{"type": "IP|DOMAIN|HASH|URL|CVE|EMAIL", "value": "...", "context": "..."}],
  "recommendations": ["actionable recommendation 1", "recommendation 2"],
  "sources": ["source1", "source2"]
}
Be specific, factual and professional. Base every claim on the data provided.
If data is missing or unverifiable, say so explicitly and lower confidence.`;

export async function analysisAgent(target: string, bundle: EnrichmentBundle): Promise<AnalysisResult> {
  const context = buildContextText(bundle);

  if (isAIEnabled()) {
    const { data, usedAI } = await aiJSON<AnalysisResult>(
      ANALYSIS_SYSTEM_PROMPT,
      `Target: ${target}
Type: ${bundle.type}

Enrichment data:
${context}`
    );

    if (usedAI && data) {
      return { ...normalizeAnalysis(data), usedAI: true };
    }
  }

  return { ...ruleBasedAssessment(bundle), usedAI: false };
}

// ---------- Reporter Agent ----------
// Aggregates data from all internal modules into a single report payload.
export async function reporterAgent(modules: string[]): Promise<Record<string, any>> {
  const bundle: Record<string, any> = {};

  const wants = (m: string) => modules.includes(m) || modules.includes('all') || modules.length === 0;

  if (wants('iocs')) {
    const { data, total } = await getIOCs({ limit: 100 });
    bundle.iocs = { data, total };
  }

  if (wants('threats')) {
    bundle.threats = await loadThreatFeeds(undefined, 15);
  }

  if (wants('ip') || wants('domain') || wants('url') || wants('hash') || wants('cve')) {
    const recent = await getIOCs({ limit: 20 });
    bundle.recentAnalyses = recent.data;
  }

  return bundle;
}

function buildContextText(bundle: EnrichmentBundle): string {
  const lines: string[] = [];

  if (bundle.ip) {
    lines.push(
      `IP INTEL (${bundle.ip.source}): ` +
        JSON.stringify(bundle.ip.data, null, 2)
    );
  }
  if (bundle.domain) {
    lines.push(
      `DOMAIN INTEL (${bundle.domain.source}): ` +
        JSON.stringify({ dns: summarizeDNS(bundle.domain.dns), security: bundle.domain.security }, null, 2)
    );
  }
  if (bundle.cve) {
    lines.push(`CVE INTEL (${bundle.cve.source}): ` + JSON.stringify(bundle.cve.results, null, 2));
  }
  if (bundle.hash) {
    lines.push(`HASH INTEL (${bundle.hash.source}): ` + JSON.stringify(bundle.hash, null, 2));
  }
  if (bundle.threats?.length) {
    lines.push(`THREAT FEEDS: ` + JSON.stringify(bundle.threats.slice(0, 3), null, 2));
  }

  return lines.join('\n\n') || 'No enrichment data available for this target.';
}

function summarizeDNS(dns: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [type, rec] of Object.entries(dns || {})) {
    const answers = rec?.Answer?.slice(0, 5).map((a: any) => a.data) || [];
    out[type] = answers;
  }
  return out;
}

// Rule-based fallback that uses real enrichment data (used when AI is off)
function ruleBasedAssessment(bundle: EnrichmentBundle): AnalysisResult {
  const findings: string[] = [];
  const indicators: AnalysisResult['indicators'] = [];
  const recommendations: string[] = [];
  const sources: string[] = [];
  let score = 0;

  if (bundle.ip) {
    const d = bundle.ip.data;
    sources.push(bundle.ip.source);
    indicators.push({ type: 'IP', value: bundle.target, context: 'Analyzed target' });
    findings.push(`Location: ${d.city}, ${d.regionName}, ${d.country} (${d.countryCode})`);
    findings.push(`ISP: ${d.org || d.isp || 'Unknown'}`);
    if (d.proxy) {
      score += 40;
      findings.push('Proxy/VPN infrastructure detected');
      recommendations.push('IP is a known proxy — verify the source of traffic');
    }
    if (d.hosting) {
      score += 20;
      findings.push('Hosting/data-center IP range');
      recommendations.push('Monitor connections from this hosting range');
    }
  }

  if (bundle.domain) {
    sources.push(bundle.domain.source);
    indicators.push({ type: 'DOMAIN', value: bundle.target, context: 'Analyzed target' });
    if (bundle.domain.security?.hasSPF) findings.push('SPF record present');
    else {
      score += 15;
      findings.push('Missing SPF record — spoofing risk');
    }
    if (!bundle.domain.security?.hasDMARC) {
      score += 10;
      findings.push('Missing DMARC policy');
    }
    recommendations.push('Review DNS security posture (SPF/DMARC/DKIM)');
  }

  if (bundle.cve) {
    sources.push(bundle.cve.source);
    for (const cve of bundle.cve.results || []) {
      indicators.push({ type: 'CVE', value: cve.id, context: cve.description?.slice(0, 120) });
      findings.push(`CVE ${cve.id}: CVSS ${cve.cvssScore} (${cve.cvssSeverity})`);
      if ((cve.cvssScore || 0) >= 9) score += 40;
      else if ((cve.cvssScore || 0) >= 7) score += 25;
      else score += 10;
    }
    recommendations.push('Prioritize patching of critical/high CVEs');
  }

  if (bundle.hash) {
    sources.push(bundle.hash.source);
    if (bundle.hash.found) {
      score += 50;
      indicators.push({ type: 'HASH', value: bundle.target, context: 'Known malware sample' });
      findings.push(`Hash matches known ${bundle.hash.data.signature || 'malware sample'}`);
      recommendations.push('Block hash at endpoint and gateway');
    } else {
      findings.push('Hash not found in malware databases');
    }
  }

  if (bundle.threats?.length) {
    sources.push('Threat Feeds');
  }

  const level =
    score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : score >= 10 ? 'LOW' : 'INFO';
  const threatLevel = (level === 'HIGH' ? 'HIGH' : level === 'MEDIUM' ? 'MEDIUM' : level === 'LOW' ? 'LOW' : 'INFO') as AnalysisResult['threatLevel'];

  recommendations.push(
    'Cross-reference findings against additional threat feeds',
    'Review correlated logs for any matching indicators'
  );

  return {
    summary: `Rule-based assessment of "${bundle.target}" (${bundle.type}) using real enrichment data from ${sources.join(', ') || 'local heuristics'}.`,
    threatLevel,
    confidence: Math.max(40, Math.min(90, 100 - score)),
    keyFindings: findings.length ? findings.slice(0, 6) : ['No notable findings from available sources'],
    indicators,
    recommendations: [...new Set(recommendations)].slice(0, 6),
    sources,
    usedAI: false,
  };
}

function normalizeAnalysis(data: Partial<AnalysisResult>): AnalysisResult {
  return {
    summary: data.summary || 'Analysis completed.',
    threatLevel: data.threatLevel || 'MEDIUM',
    confidence: typeof data.confidence === 'number' ? data.confidence : 60,
    keyFindings: data.keyFindings || [],
    indicators: data.indicators || [],
    recommendations: data.recommendations || ['Manual review recommended'],
    sources: data.sources || ['AI Analysis'],
    usedAI: true,
  };
}
