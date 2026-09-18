import { NextRequest, NextResponse } from 'next/server';
import { enrichmentAgent, analysisAgent } from '@/lib/agents';
import { detectType } from '@/lib/intel';
import { isAIEnabled } from '@/lib/ai';
import { upsertIOC, createAnalysis, createAlert } from '@/lib/store';
import { resolveModuleScope } from '@/lib/intel/moduleScope';

export const maxDuration = 60;

// AI Threat Analyst — orchestrates enrichment + analysis agents
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, type, context } = body;

    const { module: aiModule, error: moduleError } = resolveModuleScope(request, body);
    if (moduleError) {
      return NextResponse.json({ success: false, error: moduleError }, { status: 400 });
    }

    if (!target) {
      return NextResponse.json(
        {
          success: false,
          error: 'Target is required',
          validTypes: ['ip', 'domain', 'hash', 'cve', 'url', 'general'],
        },
        { status: 400 }
      );
    }

    const resolvedType = type || detectType(target);
    const aiEnabled = isAIEnabled();

    console.log(`[AI] Analyzing ${resolvedType}: ${target} (ai=${aiEnabled ? 'on' : 'off'})`);

    // Agent 1: Enrichment — gather real data from the relevant modules
    const enrichment = await enrichmentAgent(target, resolvedType);

    // Agent 2: Analysis — synthesize with LLM (or rule-based fallback)
    const analysis = await analysisAgent(target, enrichment);

    // Persist (non-blocking)
    try {
      const ioc = await upsertIOC({
        type: mapTypeToIOC(resolvedType),
        value: target,
        description: analysis.summary?.substring(0, 500),
        severity: analysis.threatLevel,
        confidence: analysis.confidence,
        status: mapThreatToStatus(analysis.threatLevel),
        source: analysis.usedAI ? 'AI-Analysis' : 'Rule-Based',
        rawResponse: JSON.stringify({ enrichment, analysis }).substring(0, 20000),
        tags: [resolvedType, analysis.usedAI ? 'ai' : 'rules', analysis.threatLevel.toLowerCase()],
      });

      await createAnalysis({
        iocId: ioc.id,
        source: analysis.usedAI ? 'groq-llm' : 'rule-engine',
        sourceType: 'AI_ANALYSIS',
        rawData: JSON.stringify(analysis),
        summary: analysis.summary,
        findings: analysis.keyFindings,
        verified: analysis.usedAI,
      });

      if (['CRITICAL', 'HIGH'].includes(analysis.threatLevel)) {
        await createAlert({
          iocId: ioc.id,
          title: `AI Alert: ${analysis.threatLevel} - ${target}`,
          description: analysis.summary,
          severity: analysis.threatLevel as string,
          type: 'ANOMALY_DETECTED',
        });
      }
    } catch (storeError) {
      console.error('Store save error (non-critical):', storeError);
    }

    return NextResponse.json({
      success: true,
      module: aiModule,
      source: analysis.usedAI ? 'Groq-LLM + Agent Engine' : 'Agent Engine (rule-based fallback)',
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      aiEnabled,
      usedAI: analysis.usedAI,
      target,
      type: resolvedType,
      enrichment: enrichForDisplay(enrichment),
      analysis,
      message: `Analysis complete. Threat Level: ${analysis.threatLevel}${analysis.usedAI ? '' : ' (AI not configured — set GROQ_API_KEY for LLM analysis)'}`,
    });
  } catch (error) {
    console.error('AI Analysis Error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Analysis failed',
    }, { status: 500 });
  }
}

// GET returns status/config
export async function GET() {
  return NextResponse.json({
    success: true,
    aiEnabled: isAIEnabled(),
    provider: 'Groq (OpenAI-compatible)',
    model: process.env.AI_MODEL || 'llama-3.3-70b-versatile',
    agents: ['enrichmentAgent', 'analysisAgent', 'reporterAgent'],
    message: isAIEnabled()
      ? 'AI configured — POST a target for LLM-powered analysis'
      : 'AI not configured — set GROQ_API_KEY. Rule-based fallback active.',
  });
}

function enrichForDisplay(bundle: any) {
  const out: Record<string, any> = {};
  if (bundle.ip) out.ip = bundle.ip.data;
  if (bundle.domain) {
    out.domain = {
      dns: bundle.domain.dns,
      security: bundle.domain.security,
      whois: bundle.domain.whois,
    };
  }
  if (bundle.cve) out.cve = bundle.cve.results;
  if (bundle.hash) out.hash = bundle.hash;
  return out;
}

function mapTypeToIOC(type: string): string {
  const mapping: Record<string, string> = {
    ip: 'IP',
    domain: 'DOMAIN',
    hash: 'HASH',
    cve: 'CVE',
    url: 'URL',
    email: 'EMAIL',
    mobile: 'HASH',
  };
  return mapping[type.toLowerCase()] || 'IP';
}

function mapThreatToStatus(threatLevel?: string): string {
  const mapping: Record<string, string> = {
    CRITICAL: 'MALICIOUS',
    HIGH: 'SUSPICIOUS',
    MEDIUM: 'SUSPICIOUS',
    LOW: 'UNKNOWN',
    INFO: 'BENIGN',
  };
  return mapping[threatLevel || ''] || 'UNKNOWN';
}
