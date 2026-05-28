import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';

const execFileAsync = promisify(execFile);

export interface AnalysisResult {
  threats: Array<{
    title: string;
    description: string;
    severity: 'bajo' | 'medio' | 'alto' | 'critico';
    category: string;
  }>;
  overallRiskLevel: 'bajo' | 'medio' | 'alto' | 'critico';
  summary: string;
  recommendations: string[];
  sources: Array<{
    title: string;
    url: string;
    relevance: string;
  }>;
}

async function runScript(scriptName: string, args: string[] = []): Promise<string> {
  const scriptPath = path.join(process.cwd(), 'scripts', scriptName);
  const { stdout } = await execFileAsync('node', [scriptPath, ...args], {
    timeout: 120000,
    maxBuffer: 10 * 1024 * 1024,
    cwd: process.cwd(),
    env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=128' },
  });
  return stdout.trim();
}

export async function analyzeIntelligence(
  urls: string[],
  searchQueries: string[]
): Promise<AnalysisResult> {
  const result = await runScript('analyze.js', [
    JSON.stringify(urls || []),
    JSON.stringify(searchQueries || [])
  ]);

  try {
    return JSON.parse(result) as AnalysisResult;
  } catch {
    throw new Error('Error al procesar el análisis. Intente nuevamente.');
  }
}

export async function generateReport(
  templateContent: string,
  analysis: AnalysisResult
): Promise<string> {
  const result = await runScript('generate-report.js', [
    JSON.stringify({ templateContent, analysis })
  ]);

  try {
    const parsed = JSON.parse(result);
    return parsed.content || 'Error al generar el informe';
  } catch {
    throw new Error('Error al generar el informe.');
  }
}

export async function updateReport(
  existingContent: string,
  _existingTitle: string,
  additionalUrls: string[],
  additionalNews: string,
  additionalContext: string
): Promise<string> {
  const result = await runScript('update-report.js', [
    JSON.stringify({ existingContent, additionalUrls, additionalNews, additionalContext })
  ]);

  try {
    const parsed = JSON.parse(result);
    return parsed.content || existingContent;
  } catch {
    return existingContent;
  }
}
