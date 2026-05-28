import { NextResponse } from 'next/server';
import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';

const execFileAsync = promisify(execFile);

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { operation, data } = body;

    const scriptName = operation === 'analyze' ? 'analyze.js'
      : operation === 'generate-report' ? 'generate-report.js'
      : operation === 'update-report' ? 'update-report.js'
      : null;

    if (!scriptName) {
      return NextResponse.json({ error: 'Operación inválida' }, { status: 400 });
    }

    const scriptPath = path.join(process.cwd(), 'scripts', scriptName);
    
    // For analyze, pass urls and queries as separate args
    // For others, pass the whole data object
    let args: string[];
    if (operation === 'analyze') {
      args = [JSON.stringify(data.urls || []), JSON.stringify(data.searchQueries || [])];
    } else {
      args = [JSON.stringify(data)];
    }

    const { stdout, stderr } = await execFileAsync('node', [scriptPath, ...args], {
      timeout: 180000, // 3 minutes timeout for AI operations
      maxBuffer: 20 * 1024 * 1024, // 20MB buffer for large reports
      cwd: process.cwd(),
      env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=256' },
    });

    if (stderr && !stderr.includes('ExperimentalWarning') && !stderr.includes('DeprecationWarning')) {
      console.error('Script stderr:', stderr);
    }

    const result = JSON.parse(stdout.trim());
    return NextResponse.json(result);
  } catch (error: unknown) {
    console.error('AI operation error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error en la operación de IA';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
