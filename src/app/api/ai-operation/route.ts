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
      return NextResponse.json({ error: 'Invalid operation' }, { status: 400 });
    }

    const scriptPath = path.join(process.cwd(), 'scripts', scriptName);
    const args = operation === 'analyze'
      ? [JSON.stringify(data.urls || []), JSON.stringify(data.searchQueries || [])]
      : [JSON.stringify(data)];

    const { stdout } = await execFileAsync('node', [scriptPath, ...args], {
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024,
      cwd: process.cwd(),
      env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=128' },
    });

    const result = JSON.parse(stdout.trim());
    return NextResponse.json(result);
  } catch (error: unknown) {
    console.error('AI operation error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error en la operación de IA';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}
