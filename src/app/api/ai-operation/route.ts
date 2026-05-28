import { NextResponse } from 'next/server';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFileSync, unlinkSync } from 'fs';
import path from 'path';
import os from 'os';

const execFileAsync = promisify(execFile);

export async function POST(request: Request) {
  const tmpFiles: string[] = [];
  
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
    
    // Write data to a temp file to avoid command line escaping issues
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `vip-ai-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    tmpFiles.push(tmpFile);

    let inputData: Record<string, unknown>;
    if (operation === 'analyze') {
      inputData = {
        urls: data.urls || [],
        searchQueries: data.searchQueries || []
      };
    } else {
      inputData = data;
    }

    writeFileSync(tmpFile, JSON.stringify(inputData), 'utf-8');

    // Pass temp file path as argument - scripts read from it
    // Analyze can take up to 5 minutes with retries, generate-report up to 3 minutes
    const timeout = operation === 'analyze' ? 360000 : 240000;
    const { stdout, stderr } = await execFileAsync('node', [scriptPath, tmpFile], {
      timeout,
      maxBuffer: 20 * 1024 * 1024,
      cwd: process.cwd(),
      env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=512' },
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
  } finally {
    // Clean up temp files
    for (const f of tmpFiles) {
      try { unlinkSync(f); } catch {}
    }
  }
}
