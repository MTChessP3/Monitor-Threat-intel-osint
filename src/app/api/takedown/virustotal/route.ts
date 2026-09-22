import { NextResponse } from 'next/server';
import { virustotalPreCheck } from '@/lib/takedown/virustotal';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { url, apiKey } = body;

    if (!url) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    const apiKeyUsed = apiKey || process.env.VIRUSTOTAL_API_KEY || '';
    if (!apiKeyUsed) {
      return NextResponse.json({
        error: 'VirusTotal API key required',
        url,
        classification: 'UNKNOWN',
      }, { status: 400 });
    }

    const result = await virustotalPreCheck(url, apiKeyUsed);

    return NextResponse.json(result);
  } catch (error) {
    console.error('VirusTotal pre-check error:', error);
    return NextResponse.json({
      error: 'VirusTotal pre-check failed',
      url: body?.url,
      classification: 'ERROR',
    }, { status: 500 });
  }
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const url = searchParams.get('url');
    const apiKey = searchParams.get('apiKey') || process.env.VIRUSTOTAL_API_KEY || '';

    if (!url) {
      return NextResponse.json({ error: 'URL parameter required' }, { status: 400 });
    }
    if (!apiKey) {
      return NextResponse.json({ error: 'API key required' }, { status: 400 });
    }

    const result = await virustotalPreCheck(url, apiKey);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json({ error: 'VirusTotal query failed' }, { status: 500 });
  }
}
