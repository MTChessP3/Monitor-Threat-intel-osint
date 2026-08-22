import { NextResponse } from 'next/server';
import * as XLSX from 'xlsx';
import { parse } from 'csv-parse/sync';

const URL_REGEX = /(?:https?:\/\/)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?/gi;

function extractUrlsFromText(text: string): string[] {
  const urls = text.match(URL_REGEX) || [];
  const normalized = urls.map(u => {
    if (!u.startsWith('http://') && !u.startsWith('https://')) {
      return 'https://' + u;
    }
    return u;
  });
  return [...new Set(normalized)];
}

function parseTxt(content: string): string[] {
  return extractUrlsFromText(content);
}

function parseCsv(content: string): string[] {
  try {
    const records = parse(content, {
      columns: false,
      skip_empty_lines: true,
      trim: true,
    });
    const allText = records.flat().join(' ');
    return extractUrlsFromText(allText);
  } catch {
    return extractUrlsFromText(content);
  }
}

function parseXlsx(buffer: Buffer): string[] {
  try {
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    let allText = '';
    for (const sheetName of workbook.SheetNames) {
      const sheet = workbook.Sheets[sheetName];
      const json = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });
      for (const row of json as string[][]) {
        allText += row.join(' ') + ' ';
      }
    }
    return extractUrlsFromText(allText);
  } catch {
    return [];
  }
}

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return NextResponse.json({ error: 'No se proporcionó ningún archivo' }, { status: 400 });
    }

    const validExtensions = ['.txt', '.csv', '.xlsx'];
    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!validExtensions.includes(ext)) {
      return NextResponse.json(
        { error: 'Formato no soportado. Use .txt, .csv o .xlsx' },
        { status: 400 }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    let urls: string[] = [];

    switch (ext) {
      case '.txt':
        urls = parseTxt(buffer.toString('utf-8'));
        break;
      case '.csv':
        urls = parseCsv(buffer.toString('utf-8'));
        break;
      case '.xlsx':
        urls = parseXlsx(buffer);
        break;
    }

    // Validate URLs
    const validUrls = urls.filter(url => {
      try {
        new URL(url);
        return true;
      } catch {
        return false;
      }
    });

    return NextResponse.json({
      fileName: file.name,
      fileSize: file.size,
      extension: ext,
      totalUrlsFound: urls.length,
      validUrls: validUrls,
      validCount: validUrls.length,
    });
  } catch (error: unknown) {
    console.error('Error processing file:', error);
    const errorMessage = error instanceof Error ? error.message : 'Error al procesar el archivo';
    return NextResponse.json({ error: errorMessage }, { status: 500 });
  }
}