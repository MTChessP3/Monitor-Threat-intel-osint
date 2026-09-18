import { extractUrlsFromText, isValidUrl } from './defang';

interface ParsedFileResult {
  urls: string[];
  validUrls: string[];
  invalidUrls: string[];
  fileName: string;
  fileType: string;
  totalLines: number;
  duplicateCount: number;
}

export async function parseTxtFile(buffer: Buffer): Promise<ParsedFileResult> {
  const text = buffer.toString('utf-8');
  const lines = text.split(/\r?\n/);
  const urls = extractUrlsFromText(text);
  const validUrls = urls.filter(u => isValidUrl(u));
  const invalidUrls = urls.filter(u => !isValidUrl(u));

  return {
    urls: [...new Set(urls)],
    validUrls: [...new Set(validUrls)],
    invalidUrls,
    fileName: '',
    fileType: '.txt',
    totalLines: lines.length,
    duplicateCount: urls.length - new Set(urls).size,
  };
}

export async function parseCsvFile(buffer: Buffer): Promise<ParsedFileResult> {
  const text = buffer.toString('utf-8');
  const lines = text.split(/\r?\n/);
  const urls = extractUrlsFromText(text);
  const validUrls = urls.filter(u => isValidUrl(u));
  const invalidUrls = urls.filter(u => !isValidUrl(u));

  let detectedColumn = '';
  if (lines.length > 0) {
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
    const urlColumnIndex = headers.findIndex(h =>
      h.includes('url') || h.includes('link') || h.includes('malicious') || h.includes('phishing') || h.includes('threat') || h.includes('domain') || h.includes('host')
    );
    if (urlColumnIndex >= 0) {
      detectedColumn = headers[urlColumnIndex];
    }
  }

  return {
    urls: [...new Set(urls)],
    validUrls: [...new Set(validUrls)],
    invalidUrls,
    fileName: '',
    fileType: '.csv',
    totalLines: lines.length,
    duplicateCount: urls.length - new Set(urls).size,
  };
}

export async function parseXlsxFile(buffer: Buffer): Promise<ParsedFileResult> {
  const xlsx = require('xlsx');
  const workbook = xlsx.read(buffer, { type: 'buffer' });
  const sheetName = workbook.SheetNames[0];
  const worksheet = workbook.Sheets[sheetName];
  const jsonData: Record<string, string>[] = xlsx.utils.sheet_to_json(worksheet, { defval: '' });

  const urls: string[] = [];
  let detectedColumn = '';
  const headers = jsonData.length > 0 ? Object.keys(jsonData[0]).map(h => h.toLowerCase()) : [];
  const urlColumnIndex = headers.findIndex(h =>
    h.includes('url') || h.includes('link') || h.includes('malicious') || h.includes('phishing') || h.includes('threat')
  );

  if (urlColumnIndex >= 0) {
    detectedColumn = headers[urlColumnIndex];
  }

  for (const row of jsonData) {
    if (detectedColumn) {
      const val = row[detectedColumn] || '';
      if (typeof val === 'string' && val.trim()) {
        const normalized = normalizeUrl(val.trim());
        if (isValidUrl(normalized)) {
          urls.push(normalized);
        }
      }
    }
    for (const key of Object.keys(row)) {
      const val = row[key];
      if (typeof val === 'string') {
        const extracted = extractUrlsFromText(val);
        urls.push(...extracted);
      }
    }
  }

  const validUrls = urls.filter(u => isValidUrl(u));
  const invalidUrls = urls.filter(u => !isValidUrl(u));

  return {
    urls: [...new Set(urls)],
    validUrls: [...new Set(validUrls)],
    invalidUrls,
    fileName: '',
    fileType: '.xlsx',
    totalLines: jsonData.length,
    duplicateCount: urls.length - new Set(urls).size,
  };
}

export async function parseFile(buffer: Buffer, fileName: string): Promise<ParsedFileResult> {
  const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();

  switch (ext) {
    case '.txt': {
      const result = await parseTxtFile(buffer);
      return { ...result, fileName };
    }
    case '.csv': {
      const result = await parseCsvFile(buffer);
      return { ...result, fileName };
    }
    case '.xlsx': {
      const result = await parseXlsxFile(buffer);
      return { ...result, fileName };
    }
    default:
      throw new Error(`Formato de archivo no soportado: ${ext}`);
  }
}

function normalizeUrl(url: string): string {
  let normalized = url.trim();
  if (!normalized.match(/^https?:\/\//i)) {
    normalized = 'https://' + normalized;
  }
  try {
    const parsed = new URL(normalized);
    return parsed.toString();
  } catch {
    return normalized;
  }
}
