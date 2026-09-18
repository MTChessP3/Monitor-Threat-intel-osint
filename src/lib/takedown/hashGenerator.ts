import crypto from 'crypto';

export function sha256(data: Buffer | string): string {
  const buffer = typeof data === 'string' ? Buffer.from(data) : data;
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export async function sha256WebCrypto(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function sha256File(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function generateTransactionId(): string {
  return crypto.randomUUID();
}

export function computeBatchHash(
  fileContent: Buffer,
  urls: string[],
  services: string[]
): { fileHash: string; urlsHash: string; batchHash: string } {
  const fileHash = sha256File(fileContent);
  const urlsHash = sha256(urls.sort().join('\n'));
  const batchHash = sha256(`${fileHash}-${urlsHash}-${services.sort().join(',')}`);
  return { fileHash, urlsHash, batchHash };
}
