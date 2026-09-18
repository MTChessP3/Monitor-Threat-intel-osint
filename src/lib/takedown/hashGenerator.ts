export async function sha256(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateTransactionId(): string {
  return crypto.randomUUID();
}

export async function sha256OfFile(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function computeBatchHash(
  fileBuffer: ArrayBuffer,
  urls: string[],
  services: string[]
): Promise<{ fileHash: string; urlsHash: string; batchHash: string }> {
  const fileHash = await sha256OfFile(fileBuffer);
  const urlsHash = await sha256(urls.sort().join('\n'));
  const batchHash = await sha256(`${fileHash}-${urlsHash}-${services.sort().join(',')}`);
  return { fileHash, urlsHash, batchHash };
}
