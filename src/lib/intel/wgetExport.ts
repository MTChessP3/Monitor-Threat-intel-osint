// wget-style mirror export: fetch each discovered path and pack into a real ZIP
// (minimal ZIP writer, STORE method, no external dependencies).

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) NEXUS-Forensic/5.1';
const MAX_FETCH_SIZE = 3 * 1024 * 1024;
const MAX_TOTAL_SIZE = 20 * 1024 * 1024;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function sanitizeZipName(name: string, fallback: string): string {
  let safe = name.replace(/\\/g, '/').split('/').filter(Boolean).pop() || fallback;
  safe = safe.replace(/[?*:"<>|]/g, '_').replace(/^\.+/, '').slice(0, 80) || fallback;
  if (safe.endsWith('/')) safe += 'index.html';
  return safe;
}

export function buildZip(files: { name: string; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const crc = crc32(f.data);
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0x0800, 6);
    lfh.writeUInt16LE(0, 8);
    lfh.writeUInt16LE(0, 10);
    lfh.writeUInt16LE(0x21, 12);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(f.data.length, 18);
    lfh.writeUInt32LE(f.data.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);
    parts.push(lfh, nameBuf, f.data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0x0800, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0x21, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(f.data.length, 20);
    cd.writeUInt32LE(f.data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBuf);
    offset += lfh.length + nameBuf.length + f.data.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...parts, cdBuf, eocd]);
}

export interface MirrorUrl { url: string; name: string; }

export async function mirrorUrls(urls: MirrorUrl[], limit = 100): Promise<{ name: string; data: Buffer }[]> {
  const files: { name: string; data: Buffer }[] = [];
  let total = 0;
  const batches: MirrorUrl[][] = [];
  for (let i = 0; i < Math.min(urls.length, limit); i += 8) batches.push(urls.slice(i, i + 8));
  for (const batch of batches) {
    await Promise.all(
      batch.map(async (u) => {
        try {
          if (!/^https?:\/\//i.test(u.url)) return;
          const res = await fetch(u.url, {
            redirect: 'follow',
            headers: { 'User-Agent': UA },
            signal: AbortSignal.timeout(9000),
          });
          if (!res.ok) return;
          const cl = parseInt(res.headers.get('content-length') || '0');
          if (cl && cl > MAX_FETCH_SIZE) return;
          const buf = Buffer.from(await res.arrayBuffer());
          if (buf.length === 0 || buf.length > MAX_FETCH_SIZE) return;
          if (total + buf.length > MAX_TOTAL_SIZE) return;
          total += buf.length;
          const name = sanitizeZipName(u.name, 'resource');
          if (!files.some(f => f.name === name)) files.push({ name, data: buf });
        } catch { /* skip unreachable path */ }
      })
    );
  }
  return files;
}

export function mimeForPath(path: string): string {
  const ext = (path.match(/\.([a-z0-9]+)$/i)?.[1] || 'bin').toLowerCase();
  const map: Record<string, string> = {
    html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', php: 'text/html; charset=utf-8',
    txt: 'text/plain; charset=utf-8', log: 'text/plain; charset=utf-8', sql: 'text/plain; charset=utf-8',
    json: 'application/json', js: 'application/javascript', mjs: 'application/javascript',
    css: 'text/css', xml: 'application/xml', csv: 'text/csv',
    zip: 'application/zip', gz: 'application/gzip', tgz: 'application/gzip', tar: 'application/x-tar',
    pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
    db: 'application/octet-stream', sqlite: 'application/octet-stream', bak: 'application/octet-stream',
    bin: 'application/octet-stream',
  };
  return map[ext] || 'application/octet-stream';
}
