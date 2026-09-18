export function defangUrl(url: string): string {
  let defanged = url
    .replace(/^https?:\/\//i, '')
    .replace(/^hxxps?:\/\//i, '');

  defanged = defanged
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]')
    .replace(/:/g, '[:]');

  if (!defanged.match(/^hxxps?:\/\//i)) {
    defanged = 'hxxps://' + defanged;
  }

  return defanged;
}

export function defangUrls(urls: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const url of urls) {
    result[url] = defangUrl(url);
  }
  return result;
}

export function normalizeUrl(url: string): string {
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

export function extractUrlsFromText(text: string): string[] {
  const urlRegex = /(?:https?:\/\/|hxxps?:\/\/)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:[\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?/gi;
  const matches = text.match(urlRegex) || [];
  const unique = new Set(matches.map(u => normalizeUrl(u)));
  return Array.from(unique);
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(normalizeUrl(url));
    return true;
  } catch {
    return false;
  }
}

export function sanitizeUrl(url: string): string {
  return normalizeUrl(url).replace(/[<>"'\\]/g, '');
}
