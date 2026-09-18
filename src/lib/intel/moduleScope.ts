import { NextRequest } from 'next/server';

// Per-module request scoping: isolates search state/caching across modules.
// Every search-query endpoint must declare its originating module so no global
// `last_search` state or generalized cache leaks between modules (ip_risk,
// file_analysis, scanner, forensics, iocs, etc.).

export const MODULES = [
  'dashboard',
  'iocs',
  'ip',
  'domain',
  'url',
  'hash',
  'cve',
  'darkweb',
  'forensics',
  'mobile',
  'social',
  'brand',
  'exec',
  'dnsdump',
  'fakeapp',
  'sandbox',
  'ai',
  'threats',
  'reports',
  'sources',
  'export',
];

export interface ModuleScopeResult {
  module: string;
  error: string;
}

export function resolveModuleScope(request: NextRequest, body?: Record<string, any>): ModuleScopeResult {
  const raw =
    request.nextUrl.searchParams.get('module') ||
    (body && typeof body.module === 'string' ? body.module : '') ||
    '';
  const m = raw.trim().toLowerCase();
  if (!m) {
    return {
      module: '',
      error: 'Missing required "module" parameter (per-module scoping). Send ?module=<tab> or body.module.',
    };
  }
  if (!MODULES.includes(m)) {
    return { module: '', error: `Unknown module "${raw}". Allowed modules: ${MODULES.join(', ')}` };
  }
  return { module: m, error: '' };
}