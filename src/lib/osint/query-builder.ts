/**
 * Google Dorking Query Builder
 *
 * Builds search queries from templates by injecting target variables,
 * applying filters (site, filetype, date range), and performing
 * RFC 3986 URL encoding for search engine compatibility.
 */

import { DorkTemplate, SeverityLevel, DORK_TEMPLATES, SEVERITY_COLORS } from './dork-templates';

// ============================================================================
// Target Types
// ============================================================================
export interface TargetInput {
  name?: string;
  email?: string;
  alias?: string;
  phone?: string;
  domain?: string;
}

export interface SearchFilters {
  site?: string;
  filetype?: string;
  dateRange?: string;
}

export interface DorkSearchRequest {
  target: TargetInput;
  filters: SearchFilters;
  templateIds: string[];
  engines: string[];
}

// ============================================================================
// URL Encoding Utility (RFC 3986)
// ============================================================================
const RFC3986_UNRESERVED = /[A-Za-z0-9\-_.~]/;

/**
 * RFC 3986 compliant URL encoding.
 * Encodes characters that are not in the unreserved set.
 * Specifically handles characters that break search engine queries:
 *   : -> %3A  " -> %22  / -> %2F  ? -> %3F  # -> %23
 *   [ -> %5B  ] -> %5D  @ -> %40  ! -> %21
 *   $ -> %24  & -> %26  ' -> %27  ( -> %28
 *   ) -> %29  * -> %2A  + -> %2B  , -> %2C
 *   ; -> %3B  = -> %3D  % -> %25  < -> %3C
 *   > -> %3E  { -> %7B  } -> %7D  | -> %7C
 *   \ -> %5C  ^ -> %5E  ` -> %60  ~ -> %7E
 *   space -> %20 (NOT +)
 */
export function rfc3986Encode(str: string): string {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (RFC3986_UNRESERVED.test(ch)) {
      result += ch;
    } else {
      const bytes = Buffer.from(ch, 'utf-8');
      for (const byte of bytes) {
        result += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  return result;
}

/**
 * Build a search engine URL from a query string
 */
export function buildSearchUrl(query: string, engine: string): string {
  const encoded = rfc3986Encode(query);

  switch (engine) {
    case 'google':
      return `https://www.google.com/search?q=${encoded}&num=20`;
    case 'bing':
      return `https://www.bing.com/search?q=${encoded}&count=20`;
    case 'duckduckgo':
      return `https://duckduckgo.com/?q=${encoded}`;
    case 'yandex':
      return `https://yandex.com/search/?text=${encoded}`;
    default:
      return `https://www.google.com/search?q=${encoded}&num=20`;
  }
}

// ============================================================================
// Target Variable Extraction
// ============================================================================
/**
 * Extract searchable terms from target input.
 * Returns an array of distinct search terms.
 */
export function extractTargetTerms(target: TargetInput): string[] {
  const terms: string[] = [];

  if (target.name) {
    terms.push(target.name);
    // Also extract individual name parts
    const parts = target.name.split(/\s+/).filter(p => p.length > 2);
    if (parts.length > 1) {
      terms.push(...parts);
    }
  }

  if (target.email) {
    terms.push(target.email);
    // Extract email username (before @)
    const emailUser = target.email.split('@')[0];
    if (emailUser.length > 2) {
      terms.push(emailUser);
    }
    // Extract email domain
    const emailDomain = target.email.split('@')[1];
    if (emailDomain) {
      terms.push(emailDomain);
    }
  }

  if (target.alias) {
    terms.push(target.alias);
  }

  if (target.phone) {
    // Strip non-digit chars for search
    const digitsOnly = target.phone.replace(/\D/g, '');
    terms.push(target.phone);
    if (digitsOnly.length > 6) {
      terms.push(digitsOnly);
    }
    // Common phone formats
    if (digitsOnly.length >= 10) {
      const last4 = digitsOnly.slice(-4);
      const areaCode = digitsOnly.slice(0, 3);
      terms.push(`"${areaCode}" "${last4}"`);
    }
  }

  if (target.domain) {
    terms.push(target.domain);
  }

  // Remove duplicates
  return [...new Set(terms)];
}

/**
 * Get the primary target string for template injection.
 * Prioritizes: email > name > alias > phone > domain
 */
export function getPrimaryTarget(target: TargetInput): string {
  if (target.email) return target.email;
  if (target.name) return target.name;
  if (target.alias) return target.alias;
  if (target.phone) return target.phone;
  if (target.domain) return target.domain;
  return '';
}

/**
 * Get domain from target (extracted from email or provided)
 */
export function getTargetDomain(target: TargetInput): string {
  if (target.domain) return target.domain;
  if (target.email) return target.email.split('@')[1] || '';
  return '';
}

// ============================================================================
// Dork-to-Natural Query Converter
// ============================================================================
/**
 * Convert a Google Dork query into a natural-language query that
 * generic search engines (ZAI Web Search, etc.) can process.
 *
 * Google dork operators (intitle:, inurl:, filetype:, site:, etc.)
 * are NOT understood by ZAI Web Search. This function strips those
 * operators and converts them to plain keyword terms that produce
 * meaningful results on generic search APIs.
 *
 * Examples:
 *   intitle:"login" "Juan Perez"       → "Juan Perez" login
 *   filetype:sql "correo@empresa.com"   → "correo@empresa.com" sql file
 *   site:linkedin.com "Juan Perez"      → "Juan Perez" linkedin.com
 *   inurl:admin "empresa.com"           → "empresa.com" admin
 */
export function dorkToNaturalQuery(dorkQuery: string): string {
  let q = dorkQuery;

  // Convert intitle:"X" → X
  q = q.replace(/intitle:"([^"]+)"/g, '$1');
  // Convert intitle:X → X
  q = q.replace(/intitle:([^\s"]+)/g, '$1');

  // Convert inurl:X → X
  q = q.replace(/inurl:"([^"]+)"/g, '$1');
  q = q.replace(/inurl:([^\s"]+)/g, '$1');

  // Convert filetype:X → X file
  q = q.replace(/filetype:(\w+)/g, '$1');

  // Convert site:X → X (keep domain as keyword)
  q = q.replace(/site:"([^"]+)"/g, '$1');
  q = q.replace(/site:([^\s"]+)/g, '$1');

  // Remove OR (keep surrounding terms)
  q = q.replace(/\bOR\b/g, '');

  // Remove after: filters (not supported)
  q = q.replace(/after:\w+/g, '');

  // Remove remaining unsupported operators
  q = q.replace(/cache:[^\s]+/g, '');
  q = q.replace(/related:[^\s]+/g, '');
  q = q.replace(/link:[^\s]+/g, '');
  q = q.replace(/info:[^\s]+/g, '');
  q = q.replace(/define:[^\s]+/g, '');
  q = q.replace(/allintitle:[^\s]+/g, '');
  q = q.replace(/allinurl:[^\s]+/g, '');
  q = q.replace(/allintext:[^\s]+/g, '');

  // Clean up leftover colons from partially-converted operators
  // e.g. ".git" → .git  (remove wrapping quotes around simple terms)
  // But keep quoted phrases that are meaningful
  q = q.replace(/\s{2,}/g, ' ').trim();

  // Remove leading/trailing stray operators or punctuation
  q = q.replace(/^[\s:]+/, '').replace(/[\s:]+$/, '');

  return q;
}

// ============================================================================
// Query Building
// ============================================================================
/**
 * Build a complete dork query from a template, target, and filters.
 *
 * Replaces template placeholders:
 *   {{TARGET}} -> primary target string
 *   {{TARGET_DOMAIN}} -> target domain
 *   {{TARGET_EMAIL}} -> target email
 *   {{TARGET_NAME}} -> target name
 *   {{TARGET_ALIAS}} -> target alias/username
 *   {{TARGET_PHONE}} -> target phone
 *
 * Then appends filter clauses:
 *   site: filter
 *   filetype: filter (if not already in query)
 *   date range filter
 */
export function buildQueryFromTemplate(
  template: DorkTemplate,
  target: TargetInput,
  filters: SearchFilters
): string {
  let query = template.query;

  // Replace placeholders
  const primaryTarget = getPrimaryTarget(target);
  query = query.replace(/\{\{TARGET\}\}/g, primaryTarget);
  query = query.replace(/\{\{TARGET_DOMAIN\}\}/g, getTargetDomain(target));
  query = query.replace(/\{\{TARGET_EMAIL\}\}/g, target.email || primaryTarget);
  query = query.replace(/\{\{TARGET_NAME\}\}/g, target.name || primaryTarget);
  query = query.replace(/\{\{TARGET_ALIAS\}\}/g, target.alias || primaryTarget);
  query = query.replace(/\{\{TARGET_PHONE\}\}/g, target.phone || primaryTarget);

  // Apply site filter
  if (filters.site && !query.toLowerCase().includes('site:')) {
    query += ` site:${filters.site}`;
  }

  // Apply filetype filter (only if template doesn't already have filetype:)
  if (filters.filetype && !query.toLowerCase().includes('filetype:')) {
    query += ` filetype:${filters.filetype}`;
  }

  // Apply date range filter
  if (filters.dateRange) {
    const dateMapping: Record<string, string> = {
      'last_day': ' after:yesterday',
      'last_week': ' after:week',
      'last_month': ' after:month',
      'last_year': ' after:year',
    };
    const dateClause = dateMapping[filters.dateRange];
    if (dateClause) {
      query += dateClause;
    }
  }

  return query;
}

// ============================================================================
// Multi-Field ZAI Query Builder
// ============================================================================
/**
 * For each template, generate ONE natural-language query per target field.
 * This ensures all provided fields (name, email, alias, phone, domain)
 * are searched — not just the primary one.
 *
 * Returns both the original dork query (for display / "Open in Google")
 * and a ZAI-compatible natural query (for actual search execution).
 */
export interface MultiFieldQuery {
  /** The dork-formatted query (for display in UI) */
  dorkQuery: string;
  /** The natural-language query (for ZAI search execution) */
  zaiQuery: string;
  /** Which target field this query targets */
  targetField: string;
  /** The template this query was built from */
  templateId: string;
  templateName: string;
  severity: SeverityLevel;
  category: string;
}

export function buildMultiFieldZAIQueries(
  template: DorkTemplate,
  target: TargetInput,
  filters: SearchFilters
): MultiFieldQuery[] {
  const results: MultiFieldQuery[] = [];

  // Collect all available target fields
  const fields: Array<{ key: string; value: string }> = [];
  if (target.name) fields.push({ key: 'name', value: target.name });
  if (target.email) fields.push({ key: 'email', value: target.email });
  if (target.alias) fields.push({ key: 'alias', value: target.alias });
  if (target.phone) fields.push({ key: 'phone', value: target.phone });
  if (target.domain) fields.push({ key: 'domain', value: target.domain });

  // If no fields at all, use a single fallback
  if (fields.length === 0) {
    fields.push({ key: 'unknown', value: '' });
  }

  for (const field of fields) {
    // Build the raw query with this field as {{TARGET}}
    let rawQuery = template.query;

    // Replace field-specific placeholders first (they reference specific fields)
    rawQuery = rawQuery.replace(/\{\{TARGET_DOMAIN\}\}/g, getTargetDomain(target));
    rawQuery = rawQuery.replace(/\{\{TARGET_EMAIL\}\}/g, target.email || field.value);
    rawQuery = rawQuery.replace(/\{\{TARGET_NAME\}\}/g, target.name || field.value);
    rawQuery = rawQuery.replace(/\{\{TARGET_ALIAS\}\}/g, target.alias || field.value);
    rawQuery = rawQuery.replace(/\{\{TARGET_PHONE\}\}/g, target.phone || field.value);

    // Replace generic {{TARGET}} with this specific field value
    rawQuery = rawQuery.replace(/\{\{TARGET\}\}/g, field.value);

    // Apply optional filters to the dork query
    if (filters.site && !rawQuery.toLowerCase().includes('site:')) {
      rawQuery += ` site:${filters.site}`;
    }
    if (filters.filetype && !rawQuery.toLowerCase().includes('filetype:')) {
      rawQuery += ` filetype:${filters.filetype}`;
    }
    if (filters.dateRange) {
      const dateMapping: Record<string, string> = {
        'last_day': ' after:yesterday',
        'last_week': ' after:week',
        'last_month': ' after:month',
        'last_year': ' after:year',
      };
      const dateClause = dateMapping[filters.dateRange];
      if (dateClause) rawQuery += dateClause;
    }

    // Convert to natural language for ZAI
    const zaiQuery = dorkToNaturalQuery(rawQuery);

    // Only add if the ZAI query has meaningful content
    if (zaiQuery.trim().length > 2) {
      results.push({
        dorkQuery: rawQuery,
        zaiQuery,
        targetField: field.key,
        templateId: template.id,
        templateName: template.name,
        severity: template.severity,
        category: template.category,
      });
    }
  }

  return results;
}

/**
 * Deduplicate search results by URL.
 * Keeps the first occurrence of each URL.
 */
export function deduplicateResults(items: DorkSearchResultItem[]): DorkSearchResultItem[] {
  const seen = new Set<string>();
  return items.filter(item => {
    const normalizedUrl = item.url.toLowerCase().replace(/\/+$/, '');
    if (seen.has(normalizedUrl)) return false;
    seen.add(normalizedUrl);
    return true;
  });
}

/**
 * Build queries for a set of template IDs
 */
export function buildQueriesFromTemplateIds(
  templateIds: string[],
  target: TargetInput,
  filters: SearchFilters
): Array<{ templateId: string; templateName: string; query: string; severity: SeverityLevel; category: string }> {
  const results: Array<{ templateId: string; templateName: string; query: string; severity: SeverityLevel; category: string }> = [];

  for (const id of templateIds) {
    const template = DORK_TEMPLATES.find(t => t.id === id);
    if (template) {
      results.push({
        templateId: template.id,
        templateName: template.name,
        query: buildQueryFromTemplate(template, target, filters),
        severity: template.severity,
        category: template.category,
      });
    }
  }

  return results;
}

// ============================================================================
// Severity Scoring Engine (Heuristic)
// ============================================================================
/**
 * Determine severity based on dork category and content.
 * This supplements the template-based severity with dynamic scoring.
 */
export function scoreSeverity(query: string, category: string): SeverityLevel {
  const q = query.toLowerCase();

  // CRITICAL indicators
  if (q.includes('password') && (q.includes('filetype:txt') || q.includes('filetype:csv'))) return 'CRITICAL';
  if (q.includes('filetype:env') || q.includes('.env')) return 'CRITICAL';
  if (q.includes('filetype:sql') && (q.includes('insert') || q.includes('create table'))) return 'CRITICAL';
  if (q.includes('private key') || q.includes('rsa')) return 'CRITICAL';
  if (q.includes('api_key') || q.includes('apikey')) return 'CRITICAL';
  if (q.includes('"default password"')) return 'CRITICAL';
  if (q.includes('".git"')) return 'CRITICAL';
  if (q.includes('filetype:db') || q.includes('filetype:sqlite')) return 'CRITICAL';

  // HIGH indicators
  if (q.includes('phpmyadmin') || q.includes('inurl:admin')) return 'HIGH';
  if (q.includes('filetype:zip') || q.includes('filetype:rar') || q.includes('filetype:bak')) return 'HIGH';
  if (q.includes('filetype:conf') || q.includes('filetype:ini') || q.includes('filetype:config')) return 'HIGH';
  if (q.includes('swagger') || q.includes('graphql') || q.includes('inurl:api')) return 'HIGH';
  if (q.includes('leak') || q.includes('breach')) return 'HIGH';
  if (q.includes('confidential') || q.includes('interno') || q.includes('privado')) return 'HIGH';
  if (category === 'sensitive_info') return 'HIGH';

  // MEDIUM indicators
  if (q.includes('sql syntax error') || q.includes('mysql_fetch')) return 'MEDIUM';
  if (q.includes('filetype:log') || q.includes('"error"')) return 'MEDIUM';
  if (q.includes('warning') || q.includes('fatal') || q.includes('stack trace')) return 'MEDIUM';
  if (q.includes('login') || q.includes('wp-login')) return 'MEDIUM';
  if (category === 'login_pages' || category === 'security') return 'MEDIUM';

  // LOW (default for general)
  return 'LOW';
}

// ============================================================================
// Search Result Types
// ============================================================================
export interface DorkSearchResultItem {
  title: string;
  url: string;
  snippet: string;
  source: string;
  position: number;
}

export interface DorkSearchResult {
  templateId: string;
  templateName: string;
  query: string;
  severity: SeverityLevel;
  category: string;
  engine: string;
  searchUrl: string;
  resultCount: number;
  results: DorkSearchResultItem[];
  completedAt: string;
  error?: string;
}

export interface DorkSearchProgress {
  taskId: string;
  totalQueries: number;
  completedQueries: number;
  totalResults: number;
  currentResults: DorkSearchResult[];
  startedAt: string;
  status: 'running' | 'completed' | 'error';
  error?: string;
}

// ============================================================================
// User-Agent Rotation
// ============================================================================
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
];

export function getRandomUserAgent(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}
