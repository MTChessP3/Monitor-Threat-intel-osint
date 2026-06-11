/**
 * Smart OSINT Search Query Generator
 *
 * Instead of using Google Dork templates (which require Google-specific operators
 * that ZAI Web Search doesn't support), this module generates intelligent,
 * natural-language queries for each target field provided.
 *
 * Strategy:
 * - For each field (name, email, alias, phone, domain), generate 2-3 targeted queries
 * - Each query combines the field value with context-relevant keywords
 * - Total queries: ~10-20 (not 100+ like the old template×field approach)
 * - Queries are designed for generic web search engines (ZAI, Bing API, etc.)
 */

import { type TargetInput, type SearchFilters, type DorkSearchResultItem, type DorkCategory } from './query-builder';
import { DORK_TEMPLATES, type SeverityLevel } from './dork-templates';

// ============================================================================
// Types
// ============================================================================
export interface SmartQuery {
  /** Unique ID for this query */
  id: string;
  /** Human-readable label for UI display */
  label: string;
  /** The actual natural-language query to send to ZAI */
  query: string;
  /** Which target field this query is based on */
  targetField: 'name' | 'email' | 'alias' | 'phone' | 'domain';
  /** The target value used */
  targetValue: string;
  /** Dork category this maps to (for grouping in UI) */
  category: DorkCategory;
  /** Severity level */
  severity: SeverityLevel;
  /** Original dork query equivalent (for "Open in Google" link) */
  dorkEquivalent: string;
}

export interface SmartQueryGroup {
  field: string;
  fieldLabel: string;
  queries: SmartQuery[];
}

// ============================================================================
// Category Context Keywords
// ============================================================================
const CATEGORY_CONTEXT: Record<DorkCategory, { keywords: string[]; severity: SeverityLevel }> = {
  login_pages: { keywords: ['login', 'admin panel', 'authentication'], severity: 'MEDIUM' },
  exposed_files: { keywords: ['exposed file', 'document leak', 'pdf'], severity: 'HIGH' },
  databases: { keywords: ['database leak', 'data dump', 'sql'], severity: 'CRITICAL' },
  sensitive_info: { keywords: ['credentials', 'password', 'api key', 'personal data'], severity: 'CRITICAL' },
  security: { keywords: ['vulnerability', 'security breach', 'exploit'], severity: 'HIGH' },
  general: { keywords: ['profile', 'information', 'social media'], severity: 'LOW' },
};

// ============================================================================
// Smart Query Builder
// ============================================================================

/**
 * Build smart, targeted OSINT queries for each provided target field.
 * Returns a flat list of queries, grouped by field.
 */
export function buildSmartQueries(
  target: TargetInput,
  selectedCategoryIds: DorkCategory[],
  filters?: SearchFilters
): SmartQuery[] {
  const queries: SmartQuery[] = [];
  let counter = 0;

  // Determine which categories to use (default: all)
  const categories = selectedCategoryIds.length > 0
    ? selectedCategoryIds
    : (Object.keys(CATEGORY_CONTEXT) as DorkCategory[]);

  const addQuery = (
    field: SmartQuery['targetField'],
    fieldLabel: string,
    value: string,
    query: string,
    category: DorkCategory,
    severity: SeverityLevel,
    dorkEquivalent: string
  ) => {
    counter++;
    queries.push({
      id: `sq-${counter}`,
      label: `${fieldLabel}: ${query.substring(0, 60)}${query.length > 60 ? '...' : ''}`,
      query,
      targetField: field,
      targetValue: value,
      category,
      severity,
      dorkEquivalent,
    });
  };

  // =========================================================================
  // NAME-based queries
  // =========================================================================
  if (target.name && target.name.trim().length > 2) {
    const name = target.name.trim();
    const nameParts = name.split(/\s+/).filter(p => p.length > 2);
    const lastName = nameParts.length > 1 ? nameParts[nameParts.length - 1] : '';
    const shortName = nameParts.length > 1 ? `${nameParts[0]} ${lastName}` : name;

    // 1. Direct name search (broadest)
    addQuery('name', 'Nombre', name, `"${name}"`, 'general', 'LOW', `"${name}"`);

    // 2. Social media presence
    addQuery('name', 'Nombre', name, `${name} linkedin OR facebook OR twitter OR instagram`, 'general', 'LOW',
      `"${name}" site:linkedin.com OR site:facebook.com OR site:twitter.com`);

    // 3. News / media mentions
    addQuery('name', 'Nombre', name, `"${name}" noticias OR news OR artículo`, 'general', 'LOW',
      `"${name}" site:news.google.com OR site:reuters.com`);

    // 4. Sensitive info / credential exposure
    if (categories.includes('sensitive_info')) {
      addQuery('name', 'Nombre', name, `"${name}" password OR credentials OR leak OR filtración`, 'sensitive_info', 'CRITICAL',
        `"${name}" "password" OR "credentials" OR "leak"`);
    }

    // 5. Data breach mentions
    if (categories.includes('databases')) {
      addQuery('name', 'Nombre', name, `"${name}" data breach OR filtración datos OR base datos expuesta`, 'databases', 'CRITICAL',
        `"${name}" "data breach" OR "database dump"`);
    }

    // 6. Court/legal records
    if (categories.includes('security')) {
      addQuery('name', 'Nombre', name, `"${name}" demanda OR court OR sentencia OR proceso judicial`, 'security', 'MEDIUM',
        `"${name}" filetype:pdf "sentencia" OR "resolución"`);
    }

    // 7. Exposed documents
    if (categories.includes('exposed_files')) {
      addQuery('name', 'Nombre', name, `"${name}" filetype:pdf OR filetype:doc OR documento confidencial`, 'exposed_files', 'HIGH',
        `"${name}" filetype:pdf OR filetype:doc`);
    }
  }

  // =========================================================================
  // EMAIL-based queries
  // =========================================================================
  if (target.email && target.email.trim().length > 3) {
    const email = target.email.trim();
    const emailUser = email.split('@')[0];
    const emailDomain = email.split('@')[1] || '';

    // 1. Direct email search
    addQuery('email', 'Correo', email, `"${email}"`, 'general', 'MEDIUM', `"${email}"`);

    // 2. Email in data breaches / leaks
    if (categories.includes('sensitive_info') || categories.includes('databases')) {
      addQuery('email', 'Correo', email, `"${email}" leak OR breach OR filtración OR datos expuestos OR stolen`, 'sensitive_info', 'CRITICAL',
        `"${email}" "leak" OR "breach" OR "password"`);
    }

    // 3. Email with password/credential exposure
    if (categories.includes('sensitive_info')) {
      addQuery('email', 'Correo', email, `"${email}" password OR contraseña OR credentials OR api_key`, 'sensitive_info', 'CRITICAL',
        `"${email}" "password" filetype:txt OR filetype:csv`);
    }

    // 4. Email domain exposure
    if (emailDomain && categories.includes('exposed_files')) {
      addQuery('email', 'Correo', email, `"@${emailDomain}" filetype:xlsx OR filetype:csv OR employee list`, 'exposed_files', 'HIGH',
        `"@${emailDomain}" filetype:xlsx OR filetype:csv OR filetype:txt`);
    }

    // 5. Email on social/profiles
    if (categories.includes('general')) {
      addQuery('email', 'Correo', email, `"${email}" profile OR cuenta OR registro`, 'general', 'LOW',
        `"${email}" site:linkedin.com OR site:facebook.com`);
    }

    // 6. Email username variations
    if (emailUser.length > 3 && categories.includes('login_pages')) {
      addQuery('email', 'Correo', email, `"${emailUser}" login OR account OR sign up`, 'login_pages', 'MEDIUM',
        `"${emailUser}" inurl:login OR inurl:signup`);
    }
  }

  // =========================================================================
  // ALIAS-based queries
  // =========================================================================
  if (target.alias && target.alias.trim().length > 2) {
    const alias = target.alias.trim();

    // 1. Direct alias search
    addQuery('alias', 'Alias', alias, `"${alias}"`, 'general', 'LOW', `"${alias}"`);

    // 2. Alias on social platforms
    addQuery('alias', 'Alias', alias, `${alias} site:github.com OR site:reddit.com OR site:twitter.com OR site:instagram.com`, 'general', 'LOW',
      `"${alias}" site:github.com OR site:reddit.com OR site:twitter.com`);

    // 3. Alias in forums/communities
    if (categories.includes('general')) {
      addQuery('alias', 'Alias', alias, `"${alias}" forum OR comunidad OR perfil OR profile`, 'general', 'MEDIUM',
        `"${alias}" site:reddit.com OR inurl:forum`);
    }

    // 4. Alias credential exposure
    if (categories.includes('sensitive_info')) {
      addQuery('alias', 'Alias', alias, `"${alias}" password OR leak OR breach OR credentials`, 'sensitive_info', 'CRITICAL',
        `"${alias}" "password" OR "leak" OR "breach"`);
    }

    // 5. Alias on developer platforms
    if (categories.includes('security')) {
      addQuery('alias', 'Alias', alias, `"${alias}" github OR stackoverflow OR npm OR docker`, 'security', 'MEDIUM',
        `"${alias}" site:github.com OR site:stackoverflow.com`);
    }
  }

  // =========================================================================
  // PHONE-based queries
  // =========================================================================
  if (target.phone && target.phone.trim().length > 6) {
    const phone = target.phone.trim();
    const digits = phone.replace(/\D/g, '');

    // 1. Direct phone search
    addQuery('phone', 'Teléfono', phone, `"${phone}"`, 'general', 'MEDIUM', `"${phone}"`);

    // 2. Phone digits only
    if (digits.length >= 7 && digits !== phone) {
      addQuery('phone', 'Teléfono', phone, `"${digits}"`, 'general', 'MEDIUM', `"${digits}"`);
    }

    // 3. Phone in data leaks
    if (categories.includes('sensitive_info') || categories.includes('databases')) {
      addQuery('phone', 'Teléfono', phone, `"${phone}" leak OR datos OR filtración OR exposed`, 'sensitive_info', 'HIGH',
        `"${phone}" "leak" OR "breach" OR filetype:csv`);
    }

    // 4. Phone directory / who-called
    if (categories.includes('general')) {
      addQuery('phone', 'Teléfono', phone, `"${phone}" quién llamó OR who called OR directorio OR spam`, 'general', 'LOW',
        `"${phone}" directory OR "who called"`);
    }
  }

  // =========================================================================
  // DOMAIN-based queries
  // =========================================================================
  if (target.domain && target.domain.trim().length > 3) {
    const domain = target.domain.trim();

    // 1. Direct domain search
    addQuery('domain', 'Dominio', domain, `"${domain}"`, 'general', 'LOW', `"${domain}"`);

    // 2. Domain WHOIS / registration
    if (categories.includes('general')) {
      addQuery('domain', 'Dominio', domain, `"${domain}" WHOIS OR domain registration OR registrant`, 'general', 'LOW',
        `"${domain}" "WHOIS" OR "domain registration"`);
    }

    // 3. Domain exposed files
    if (categories.includes('exposed_files')) {
      addQuery('domain', 'Dominio', domain, `"${domain}" exposed files OR .env OR .git OR filetype:sql`, 'exposed_files', 'CRITICAL',
        `"${domain}" filetype:sql OR filetype:env OR ".git"`);
    }

    // 4. Domain vulnerabilities
    if (categories.includes('security')) {
      addQuery('domain', 'Dominio', domain, `"${domain}" vulnerability OR CVE OR exploit OR security`, 'security', 'HIGH',
        `"${domain}" "vulnerability" OR "CVE" OR "exploit"`);
    }

    // 5. Domain login/admin panels
    if (categories.includes('login_pages')) {
      addQuery('domain', 'Dominio', domain, `"${domain}" admin login OR panel OR dashboard`, 'login_pages', 'MEDIUM',
        `"${domain}" inurl:admin OR inurl:login`);
    }
  }

  // =========================================================================
  // Apply optional filters
  // =========================================================================
  // Site filter: append to queries if provided
  if (filters?.site) {
    for (const q of queries) {
      if (!q.query.includes(filters.site)) {
        q.query += ` ${filters.site}`;
        q.dorkEquivalent += ` site:${filters.site}`;
      }
    }
  }

  return queries;
}

/**
 * Group smart queries by target field for organized display.
 */
export function groupSmartQueriesByField(queries: SmartQuery[]): SmartQueryGroup[] {
  const fieldOrder: Array<{ key: SmartQuery['targetField']; label: string }> = [
    { key: 'name', label: 'Nombre Completo' },
    { key: 'email', label: 'Correo Electrónico' },
    { key: 'alias', label: 'Alias / Username' },
    { key: 'phone', label: 'Teléfono' },
    { key: 'domain', label: 'Dominio' },
  ];

  const groups: SmartQueryGroup[] = [];
  for (const { key, label } of fieldOrder) {
    const fieldQueries = queries.filter(q => q.targetField === key);
    if (fieldQueries.length > 0) {
      groups.push({ field: key, fieldLabel: label, queries: fieldQueries });
    }
  }

  return groups;
}

/**
 * Build a Google search URL from a dork-equivalent query
 */
export function buildGoogleUrl(query: string): string {
  const encoded = encodeURIComponent(query);
  return `https://www.google.com/search?q=${encoded}&num=20`;
}

/**
 * Deduplicate search results by URL.
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
