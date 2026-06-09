/**
 * Google Dorking OSINT Template Library
 *
 * Each template has:
 * - id: unique identifier
 * - name: display name
 * - query: dork query template with {{TARGET}} placeholder
 * - category: which tab it belongs to
 * - severity: heuristic risk level (CRITICAL / HIGH / MEDIUM / LOW)
 * - description: what this dork searches for
 * - engines: which search engines support this dork
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type DorkCategory = 'login_pages' | 'exposed_files' | 'databases' | 'sensitive_info' | 'security' | 'general';

export interface DorkTemplate {
  id: string;
  name: string;
  query: string;
  category: DorkCategory;
  severity: SeverityLevel;
  description: string;
  engines: string[];
}

export const CATEGORY_META: Record<DorkCategory, { label: string; icon: string; color: string }> = {
  login_pages: { label: 'Login Pages', icon: 'log-in', color: 'text-orange-400' },
  exposed_files: { label: 'Exposed Files', icon: 'file-warning', color: 'text-red-400' },
  databases: { label: 'Databases', icon: 'database', color: 'text-purple-400' },
  sensitive_info: { label: 'Sensitive Info', icon: 'eye', color: 'text-amber-400' },
  security: { label: 'Security', icon: 'shield', color: 'text-cyan-400' },
  general: { label: 'General', icon: 'search', color: 'text-blue-400' },
};

export const SEVERITY_COLORS: Record<SeverityLevel, { bg: string; text: string; border: string; dot: string }> = {
  CRITICAL: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-500' },
  HIGH: { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30', dot: 'bg-orange-500' },
  MEDIUM: { bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-500' },
  LOW: { bg: 'bg-blue-500/15', text: 'text-blue-400', border: 'border-blue-500/30', dot: 'bg-blue-500' },
};

export const DORK_TEMPLATES: DorkTemplate[] = [
  // ==========================================================================
  // LOGIN PAGES
  // ==========================================================================
  {
    id: 'login-panels',
    name: 'Login panels',
    query: 'intitle:"login" "{{TARGET}}"',
    category: 'login_pages',
    severity: 'MEDIUM',
    description: 'Busca paneles de login relacionados con el objetivo',
    engines: ['google', 'bing', 'duckduckgo', 'yandex'],
  },
  {
    id: 'wordpress-login',
    name: 'WordPress login',
    query: 'inurl:wp-login.php "{{TARGET}}"',
    category: 'login_pages',
    severity: 'MEDIUM',
    description: 'Busca paginas de login de WordPress vinculadas al objetivo',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'admin-panels',
    name: 'Admin panels',
    query: 'inurl:admin OR inurl:administrator "{{TARGET}}"',
    category: 'login_pages',
    severity: 'HIGH',
    description: 'Paneles de administracion expuestos relacionados con el objetivo',
    engines: ['google', 'bing', 'duckduckgo', 'yandex'],
  },
  {
    id: 'phpmyadmin',
    name: 'phpMyAdmin',
    query: 'inurl:phpmyadmin "{{TARGET}}"',
    category: 'login_pages',
    severity: 'HIGH',
    description: 'Interfaces de phpMyAdmin accesibles publicamente',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'cpanel-login',
    name: 'cPanel login',
    query: 'intitle:"cPanel" "{{TARGET}}"',
    category: 'login_pages',
    severity: 'MEDIUM',
    description: 'Paneles de control cPanel relacionados con el dominio del objetivo',
    engines: ['google', 'bing'],
  },

  // ==========================================================================
  // EXPOSED FILES
  // ==========================================================================
  {
    id: 'exposed-sql',
    name: 'Exposed SQL files',
    query: 'filetype:sql "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'CRITICAL',
    description: 'Archivos SQL expuestos que pueden contener datos de bases de datos',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'password-files',
    name: 'Password files',
    query: 'filetype:txt "password" "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'CRITICAL',
    description: 'Archivos de texto que contienen contrasenas en texto claro',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'env-files',
    name: 'Environment files',
    query: 'filetype:env "{{TARGET}}" OR ".env" "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'CRITICAL',
    description: 'Archivos de configuracion de entorno con credenciales y secretos',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'config-files',
    name: 'Config files',
    query: 'filetype:conf OR filetype:config OR filetype:ini "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'HIGH',
    description: 'Archivos de configuracion expuestos con parametros sensibles',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'backup-files',
    name: 'Backup files',
    query: 'filetype:zip OR filetype:rar OR filetype:bak "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'HIGH',
    description: 'Archivos de backup comprimidos o copias de seguridad expuestas',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'exposed-git',
    name: 'Exposed .git',
    query: 'inurl:".git" "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'CRITICAL',
    description: 'Repositorios Git expuestos que pueden revelar codigo fuente',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'public-documents',
    name: 'Public documents',
    query: 'filetype:pdf OR filetype:doc OR filetype:xlsx "{{TARGET}}"',
    category: 'exposed_files',
    severity: 'LOW',
    description: 'Documentos publicos (PDF, Word, Excel) relacionados con el objetivo',
    engines: ['google', 'bing', 'duckduckgo', 'yandex'],
  },

  // ==========================================================================
  // DATABASES
  // ==========================================================================
  {
    id: 'db-dumps',
    name: 'Database dumps',
    query: '"INSERT INTO" OR "CREATE TABLE" "{{TARGET}}" filetype:sql',
    category: 'databases',
    severity: 'CRITICAL',
    description: 'Volcados de bases de datos expuestos con datos potencialmente sensibles',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'db-errors',
    name: 'Database errors',
    query: '"SQL syntax error" OR "mysql_fetch" OR "Warning: mysql" "{{TARGET}}"',
    category: 'databases',
    severity: 'MEDIUM',
    description: 'Paginas que muestran errores de base de datos, revelando estructura',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'exposed-db-files',
    name: 'Exposed DB files',
    query: 'filetype:db OR filetype:sqlite OR filetype:mdb "{{TARGET}}"',
    category: 'databases',
    severity: 'CRITICAL',
    description: 'Archivos de bases de datos directamente accesibles desde la web',
    engines: ['google', 'bing'],
  },
  {
    id: 'mongodb-exposed',
    name: 'MongoDB exposed',
    query: '"mongo" intitle:"mongo" "{{TARGET}}"',
    category: 'databases',
    severity: 'HIGH',
    description: 'Interfaces de MongoDB expuestas publicamente',
    engines: ['google', 'bing'],
  },

  // ==========================================================================
  // SENSITIVE INFO
  // ==========================================================================
  {
    id: 'credentials-default',
    name: 'Default credentials',
    query: '"default password" OR "contrasena por defecto" "{{TARGET}}"',
    category: 'sensitive_info',
    severity: 'CRITICAL',
    description: 'Paginas que listan credenciales por defecto para sistemas del objetivo',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'api-keys',
    name: 'API keys exposed',
    query: '"api_key" OR "apikey" OR "api-key" "{{TARGET}}" filetype:json OR filetype:env OR filetype:yml',
    category: 'sensitive_info',
    severity: 'CRITICAL',
    description: 'Claves API expuestas en archivos de configuracion',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'private-keys',
    name: 'Private keys',
    query: '"BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY" "{{TARGET}}"',
    category: 'sensitive_info',
    severity: 'CRITICAL',
    description: 'Claves privadas RSA o SSL expuestas publicamente',
    engines: ['google', 'bing'],
  },
  {
    id: 'email-exposure',
    name: 'Email exposure',
    query: '"@{{TARGET_DOMAIN}}" filetype:xlsx OR filetype:csv OR filetype:txt',
    category: 'sensitive_info',
    severity: 'HIGH',
    description: 'Listas de correos electronicos del dominio del objetivo en archivos',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'internal-docs',
    name: 'Internal documents',
    query: '"confidential" OR "interno" OR "privado" "{{TARGET}}" filetype:pdf OR filetype:doc',
    category: 'sensitive_info',
    severity: 'HIGH',
    description: 'Documentos internos o confidenciales del objetivo',
    engines: ['google', 'bing', 'duckduckgo'],
  },

  // ==========================================================================
  // SECURITY
  // ==========================================================================
  {
    id: 'error-logs',
    name: 'Error logs',
    query: '"error" OR "warning" OR "fatal" "{{TARGET}}" filetype:log',
    category: 'security',
    severity: 'MEDIUM',
    description: 'Archivos de registro de errores que pueden revelar rutas y configuraciones',
    engines: ['google', 'bing'],
  },
  {
    id: 'open-directories',
    name: 'Open directories',
    query: 'intitle:"index of" "{{TARGET}}"',
    category: 'security',
    severity: 'LOW',
    description: 'Directorios abiertos que permiten listar archivos del servidor',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'vulnerable-pages',
    name: 'Vulnerable pages',
    query: '"Warning" OR "Fatal error" OR "Stack Trace" "{{TARGET}}"',
    category: 'security',
    severity: 'MEDIUM',
    description: 'Paginas que muestran advertencias o errores que revelan informacion del sistema',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'server-headers',
    name: 'Server info disclosure',
    query: '"Server:" OR "X-Powered-By" "{{TARGET}}" inurl:info OR inurl:test',
    category: 'security',
    severity: 'MEDIUM',
    description: 'Paginas que revelan informacion del servidor y tecnologias utilizadas',
    engines: ['google', 'bing'],
  },
  {
    id: 'exposed-endpoints',
    name: 'Exposed endpoints',
    query: 'inurl:api OR inurl:swagger OR inurl:graphql "{{TARGET}}"',
    category: 'security',
    severity: 'HIGH',
    description: 'Endpoints de API expuestos (Swagger, GraphQL, REST)',
    engines: ['google', 'bing', 'duckduckgo'],
  },

  // ==========================================================================
  // GENERAL
  // ==========================================================================
  {
    id: 'social-mentions',
    name: 'Social mentions',
    query: '"{{TARGET}}" site:linkedin.com OR site:twitter.com OR site:facebook.com',
    category: 'general',
    severity: 'LOW',
    description: 'Menciones del objetivo en redes sociales profesionales y personales',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'news-mentions',
    name: 'News mentions',
    query: '"{{TARGET}}" site:news.google.com OR site:reuters.com OR site:bloomberg.com',
    category: 'general',
    severity: 'LOW',
    description: 'Menciones del objetivo en medios de comunicacion y agencias de noticias',
    engines: ['google', 'bing'],
  },
  {
    id: 'court-records',
    name: 'Court records',
    query: '"{{TARGET}}" site:judiciary OR site:court OR filetype:pdf "sentencia" OR "resolucion"',
    category: 'general',
    severity: 'MEDIUM',
    description: 'Registros judiciales y documentos legales relacionados con el objetivo',
    engines: ['google', 'bing'],
  },
  {
    id: 'domain-registration',
    name: 'Domain registration',
    query: '"{{TARGET}}" "WHOIS" OR "domain registration" OR "registrant"',
    category: 'general',
    severity: 'LOW',
    description: 'Informacion de registro de dominios vinculados al objetivo',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'data-broker',
    name: 'Data broker mentions',
    query: '"{{TARGET}}" "personal data" OR "datos personales" OR "leak" OR "breach"',
    category: 'general',
    severity: 'HIGH',
    description: 'Menciones del objetivo en contextos de filtraciones o brechas de datos',
    engines: ['google', 'bing', 'duckduckgo'],
  },
  {
    id: 'forum-mentions',
    name: 'Forum mentions',
    query: '"{{TARGET}}" site:reddit.com OR site:stackoverflow.com OR inurl:forum',
    category: 'general',
    severity: 'LOW',
    description: 'Menciones del objetivo en foros y comunidades en linea',
    engines: ['google', 'bing', 'duckduckgo'],
  },
];

/**
 * Get templates for a specific category
 */
export function getTemplatesByCategory(category: DorkCategory): DorkTemplate[] {
  return DORK_TEMPLATES.filter(t => t.category === category);
}

/**
 * Get templates by their IDs
 */
export function getTemplatesByIds(ids: string[]): DorkTemplate[] {
  return DORK_TEMPLATES.filter(t => ids.includes(t.id));
}

/**
 * Get all categories
 */
export function getAllCategories(): DorkCategory[] {
  return ['login_pages', 'exposed_files', 'databases', 'sensitive_info', 'security', 'general'];
}

/**
 * Get severity for a template
 */
export function getTemplateSeverity(templateId: string): SeverityLevel {
  const template = DORK_TEMPLATES.find(t => t.id === templateId);
  return template?.severity || 'LOW';
}
