// Web Forensic Analysis Engine — Lookyloo-style live capture (v5.1).
// Performs real-time crawling (gospider/siteone-crawler-style), JS secret extraction
// (SecretFinder-style), directory fuzzing (ffuf/dirb-style, incl. recursive fuzzing),
// artifact download & deep analysis (wget/curl-style): archive contents extraction
// (ZIP/TAR.GZ), SQL schema parsing, SQLite scanning, config parsing, directory-listing
// crawling, robots.txt/sitemap.xml seeding and API endpoint discovery from JS.
// Produces per-analysis container: /analisis_[dominio]_[timestamp]/
//   _fuzzing_tree/  (interactive directory structure)
//   _artifacts/phishing_kits/  (archives: .zip/.rar/.tar.gz/.7z)
//   _artifacts/databases/      (dumps: .sql/.db/.sqlite/.bak)
//   _metadata.json             (DNS, IP/ASN/geo, subdomains, attribution, risk)

import { gunzip } from 'node:zlib';
import { promisify } from 'node:util';

const gunzipAsync = promisify(gunzip);

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) NEXUS-Forensic/5.1';
const FETCH_TIMEOUT = 12000;
const MAX_CRAWL_DEPTH = 3;
const MAX_CRAWL_PAGES = 45;
const MAX_FUZZ_CONCURRENT = 20;
const FUZZ_TIMEOUT = 6000;
const MAX_RECURSIVE_DIRS = 8;
const MAX_RECURSIVE_DEPTH = 2;
const MAX_RECURSIVE_PROBES = 300;
const MAX_ARTIFACT_DOWNLOADS = 12;
const MAX_ARTIFACT_SIZE = 30 * 1024 * 1024;

export interface ResourceTreeNode {
  id: string;
  url: string;
  parentId: string | null;
  name: string;
  type: 'page' | 'script' | 'style' | 'image' | 'font' | 'document' | 'other' | 'redirect' | 'fuzz' | 'api';
  status: number;
  contentType: string | null;
  size: number | null;
  depth: number;
  redirectChain: string[];
  discoveredAt: string;
  children: ResourceTreeNode[];
  meta?: {
    secrets?: string[];
    forms?: number;
    links?: number;
    scripts?: number;
    title?: string;
    category?: string;
    sensitive?: boolean;
    endpoints?: string[];
  };
}

export interface ArtifactEntry {
  name: string;
  size: number;
  type: 'file' | 'dir';
}

export interface ArtifactTable {
  name: string;
  columns: string[];
  rows: number;
}

export interface ArtifactStructure {
  kind: 'archive' | 'sql' | 'sqlite' | 'config' | 'directory' | 'text' | 'binary' | 'unknown';
  entries?: ArtifactEntry[];
  tables?: ArtifactTable[];
  keys?: { key: string; value: string }[];
  emails?: string[];
  urls?: string[];
  note?: string;
  sensitive?: boolean;
}

export interface ForensicArtifact {
  id: string;
  url: string;
  localPath: string;
  category: 'phishing_kit' | 'database' | 'config' | 'backup' | 'other';
  kind: string;
  status: number;
  size: number;
  contentType: string | null;
  downloaded: boolean;
  hash?: string;
  structure?: ArtifactStructure;
}

export interface ForensicMetadata {
  domain: string;
  timestamp: string;
  name: string;
  id: string;
  risk: { level: string; score: number };
  ip: string | null;
  asn: string | null;
  isp: string | null;
  geo: { country: string; city: string; lat: number; lon: number } | null;
  dns: Record<string, any>;
  subdomains: string[];
  httpHeaders: any;
  ssl: any;
  attribution: {
    emails: string[];
    telegramIds: string[];
    trackingIds: string[];
    apiKeys: string[];
    comments: string[];
    toolSignatures: string[];
    links: string[];
  };
  resourceTree: ResourceTreeNode;
  fuzzingSummary: {
    totalProbed: number;
    byStatus: Record<number, number>;
    byCategory: Record<string, number>;
    exposed: number;
    archiveEntries?: number;
    dbTables?: number;
  };
  artifacts: ForensicArtifact[];
  verdict: string;
}

interface FuzzPathDef { path: string; category: 'kit' | 'admin' | 'db' | 'backup' | 'config' | 'common'; }

const FUZZ_PATHS: FuzzPathDef[] = [
  // admin panels / backends
  { path: 'admin', category: 'admin' }, { path: 'admin/', category: 'admin' },
  { path: 'administrator', category: 'admin' }, { path: 'administrator/index.php', category: 'admin' },
  { path: 'administrator/login.php', category: 'admin' }, { path: 'administrator2', category: 'admin' },
  { path: 'wp-admin', category: 'admin' }, { path: 'wp-login.php', category: 'admin' },
  { path: 'wp-content/uploads/', category: 'common' }, { path: 'xmlrpc.php', category: 'admin' },
  { path: 'panel', category: 'admin' }, { path: 'panel/', category: 'admin' },
  { path: 'paneladmin', category: 'admin' }, { path: 'cpanel', category: 'admin' },
  { path: 'phpmyadmin/', category: 'admin' }, { path: 'phpmyadmin2', category: 'admin' },
  { path: 'pma/', category: 'admin' }, { path: 'myadmin', category: 'admin' },
  { path: 'dbadmin', category: 'admin' }, { path: 'adminer.php', category: 'admin' },
  { path: 'login', category: 'admin' }, { path: 'login.php', category: 'admin' },
  { path: 'login.html', category: 'admin' }, { path: 'login.aspx', category: 'admin' },
  { path: 'signin', category: 'admin' }, { path: 'dashboard', category: 'admin' },
  { path: 'manager', category: 'admin' }, { path: 'management', category: 'admin' },
  { path: 'manage', category: 'admin' }, { path: 'cp', category: 'admin' },
  { path: 'controlpanel', category: 'admin' }, { path: 'backoffice', category: 'admin' },
  { path: 'console', category: 'admin' }, { path: 'portal', category: 'admin' },
  { path: 'staff', category: 'admin' }, { path: 'users', category: 'admin' },
  { path: 'user/login', category: 'admin' }, { path: 'member', category: 'admin' },
  { path: 'account', category: 'admin' }, { path: 'webadmin', category: 'admin' },
  { path: 'adm', category: 'admin' }, { path: 'administrador', category: 'admin' },
  { path: 'sistema', category: 'admin' }, { path: 'master', category: 'admin' },
  { path: 'drupal/', category: 'common' }, { path: 'sites/default/files/', category: 'common' },
  // backups
  { path: 'backup', category: 'backup' }, { path: 'backup/', category: 'backup' },
  { path: 'backups', category: 'backup' },
  { path: 'index.php~', category: 'backup' }, { path: 'index.php.bak', category: 'backup' },
  { path: 'index.html.bak', category: 'backup' }, { path: 'index.htm.bak', category: 'backup' },
  { path: 'index.old', category: 'backup' }, { path: 'index.save', category: 'backup' },
  { path: 'index.tar.gz', category: 'backup' }, { path: 'index.tar', category: 'backup' },
  { path: 'site.tar.gz', category: 'backup' }, { path: 'web.tar.gz', category: 'backup' },
  { path: 'html.zip', category: 'backup' }, { path: 'htdocs.zip', category: 'backup' },
  { path: 'htdocs.tar.gz', category: 'backup' }, { path: 'public_html.zip', category: 'backup' },
  { path: 'webroot.zip', category: 'backup' }, { path: '.backup', category: 'backup' },
  { path: '.swp', category: 'backup' },
  // databases / credential dumps
  { path: 'db', category: 'db' }, { path: 'database', category: 'db' },
  { path: 'dump.sql', category: 'db' }, { path: 'db.sql', category: 'db' },
  { path: 'database.sql', category: 'db' }, { path: 'backup.sql', category: 'db' },
  { path: 'data.sql', category: 'db' }, { path: '.sql', category: 'db' },
  { path: 'db.sql.gz', category: 'db' }, { path: 'db.sql.zip', category: 'db' },
  { path: 'dump.db', category: 'db' }, { path: 'backup.db', category: 'db' },
  { path: 'app.db', category: 'db' }, { path: 'users.db', category: 'db' },
  { path: 'database.db', category: 'db' }, { path: 'data.db', category: 'db' },
  { path: 'sqlite.db', category: 'db' }, { path: '.sqlite3', category: 'db' },
  { path: 'site.sql', category: 'db' }, { path: 'wp.sql', category: 'db' },
  { path: 'joomla.sql', category: 'db' }, { path: 'users.sql', category: 'db' },
  { path: 'mysqldump.sql', category: 'db' }, { path: 'db_backup.sql', category: 'db' },
  { path: 'backup_database.sql', category: 'db' }, { path: 'dump.txt', category: 'db' },
  { path: 'dump.gz', category: 'db' }, { path: 'dump.tar.gz', category: 'db' },
  { path: 'logins.txt', category: 'db' }, { path: 'credentials.txt', category: 'db' },
  { path: 'creds.txt', category: 'db' }, { path: 'users.txt', category: 'db' },
  { path: 'passwords.txt', category: 'db' }, { path: 'password.txt', category: 'db' },
  { path: 'emails.txt', category: 'db' }, { path: 'cc.txt', category: 'db' },
  { path: 'cards.txt', category: 'db' }, { path: 'cc.zip', category: 'db' },
  { path: 'victims.txt', category: 'db' }, { path: 'victim.txt', category: 'db' },
  { path: 'logs.txt', category: 'db' }, { path: 'logs.zip', category: 'db' },
  { path: 'tokens.txt', category: 'db' }, { path: 'sessions.txt', category: 'db' },
  { path: 'db.zip', category: 'db' }, { path: 'dump.zip', category: 'db' },
  { path: 'sql.zip', category: 'db' }, { path: 'data.zip', category: 'db' },
  // configs / secrets
  { path: 'config.php', category: 'config' }, { path: 'config.php.bak', category: 'config' },
  { path: 'config.old', category: 'config' }, { path: 'config.save', category: 'config' },
  { path: 'config.txt', category: 'config' }, { path: 'config.bak', category: 'config' },
  { path: 'settings.php', category: 'config' }, { path: 'settings.php.bak', category: 'config' },
  { path: 'settings.old', category: 'config' }, { path: 'wp-config.php', category: 'config' },
  { path: 'wp-config.php.bak', category: 'config' }, { path: 'wp-config.php.save', category: 'config' },
  { path: 'wp-config.php.txt', category: 'config' }, { path: 'wp-config.old', category: 'config' },
  { path: 'configuration.php', category: 'config' },
  { path: '.env', category: 'config' }, { path: '.env.backup', category: 'config' },
  { path: '.env.example', category: 'config' }, { path: '.env.local', category: 'config' },
  { path: '.env.production', category: 'config' },
  { path: 'config.inc.php', category: 'config' }, { path: 'config.yml', category: 'config' },
  { path: 'config.json', category: 'config' },
  { path: 'composer.json', category: 'config' }, { path: 'package.json', category: 'config' },
  { path: 'composer.lock', category: 'config' },
  { path: 'phpinfo.php', category: 'config' }, { path: 'info.php', category: 'config' },
  { path: 'test.php', category: 'config' }, { path: 'php.ini', category: 'config' },
  { path: '.htaccess', category: 'config' }, { path: '.htpasswd', category: 'config' },
  { path: '.user.ini', category: 'config' }, { path: '.DS_Store', category: 'config' },
  { path: '.ftpconfig', category: 'config' }, { path: '.gitignore', category: 'config' },
  { path: 'db.php', category: 'config' }, { path: 'dbconnect.php', category: 'config' },
  { path: 'connection.php', category: 'config' }, { path: 'connect.php', category: 'config' },
  { path: 'conn.php', category: 'config' }, { path: 'database.php', category: 'config' },
  { path: 'database.yml', category: 'config' }, { path: 'web.config', category: 'config' },
  { path: 'storage/logs/laravel.log', category: 'config' }, { path: 'storage/logs/', category: 'common' },
  { path: '.git/config', category: 'config' }, { path: '.git/HEAD', category: 'config' },
  { path: '.gitignore', category: 'config' },
  { path: 'server-status', category: 'config' }, { path: 'server-info', category: 'config' },
  { path: 'phpunit.xml', category: 'config' },
  // phishing kits (named archives)
  { path: 'main.zip', category: 'kit' }, { path: 'site.zip', category: 'kit' },
  { path: 'update.zip', category: 'kit' }, { path: 'theme.zip', category: 'kit' },
  { path: 'backup.zip', category: 'kit' }, { path: 'panel.zip', category: 'kit' },
  { path: 'panel.rar', category: 'kit' }, { path: 'kit.zip', category: 'kit' },
  { path: 'phishing.zip', category: 'kit' }, { path: 'template.zip', category: 'kit' },
  { path: 'assets.zip', category: 'kit' }, { path: 'files.zip', category: 'kit' },
  { path: 'source.zip', category: 'kit' }, { path: 'web.zip', category: 'kit' },
  { path: 'index.zip', category: 'kit' }, { path: 'home.zip', category: 'kit' },
  { path: 'www.zip', category: 'kit' }, { path: 'login.zip', category: 'kit' },
  { path: 'verify.zip', category: 'kit' }, { path: 'capture.zip', category: 'kit' },
  { path: 'inc.zip', category: 'kit' }, { path: 'template2.zip', category: 'kit' },
  { path: 'facebook.zip', category: 'kit' }, { path: 'whatsapp.zip', category: 'kit' },
  { path: 'whatsapp.rar', category: 'kit' }, { path: 'paypal.zip', category: 'kit' },
  { path: 'apple.zip', category: 'kit' }, { path: 'icloud.zip', category: 'kit' },
  { path: 'microsoft.zip', category: 'kit' }, { path: 'office365.zip', category: 'kit' },
  { path: 'outlook.zip', category: 'kit' }, { path: 'netflix.zip', category: 'kit' },
  { path: 'gmail.zip', category: 'kit' }, { path: 'google.zip', category: 'kit' },
  { path: 'amazon.zip', category: 'kit' }, { path: 'dhl.zip', category: 'kit' },
  { path: 'fedex.zip', category: 'kit' }, { path: 'usps.zip', category: 'kit' },
  { path: 'steam.zip', category: 'kit' }, { path: 'instagram.zip', category: 'kit' },
  { path: 'telegram.zip', category: 'kit' }, { path: 'banking.zip', category: 'kit' },
  { path: 'bank.zip', category: 'kit' },
  { path: '.rar', category: 'kit' }, { path: '.tar.gz', category: 'kit' },
  // common dirs / infra
  { path: 'vendor', category: 'common' }, { path: 'uploads/', category: 'common' },
  { path: 'images/', category: 'common' }, { path: 'css/', category: 'common' },
  { path: 'js/', category: 'common' }, { path: 'assets/', category: 'common' },
  { path: 'tmp/', category: 'common' }, { path: 'temp/', category: 'common' },
  { path: 'logs/', category: 'common' }, { path: 'log/', category: 'common' },
  { path: 'error_log', category: 'common' }, { path: 'debug.log', category: 'common' },
  { path: 'access.log', category: 'common' },
  { path: 'storage/', category: 'common' }, { path: 'joomla/', category: 'common' },
  { path: 'dev/', category: 'common' }, { path: 'src/', category: 'common' },
  { path: 'public/', category: 'common' }, { path: 'private/', category: 'common' },
  { path: 'protected/', category: 'common' }, { path: 'secret/', category: 'common' },
  { path: 'hidden/', category: 'common' }, { path: 'downloads/', category: 'common' },
  { path: 'docs/', category: 'common' }, { path: 'doc/', category: 'common' },
  { path: 'readme.md', category: 'common' }, { path: '.well-known/', category: 'common' },
  // VCS / dev artifacts
  { path: '.svn/', category: 'common' }, { path: '.svn/entries', category: 'config' },
  { path: '.svn/wc.db', category: 'config' }, { path: '.hg/', category: 'common' },
  { path: '.bzr/', category: 'common' }, { path: '.idea/', category: 'common' },
  { path: '.Trash/', category: 'common' }, { path: 'Thumbs.db', category: 'common' },
  { path: '.vscode/', category: 'common' },
  // app servers / CMS internals
  { path: 'tomcat/', category: 'common' }, { path: 'tomcat/manager/', category: 'admin' },
  { path: 'manager/html', category: 'admin' }, { path: 'jboss/', category: 'common' },
  { path: 'glassfish/', category: 'common' }, { path: 'weblogic/', category: 'common' },
  { path: 'wp-includes/', category: 'common' }, { path: 'wp-content/debug.log', category: 'config' },
  { path: 'wp-content/cache/', category: 'common' }, { path: 'wp-json/', category: 'common' },
  { path: 'admin-ajax.php', category: 'common' }, { path: 'wc-admin', category: 'admin' },
  { path: 'myaccount', category: 'admin' }, { path: 'my-account', category: 'admin' },
  { path: 'account/', category: 'common' }, { path: 'checkout/', category: 'common' },
  { path: 'cart/', category: 'common' },
  // installers / updaters
  { path: 'install.php', category: 'config' }, { path: 'installer/', category: 'common' },
  { path: 'install/install.php', category: 'config' }, { path: 'setup.php', category: 'config' },
  { path: 'setup/', category: 'common' }, { path: 'update.php', category: 'config' },
  { path: 'upgrade.php', category: 'config' }, { path: 'upgrade/', category: 'common' },
  { path: 'installer.php', category: 'config' },
  // phishing targets multi-idioma (es/pt/fr/de/it/en)
  { path: 'verificar.php', category: 'kit' }, { path: 'confirmar.php', category: 'kit' },
  { path: 'tarjeta.php', category: 'kit' }, { path: 'pago.php', category: 'kit' },
  { path: 'banca.php', category: 'kit' }, { path: 'banco.php', category: 'kit' },
  { path: 'cuenta.php', category: 'kit' }, { path: 'resultado.php', category: 'kit' },
  { path: 'acceso.php', category: 'kit' }, { path: 'ingreso.php', category: 'kit' },
  { path: 'cliente.php', category: 'kit' }, { path: 'victimas/', category: 'common' },
  { path: 'datos.txt', category: 'db' }, { path: 'informe.txt', category: 'db' },
  { path: 'cartao.php', category: 'kit' }, { path: 'pagamento.php', category: 'kit' },
  { path: 'conta.php', category: 'kit' }, { path: 'verification.php', category: 'kit' },
  { path: 'carte.php', category: 'kit' }, { path: 'paiement.php', category: 'kit' },
  { path: 'compte.php', category: 'kit' }, { path: 'banque.php', category: 'kit' },
  { path: 'verifizierung.php', category: 'kit' }, { path: 'zahlung.php', category: 'kit' },
  { path: 'konto.php', category: 'kit' }, { path: 'bank.php', category: 'kit' },
  { path: 'verifica.php', category: 'kit' }, { path: 'carta.php', category: 'kit' },
  { path: 'conto.php', category: 'kit' }, { path: 'creditcard.php', category: 'kit' },
  { path: 'carding.php', category: 'kit' }, { path: 'carder.php', category: 'kit' },
  { path: 'swipe.php', category: 'kit' }, { path: 'otp.php', category: 'kit' },
  { path: 'otp/', category: 'common' }, { path: 'mfa.php', category: 'kit' },
  { path: '2fa.php', category: 'kit' }, { path: 'billing/', category: 'common' },
  { path: 'invoice/', category: 'common' }, { path: 'receipt/', category: 'common' },
  // kit archives multi-idioma
  { path: 'banco.zip', category: 'kit' }, { path: 'banca.zip', category: 'kit' },
  { path: 'cartao.zip', category: 'kit' }, { path: 'carte.zip', category: 'kit' },
  { path: 'compte.zip', category: 'kit' }, { path: 'konto.zip', category: 'kit' },
  { path: 'conto.zip', category: 'kit' }, { path: 'paiement.zip', category: 'kit' },
  { path: 'pagamento.zip', category: 'kit' }, { path: 'zahlung.zip', category: 'kit' },
  { path: 'cards.zip', category: 'kit' }, { path: 'otp.zip', category: 'kit' },
  { path: 'mfa.zip', category: 'kit' }, { path: 'billing.zip', category: 'kit' },
  { path: 'receipt.zip', category: 'kit' }, { path: 'datos.zip', category: 'kit' },
  { path: 'alldata.zip', category: 'kit' }, { path: 'cart.zip', category: 'kit' },
  // backup variants de páginas clave
  { path: '.html.bak', category: 'backup' }, { path: '.htm.old', category: 'backup' },
  { path: 'index.html.old', category: 'backup' }, { path: 'index.htm.old', category: 'backup' },
  { path: 'login.php.bak', category: 'backup' }, { path: 'login.php.old', category: 'backup' },
  { path: 'login.php.save', category: 'backup' }, { path: 'login.php.txt', category: 'backup' },
  { path: 'config.php.save', category: 'config' }, { path: 'config.php.old', category: 'config' },
  { path: 'config.php~', category: 'backup' }, { path: '.env.old', category: 'config' },
  { path: '.env.save', category: 'config' }, { path: 'wp-config.php~', category: 'backup' },
  { path: 'phpinfo.php.bak', category: 'backup' }, { path: 'test.php.bak', category: 'backup' },
  // logs / acceso
  { path: 'access_log', category: 'common' }, { path: 'apache_access.log', category: 'common' },
  { path: 'nginx_access.log', category: 'common' }, { path: 'errorlog', category: 'common' },
  { path: 'php_errors.log', category: 'common' }, { path: 'auth.log', category: 'common' },
  { path: 'syslog', category: 'common' }, { path: 'bot.log', category: 'common' },
  { path: 'crawler.log', category: 'common' },
  // tokens / sesiones robadas
  { path: 'token.txt', category: 'db' }, { path: 'tokens/', category: 'common' },
  { path: 'session/', category: 'common' }, { path: 'sessions/', category: 'common' },
  { path: 'cookies.txt', category: 'db' }, { path: 'cookies/', category: 'common' },
  { path: 'history.txt', category: 'db' },
  // paneles con variantes
  { path: 'admin-login', category: 'admin' }, { path: 'admin_login', category: 'admin' },
  { path: 'login-admin', category: 'admin' }, { path: 'panel-login', category: 'admin' },
  { path: 'loginpanel', category: 'admin' }, { path: 'administrator/', category: 'admin' },
];

// Paths re-probed recursively inside discovered directories (ffuf -recursion / dirb -r style)
const RECURSIVE_PATHS: FuzzPathDef[] = [
  { path: 'login.php', category: 'admin' }, { path: 'login.html', category: 'admin' },
  { path: 'index.php', category: 'kit' }, { path: 'index2.php', category: 'kit' },
  { path: 'home.php', category: 'kit' },
  { path: 'admin.php', category: 'admin' }, { path: 'panel.php', category: 'admin' },
  { path: 'verify.php', category: 'kit' }, { path: 'check.php', category: 'kit' },
  { path: 'capture.php', category: 'kit' }, { path: 'get.php', category: 'kit' },
  { path: 'post.php', category: 'kit' }, { path: 'send.php', category: 'kit' },
  { path: 'load.php', category: 'kit' }, { path: 'stealer.php', category: 'kit' },
  { path: 'result.php', category: 'kit' }, { path: 'results.php', category: 'kit' },
  { path: 'config.php', category: 'config' }, { path: 'config.inc.php', category: 'config' },
  { path: 'config.php.bak', category: 'config' }, { path: 'config.txt', category: 'config' },
  { path: 'settings.php', category: 'config' }, { path: 'settings.php.bak', category: 'config' },
  { path: 'db.php', category: 'config' }, { path: 'conn.php', category: 'config' },
  { path: 'database.php', category: 'config' }, { path: '.env', category: 'config' },
  { path: '.htaccess', category: 'config' },
  { path: 'admin/', category: 'admin' }, { path: 'config/', category: 'common' },
  { path: 'inc/', category: 'common' }, { path: 'include/', category: 'common' },
  { path: 'includes/', category: 'common' }, { path: 'lib/', category: 'common' },
  { path: 'data/', category: 'common' }, { path: 'files/', category: 'common' },
  { path: 'temp/', category: 'common' }, { path: 'logs/', category: 'common' },
  { path: 'src/', category: 'common' }, { path: 'private/', category: 'common' },
  { path: 'log.txt', category: 'db' }, { path: 'data.txt', category: 'db' },
  { path: 'logins.txt', category: 'db' }, { path: 'credentials.txt', category: 'db' },
  { path: 'creds.txt', category: 'db' }, { path: 'users.txt', category: 'db' },
  { path: 'emails.txt', category: 'db' }, { path: 'victim.txt', category: 'db' },
  { path: 'dump.sql', category: 'db' }, { path: 'db.sql', category: 'db' },
  { path: 'database.sql', category: 'db' }, { path: 'db.sql.gz', category: 'db' },
  { path: 'db.zip', category: 'db' }, { path: 'users.db', category: 'db' },
  { path: 'app.db', category: 'db' }, { path: 'logins.zip', category: 'db' },
  { path: 'main.zip', category: 'kit' }, { path: 'site.zip', category: 'kit' },
  { path: 'backup.zip', category: 'kit' }, { path: 'kit.zip', category: 'kit' },
  { path: 'index.zip', category: 'kit' }, { path: 'login.zip', category: 'kit' },
  { path: 'index.php.bak', category: 'backup' },
];

const KIT_EXT = /\.(zip|rar|tar\.gz|tgz|7z)$/i;
const DB_EXT = /\.(sql|db|sqlite|sqlite3|bak|dump|mysql|mdb|accdb|txt)$/i;
const CONFIG_EXT = /\.(env|config|conf|ini|yaml|yml|json|php|inc)$/i;
const BACKUP_EXT = /\.(bak|backup|old|orig|save|swp|~)$/i;

const SECRET_PATTERNS: [RegExp, string][] = [
  [/AIza[0-9A-Za-z\-_]{35}/g, 'Google API Key'],
  [/sk_(?:live|test)_[0-9a-zA-Z]{20,40}/g, 'Stripe Secret Key'],
  [/pk_(?:live|test)_[0-9a-zA-Z]{20,40}/g, 'Stripe Publishable Key'],
  [/AKIA[0-9A-Z]{16}/g, 'AWS Access Key ID'],
  [/[0-9a-zA-Z/+=]{40}/g, 'AWS Secret Access Key (base64)'],
  [/ghp_[0-9A-Za-z]{36,40}/g, 'GitHub Personal Access Token'],
  [/gho_[0-9A-Za-z]{36,40}/g, 'GitHub OAuth Token'],
  [/ghu_[0-9A-Za-z]{36,40}/g, 'GitHub User Token'],
  [/ghs_[0-9A-Za-z]{36,40}/g, 'GitHub Server Token'],
  [/ghr_[0-9A-Za-z]{36,40}/g, 'GitHub Refresh Token'],
  [/xox[baprs]-[0-9A-Za-z\-]{10,60}/g, 'Slack Token'],
  [/xoxp-[0-9A-Za-z\-]{10,60}/g, 'Slack User Token'],
  [/xoxb-[0-9A-Za-z\-]{10,60}/g, 'Slack Bot Token'],
  [/xapp-[0-9A-Za-z\-]{10,60}/g, 'Slack App Token'],
  [/sk_live_[0-9a-zA-Z]{20,40}/g, 'Stripe Live Secret'],
  [/rk_live_[0-9a-zA-Z]{20,40}/g, 'Stripe Restricted Key'],
  [/rk_test_[0-9a-zA-Z]{20,40}/g, 'Stripe Test Restricted Key'],
  [/sq0atp-[0-9A-Za-z\-_]{22}/g, 'Square Access Token'],
  [/sq0csp-[0-9A-Za-z\-_]{22}/g, 'Square OAuth Secret'],
  [/access_token\$[0-9A-Za-z]{20,}/g, 'Facebook Access Token'],
  [/EAACEdEose0cBA[0-9A-Za-z]+/g, 'Facebook App Token'],
  [/Bearer\s+[A-Za-z0-9\-\._~+/]+=*/g, 'Bearer Token'],
  [/Authorization:\s*Bearer\s+[A-Za-z0-9\-\._~+/]+=*/gi, 'Auth Header'],
  [/api[_-]?key["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'Generic API Key'],
  [/secret[_-]?key["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'Secret Key'],
  [/private[_-]?key["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'Private Key'],
  [/jwt[_-]?secret["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi, 'JWT Secret'],
];

function classifyPath(path: string, category: string): 'phishing_kit' | 'database' | 'config' | 'backup' | 'other' {
  if (KIT_EXT.test(path)) return 'phishing_kit';
  if (DB_EXT.test(path)) return 'database';
  if (CONFIG_EXT.test(path) || category === 'config') return 'config';
  if (BACKUP_EXT.test(path) || category === 'backup') return 'backup';
  return 'other';
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = FETCH_TIMEOUT): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal, headers: { 'User-Agent': UA, ...options.headers } });
  } finally {
    clearTimeout(id);
  }
}

function extractLinks(html: string, baseUrl: string): string[] {
  const links: string[] = [];
  const hrefRegex = /href=["']([^"']+)["']/gi;
  const srcRegex = /src=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(html)) !== null) links.push(match[1]);
  while ((match = srcRegex.exec(html)) !== null) links.push(match[1]);
  return [...new Set(links.map(l => {
    try { return new URL(l, baseUrl).href; } catch { return l; }
  }))];
}

function extractScripts(html: string, baseUrl: string): string[] {
  const scripts: string[] = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["']/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    try { scripts.push(new URL(match[1], baseUrl).href); } catch {}
  }
  return [...new Set(scripts)];
}

function extractForms(html: string): number {
  return (html.match(/<form/gi) || []).length;
}

function findSecrets(content: string): string[] {
  const found: string[] = [];
  for (const [re, label] of SECRET_PATTERNS) {
    const matches = content.match(re) || [];
    for (const m of matches.slice(0, 3)) {
      found.push(`${label}: ${m.length > 60 ? m.slice(0, 60) + '...' : m}`);
    }
  }
  return [...new Set(found)].slice(0, 15);
}

// API endpoint discovery from JS/HTML (gospider/siteone-crawler style)
function extractEndpoints(content: string, baseUrl: string): string[] {
  const out = new Set<string>();
  const patterns = [
    /["'`](\/(?:api|v\d|ajax|rest|wp-json|graphql|admin|auth|login|verify|get|send|load)[^"'`\s?#]*?)["'`]/gi,
    /(?:fetch|axios\.(?:get|post|put|patch)|XMLHttpRequest[^)]*?open\([^)]*?)\s*\(\s*["'`]([^"'`\s]+)["'`]/gi,
    /url\s*[:=]\s*["'`]([^"'`\s]+)["'`]/gi,
    /action=["']([^"']+)["']/gi,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) {
      const raw = m[1];
      if (!raw || raw.startsWith('#') || raw.startsWith('data:') || raw.startsWith('mailto:')) continue;
      try {
        const abs = new URL(raw, baseUrl).href;
        if (new URL(abs).hostname === new URL(baseUrl).hostname) out.add(abs);
      } catch {}
    }
  }
  return [...out].slice(0, 25);
}

function getResourceType(contentType: string | null, url: string): ResourceTreeNode['type'] {
  if (!contentType) {
    const ext = url.split('?')[0].split('.').pop()?.toLowerCase() || '';
    if (['js', 'mjs', 'ts'].includes(ext)) return 'script';
    if (['css', 'scss', 'less'].includes(ext)) return 'style';
    if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'avif'].includes(ext)) return 'image';
    if (['woff', 'woff2', 'ttf', 'eot', 'otf'].includes(ext)) return 'font';
    if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return 'document';
    return 'other';
  }
  if (contentType.startsWith('text/html')) return 'page';
  if (contentType.startsWith('application/javascript') || contentType.startsWith('text/javascript')) return 'script';
  if (contentType.startsWith('text/css')) return 'style';
  if (contentType.startsWith('image/')) return 'image';
  if (contentType.startsWith('font/') || contentType.includes('woff')) return 'font';
  if (contentType.startsWith('application/pdf') || contentType.includes('document')) return 'document';
  return 'other';
}

async function crawlPage(url: string, visited: Set<string>, tree: ResourceTreeNode[], parentId: string | null, depth: number): Promise<ResourceTreeNode[]> {
  if (depth > MAX_CRAWL_DEPTH || visited.size >= MAX_CRAWL_PAGES || visited.has(url)) return [];
  visited.add(url);

  const nodeId = Buffer.from(url).toString('base64url').slice(0, 16);
  let status = 0, contentType: string | null = null, size = 0;
  let html = '', redirectChain: string[] = [];
  let secrets: string[] = [], forms = 0, links = 0, scripts = 0, title = '';
  const endpoints: string[] = [];

  try {
    const res = await fetchWithTimeout(url, { redirect: 'manual' });
    status = res.status;
    contentType = res.headers.get('content-type');
    const cl = res.headers.get('content-length');
    size = cl ? parseInt(cl) : 0;

    // Follow redirects manually to build chain
    let currentRes = res;
    let currentUrl = url;
    while (currentRes.status >= 300 && currentRes.status < 400 && currentRes.headers.get('location')) {
      const loc = currentRes.headers.get('location')!;
      redirectChain.push(loc);
      try {
        currentRes = await fetchWithTimeout(loc, { redirect: 'manual' });
        currentUrl = loc;
      } catch { break; }
    }
    status = currentRes.status;
    contentType = currentRes.headers.get('content-type') || contentType;

    if (contentType?.startsWith('text/html')) {
      html = await currentRes.text();
      title = (html.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1] || '';
      links = extractLinks(html, currentUrl).length;
      const scriptUrls = extractScripts(html, currentUrl);
      scripts = scriptUrls.length;
      forms = extractForms(html);
      secrets = findSecrets(html);
      endpoints.push(...extractEndpoints(html, currentUrl));

      // Recursively crawl linked pages (same domain only)
      const childLinks = extractLinks(html, currentUrl).filter(l => {
        try { return new URL(l).hostname === new URL(url).hostname; } catch { return false; }
      });
      const seedSet = new Set(childLinks.slice(0, 6));
      for (const ep of endpoints) seedSet.add(ep);
      for (const link of [...seedSet].slice(0, 8)) {
        if (!visited.has(link) && !link.includes('logout') && !link.includes('javascript:')) {
          const children = await crawlPage(link, visited, tree, nodeId, depth + 1);
          tree.push(...children);
        }
      }

      // Analyze JS files for secrets + endpoints (SecretFinder-style)
      for (const scriptUrl of scriptUrls.slice(0, 6)) {
        try {
          const sRes = await fetchWithTimeout(scriptUrl, { redirect: 'follow' });
          if (sRes.ok) {
            const jsContent = await sRes.text();
            const jsSecrets = findSecrets(jsContent);
            const jsEndpoints = extractEndpoints(jsContent, scriptUrl);
            if (jsSecrets.length > 0 || jsEndpoints.length > 0) {
              secrets.push(...jsSecrets.map(s => `[JS] ${s}`));
              const scriptNode: ResourceTreeNode = {
                id: Buffer.from(scriptUrl).toString('base64url').slice(0, 16),
                url: scriptUrl,
                parentId: nodeId,
                name: scriptUrl.split('/').pop() || 'script.js',
                type: 'script',
                status: sRes.status,
                contentType: sRes.headers.get('content-type'),
                size: parseInt(sRes.headers.get('content-length') || '0'),
                depth: depth + 1,
                redirectChain: [],
                discoveredAt: new Date().toISOString(),
                children: [],
                meta: { secrets: jsSecrets, endpoints: jsEndpoints }
              };
              tree.push(scriptNode);
              // Feed discovered API endpoints into the crawl
              for (const ep of jsEndpoints.slice(0, 4)) {
                if (!visited.has(ep)) {
                  const epChildren = await crawlPage(ep, visited, tree, scriptNode.id, depth + 2);
                  tree.push(...epChildren);
                }
              }
            }
          }
        } catch {}
      }
    } else if (contentType?.includes('json') || contentType?.includes('javascript')) {
      try {
        const body = await currentRes.text();
        const bodySecrets = findSecrets(body);
        if (bodySecrets.length > 0) secrets.push(...bodySecrets);
      } catch {}
    }
  } catch (e) {
    status = 0;
  }

  const node: ResourceTreeNode = {
    id: nodeId,
    url: url,
    parentId,
    name: url.split('/').pop() || url,
    type: getResourceType(contentType, url),
    status,
    contentType,
    size,
    depth,
    redirectChain,
    discoveredAt: new Date().toISOString(),
    children: [],
    meta: { secrets: secrets.slice(0, 10), forms, links, scripts, title, endpoints: endpoints.slice(0, 10) }
  };
  tree.push(node);
  return tree;
}

// Parse ZIP central directory (no external deps) → internal file listing
function parseZip(buf: Buffer): ArtifactStructure {
  const entries: ArtifactEntry[] = [];
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 131072); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return { kind: 'archive', entries: [], note: 'ZIP detected but central directory not found' };
  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  let off = cdOffset;
  for (let i = 0; i < Math.min(count, 500); i++) {
    if (off + 46 > buf.length) break;
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const name = buf.subarray(off + 46, off + 46 + nameLen).toString('utf8');
    entries.push({ name, size: compSize, type: name.endsWith('/') ? 'dir' : 'file' });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return { kind: 'archive', entries: entries.slice(0, 300), note: `ZIP archive (${count} entries)` };
}

// Parse TAR (ustar) after gunzip → internal file listing
function parseTar(buf: Buffer): ArtifactStructure {
  const entries: ArtifactEntry[] = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const name = buf.subarray(off, off + 100).toString('utf8').replace(/\0.*$/, '');
    if (!name) break;
    const sizeStr = buf.subarray(off + 124, off + 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const type = String.fromCharCode(buf[off + 156] || 48);
    if (type === 'x' || type === 'g') { off += 512; continue; }
    entries.push({ name, size, type: type === '5' || name.endsWith('/') ? 'dir' : 'file' });
    off += 512 + Math.ceil(size / 512) * 512;
    if (entries.length > 500) break;
  }
  return { kind: 'archive', entries: entries.slice(0, 300), note: `TAR archive (${entries.length} entries)` };
}

// Parse SQL dump → tables, columns, row counts, emails
function parseSqlDump(text: string): ArtifactStructure {
  const tables: ArtifactTable[] = [];
  const emailSet = new Set<string>();
  for (const e of (text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])) emailSet.add(e.toLowerCase());
  const tableRe = /CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[`"]?([\w$-]+)[`"]?\s*\(/gi;
  let m;
  const colRe = /[`"]?([\w$-]{1,64})[`"]?\s+(?:INT|VARCHAR|TEXT|CHAR|BLOB|TIMESTAMP|DATETIME|DATE|TIME|BOOL|BOOLEAN|FLOAT|DOUBLE|DECIMAL|ENUM|JSON|LONGTEXT|MEDIUMTEXT|TINYTEXT|TINYINT|SMALLINT|MEDIUMINT|BIGINT|INTEGER|SERIAL|UUID|BINARY|VARBINARY|MEDIUMBLOB|LONGBLOB)\b/gi;
  while ((m = tableRe.exec(text)) && tables.length < 60) {
    const tname = m[1];
    const start = text.indexOf('(', m.index);
    let depth = 0, i = start;
    for (; i < text.length; i++) {
      const c = text[i];
      if (c === '(') depth++;
      else if (c === ')') { depth--; if (depth === 0) break; }
    }
    const block = text.slice(start + 1, i);
    const cols: string[] = [];
    let cm;
    const esc = tname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    while ((cm = colRe.exec(block)) && cols.length < 40) cols.push(cm[1]);
    const rows = (text.match(new RegExp(`INSERT INTO\\s+[\\\`"]?${esc}[\\\`"]?`, 'gi')) || []).length;
    tables.push({ name: tname, columns: cols, rows });
  }
  const sensitive = tables.some(t => /user|login|pass|cc|card|log|victim|account|session|token|email/i.test(t.name));
  return { kind: 'sql', tables: tables.slice(0, 60), emails: [...emailSet].slice(0, 25), note: `SQL dump — ${tables.length} table(s), ${emailSet.size} email(s)`, sensitive };
}

// SQLite binary scan
function parseSqlite(buf: Buffer): ArtifactStructure {
  const tables: ArtifactTable[] = [];
  const text = buf.toString('latin1');
  const re = /CREATE TABLE\s+[`"]?([\w$-]+)[`"]?\s*\(/gi;
  let m;
  while ((m = re.exec(text)) && tables.length < 60) {
    tables.push({ name: m[1], columns: [], rows: 0 });
  }
  for (const t of tables) {
    const esc = t.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    t.rows = (text.match(new RegExp(esc + '\\x00', 'g')) || []).length || 0;
  }
  const sensitive = tables.some(t => /user|login|pass|card|log|victim|account|session|token/i.test(t.name));
  return { kind: 'sqlite', tables: tables.slice(0, 60), note: `SQLite database — ${tables.length} table(s)`, sensitive };
}

// Config key/value parsing (.env/.ini/.php/.json style)
function parseConfig(text: string): ArtifactStructure {
  const keys: { key: string; value: string }[] = [];
  const emailSet = new Set<string>();
  for (const e of (text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])) emailSet.add(e.toLowerCase());
  const lines = text.split(/\r?\n/).slice(0, 400);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith(';') || trimmed.startsWith('/*')) continue;
    const eq = trimmed.indexOf('=');
    if (eq > 0) {
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
      if (key.length > 1 && key.length < 40 && value.length > 0 && value.length < 200) {
        if (/(pass|secret|key|token|api|auth|pwd|db_host|db_user)/i.test(key)) {
          if (value.length > 4) value = value.slice(0, 3) + '***';
        }
        keys.push({ key, value });
      }
    } else if (/^\$/.test(trimmed)) {
      const m2 = trimmed.match(/^\$(\w+)\s*=\s*(.+)$/);
      if (m2 && m2[2].length < 200) {
        let value = m2[2];
        if (/(pass|secret|key|token|api|auth|pwd)/i.test(m2[1])) value = value.slice(0, 3) + '***';
        keys.push({ key: m2[1], value });
      }
    }
  }
  const sensitive = keys.some(k => /(pass|secret|key|token|api|auth|pwd)/i.test(k.key));
  return { kind: 'config', keys: keys.slice(0, 40), emails: [...emailSet].slice(0, 15), note: `Config file — ${keys.length} key(s) parsed`, sensitive };
}

// Apache/nginx directory listing parse (wget -r style)
function parseDirListingHtml(html: string, baseUrl: string): ArtifactEntry[] {
  const entries: ArtifactEntry[] = [];
  const hrefRe = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let m;
  while ((m = hrefRe.exec(html)) && entries.length < 120) {
    let href = m[1];
    const text = m[2].replace(/<[^>]+>/g, '').trim();
    if (!href || href.startsWith('?') || href.startsWith('#')) continue;
    if (href.startsWith('mailto:') || href.startsWith('javascript:')) continue;
    if (href.includes('..')) continue;
    let isDir = href.endsWith('/');
    if (href.startsWith('http')) {
      try {
        const u = new URL(href);
        if (u.hostname !== new URL(baseUrl).hostname) continue;
        href = u.pathname;
        isDir = href.endsWith('/');
      } catch { continue; }
    }
    const display = text || href;
    entries.push({ name: display, size: 0, type: isDir ? 'dir' : 'file' });
  }
  return entries;
}

// Directory listing crawl (wget -r style): fetch listed files, add to tree/artifacts
async function crawlDirListing(url: string, depth: number, visited: Set<string>, tree: ResourceTreeNode[], artifacts: ForensicArtifact[], parentId: string | null): Promise<void> {
  if (depth > 1 || visited.has(url)) return;
  visited.add(url);
  try {
    const res = await fetchWithTimeout(url, { redirect: 'follow' }, FUZZ_TIMEOUT);
    if (!res.ok) return;
    const html = await res.text();
    if (!/index|Index|directory/i.test(html.slice(0, 2000))) return;
    const entries = parseDirListingHtml(html, url);
    if (entries.length === 0) return;
    for (const e of entries.slice(0, 40)) {
      const fileUrl = url.endsWith('/') ? url + encodeURIComponent(e.name) : url + '/' + encodeURIComponent(e.name);
      if (visited.has(fileUrl)) continue;
      visited.add(fileUrl);
      if (e.type === 'dir') {
        await crawlDirListing(fileUrl, depth + 1, visited, tree, artifacts, parentId);
        continue;
      }
      const cat = classifyPath(fileUrl, 'common');
      if (cat !== 'other') {
        artifacts.push({
          id: Buffer.from(fileUrl).toString('base64url').slice(0, 16),
          url: fileUrl,
          localPath: `_artifacts/${cat}/${fileUrl.split('/').pop()}`,
          category: cat,
          kind: 'listing',
          status: 200,
          size: e.size,
          contentType: null,
          downloaded: false,
        });
      }
      tree.push({
        id: Buffer.from(fileUrl).toString('base64url').slice(0, 16),
        url: fileUrl,
        parentId,
        name: e.name,
        type: 'fuzz',
        status: 200,
        contentType: null,
        size: e.size || null,
        depth,
        redirectChain: [],
        discoveredAt: new Date().toISOString(),
        children: [],
        meta: { category: 'common', sensitive: cat !== 'other', title: `[dir listing] ${e.type}` },
      });
    }
  } catch {}
}

async function fuzzDirectories(baseUrl: string, discoveredDirs: string[] = []): Promise<{ tree: ResourceTreeNode[]; artifacts: ForensicArtifact[] }> {
  const fuzzTree: ResourceTreeNode[] = [];
  const artifacts: ForensicArtifact[] = [];
  const probeHistory = new Set<string>();
  let dirCount = 0;
  let probeCount = 0;

  const probe = async (p: FuzzPathDef, prefix: string, depth: number, parentId: string | null): Promise<void> => {
    const url = `${baseUrl}/${prefix}${p.path}`;
    if (probeHistory.has(url)) return;
    if (probeCount >= FUZZ_PATHS.length + MAX_RECURSIVE_PROBES) return;
    probeHistory.add(url);
    probeCount++;
    try {
      const res = await fetchWithTimeout(url, { method: 'GET', redirect: 'manual' }, FUZZ_TIMEOUT);
      const status = res.status;
      const size = parseInt(res.headers.get('content-length') || '0');
      const contentType = res.headers.get('content-type');
      const category = classifyPath(p.path, p.category);
      const sensitive = p.category !== 'common';

      const entry: ResourceTreeNode = {
        id: Buffer.from(url).toString('base64url').slice(0, 16),
        url,
        parentId,
        name: p.path,
        type: 'fuzz',
        status,
        contentType,
        size,
        depth,
        redirectChain: [],
        discoveredAt: new Date().toISOString(),
        children: [],
        meta: { category: p.category, sensitive }
      };
      fuzzTree.push(entry);

      const exposed = (status === 200 || status === 403);
      if (exposed) {
        if (category !== 'other') {
          artifacts.push({
            id: Buffer.from(url).toString('base64url').slice(0, 16),
            url,
            localPath: `_artifacts/${category}/${(prefix + p.path).replace(/\//g, '_')}`,
            category,
            kind: p.category,
            status,
            size,
            contentType,
            downloaded: false,
          });
        }

        // Directory-listing detection: fetch body of sensitive 200s
        if (status === 200 && sensitive && contentType?.includes('html')) {
          try {
            const body = await res.clone().text();
            if (/Index of|Directory listing|Parent Directory/i.test(body.slice(0, 3000))) {
              entry.meta!.title = '[dir listing]';
              await crawlDirListing(url, 0, probeHistory, fuzzTree, artifacts, entry.id);
            }
          } catch {}
        }

        // Recursive fuzzing inside discovered directories (ffuf -recursion style)
        const dirish = p.path.endsWith('/') || p.category === 'admin' || p.category === 'common';
        if (dirish && status === 200 && depth < MAX_RECURSIVE_DEPTH && dirCount < MAX_RECURSIVE_DIRS) {
          dirCount++;
          const childPrefix = prefix + p.path + (p.path.endsWith('/') ? '' : '/');
          const batch = RECURSIVE_PATHS.slice(0, 50);
          for (let i = 0; i < batch.length; i += MAX_FUZZ_CONCURRENT) {
            await Promise.allSettled(
              batch.slice(i, i + MAX_FUZZ_CONCURRENT).map(sub => probe(sub, childPrefix, depth + 1, entry.id))
            );
          }
        }
      }
    } catch {}
  };

  // Main fuzz pass
  for (let i = 0; i < FUZZ_PATHS.length; i += MAX_FUZZ_CONCURRENT) {
    await Promise.allSettled(FUZZ_PATHS.slice(i, i + MAX_FUZZ_CONCURRENT).map(p => probe(p, '', 0, null)));
  }

  // Fuzz directories discovered during crawl (links/forms/JS endpoints ending in /)
  for (const dir of discoveredDirs.slice(0, 4)) {
    if (probeCount >= FUZZ_PATHS.length + MAX_RECURSIVE_PROBES) break;
    const rel = dir.replace(baseUrl + '/', '').replace(/\/$/, '');
    const dirNode: ResourceTreeNode = {
      id: Buffer.from(dir).toString('base64url').slice(0, 16),
      url: dir,
      parentId: null,
      name: rel + '/',
      type: 'fuzz',
      status: 200,
      contentType: 'text/html',
      size: 0,
      depth: 0,
      redirectChain: [],
      discoveredAt: new Date().toISOString(),
      children: [],
      meta: { category: 'common', sensitive: true, title: '[crawl dir]' },
    };
    fuzzTree.push(dirNode);
    const batch = RECURSIVE_PATHS.slice(0, 50);
    for (let i = 0; i < batch.length; i += MAX_FUZZ_CONCURRENT) {
      await Promise.allSettled(
        batch.slice(i, i + MAX_FUZZ_CONCURRENT).map(sub => probe(sub, rel.endsWith('/') ? rel : rel + '/', 1, dirNode.id))
      );
    }
  }

  // Root-level directory listing (wget -r style)
  try {
    const res = await fetchWithTimeout(baseUrl + '/', { redirect: 'follow' }, FUZZ_TIMEOUT);
    if (res.ok && res.headers.get('content-type')?.includes('html')) {
      const body = await res.text();
      if (/Index of|Directory listing|Parent Directory/i.test(body.slice(0, 3000))) {
        const rootNode: ResourceTreeNode = {
          id: Buffer.from(baseUrl + '/').toString('base64url').slice(0, 16),
          url: baseUrl + '/',
          parentId: null,
          name: '/',
          type: 'fuzz',
          status: res.status,
          contentType: res.headers.get('content-type'),
          size: parseInt(res.headers.get('content-length') || '0'),
          depth: 0,
          redirectChain: [],
          discoveredAt: new Date().toISOString(),
          children: [],
          meta: { category: 'common', sensitive: true, title: '[dir listing]' } as any,
        };
        fuzzTree.push(rootNode);
        await crawlDirListing(baseUrl + '/', 0, probeHistory, fuzzTree, artifacts, rootNode.id);
      }
    }
  } catch {}

  return { tree: fuzzTree, artifacts };
}

async function analyzeArtifactContent(a: ForensicArtifact, buf: Buffer): Promise<ArtifactStructure | undefined> {
  try {
    const pathname = new URL(a.url).pathname.toLowerCase();
    // ZIP magic
    if (buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05)) {
      const st = parseZip(buf);
      return st;
    }
    // GZIP → TAR
    if (buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
      try {
        const inflated = await gunzipAsync(buf as any);
        return parseTar(Buffer.from(inflated as any));
      } catch { return { kind: 'binary', note: 'gzip archive (extraction failed)' }; }
    }
    // SQLite
    if (buf.subarray(0, 16).toString('latin1') === 'SQLite format 3\0') {
      return parseSqlite(buf);
    }
    const head = buf.subarray(0, 4096).toString('latin1');
    // SQL dump
    if (/\.(sql|dump|bak|mysql)$/i.test(pathname) || /CREATE TABLE|INSERT INTO/i.test(head)) {
      return parseSqlDump(buf.toString('latin1'));
    }
    // Config files
    if (/\.(env|ini|conf|config|cfg|yml|yaml|php|json)$/i.test(pathname) || a.category === 'config') {
      return parseConfig(buf.toString('latin1'));
    }
    // Directory listing HTML
    if (a.contentType?.includes('html') || /Index of|Directory listing|<title>Index/i.test(head)) {
      const entries = parseDirListingHtml(buf.toString('latin1'), a.url);
      if (entries.length > 0) return { kind: 'directory', entries: entries.slice(0, 120), note: `Directory listing — ${entries.length} item(s)` };
    }
    // Text content: extract emails/URLs
    if (a.contentType?.includes('text') || /\.(txt|log|bak)$/i.test(pathname)) {
      const text = buf.toString('utf8');
      const emails = [...new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])].slice(0, 25);
      const urls = [...new Set(text.match(/https?:\/\/[^\s"'<>]+/g) || [])].slice(0, 20);
      const sensitive = /(pass|login|user|victim|card|cc_|credential|token)/i.test(text.slice(0, 10000));
      if (emails.length || urls.length || sensitive) {
        return { kind: 'text', emails, urls, sensitive, note: 'Text artifact — extracted emails/URLs' };
      }
    }
    return undefined;
  } catch {
    return { kind: 'binary', note: 'Binary file (structure unavailable)' };
  }
}

async function downloadArtifacts(artifacts: ForensicArtifact[]): Promise<ForensicArtifact[]> {
  const downloaded: ForensicArtifact[] = [];
  for (const a of artifacts.slice(0, MAX_ARTIFACT_DOWNLOADS)) {
    try {
      const res = await fetchWithTimeout(a.url, { method: 'GET', redirect: 'follow' }, 25000);
      if (!res.ok) continue;
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.byteLength > MAX_ARTIFACT_SIZE) continue;
      a.size = buf.byteLength;
      a.contentType = res.headers.get('content-type') || a.contentType;
      a.hash = Buffer.from(await crypto.subtle.digest('SHA-256', buf)).toString('hex').slice(0, 16);
      a.downloaded = true;
      a.structure = await analyzeArtifactContent(a, buf);
      downloaded.push(a);
    } catch {}
  }
  return downloaded;
}

async function getIPInfo(ip: string): Promise<{ asn: string | null; isp: string | null; geo: any }> {
  try {
    const res = await fetchWithTimeout(`http://ip-api.com/json/${ip}?fields=status,message,country,city,lat,lon,isp,as,asname`, {}, 5000);
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        return {
          asn: data.as || null,
          isp: data.isp || null,
          geo: { country: data.country, city: data.city, lat: data.lat, lon: data.lon }
        };
      }
    }
  } catch {}
  return { asn: null, isp: null, geo: null };
}

// robots.txt + sitemap.xml seeding (gospider --robots style)
async function discoverSeedUrls(baseUrl: string): Promise<string[]> {
  const seeds = new Set<string>();
  try {
    const robots = await fetchWithTimeout(baseUrl + '/robots.txt', { redirect: 'follow' }, 6000);
    if (robots.ok && robots.headers.get('content-type')?.includes('text')) {
      const text = await robots.text();
      for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (/^(allow|disallow)\s*:/i.test(t)) {
          const p = t.split(':').slice(1).join(':').trim().replace(/^\*/, '');
          if (p && !p.startsWith('*')) seeds.add(p.replace(/^https?:\/\/[^/]+/i, ''));
        } else if (/^sitemap\s*:/i.test(t)) {
          const s = t.split(':').slice(1).join(':').trim();
          if (s.startsWith('http')) seeds.add(s);
        }
      }
    }
  } catch {}
  try {
    const sm = await fetchWithTimeout(baseUrl + '/sitemap.xml', { redirect: 'follow' }, 6000);
    if (sm.ok) {
      const text = await sm.text();
      const locs = text.match(/<loc>([^<]+)<\/loc>/gi) || [];
      for (const loc of locs.slice(0, 25)) {
        const u = loc.replace(/<\/?loc>/gi, '').trim();
        if (u.startsWith('http')) seeds.add(u);
      }
    }
  } catch {}
  return [...seeds].slice(0, 30);
}

export async function runForensicAnalysis(input: string): Promise<ForensicMetadata> {
  const domain = input.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  const baseUrl = `https://${domain}`;
  const timestamp = new Date().toISOString();
  const name = `analisis_${domain}_${Date.now()}`;
  const id = Buffer.from(name).toString('base64url').slice(0, 32);

  // ---- DNS Reconnaissance (Google DoH) ----
  const dns: Record<string, any> = {};
  const ipSet = new Set<string>();
  try {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
    const settled = await Promise.allSettled(
      types.map((t) =>
        fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${t}`, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => r.json())
      )
    );
    settled.forEach((res, i) => {
      dns[types[i]] = res.status === 'fulfilled' ? res.value : { Status: 2, Answer: [] };
    });
    (dns.A?.Answer || []).forEach((a: any) => a.data && ipSet.add(a.data));
  } catch { /* dns unavailable */ }

  // ---- IP Enrichment (ASN, ISP, Geo) ----
  let asn: string | null = null, isp: string | null = null, geo: any = null, primaryIp: string | null = null;
  const ipList = [...ipSet];
  primaryIp = ipList[0] || null;
  if (primaryIp) {
    const ipInfo = await getIPInfo(primaryIp);
    asn = ipInfo.asn;
    isp = ipInfo.isp;
    geo = ipInfo.geo;
  }

  // ---- Subdomain Enumeration (crt.sh) ----
  const subdomains: string[] = [];
  try {
    const crt = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
    if (crt.ok) {
      const rows = await crt.json();
      const seen = new Set<string>();
      for (const r of (rows || []).slice(0, 200)) {
        for (const nameRaw of String(r.name_value || '').split('\n')) {
          const n = nameRaw.trim().toLowerCase();
          if (n.endsWith(domain) && !n.includes('*') && !seen.has(n)) {
            seen.add(n);
            subdomains.push(n);
          }
        }
      }
    }
  } catch { /* crt.sh unavailable */ }

  // ---- HTTP Headers & SSL ----
  let httpHeaders: any = {};
  try {
    const res = await fetchWithTimeout(baseUrl, { redirect: 'follow' });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    const securityHeaders = {
      'Strict-Transport-Security': !!headers['strict-transport-security'],
      'Content-Security-Policy': !!headers['content-security-policy'],
      'X-Frame-Options': !!headers['x-frame-options'],
      'X-Content-Type-Options': !!headers['x-content-type-options'],
      'Referrer-Policy': !!headers['referrer-policy'],
      'Permissions-Policy': !!headers['permissions-policy'],
    };
    httpHeaders = {
      statusCode: res.status,
      server: headers['server'] || 'Unknown',
      headers,
      securityHeaders,
      securityScore: `${Object.values(securityHeaders).filter(Boolean).length}/6`,
    };
  } catch { httpHeaders = { statusCode: 0, error: 'Failed to fetch', securityHeaders: {} }; }

  let ssl: any = {};
  try {
    const res = await fetchWithTimeout(baseUrl, { method: 'HEAD' });
    ssl = { secure: res.url.startsWith('https:'), protocol: 'TLS (verified)', subject: domain };
  } catch { ssl = { secure: false, error: 'Could not establish HTTPS connection' }; }

  // ---- Live Crawl (gospider-style) with robots/sitemap seeding ----
  const visited = new Set<string>();
  const resourceTree: ResourceTreeNode[] = [];
  const rootNode = await crawlPage(baseUrl, visited, resourceTree, null, 0);
  const seeds = await discoverSeedUrls(baseUrl);
  for (const seed of seeds) {
    if (visited.size >= MAX_CRAWL_PAGES) break;
    try {
      const u = new URL(seed);
      if (u.hostname === domain && !visited.has(seed)) {
        const seedNodes = await crawlPage(seed, visited, resourceTree, null, 1);
        resourceTree.push(...seedNodes);
      }
    } catch {}
  }

  // ---- Directory Fuzzing (ffuf/dirb-style + recursion) ----
  const discoveredDirs = resourceTree
    .filter(n => n.status === 200 && n.url.endsWith('/') && n.type !== 'fuzz')
    .map(n => n.url);
  const { tree: fuzzTree, artifacts: fuzzArtifacts } = await fuzzDirectories(baseUrl, discoveredDirs);

  // ---- Artifact Download + Deep Analysis (wget/curl-style) ----
  const downloadedArtifacts = await downloadArtifacts(fuzzArtifacts);

  // ---- Attribution from crawled pages + artifact content ----
  const allHtml = resourceTree.filter(n => n.type === 'page').map(n => n.meta?.title || '').join(' ');
  const emailMatches = allHtml.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  const artifactEmails = downloadedArtifacts.flatMap(a => a.structure?.emails || []);
  const telegramMatches = allHtml.match(/(?:t\.me\/|telegram\.me\/|@)([a-zA-Z0-9_]{4,32})/g) || [];
  const trackingMatches = allHtml.match(/[?&](?:id|tid|client|zone|site)=([A-Za-z0-9\-_]+)/g) || [];
  const attribution = {
    emails: [...new Set([...emailMatches, ...artifactEmails])].filter(e => !e.match(/\.(png|jpg|svg|gif|webp)$/i)).slice(0, 15),
    telegramIds: [...new Set(telegramMatches)].slice(0, 10),
    trackingIds: [...new Set(trackingMatches)].map(m => m.replace(/^[?&]/, '')).slice(0, 10),
    apiKeys: resourceTree.flatMap(n => n.meta?.secrets || []).filter(s => s.includes('Key') || s.includes('Token') || s.includes('Secret')).slice(0, 10),
    comments: resourceTree.flatMap(n => n.meta?.secrets || []).slice(0, 5),
    toolSignatures: [] as string[],
    links: [...new Set(resourceTree.flatMap(n => extractLinks('', n.url)))]?.slice(0, 20) || [],
  };

  // Detect tool signatures
  const allContent = resourceTree.filter(n => n.type === 'page').map(n => n.meta?.title || '').join(' ');
  if (/wp-content|wp-includes|wp-json/i.test(allContent)) attribution.toolSignatures.push('WordPress');
  if (/cPanel|WHM/i.test(allContent)) attribution.toolSignatures.push('cPanel');
  if (/Plesk/i.test(allContent)) attribution.toolSignatures.push('Plesk');
  if (/Elementor/i.test(allContent)) attribution.toolSignatures.push('Elementor');
  if (/SiteGround/i.test(allContent)) attribution.toolSignatures.push('SiteGround');
  if (/Hostinger|hPanel/i.test(allContent)) attribution.toolSignatures.push('Hostinger');
  if (/Cloudflare/i.test(allContent)) attribution.toolSignatures.push('Cloudflare');
  if (/nginx/i.test(httpHeaders.server)) attribution.toolSignatures.push('nginx');
  if (/Apache/i.test(httpHeaders.server)) attribution.toolSignatures.push('Apache');

  // ---- Risk Scoring ----
  let score = 0;
  const signals: string[] = [];
  const kitCount = downloadedArtifacts.filter(a => a.category === 'phishing_kit').length;
  const dbCount = downloadedArtifacts.filter(a => a.category === 'database').length;
  const configCount = downloadedArtifacts.filter(a => a.category === 'config').length;
  const backupCount = downloadedArtifacts.filter(a => a.category === 'backup').length;
  const sensitiveStructure = downloadedArtifacts.filter(a => a.structure?.sensitive).length;
  if (kitCount > 0) { score += 40; signals.push(`${kitCount} phishing kit(s) exposed`); }
  if (dbCount > 0) { score += 35; signals.push(`${dbCount} exposed database file(s)`); }
  if (configCount > 0) { score += 15; signals.push(`${configCount} config file(s) exposed`); }
  if (backupCount > 0) { score += 10; signals.push(`${backupCount} backup file(s) exposed`); }
  if (sensitiveStructure > 0) { score += 10; signals.push(`Sensitive data inside artifacts (credentials/tables)`); }
  if (attribution.apiKeys.length > 0) { score += 10; signals.push('Hardcoded API keys/secrets in page source'); }
  if (httpHeaders.securityScore) {
    const n = parseInt(String(httpHeaders.securityScore).split('/')[0]);
    if (n < 3) { score += 5; signals.push('Weak security headers'); }
  }
  if (attribution.telegramIds.length > 0) { score += 8; signals.push('Telegram contact IDs found'); }
  if (score === 0 && (resourceTree.some(n => n.meta?.forms && n.meta.forms > 0) || resourceTree.some(n => n.meta?.title?.toLowerCase().includes('admin')))) {
    score = 2;
  }
  const level = score >= 60 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 15 ? 'MEDIUM' : 'LOW';

  // ---- Fuzzing Summary ----
  const archiveEntries = downloadedArtifacts.filter(a => a.structure?.kind === 'archive').reduce((acc, a) => acc + (a.structure?.entries?.length || 0), 0);
  const dbTables = downloadedArtifacts.filter(a => a.structure?.kind === 'sql' || a.structure?.kind === 'sqlite').reduce((acc, a) => acc + (a.structure?.tables?.length || 0), 0);
  const fuzzingSummary = {
    totalProbed: fuzzTree.length,
    byStatus: fuzzTree.reduce((acc, n) => { acc[n.status] = (acc[n.status] || 0) + 1; return acc; }, {} as Record<number, number>),
    byCategory: fuzzTree.reduce((acc, n) => { const cat = n.meta?.category || 'unknown'; acc[cat] = (acc[cat] || 0) + 1; return acc; }, {} as Record<string, number>),
    exposed: fuzzTree.filter(n => n.meta?.sensitive && (n.status === 200 || n.status === 403)).length,
    archiveEntries,
    dbTables,
  };

  // ---- Build complete resource tree (root + fuzz) ----
  const rootResourceTree: ResourceTreeNode = {
    id: 'root',
    url: baseUrl,
    parentId: null,
    name: domain,
    type: 'page',
    status: httpHeaders.statusCode || 0,
    contentType: 'text/html',
    size: 0,
    depth: 0,
    redirectChain: [],
    discoveredAt: new Date().toISOString(),
    children: resourceTree.filter(n => n.parentId === null).concat(fuzzTree.filter(n => n.parentId === null)),
    meta: { title: domain }
  };

  return {
    domain,
    timestamp,
    name,
    id,
    risk: { level, score },
    ip: primaryIp,
    asn,
    isp,
    geo,
    dns,
    subdomains: subdomains.slice(0, 50),
    httpHeaders,
    ssl,
    attribution,
    resourceTree: rootResourceTree,
    fuzzingSummary,
    artifacts: downloadedArtifacts,
    verdict: score === 0 ? 'No critical indicators found' : signals.join('; '),
  };
}

export const FORENSICS_PATHS = FUZZ_PATHS.map((p) => p.path);
