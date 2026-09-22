import type {
  Kpi, TrendPoint, ActivityItem, Threat, BrandTarget, FakeApp,
  ExecutiveProfile, ExposureFinding, SocialChannel, SocialMessage,
  ForensicsAnalysis, DomainRecord, DorkQuery, DorkResult,
  ReportTemplate, GeneratedReport, ApiKeyEntry, Brand,
} from './types';

// ============================================================
// BRANDS BEING MONITORED (11 real brands)
// ============================================================
export const brands: Brand[] = [
  { id: 'br1',  name: 'Bancolombia',                country: 'Colombia',    type: 'Bank',      domain: 'bancolombia.com',        status: 'active',   findings: 7  },
  { id: 'br2',  name: 'Banco AgroMercantil',        country: 'Guatemala',   type: 'Bank',      domain: 'agromercantil.com',      status: 'active',   findings: 3  },
  { id: 'br3',  name: 'Banco Agrícola',             country: 'El Salvador', type: 'Bank',      domain: 'bancoagricola.com',      status: 'active',   findings: 4  },
  { id: 'br4',  name: 'Banistmo',                   country: 'Panamá',      type: 'Bank',      domain: 'banistmo.com',           status: 'active',   findings: 2  },
  { id: 'br5',  name: 'Nequi',                      country: 'Colombia',    type: 'Fintech',   domain: 'nequi.com',              status: 'flagged',  findings: 11 },
  { id: 'br6',  name: 'Zaswin',                     country: 'Colombia',    type: 'Fintech',   domain: 'zaswin.com',             status: 'active',   findings: 1  },
  { id: 'br7',  name: 'Renting',                    country: 'Colombia',    type: 'Services',  domain: 'renting.com.co',         status: 'active',   findings: 0  },
  { id: 'br8',  name: 'Suvalor',                    country: 'Colombia',    type: 'Services',  domain: 'suvalor.com',            status: 'active',   findings: 2  },
  { id: 'br9',  name: 'Wompi',                      country: 'Colombia',    type: 'Fintech',   domain: 'wompi.co',               status: 'flagged',  findings: 9  },
  { id: 'br10', name: 'Wenia',                      country: 'Colombia',    type: 'Fintech',   domain: 'wenia.com',              status: 'flagged',  findings: 6  },
];

// ============================================================
// DASHBOARD
// ============================================================
export const dashboardKpis: Kpi[] = [
  { label: 'Total Threats',        value: 1842,  delta: 18.4, hint: 'vs. semana anterior' },
  { label: 'Critical Alerts',      value: 53,    delta: 12.0, hint: '+6 esta semana' },
  { label: 'Brands Monitored',     value: 11,    delta: 0,    hint: 'Bancolombia · Nequi · Wompi …' },
  { label: 'Apps Analyzed',        value: 142,   delta: 24.0, hint: '+27 este mes' },
  { label: 'Reports Generated',    value: 67,    delta: 8.0,  hint: '+5 esta semana' },
  { label: 'Messages Collected',   value: 24531, delta: 22.7, hint: '+4.6k esta semana' },
];

export const trendData: TrendPoint[] = [
  { date: '2026-05-19', threats: 142, scans: 268, mentions: 412 },
  { date: '2026-05-22', threats: 168, scans: 298, mentions: 487 },
  { date: '2026-05-25', threats: 151, scans: 281, mentions: 451 },
  { date: '2026-05-28', threats: 198, scans: 342, mentions: 567 },
  { date: '2026-05-31', threats: 178, scans: 312, mentions: 521 },
  { date: '2026-06-03', threats: 214, scans: 367, mentions: 612 },
  { date: '2026-06-06', threats: 198, scans: 354, mentions: 587 },
  { date: '2026-06-09', threats: 234, scans: 398, mentions: 678 },
  { date: '2026-06-12', threats: 221, scans: 381, mentions: 645 },
  { date: '2026-06-15', threats: 267, scans: 421, mentions: 712 },
  { date: '2026-06-18', threats: 248, scans: 405, mentions: 689 },
];

export const threatDistribution = [
  { name: 'Phishing',     value: 612, color: '#ef4444' },
  { name: 'Brand Abuse',  value: 487, color: '#f59e0b' },
  { name: 'Malware',      value: 334, color: '#a855f7' },
  { name: 'Data Leak',    value: 258, color: '#06b6d4' },
  { name: 'Domain',       value: 151, color: '#10b981' },
];

// Threats per brand — used by the brand-by-threat bar chart
export const threatsByBrand = [
  { brand: 'Nequi',       threats: 312 },
  { brand: 'Wompi',       threats: 287 },
  { brand: 'Wenia',       threats: 198 },
  { brand: 'Bancolombia', threats: 187 },
  { brand: 'Agrícola',    threats: 142 },
  { brand: 'AgroMerc',    threats:  98 },
  { brand: 'Banistmo',    threats:  76 },
  { brand: 'Suvalor',     threats:  54 },
  { brand: 'Zaswin',      threats:  41 },
  { brand: 'Renting',     threats:  23 },
];

export const recentActivity: ActivityItem[] = [
  { id: 'a1', type: 'alert',   message: 'Phishing kit detectado imitando Nequi en login-nequi-seguro.tk',                severity: 'critical', timestamp: '2026-06-19T08:42:00Z', actor: 'System' },
  { id: 'a2', type: 'scan',    message: 'Análisis de dominio completado para wompi-fake-checkout.com — 8 subdominios',    severity: 'medium',   timestamp: '2026-06-19T08:21:00Z', actor: 'scheduler' },
  { id: 'a3', type: 'monitor', message: 'Canal Telegram @wenia_airdrop_scams publicó 47 mensajes con keywords flaggeadas', severity: 'high',     timestamp: '2026-06-19T07:55:00Z', actor: 'System' },
  { id: 'a4', type: 'report',  message: 'Reporte ejecutivo semanal generado (PDF, 3.1 MB) — 11 marcas',                    severity: 'info',     timestamp: '2026-06-19T07:00:00Z', actor: 'admin@datacyber.io' },
  { id: 'a5', type: 'apikey',  message: 'API key de VirusTotal validada — quota 4123/500000',                              severity: 'info',     timestamp: '2026-06-19T06:30:00Z', actor: 'admin@datacyber.io' },
  { id: 'a6', type: 'alert',   message: 'App falsa detectada imitando "Nequi Bolsillos" en Google Play',                   severity: 'high',     timestamp: '2026-06-18T22:14:00Z', actor: 'System' },
  { id: 'a7', type: 'login',   message: 'Nuevo login desde 181.46.x.x (Bogotá, CO)',                                        severity: 'low',      timestamp: '2026-06-18T18:02:00Z', actor: 'admin@datacyber.io' },
  { id: 'a8', type: 'scan',    message: 'Análisis forense de URL completado para https://wompi-pagos-seguros.tk',         severity: 'critical', timestamp: '2026-06-18T17:33:00Z', actor: 'analyst@datacyber.io' },
  { id: 'a9', type: 'alert',   message: 'Credenciales del CTO de Wenia filtradas en foro de darkweb',                      severity: 'critical', timestamp: '2026-06-19T04:02:00Z', actor: 'System' },
  { id: 'a10', type: 'monitor', message: 'Mención de "Banistmo fraud" en Reddit r/Panama — sentimiento negativo',         severity: 'medium',   timestamp: '2026-06-18T15:42:00Z', actor: 'System' },
];

// ============================================================
// THREATS
// ============================================================
export const threats: Threat[] = [
  { id: 't1',  title: 'Phishing kit en login-nequi-seguro.tk imitando Nequi',           source: 'URL Forensics',       severity: 'critical', status: 'investigating', category: 'phishing',    detectedAt: '2026-06-18T17:33:00Z', confidence: 96 },
  { id: 't2',  title: 'App falsa "Nequi Bolsillos Pro" en Google Play',                 source: 'Brand Protection',    severity: 'high',     status: 'new',           category: 'brand_abuse', detectedAt: '2026-06-18T22:14:00Z', confidence: 88 },
  { id: 't3',  title: 'Credenciales del CTO de Wenia filtradas en darkweb',             source: 'Executive Protection',severity: 'critical', status: 'new',           category: 'data_leak',   detectedAt: '2026-06-19T04:02:00Z', confidence: 92 },
  { id: 't4',  title: 'Typosquat bancolombiа-login.com registrado ( Cyrillic )',        source: 'Brand Protection',    severity: 'high',     status: 'investigating', category: 'domain',      detectedAt: '2026-06-19T03:18:00Z', confidence: 81 },
  { id: 't5',  title: 'APK de Wompi con malware firmado y distribuido en foros',        source: 'Sandbox',             severity: 'high',     status: 'investigating', category: 'malware',     detectedAt: '2026-06-18T15:20:00Z', confidence: 84 },
  { id: 't6',  title: 'Telegram @wenia_airdrop_scams vendiendo "doble saldo Wenia"',    source: 'Social Monitoring',   severity: 'critical', status: 'new',           category: 'social',      detectedAt: '2026-06-19T07:55:00Z', confidence: 79 },
  { id: 't7',  title: 'SSL caducado en api.bancoagricola.com (El Salvador)',            source: 'Domain Analysis',     severity: 'medium',   status: 'resolved',      category: 'domain',      detectedAt: '2026-06-17T11:00:00Z', confidence: 100 },
  { id: 't8',  title: 'Túnel DNS sospechoso detectado en subdominio de Banistmo',       source: 'Domain Analysis',     severity: 'medium',   status: 'investigating', category: 'domain',      detectedAt: '2026-06-18T09:42:00Z', confidence: 67 },
  { id: 't9',  title: 'Google dork expuso .env con API keys de Wompi en staging',       source: 'Google Dorking',      severity: 'critical', status: 'new',           category: 'data_leak',   detectedAt: '2026-06-19T05:11:00Z', confidence: 95 },
  { id: 't10', title: 'Falso @soporte_nequi en Twitter pidiendo credenciales',          source: 'Brand Protection',    severity: 'medium',   status: 'investigating', category: 'brand_abuse', detectedAt: '2026-06-18T14:30:00Z', confidence: 76 },
  { id: 't11', title: 'CVE-2026-4421 detectado en infraestructura expuesta de Wenia',   source: 'Domain Analysis',     severity: 'high',     status: 'investigating', category: 'malware',     detectedAt: '2026-06-18T13:09:00Z', confidence: 73 },
  { id: 't12', title: 'Sitio clon de Zaswin en zaswin-inversiones.net',                 source: 'Brand Protection',    severity: 'medium',   status: 'new',           category: 'brand_abuse', detectedAt: '2026-06-19T02:00:00Z', confidence: 68 },
  { id: 't13', title: 'Credenciales de empleado de Banco AgroMercantil en combolist',   source: 'Executive Protection',severity: 'high',     status: 'new',           category: 'data_leak',   detectedAt: '2026-06-18T20:42:00Z', confidence: 85 },
  { id: 't14', title: 'Dominio typosquat renting-colombia.com registrado hace 3 días',  source: 'Brand Protection',    severity: 'low',      status: 'investigating', category: 'domain',      detectedAt: '2026-06-18T08:11:00Z', confidence: 58 },
  { id: 't15', title: 'Canal de Discord vendiendo "cuentas Suvalor verificadas"',       source: 'Social Monitoring',   severity: 'high',     status: 'new',           category: 'social',      detectedAt: '2026-06-19T06:18:00Z', confidence: 82 },
];

// ============================================================
// BRAND PROTECTION
// ============================================================
export const brandTargets: BrandTarget[] = [
  { id: 'b1',  brand: 'Bancolombia',         type: 'domain',      target: 'bancolombia.com',                status: 'active',  lastScan: '2026-06-19T08:00:00Z', findings: 3 },
  { id: 'b2',  brand: 'Bancolombia',         type: 'appstore',    target: 'Nequi (Google Play)',            status: 'flagged', lastScan: '2026-06-18T22:14:00Z', findings: 2 },
  { id: 'b3',  brand: 'Bancolombia',         type: 'marketplace', target: 'bancolombia-login.com',          status: 'flagged', lastScan: '2026-06-19T03:18:00Z', findings: 4 },
  { id: 'b4',  brand: 'Bancolombia',         type: 'social',      target: '@Bancolombia (Twitter)',         status: 'active',  lastScan: '2026-06-19T07:00:00Z', findings: 0 },
  { id: 'b5',  brand: 'Nequi',               type: 'domain',      target: 'nequi.com',                      status: 'active',  lastScan: '2026-06-19T08:00:00Z', findings: 5 },
  { id: 'b6',  brand: 'Nequi',               type: 'appstore',    target: 'Nequi Bolsillos (Google Play)',  status: 'flagged', lastScan: '2026-06-18T22:14:00Z', findings: 3 },
  { id: 'b7',  brand: 'Nequi',               type: 'marketplace', target: 'login-nequi-seguro.tk',          status: 'flagged', lastScan: '2026-06-18T17:33:00Z', findings: 6 },
  { id: 'b8',  brand: 'Wompi',               type: 'domain',      target: 'wompi.co',                       status: 'active',  lastScan: '2026-06-19T08:00:00Z', findings: 4 },
  { id: 'b9',  brand: 'Wompi',               type: 'marketplace', target: 'wompi-fake-checkout.com',        status: 'flagged', lastScan: '2026-06-19T08:21:00Z', findings: 5 },
  { id: 'b10', brand: 'Wompi',               type: 'appstore',    target: 'Wompi Pagos (Google Play)',      status: 'active',  lastScan: '2026-06-19T06:30:00Z', findings: 0 },
  { id: 'b11', brand: 'Wenia',               type: 'domain',      target: 'wenia.com',                      status: 'active',  lastScan: '2026-06-19T08:00:00Z', findings: 3 },
  { id: 'b12', brand: 'Wenia',               type: 'marketplace', target: 'wenia-airdrop-scams.tk',         status: 'flagged', lastScan: '2026-06-19T07:55:00Z', findings: 3 },
  { id: 'b13', brand: 'Banco AgroMercantil', type: 'domain',      target: 'agromercantil.com',              status: 'active',  lastScan: '2026-06-19T05:00:00Z', findings: 1 },
  { id: 'b14', brand: 'Banco AgroMercantil', type: 'social',      target: '@AgroMercantilGT (Twitter)',     status: 'active',  lastScan: '2026-06-19T04:00:00Z', findings: 0 },
  { id: 'b15', brand: 'Banco Agrícola',      type: 'domain',      target: 'bancoagricola.com',              status: 'active',  lastScan: '2026-06-19T08:00:00Z', findings: 2 },
  { id: 'b16', brand: 'Banco Agrícola',      type: 'domain',      target: 'api.bancoagricola.com',          status: 'active',  lastScan: '2026-06-17T11:00:00Z', findings: 0 },
  { id: 'b17', brand: 'Banistmo',            type: 'domain',      target: 'banistmo.com',                   status: 'active',  lastScan: '2026-06-19T08:00:00Z', findings: 1 },
  { id: 'b18', brand: 'Banistmo',            type: 'marketplace', target: 'banistmo-online.com',            status: 'flagged', lastScan: '2026-06-18T09:42:00Z', findings: 1 },
  { id: 'b19', brand: 'Zaswin',              type: 'domain',      target: 'zaswin.com',                     status: 'active',  lastScan: '2026-06-19T07:30:00Z', findings: 0 },
  { id: 'b20', brand: 'Zaswin',              type: 'marketplace', target: 'zaswin-inversiones.net',         status: 'flagged', lastScan: '2026-06-19T02:00:00Z', findings: 1 },
  { id: 'b21', brand: 'Renting',             type: 'domain',      target: 'renting.com.co',                 status: 'active',  lastScan: '2026-06-19T06:00:00Z', findings: 0 },
  { id: 'b22', brand: 'Renting',             type: 'marketplace', target: 'renting-colombia.com',           status: 'flagged', lastScan: '2026-06-18T08:11:00Z', findings: 1 },
  { id: 'b23', brand: 'Suvalor',             type: 'domain',      target: 'suvalor.com',                    status: 'active',  lastScan: '2026-06-19T07:00:00Z', findings: 1 },
  { id: 'b24', brand: 'Suvalor',             type: 'social',      target: 'Discord db-marketplace',         status: 'flagged', lastScan: '2026-06-19T06:18:00Z', findings: 1 },
];

export const fakeApps: FakeApp[] = [
  { id: 'f1', appName: 'Nequi Bolsillos Pro - 2x Saldo',  developer: 'FreeTools2024',  platform: 'Google Play', impersonated: 'Nequi',               maliciousScore: 87, detectedAt: '2026-06-18T22:14:00Z', status: 'pending'  },
  { id: 'f2', appName: 'Wompi Pagos - Checkout',          developer: 'DevStudioX',     platform: 'Third-party', impersonated: 'Wompi',               maliciousScore: 94, detectedAt: '2026-06-17T11:08:00Z', status: 'reported' },
  { id: 'f3', appName: 'Wenia Airdrop - Crypto',          developer: 'CryptoAppsInc',  platform: 'Google Play', impersonated: 'Wenia',               maliciousScore: 62, detectedAt: '2026-06-15T16:42:00Z', status: 'removed'  },
  { id: 'f4', appName: 'Bancolombia Móvil',               developer: 'QRTools',        platform: 'Third-party', impersonated: 'Bancolombia',         maliciousScore: 71, detectedAt: '2026-06-14T09:21:00Z', status: 'pending'  },
  { id: 'f5', appName: 'Banistmo Banca Persona',          developer: 'PanamaApps',     platform: 'Third-party', impersonated: 'Banistmo',            maliciousScore: 78, detectedAt: '2026-06-13T14:08:00Z', status: 'reported' },
  { id: 'f6', appName: 'Agrícola SV Móvil',               developer: 'SVDev',          platform: 'Google Play', impersonated: 'Banco Agrícola',      maliciousScore: 55, detectedAt: '2026-06-12T10:30:00Z', status: 'pending'  },
];

// ============================================================
// EXECUTIVE PROTECTION
// ============================================================
export const executiveProfiles: ExecutiveProfile[] = [
  { id: 'e1', name: 'Juan Carlos Mora',       role: 'CEO',            company: 'Bancolombia',         exposedEmails: 3, exposedPhones: 1, leakedCredentials: 2, riskScore: 72, lastCheck: '2026-06-19T04:02:00Z', email: 'jc.mora@bancolombia.com.co', phone: '+57 310 555 0100', position: 'CEO', organization: 'Bancolombia', emailType: 'corporate', address: 'Carrera 48 # 26-85, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/juan-carlos-mora', handle: '@jcpmora', type: 'professional'}] },
  { id: 'e2', name: 'María Isabel Gutiérrez', role: 'CFO',            company: 'Bancolombia',         exposedEmails: 2, exposedPhones: 0, leakedCredentials: 1, riskScore: 54, lastCheck: '2026-06-19T04:02:00Z', email: 'm.gutierrez@bancolombia.com.co', phone: '+57 310 555 0101', position: 'CFO', organization: 'Bancolombia', emailType: 'corporate', address: 'Carrera 48 # 26-85, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/mariagutierrez', handle: '@migutierrez', type: 'professional'}] },
  { id: 'e3', name: 'Carlos Andrés Ruiz',     role: 'CTO',            company: 'Wenia',               exposedEmails: 5, exposedPhones: 2, leakedCredentials: 4, riskScore: 89, lastCheck: '2026-06-19T04:02:00Z', email: 'carlos.ruiz@wenia.com', phone: '+57 311 555 0200', position: 'CTO', organization: 'Wenia', emailType: 'both', address: 'Calle 26 # 4-60, Medellín', location: 'Medellín, Colombia', socialMedia: [{platform: 'GitHub', url: 'https://github.com/carlosruiz', handle: '@cruiz', type: 'technical'}, {platform: 'Twitter', url: 'https://twitter.com/cruiz_tech', handle: '@cruiz_tech', type: 'personal'}] },
  { id: 'e4', name: 'Ana Lucía Torres',       role: 'COO',            company: 'Nequi',               exposedEmails: 1, exposedPhones: 0, leakedCredentials: 0, riskScore: 32, lastCheck: '2026-06-19T04:02:00Z', email: 'ana.torres@nequi.com', phone: '+57 312 555 0300', position: 'COO', organization: 'Nequi', emailType: 'corporate', address: 'Carrera 7 # 24-32, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/anatorres', handle: '@atorres', type: 'professional'}] },
  { id: 'e5', name: 'Pedro Martín Herrera',   role: 'CISO',           company: 'Wompi',               exposedEmails: 2, exposedPhones: 1, leakedCredentials: 1, riskScore: 61, lastCheck: '2026-06-19T04:02:00Z', email: 'pedro.herrera@wompi.co', phone: '+57 313 555 0400', position: 'CISO', organization: 'Wompi', emailType: 'corporate', address: 'Cra 13 # 93-40, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/pedroherrera', handle: '@pherrera', type: 'professional'}] },
  { id: 'e6', name: 'Roberto Aguilar',        role: 'CEO',            company: 'Banco AgroMercantil', exposedEmails: 2, exposedPhones: 1, leakedCredentials: 1, riskScore: 58, lastCheck: '2026-06-19T04:02:00Z', email: 'r.aguilar@agromercantil.com', phone: '+57 314 555 0500', position: 'CEO', organization: 'Banco AgroMercantil', emailType: 'corporate', address: '16 Av. 1-23, Guatemala', location: 'Guatemala, Guatemala', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/robertoaguilar', handle: '@raguilar', type: 'professional'}] },
  { id: 'e7', name: 'Sofía Panameño',         role: 'CISO',           company: 'Banco Agrícola',      exposedEmails: 1, exposedPhones: 0, leakedCredentials: 0, riskScore: 28, lastCheck: '2026-06-19T04:02:00Z', email: 'sofia.panameño@bancoagricola.com', phone: '+503 2222 0700', position: 'CISO', organization: 'Banco Agrícola', emailType: 'corporate', address: '25 Av. Nte. # 11-32, San Salvador', location: 'San Salvador, El Salvador', socialMedia: [] },
  { id: 'e8', name: 'Manuel Quintero',        role: 'CEO',            company: 'Banistmo',            exposedEmails: 2, exposedPhones: 1, leakedCredentials: 1, riskScore: 52, lastCheck: '2026-06-19T04:02:00Z', email: 'manuel.quintero@banistmo.com', phone: '+507 269 4500', position: 'CEO', organization: 'Banistmo', emailType: 'corporate', address: 'Calle 50 # 49-27, Ciudad de Panamá', location: 'Panamá, Panamá', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/manuelquintero', handle: '@mquintero', type: 'professional'}] },
  { id: 'e9', name: 'Daniela Restrepo',       role: 'CEO',            company: 'Zaswin',              exposedEmails: 1, exposedPhones: 0, leakedCredentials: 0, riskScore: 24, lastCheck: '2026-06-19T04:02:00Z', email: 'daniela.restrepo@zaswin.com', phone: '+57 315 555 0900', position: 'CEO', organization: 'Zaswin', emailType: 'corporate', address: 'Carrera 9 # 12-45, Cali', location: 'Cali, Colombia', socialMedia: [] },
];

export const exposureFindings: ExposureFinding[] = [
  { id: 'x1', profileId: 'e1', type: 'email',      value: 'jc.mora@bancolombia.com.co',         source: 'Pastebin leak 2026-04',            severity: 'high',     detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x2', profileId: 'e1', type: 'credential', value: 'LinkedIn (bcrypt hash)',             source: 'Combolist 2026-Q1',                severity: 'critical', detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x3', profileId: 'e3', type: 'phone',      value: '+57 310 555 0142',                   source: 'Public directory scrape',          severity: 'medium',   detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x4', profileId: 'e3', type: 'credential', value: 'GitHub PAT (revoked)',               source: 'Darkweb forum',                    severity: 'critical', detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x5', profileId: 'e3', type: 'document',   value: 'Wenia board memo Q1-2026.pdf',       source: 'Public S3 bucket',                 severity: 'high',     detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x6', profileId: 'e2', type: 'email',      value: 'm.gutierrez@bancolombia.com.co',     source: 'Marketing vendor breach',          severity: 'medium',   detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x7', profileId: 'e5', type: 'address',    value: 'Calle 100 #45-67, Bogotá',           source: 'Corporate registry',               severity: 'low',      detectedAt: '2026-06-19T04:02:00Z' },
  { id: 'x8', profileId: 'e6', type: 'credential', value: 'Email + bcrypt hash',                source: 'Combolist GT 2026',                severity: 'high',     detectedAt: '2026-06-19T04:02:00Z' },
];

// ============================================================
// SOCIAL MONITORING
// ============================================================
export const socialChannels: SocialChannel[] = [
  { id: 's1', platform: 'Telegram', name: 'Nequi Scams',              identifier: '@nequi_scams_col',        members: 4821,  messages: 8421, alerts: 27, status: 'flagged',    lastActivity: '2026-06-19T07:55:00Z' },
  { id: 's2', platform: 'Telegram', name: 'Wenia Airdrop Scams',      identifier: '@wenia_airdrop_scams',    members: 1209,  messages: 3127, alerts: 14, status: 'flagged',    lastActivity: '2026-06-19T07:42:00Z' },
  { id: 's3', platform: 'Discord',  name: 'DB Marketplace',           identifier: 'db-marketplace',          members: 2188,  messages: 5402, alerts:  9, status: 'monitoring', lastActivity: '2026-06-19T05:18:00Z' },
  { id: 's4', platform: 'Twitter',  name: 'Bancolombia Impersonators',identifier: 'search:Bancolombia + soporte', members: 0, messages: 1429, alerts: 6, status: 'monitoring', lastActivity: '2026-06-19T04:00:00Z' },
  { id: 's5', platform: 'Reddit',   name: 'r/Panama — Banistmo',      identifier: 'r/Panama',                members: 3412,  messages: 2103, alerts:  2, status: 'monitoring', lastActivity: '2026-06-19T02:21:00Z' },
  { id: 's6', platform: 'Telegram', name: 'Wompi Carding',            identifier: '@wompi_carding_2026',     members: 894,   messages: 410,  alerts: 31, status: 'paused',     lastActivity: '2026-06-18T22:11:00Z' },
  { id: 's7', platform: 'Telegram', name: 'Agricola SV Phishing',     identifier: '@agricola_sv_phish',      members: 412,   messages: 287,  alerts:  8, status: 'monitoring', lastActivity: '2026-06-18T20:00:00Z' },
  { id: 's8', platform: 'Discord',  name: 'Suvalor Verified Sellers', identifier: 'suvalor-market',          members: 612,   messages: 391,  alerts: 12, status: 'flagged',    lastActivity: '2026-06-19T06:18:00Z' },
];

export const socialMessages: SocialMessage[] = [
  { id: 'm1', channelId: 's1', author: 'anon_4421',    content: 'Vendo logs frescos de Nequi, 1.2k cuentas, DM para precio',          timestamp: '2026-06-19T07:55:00Z', sentiment: 'negative', flagged: true, keywords: ['vendo', 'logs', 'cuentas'] },
  { id: 'm2', channelId: 's1', author: 'carder_x',     content: 'Nuevo phishing kit para Nequi con bypass de 2FA, link en bio',       timestamp: '2026-06-19T07:42:00Z', sentiment: 'negative', flagged: true, keywords: ['phishing kit', '2FA bypass'] },
  { id: 'm3', channelId: 's2', author: 'leaker_99',    content: 'Docs internos de Wenia dropeados, 4.2GB, link en bio',               timestamp: '2026-06-19T06:42:00Z', sentiment: 'negative', flagged: true, keywords: ['docs internos', 'leak'] },
  { id: 'm4', channelId: 's3', author: 'db_seller',    content: 'DB de clientes Suvalor 2026-Q1, 80k filas, muestra disponible',     timestamp: '2026-06-19T05:18:00Z', sentiment: 'negative', flagged: true, keywords: ['DB', 'muestra'] },
  { id: 'm5', channelId: 's4', author: 'soporte_nequi_falso', content: 'DM con tus credenciales para resetear tu cuenta Nequi',      timestamp: '2026-06-19T04:00:00Z', sentiment: 'negative', flagged: true, keywords: ['credenciales', 'reset'] },
  { id: 'm6', channelId: 's5', author: 'user_2811',    content: 'Alguien más recibió SMS de phishing de Banistmo hoy?',              timestamp: '2026-06-19T02:21:00Z', sentiment: 'neutral',  flagged: false, keywords: ['phishing', 'SMS'] },
  { id: 'm7', channelId: 's2', author: 'leaker_99',    content: 'Actualizando leak de Wenia con emails y hashes del CTO',            timestamp: '2026-06-18T22:30:00Z', sentiment: 'negative', flagged: true, keywords: ['emails', 'hashes'] },
  { id: 'm8', channelId: 's1', author: 'anon_4421',    content: 'Descuento por volumen en logs de Nequi solo este fin de semana',    timestamp: '2026-06-18T20:11:00Z', sentiment: 'negative', flagged: true, keywords: ['descuento', 'logs'] },
  { id: 'm9', channelId: 's8', author: 'verified_sv',  content: 'Cuentas Suvalor verificadas a 50 USD cada una, pago en crypto',     timestamp: '2026-06-19T06:18:00Z', sentiment: 'negative', flagged: true, keywords: ['cuentas', 'crypto'] },
];

// ============================================================
// URL FORENSICS
// ============================================================
export const forensicsAnalyses: ForensicsAnalysis[] = [
  {
    id: 'u1',
    url: 'https://login-nequi-seguro.tk/signin',
    submittedAt: '2026-06-18T17:30:00Z',
    status: 'completed',
    threatScore: 94,
    redirects: 3,
    finalUrl: 'https://198.51.100.42/capture.php',
    ipAddress: '198.51.100.42',
    ssl: { valid: false, issuer: "Let's Encrypt (suspicious)", validFrom: '2026-06-15', validTo: '2026-09-13' },
    detections: [
      { engine: 'VirusTotal', verdict: 'malicious (12/90)' },
      { engine: 'AbuseIPDB', verdict: 'reported 47 times' },
      { engine: 'Google Safe Browsing', verdict: 'phishing' },
      { engine: 'PhishTank', verdict: 'verified phishing' },
    ],
  },
  {
    id: 'u2',
    url: 'https://wompi-pagos-seguros.tk/checkout',
    submittedAt: '2026-06-19T08:15:00Z',
    status: 'completed',
    threatScore: 87,
    redirects: 2,
    finalUrl: 'https://203.0.113.5/auth',
    ipAddress: '203.0.113.5',
    ssl: { valid: true, issuer: 'DigiCert', validFrom: '2026-05-01', validTo: '2027-05-01' },
    detections: [
      { engine: 'VirusTotal', verdict: 'suspicious (5/90)' },
      { engine: 'Google Safe Browsing', verdict: 'deceptive' },
    ],
  },
  {
    id: 'u3',
    url: 'https://wenia-airdrop-scams.tk/claim',
    submittedAt: '2026-06-19T08:30:00Z',
    status: 'processing',
    threatScore: 0,
    redirects: 0,
    finalUrl: '',
    ipAddress: '',
    ssl: { valid: false, issuer: '', validFrom: '', validTo: '' },
    detections: [],
  },
];

// ============================================================
// DOMAIN ANALYSIS
// ============================================================
export const domainRecords: DomainRecord[] = [
  {
    id: 'd1',
    domain: 'login-nequi-seguro.tk',
    registered: '2026-06-12',
    expires: '2027-06-12',
    registrar: 'Dot TK',
    dnsSec: false,
    reputation: 8,
    openPorts: [
      { port: 80, service: 'HTTP', risk: 'high' },
      { port: 443, service: 'HTTPS', risk: 'medium' },
      { port: 22, service: 'SSH', risk: 'medium' },
      { port: 8080, service: 'HTTP-Proxy', risk: 'high' },
    ],
    subdomains: ['www.login-nequi-seguro.tk', 'api.login-nequi-seguro.tk'],
    securityHeaders: [
      { header: 'Strict-Transport-Security', status: 'fail', value: 'missing' },
      { header: 'Content-Security-Policy', status: 'fail', value: 'missing' },
      { header: 'X-Frame-Options', status: 'warn', value: 'SAMEORIGIN' },
      { header: 'X-Content-Type-Options', status: 'pass', value: 'nosniff' },
    ],
    lastScan: '2026-06-18T17:33:00Z',
  },
  {
    id: 'd2',
    domain: 'bancolombia.com',
    registered: '1996-04-12',
    expires: '2028-04-12',
    registrar: 'MarkMonitor',
    dnsSec: true,
    reputation: 92,
    openPorts: [
      { port: 443, service: 'HTTPS', risk: 'low' },
      { port: 25, service: 'SMTP', risk: 'low' },
    ],
    subdomains: ['www.bancolombia.com', 'api.bancolombia.com', 'app.bancolombia.com', 'soporte.bancolombia.com', 'cdn.bancolombia.com'],
    securityHeaders: [
      { header: 'Strict-Transport-Security', status: 'pass', value: 'max-age=31536000; includeSubDomains' },
      { header: 'Content-Security-Policy', status: 'pass', value: 'default-src https:' },
      { header: 'X-Frame-Options', status: 'pass', value: 'DENY' },
      { header: 'X-Content-Type-Options', status: 'pass', value: 'nosniff' },
    ],
    lastScan: '2026-06-19T08:00:00Z',
  },
  {
    id: 'd3',
    domain: 'wompi-fake-checkout.com',
    registered: '2026-06-15',
    expires: '2027-06-15',
    registrar: 'NameCheap',
    dnsSec: false,
    reputation: 22,
    openPorts: [
      { port: 80, service: 'HTTP', risk: 'high' },
      { port: 443, service: 'HTTPS', risk: 'medium' },
    ],
    subdomains: [],
    securityHeaders: [
      { header: 'Strict-Transport-Security', status: 'fail', value: 'missing' },
      { header: 'Content-Security-Policy', status: 'fail', value: 'missing' },
      { header: 'X-Frame-Options', status: 'fail', value: 'missing' },
      { header: 'X-Content-Type-Options', status: 'fail', value: 'missing' },
    ],
    lastScan: '2026-06-19T08:21:00Z',
  },
  {
    id: 'd4',
    domain: 'bancoagricola.com',
    registered: '2000-08-22',
    expires: '2027-08-22',
    registrar: 'GoDaddy',
    dnsSec: false,
    reputation: 78,
    openPorts: [
      { port: 443, service: 'HTTPS', risk: 'low' },
    ],
    subdomains: ['www.bancoagricola.com', 'api.bancoagricola.com', 'personas.bancoagricola.com'],
    securityHeaders: [
      { header: 'Strict-Transport-Security', status: 'pass', value: 'max-age=31536000' },
      { header: 'Content-Security-Policy', status: 'warn', value: 'default-src https: *.bancoagricola.com' },
      { header: 'X-Frame-Options', status: 'pass', value: 'SAMEORIGIN' },
      { header: 'X-Content-Type-Options', status: 'pass', value: 'nosniff' },
    ],
    lastScan: '2026-06-19T08:00:00Z',
  },
];

// ============================================================
// GOOGLE DORKING
// ============================================================
export const dorkQueries: DorkQuery[] = [
  { id: 'k1', query: 'site:pastebin.com "bancolombia.com" password',      category: 'leaks',         results: 14, lastRun: '2026-06-19T05:11:00Z', status: 'active' },
  { id: 'k2', query: 'site:github.com "NEQUI_API_KEY"',                   category: 'exposure',      results: 3,  lastRun: '2026-06-19T05:11:00Z', status: 'active' },
  { id: 'k3', query: 'intitle:"index of" "wompi" .env',                   category: 'exposure',      results: 1,  lastRun: '2026-06-19T05:11:00Z', status: 'active' },
  { id: 'k4', query: 'inurl:"/admin" site:bancoagricola.com',             category: 'infrastructure',results: 0,  lastRun: '2026-06-19T05:11:00Z', status: 'active' },
  { id: 'k5', query: '"wenia airdrop" phishing template',                 category: 'phishing',      results: 27, lastRun: '2026-06-18T22:00:00Z', status: 'active' },
  { id: 'k6', query: 'filetype:sql "bancolombia" leaked',                 category: 'leaks',         results: 2,  lastRun: '2026-06-18T22:00:00Z', status: 'paused' },
  { id: 'k7', query: 'site:telegram.me "nequi" "carding"',                category: 'leaks',         results: 8,  lastRun: '2026-06-19T06:00:00Z', status: 'active' },
  { id: 'k8', query: '"banistmo" "phishing" "klonen"',                    category: 'phishing',      results: 4,  lastRun: '2026-06-18T18:00:00Z', status: 'active' },
];

export const dorkResults: DorkResult[] = [
  { id: 'r1', queryId: 'k1', title: 'Credenciales Bancolombia - Pastebin',          url: 'https://pastebin.com/abc123', snippet: '...jc.mora@bancolombia.com.co:Password2024!...',     severity: 'critical', detectedAt: '2026-06-19T05:11:00Z' },
  { id: 'r2', queryId: 'k2', title: 'nequi-integration/config.json at main',        url: 'https://github.com/devuser/nequi-integration/blob/main/config.json', snippet: '"NEQUI_API_KEY": "sk_live_51H8..."',  severity: 'critical', detectedAt: '2026-06-19T05:11:00Z' },
  { id: 'r3', queryId: 'k3', title: 'Index of /wompi-staging',                      url: 'https://staging.wompi.co/', snippet: '.env .git/ config/ backup.sql',                    severity: 'critical', detectedAt: '2026-06-19T05:11:00Z' },
  { id: 'r4', queryId: 'k5', title: 'Wenia airdrop phishing kit - Download',        url: 'https://example-phish.com/wenia-kit.zip', snippet: 'Full Wenia phishing template with wallet drainer...', severity: 'high', detectedAt: '2026-06-18T22:00:00Z' },
  { id: 'r5', queryId: 'k1', title: 'Lista de clientes Bancolombia 2026 - Pastebin',url: 'https://pastebin.com/def456', snippet: '...80,000 customer records from Bancolombia...',    severity: 'high',     detectedAt: '2026-06-18T22:00:00Z' },
  { id: 'r6', queryId: 'k7', title: 'Telegram: nequi carding group',                url: 'https://t.me/nequi_carding', snippet: 'Vendo logs Nequi frescos 2026...',                  severity: 'critical', detectedAt: '2026-06-19T06:00:00Z' },
];

// ============================================================
// REPORTS
// ============================================================
export const reportTemplates: ReportTemplate[] = [
  { id: 'rt1', name: 'Executive Summary',                 type: 'executive',  description: 'Resumen ejecutivo para C-suite con KPIs y tendencias de riesgo',          lastGenerated: '2026-06-19T07:00:00Z', sections: ['Overview', 'Critical Risks', 'Trends', 'Recommendations'] },
  { id: 'rt2', name: 'Technical Threat Report',           type: 'technical',  description: 'Hallazgos técnicos detallados con IOCs y pasos de remediación',            lastGenerated: '2026-06-18T16:30:00Z', sections: ['Threats', 'IOCs', 'Forensics', 'Remediation'] },
  { id: 'rt3', name: 'Compliance Report (ISO 27001)',     type: 'compliance', description: 'Mapeo de cumplimiento contra controles ISO 27001',                         lastGenerated: '2026-06-15T10:00:00Z', sections: ['Scope', 'Controls', 'Gaps', 'Action Plan'] },
  { id: 'rt4', name: 'Daily Digest',                      type: 'daily',      description: 'Resumen diario automático de nuevas amenazas y escaneos',                  lastGenerated: '2026-06-19T06:00:00Z', sections: ['New Threats', 'Scans', 'Activity'] },
  { id: 'rt5', name: 'Brand Protection Report',           type: 'executive',  description: 'Estado de protección de las 11 marcas monitoreadas',                       lastGenerated: '2026-06-18T09:00:00Z', sections: ['Brands', 'Findings', 'Takedowns', 'Trends'] },
];

export const generatedReports: GeneratedReport[] = [
  { id: 'g1', title: 'Executive Summary — Week 25 (11 marcas)', template: 'Executive Summary',       period: '2026-06-13 to 2026-06-19', generatedAt: '2026-06-19T07:00:00Z', status: 'ready',      size: '3.1 MB' },
  { id: 'g2', title: 'Technical Threat Report — June',          template: 'Technical Threat Report', period: '2026-06-01 to 2026-06-19', generatedAt: '2026-06-18T16:30:00Z', status: 'ready',      size: '8.4 MB' },
  { id: 'g3', title: 'Daily Digest — 2026-06-19',               template: 'Daily Digest',            period: '2026-06-19',               generatedAt: '2026-06-19T06:00:00Z', status: 'ready',      size: '0.9 MB' },
  { id: 'g4', title: 'Brand Protection Report — June',          template: 'Brand Protection Report', period: '2026-06-01 to 2026-06-19', generatedAt: '2026-06-19T08:30:00Z', status: 'processing', size: '—' },
  { id: 'g5', title: 'Compliance Report Q2 2026',               template: 'Compliance Report (ISO 27001)', period: '2026-04-01 to 2026-06-30', generatedAt: '2026-06-18T11:00:00Z', status: 'ready', size: '5.2 MB' },
];

// ============================================================
// API KEYS
// ============================================================
export const apiKeys: ApiKeyEntry[] = [
  { id: 'k1', provider: 'VirusTotal',        label: 'VT Production',     maskedKey: 'sk_live_51H8••••••••••••••••4a9c', status: 'active',       lastUsed: '2026-06-19T08:00:00Z', quotaUsed: 4123,  quotaTotal: 500000 },
  { id: 'k2', provider: 'AbuseIPDB',         label: 'AbuseIPDB Default', maskedKey: 'abc123••••••••••••••••7f02',       status: 'active',       lastUsed: '2026-06-19T07:55:00Z', quotaUsed: 142,   quotaTotal: 10000 },
  { id: 'k3', provider: 'Shodan',            label: 'Shodan Main',       maskedKey: 'SHO••••••••••••••••••2d8e',         status: 'active',       lastUsed: '2026-06-19T08:00:00Z', quotaUsed: 89,    quotaTotal: 1000 },
  { id: 'k4', provider: 'Censys',            label: 'Censys API',        maskedKey: 'CEN••••••••••••••••••b1a4',         status: 'unconfigured', lastUsed: '—' },
  { id: 'k5', provider: 'MobSF',             label: 'MobSF Sandbox',     maskedKey: 'MSF••••••••••••••••••9c3f',         status: 'active',       lastUsed: '2026-06-18T22:14:00Z' },
  { id: 'k6', provider: 'ScreenshotMachine', label: 'SM Default',        maskedKey: 'SCR••••••••••••••••••0e2b',         status: 'active',       lastUsed: '2026-06-18T17:33:00Z' },
  { id: 'k7', provider: 'Telegram',          label: 'Telegram Bot',      maskedKey: '7424•••••••:AAE•••••••••••••••••', status: 'active',       lastUsed: '2026-06-19T07:55:00Z' },
  { id: 'k8', provider: 'Discord',           label: 'Discord Bot',       maskedKey: 'MTA•••••••••••••••••••••••',         status: 'invalid',      lastUsed: '2026-06-15T11:00:00Z' },
];
