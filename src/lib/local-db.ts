// DB simulada con localStorage para el cliente (funciona en cualquier entorno, incluido Vercel)
// Los análisis de URL/dominio siguen siendo reales (serverless API routes read-only)

import type {
  Brand, Threat, ExecutiveProfile, SocialChannel, ApiKeyEntry,
  UrlScan, DomainScan, Report, ActivityItem,
} from './types';

const STORAGE_KEY = 'datacyber-db-v1';

export interface Database {
  brands: Brand[];
  threats: Threat[];
  executives: ExecutiveProfile[];
  channels: SocialChannel[];
  apiKeys: ApiKeyEntry[];
  urlScans: UrlScan[];
  domainScans: DomainScan[];
  reports: Report[];
  activity: ActivityItem[];
}

// --- Datos iniciales (se cargan en primer uso) ---
const seedData: Database = {
  brands: [
    { id: 'br1',  name: 'Bancolombia',         country: 'Colombia',    type: 'Bank',     domain: 'bancolombia.com',   status: 'active',  findings: 7  },
    { id: 'br2',  name: 'Banco AgroMercantil', country: 'Guatemala',   type: 'Bank',     domain: 'agromercantil.com', status: 'active',  findings: 3  },
    { id: 'br3',  name: 'Banco Agrícola',      country: 'El Salvador', type: 'Bank',     domain: 'bancoagricola.com', status: 'active',  findings: 4  },
    { id: 'br4',  name: 'Banistmo',            country: 'Panamá',      type: 'Bank',     domain: 'banistmo.com',      status: 'active',  findings: 2  },
    { id: 'br5',  name: 'Nequi',               country: 'Colombia',    type: 'Fintech',  domain: 'nequi.com',         status: 'flagged', findings: 11 },
    { id: 'br6',  name: 'Zaswin',              country: 'Colombia',    type: 'Fintech',  domain: 'zaswin.com',        status: 'active',  findings: 1  },
    { id: 'br7',  name: 'Renting',             country: 'Colombia',    type: 'Services', domain: 'renting.com.co',    status: 'active',  findings: 0  },
    { id: 'br8',  name: 'Suvalor',             country: 'Colombia',    type: 'Services', domain: 'suvalor.com',       status: 'active',  findings: 2  },
    { id: 'br9',  name: 'Wompi',               country: 'Colombia',    type: 'Fintech',  domain: 'wompi.co',          status: 'flagged', findings: 9  },
    { id: 'br10', name: 'Wenia',               country: 'Colombia',    type: 'Fintech',  domain: 'wenia.com',         status: 'flagged', findings: 6  },
  ],
  threats: [
    { id: 't1',  title: 'Phishing kit en login-nequi-seguro.tk imitando Nequi',           source: 'URL Forensics',        severity: 'critical', status: 'investigating', category: 'phishing',    detectedAt: '2026-06-18T17:33:00Z', confidence: 96 },
    { id: 't2',  title: 'App falsa "Nequi Bolsillos Pro" en Google Play',                 source: 'Brand Protection',     severity: 'high',     status: 'new',           category: 'brand_abuse', detectedAt: '2026-06-18T22:14:00Z', confidence: 88 },
    { id: 't3',  title: 'Credenciales del CTO de Wenia filtradas en darkweb',             source: 'Executive Protection', severity: 'critical', status: 'new',           category: 'data_leak',   detectedAt: '2026-06-19T04:02:00Z', confidence: 92 },
    { id: 't4',  title: 'Typosquat bancolombia-login.com registrado',                     source: 'Brand Protection',     severity: 'high',     status: 'investigating', category: 'domain',      detectedAt: '2026-06-19T03:18:00Z', confidence: 81 },
    { id: 't5',  title: 'APK de Wompi con malware firmado y distribuido en foros',        source: 'Sandbox',              severity: 'high',     status: 'investigating', category: 'malware',     detectedAt: '2026-06-18T15:20:00Z', confidence: 84 },
    { id: 't6',  title: 'Telegram @wenia_airdrop_scams vendiendo "doble saldo Wenia"',    source: 'Social Monitoring',    severity: 'critical', status: 'new',           category: 'social',      detectedAt: '2026-06-19T07:55:00Z', confidence: 79 },
    { id: 't7',  title: 'SSL caducado en api.bancoagricola.com',                          source: 'Domain Analysis',      severity: 'medium',   status: 'resolved',      category: 'domain',      detectedAt: '2026-06-17T11:00:00Z', confidence: 100 },
    { id: 't8',  title: 'Túnel DNS sospechoso detectado en subdominio de Banistmo',       source: 'Domain Analysis',      severity: 'medium',   status: 'investigating', category: 'domain',      detectedAt: '2026-06-18T09:42:00Z', confidence: 67 },
    { id: 't9',  title: 'Google dork expuso .env con API keys de Wompi en staging',       source: 'Google Dorking',       severity: 'critical', status: 'new',           category: 'data_leak',   detectedAt: '2026-06-19T05:11:00Z', confidence: 95 },
    { id: 't10', title: 'Falso @soporte_nequi en Twitter pidiendo credenciales',          source: 'Brand Protection',     severity: 'medium',   status: 'investigating', category: 'brand_abuse', detectedAt: '2026-06-18T14:30:00Z', confidence: 76 },
    { id: 't11', title: 'CVE-2026-4421 detectado en infraestructura expuesta de Wenia',   source: 'Domain Analysis',      severity: 'high',     status: 'investigating', category: 'malware',     detectedAt: '2026-06-18T13:09:00Z', confidence: 73 },
    { id: 't12', title: 'Sitio clon de Zaswin en zaswin-inversiones.net',                 source: 'Brand Protection',     severity: 'medium',   status: 'new',           category: 'brand_abuse', detectedAt: '2026-06-19T02:00:00Z', confidence: 68 },
    { id: 't13', title: 'Credenciales de empleado de Banco AgroMercantil en combolist',   source: 'Executive Protection', severity: 'high',     status: 'new',           category: 'data_leak',   detectedAt: '2026-06-18T20:42:00Z', confidence: 85 },
    { id: 't14', title: 'Dominio typosquat renting-colombia.com registrado',              source: 'Brand Protection',     severity: 'low',      status: 'investigating', category: 'domain',      detectedAt: '2026-06-18T08:11:00Z', confidence: 58 },
    { id: 't15', title: 'Canal de Discord vendiendo "cuentas Suvalor verificadas"',       source: 'Social Monitoring',    severity: 'high',     status: 'new',           category: 'social',      detectedAt: '2026-06-19T06:18:00Z', confidence: 82 },
  ],
  executives: [
    { id: 'e1', name: 'Juan Carlos Mora',       role: 'CEO',  company: 'Bancolombia',         exposedEmails: 3, exposedPhones: 1, leakedCredentials: 2, riskScore: 72, lastCheck: '2026-06-19T04:02:00Z', email: 'jc.mora@bancolombia.com.co', phone: '+57 310 555 0100', position: 'CEO', organization: 'Bancolombia', emailType: 'corporate', address: 'Carrera 48 # 26-85, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/juan-carlos-mora', handle: '@jcpmora', type: 'professional'}] },
    { id: 'e2', name: 'María Isabel Gutiérrez', role: 'CFO',  company: 'Bancolombia',         exposedEmails: 2, exposedPhones: 0, leakedCredentials: 1, riskScore: 54, lastCheck: '2026-06-19T04:02:00Z', email: 'm.gutierrez@bancolombia.com.co', phone: '+57 310 555 0101', position: 'CFO', organization: 'Bancolombia', emailType: 'corporate', address: 'Carrera 48 # 26-85, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/mariagutierrez', handle: '@migutierrez', type: 'professional'}] },
    { id: 'e3', name: 'Carlos Andrés Ruiz',     role: 'CTO',  company: 'Wenia',               exposedEmails: 5, exposedPhones: 2, leakedCredentials: 4, riskScore: 89, lastCheck: '2026-06-19T04:02:00Z', email: 'carlos.ruiz@wenia.com', phone: '+57 311 555 0200', position: 'CTO', organization: 'Wenia', emailType: 'both', address: 'Calle 26 # 4-60, Medellín', location: 'Medellín, Colombia', socialMedia: [{platform: 'GitHub', url: 'https://github.com/carlosruiz', handle: '@cruiz', type: 'technical'}, {platform: 'Twitter', url: 'https://twitter.com/cruiz_tech', handle: '@cruiz_tech', type: 'personal'}] },
    { id: 'e4', name: 'Ana Lucía Torres',       role: 'COO',  company: 'Nequi',               exposedEmails: 1, exposedPhones: 0, leakedCredentials: 0, riskScore: 32, lastCheck: '2026-06-19T04:02:00Z', email: 'ana.torres@nequi.com', phone: '+57 312 555 0300', position: 'COO', organization: 'Nequi', emailType: 'corporate', address: 'Carrera 7 # 24-32, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/anatorres', handle: '@atorres', type: 'professional'}] },
    { id: 'e5', name: 'Pedro Martín Herrera',   role: 'CISO', company: 'Wompi',               exposedEmails: 2, exposedPhones: 1, leakedCredentials: 1, riskScore: 61, lastCheck: '2026-06-19T04:02:00Z', email: 'pedro.herrera@wompi.co', phone: '+57 313 555 0400', position: 'CISO', organization: 'Wompi', emailType: 'corporate', address: 'Cra 13 # 93-40, Bogotá', location: 'Bogotá, Colombia', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/pedroherrera', handle: '@pherrera', type: 'professional'}] },
    { id: 'e6', name: 'Roberto Aguilar',        role: 'CEO',  company: 'Banco AgroMercantil', exposedEmails: 2, exposedPhones: 1, leakedCredentials: 1, riskScore: 58, lastCheck: '2026-06-19T04:02:00Z', email: 'r.aguilar@agromercantil.com', phone: '+57 314 555 0500', position: 'CEO', organization: 'Banco AgroMercantil', emailType: 'corporate', address: '16 Av. 1-23, Guatemala', location: 'Guatemala, Guatemala', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/robertoaguilar', handle: '@raguilar', type: 'professional'}] },
    { id: 'e7', name: 'Sofía Panameño',         role: 'CISO', company: 'Banco Agrícola',      exposedEmails: 1, exposedPhones: 0, leakedCredentials: 0, riskScore: 28, lastCheck: '2026-06-19T04:02:00Z', email: 'sofia.panameño@bancoagricola.com', phone: '+503 2222 0700', position: 'CISO', organization: 'Banco Agrícola', emailType: 'corporate', address: '25 Av. Nte. # 11-32, San Salvador', location: 'San Salvador, El Salvador', socialMedia: [] },
    { id: 'e8', name: 'Manuel Quintero',        role: 'CEO',  company: 'Banistmo',            exposedEmails: 2, exposedPhones: 1, leakedCredentials: 1, riskScore: 52, lastCheck: '2026-06-19T04:02:00Z', email: 'manuel.quintero@banistmo.com', phone: '+507 269 4500', position: 'CEO', organization: 'Banistmo', emailType: 'corporate', address: 'Calle 50 # 49-27, Ciudad de Panamá', location: 'Panamá, Panamá', socialMedia: [{platform: 'LinkedIn', url: 'https://linkedin.com/in/manuelquintero', handle: '@mquintero', type: 'professional'}] },
    { id: 'e9', name: 'Daniela Restrepo',       role: 'CEO',  company: 'Zaswin',              exposedEmails: 1, exposedPhones: 0, leakedCredentials: 0, riskScore: 24, lastCheck: '2026-06-19T04:02:00Z', email: 'daniela.restrepo@zaswin.com', phone: '+57 315 555 0900', position: 'CEO', organization: 'Zaswin', emailType: 'corporate', address: 'Carrera 9 # 12-45, Cali', location: 'Cali, Colombia', socialMedia: [] },
  ],
  channels: [
    { id: 's1', platform: 'Telegram', name: 'Nequi Scams',               identifier: '@nequi_scams_col',           members: 4821, messages: 8421, alerts: 27, status: 'flagged',    lastActivity: '2026-06-19T07:55:00Z' },
    { id: 's2', platform: 'Telegram', name: 'Wenia Airdrop Scams',       identifier: '@wenia_airdrop_scams',       members: 1209, messages: 3127, alerts: 14, status: 'flagged',    lastActivity: '2026-06-19T07:42:00Z' },
    { id: 's3', platform: 'Discord',  name: 'DB Marketplace',            identifier: 'db-marketplace',             members: 2188, messages: 5402, alerts:  9, status: 'monitoring', lastActivity: '2026-06-19T05:18:00Z' },
    { id: 's4', platform: 'Twitter',  name: 'Bancolombia Impersonators', identifier: 'search:Bancolombia+soporte', members: 0,    messages: 1429, alerts:  6, status: 'monitoring', lastActivity: '2026-06-19T04:00:00Z' },
    { id: 's5', platform: 'Reddit',   name: 'r/Panama — Banistmo',       identifier: 'r/Panama',                   members: 3412, messages: 2103, alerts:  2, status: 'monitoring', lastActivity: '2026-06-19T02:21:00Z' },
    { id: 's6', platform: 'Telegram', name: 'Wompi Carding',             identifier: '@wompi_carding_2026',        members:  894, messages:  410, alerts: 31, status: 'paused',     lastActivity: '2026-06-18T22:11:00Z' },
    { id: 's7', platform: 'Discord',  name: 'Suvalor Verified Sellers',  identifier: 'suvalor-market',             members:  612, messages:  391, alerts: 12, status: 'flagged',    lastActivity: '2026-06-19T06:18:00Z' },
  ],
  apiKeys: [
    { id: 'k1', provider: 'VirusTotal',        label: 'VT Production',     maskedKey: 'sk_live_51H8••••••••••••••••4a9c', status: 'active',       lastUsed: '2026-06-19T08:00:00Z', quotaUsed: 4123,  quotaTotal: 500000 },
    { id: 'k2', provider: 'AbuseIPDB',         label: 'AbuseIPDB Default', maskedKey: 'abc123••••••••••••••••7f02',       status: 'active',       lastUsed: '2026-06-19T07:55:00Z', quotaUsed: 142,   quotaTotal: 10000 },
    { id: 'k3', provider: 'Shodan',            label: 'Shodan Main',       maskedKey: 'SHO••••••••••••••••••2d8e',         status: 'active',       lastUsed: '2026-06-19T08:00:00Z', quotaUsed: 89,    quotaTotal: 1000 },
    { id: 'k4', provider: 'Censys',            label: 'Censys API',        maskedKey: 'CEN••••••••••••••••••b1a4',         status: 'unconfigured', lastUsed: '—' },
    { id: 'k5', provider: 'MobSF',             label: 'MobSF Sandbox',     maskedKey: 'MSF••••••••••••••••••9c3f',         status: 'active',       lastUsed: '2026-06-18T22:14:00Z' },
    { id: 'k6', provider: 'Telegram',          label: 'Telegram Bot',      maskedKey: '7424••••••••:AAE•••••••••••••••••', status: 'active',       lastUsed: '2026-06-19T07:55:00Z' },
  ],
  urlScans: [],
  domainScans: [],
  reports: [
    { id: 'g1', title: 'Executive Summary — Week 25 (11 marcas)', template: 'Executive Summary',       period: '2026-06-13 to 2026-06-19', generatedAt: '2026-06-19T07:00:00Z', status: 'ready',      size: '3.1 MB' },
    { id: 'g2', title: 'Technical Threat Report — June',          template: 'Technical Threat Report', period: '2026-06-01 to 2026-06-19', generatedAt: '2026-06-18T16:30:00Z', status: 'ready',      size: '8.4 MB' },
  ],
  activity: [
    { id: 'a1',  type: 'alert',   message: 'Phishing kit detectado imitando Nequi en login-nequi-seguro.tk',          severity: 'critical', timestamp: '2026-06-19T08:42:00Z', actor: 'System' },
    { id: 'a2',  type: 'scan',    message: 'Análisis de dominio completado para wompi-fake-checkout.com',             severity: 'medium',   timestamp: '2026-06-19T08:21:00Z', actor: 'scheduler' },
    { id: 'a3',  type: 'monitor', message: 'Canal Telegram @wenia_airdrop_scams publicó 47 mensajes flaggeados',     severity: 'high',     timestamp: '2026-06-19T07:55:00Z', actor: 'System' },
    { id: 'a4',  type: 'report',  message: 'Reporte ejecutivo semanal generado (PDF, 3.1 MB) — 11 marcas',            severity: 'info',     timestamp: '2026-06-19T07:00:00Z', actor: 'admin@datacyber.io' },
    { id: 'a5',  type: 'apikey',  message: 'API key de VirusTotal validada — quota 4123/500000',                      severity: 'info',     timestamp: '2026-06-19T06:30:00Z', actor: 'admin@datacyber.io' },
    { id: 'a6',  type: 'alert',   message: 'App falsa detectada imitando "Nequi Bolsillos" en Google Play',           severity: 'high',     timestamp: '2026-06-18T22:14:00Z', actor: 'System' },
    { id: 'a7',  type: 'login',   message: 'Login admin@datacyber.io (Administrator) — 181.46.x.x',                   severity: 'low',      timestamp: '2026-06-18T18:02:00Z', actor: 'admin@datacyber.io' },
    { id: 'a8',  type: 'scan',    message: 'Análisis forense de URL completado para https://wompi-pagos-seguros.tk', severity: 'critical', timestamp: '2026-06-18T17:33:00Z', actor: 'analyst@datacyber.io' },
  ],
};

// --- API pública ---
export function loadDb(): Database {
  if (typeof window === 'undefined') return seedData;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(seedData));
      return seedData;
    }
    return JSON.parse(raw);
  } catch {
    return seedData;
  }
}

export function saveDb(db: Database): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(db));
}

export function resetDb(): Database {
  if (typeof window === 'undefined') return seedData;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(seedData));
  return seedData;
}

export function genId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
