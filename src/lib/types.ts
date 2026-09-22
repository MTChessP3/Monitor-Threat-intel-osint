// ============================================================
// DataCyber — Tipos del dominio de inteligencia de ciberseguridad
// ============================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ThreatStatus = 'new' | 'investigating' | 'resolved' | 'false_positive';

export interface Kpi {
  label: string;
  value: number;
  delta: number;        // % cambio vs periodo anterior
  hint: string;
}

export interface TrendPoint {
  date: string; // ISO short
  threats: number;
  scans: number;
  mentions: number;
}

export interface ActivityItem {
  id: string;
  type: 'scan' | 'alert' | 'report' | 'monitor' | 'login' | 'apikey';
  message: string;
  severity: Severity;
  timestamp: string;
  actor: string;
}

export interface Threat {
  id: string;
  title: string;
  source: string;
  severity: Severity;
  status: ThreatStatus;
  category: 'phishing' | 'malware' | 'brand_abuse' | 'data_leak' | 'domain' | 'social';
  detectedAt: string;
  confidence: number; // 0..100
}

export interface BrandTarget {
  id: string;
  brand: string;
  type: 'domain' | 'appstore' | 'marketplace' | 'social';
  target: string;
  status: 'active' | 'inactive' | 'flagged';
  lastScan: string;
  findings: number;
}

export interface FakeApp {
  id: string;
  appName: string;
  developer: string;
  platform: 'Google Play' | 'App Store' | 'Third-party';
  impersonated: string;
  maliciousScore: number;
  detectedAt: string;
  status: 'pending' | 'reported' | 'removed';
}

export interface ExecutiveProfile {
  id: string;
  name: string;
  role: string;
  company: string;
  exposedEmails: number;
  exposedPhones: number;
  leakedCredentials: number;
  riskScore: number;
  lastCheck: string;
  // New fields
  identificationNum?: string;
  email?: string;
  phone?: string;
  position?: string;
  organization?: string;
  emailType?: 'personal' | 'corporate' | 'both';
  address?: string;
  location?: string;
  socialMedia?: Array<{platform: string; url: string; handle: string; type: string}>;
  notes?: string;
  active?: boolean;
}

export interface ExposureFinding {
  id: string;
  profileId: string;
  type: 'email' | 'phone' | 'credential' | 'document' | 'address';
  value: string;
  source: string;
  severity: Severity;
  detectedAt: string;
}

export interface SocialChannel {
  id: string;
  platform: 'Telegram' | 'Discord' | 'Twitter' | 'Reddit';
  name: string;
  identifier: string;
  members: number;
  messages: number;
  alerts: number;
  status: 'monitoring' | 'paused' | 'flagged';
  lastActivity: string;
}

export interface SocialMessage {
  id: string;
  channelId: string;
  author: string;
  content: string;
  timestamp: string;
  sentiment: 'positive' | 'neutral' | 'negative';
  flagged: boolean;
  keywords: string[];
}

export interface ForensicsAnalysis {
  id: string;
  url: string;
  submittedAt: string;
  status: 'completed' | 'processing' | 'queued';
  threatScore: number;
  redirects: number;
  finalUrl: string;
  ipAddress: string;
  ssl: { valid: boolean; issuer: string; validFrom: string; validTo: string };
  detections: { engine: string; verdict: string }[];
}

export interface DomainRecord {
  id: string;
  domain: string;
  registered: string;
  expires: string;
  registrar: string;
  dnsSec: boolean;
  reputation: number;
  openPorts: { port: number; service: string; risk: Severity }[];
  subdomains: string[];
  securityHeaders: { header: string; status: 'pass' | 'warn' | 'fail'; value: string }[];
  lastScan: string;
}

export interface DorkQuery {
  id: string;
  query: string;
  category: 'leaks' | 'exposure' | 'phishing' | 'infrastructure' | 'custom';
  results: number;
  lastRun: string;
  status: 'active' | 'paused';
}

export interface DorkResult {
  id: string;
  queryId: string;
  title: string;
  url: string;
  snippet: string;
  severity: Severity;
  detectedAt: string;
}

export interface ReportTemplate {
  id: string;
  name: string;
  type: 'executive' | 'technical' | 'compliance' | 'daily';
  description: string;
  lastGenerated: string;
  sections: string[];
}

export interface GeneratedReport {
  id: string;
  title: string;
  template: string;
  period: string;
  generatedAt: string;
  status: 'ready' | 'processing' | 'failed';
  size: string;
}

export interface ApiKeyEntry {
  id: string;
  provider: string;
  label: string;
  maskedKey: string;
  status: 'active' | 'invalid' | 'unconfigured';
  lastUsed: string;
  quotaUsed?: number;
  quotaTotal?: number;
}

export type ModuleKey =
  | 'dashboard'
  | 'brand-protection'
  | 'executive-protection'
  | 'social-monitoring'
  | 'url-forensics'
  | 'domain-analysis'
  | 'google-dorking'
  | 'threats'
  | 'reports'
  | 'settings';

export interface Brand {
  id: string;
  name: string;
  country: string;
  type: 'Bank' | 'Fintech' | 'Services';
  domain: string;
  status: 'active' | 'flagged' | 'inactive';
  findings: number;
}
