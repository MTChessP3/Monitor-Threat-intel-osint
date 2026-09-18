// Shared types for the Domain Intel module.
// Each submodule (dns, whois, subdomains, infra, graph) produces a slice
// of this shape; the orchestrator (`index.ts`) assembles the full result.

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  data: string;
  priority?: number;
}

export interface DnsSection {
  A: DnsRecord[];
  AAAA: DnsRecord[];
  CNAME: DnsRecord[];
  MX: DnsRecord[];
  NS: DnsRecord[];
  TXT: DnsRecord[];
  SOA: DnsRecord[];
  CAA: DnsRecord[];
}

export interface EmailSecurity {
  hasSPF: boolean;
  spfRaw: string | null;
  spfMechanisms: string[];
  spfHardFail: boolean;
  hasDMARC: boolean;
  dmarcRaw: string | null;
  dmarcPolicy: string | null;
  hasDKIM: boolean;
  dkimSelectors: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  findings: string[];
}

export interface WhoisInfo {
  registrar: string | null;
  created: string | null;
  updated: string | null;
  expires: string | null;
  nameservers: string[];
  status: string[];
  registrantOrg: string | null;
  registrantCountry: string | null;
}

export interface SubdomainInfo {
  name: string;
  ips: string[];
  cname: string | null;
  source: 'ct' | 'brute';
}

export interface IpInfo {
  ip: string;
  reverse: string | null;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isp: string;
  org: string;
  asn: string;
  asname: string;
  lat: number;
  lon: number;
  hosting: boolean;
  proxy: boolean;
}

export interface MxHostInfo {
  host: string;
  priority: number;
  ip: string | null;
  asn: string | null;
  asname: string | null;
}

export type GraphNodeKind = 'domain' | 'subdomain' | 'ip' | 'mx' | 'asn' | 'ns';

export interface GraphNode {
  id: string;
  label: string;
  kind: GraphNodeKind;
  meta?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

export interface DomainGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RiskSignal {
  label: string;
  points: number;
  detail: string;
  kind: 'reputation' | 'security' | 'infrastructure' | 'age';
}

export interface DomainRisk {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  verdict: string;
  signals: RiskSignal[];
  recommendations: string[];
}

export interface DomainIntelResult {
  domain: string;
  timestamp: string;
  source: string;
  live: boolean;
  records: DnsSection;
  emailSecurity: EmailSecurity;
  whois: WhoisInfo | null;
  subdomains: SubdomainInfo[];
  ips: IpInfo[];
  mxHosts: MxHostInfo[];
  graph: DomainGraph;
  risk: DomainRisk;
  summary: string;
}
