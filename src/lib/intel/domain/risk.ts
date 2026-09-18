// Domain risk scoring for the Domain Intel module.
// Combines email-security posture, DNS signals, WHOIS age/expiry and
// infrastructure hosting flags into a 0-100 score with a verdict.

import type { DomainRisk, RiskSignal, DnsSection, EmailSecurity, WhoisInfo, IpInfo } from './types';
import { daysSince, daysUntil } from './whois';

// TLDs statistically over-represented in phishing/abuse registrations.
const HIGH_RISK_TLDS = ['xyz', 'top', 'click', 'work', 'loan', 'gq', 'tk', 'ml', 'cf', 'ga', 'zip', 'mov', 'icu', 'cn', 'ru', 'buzz', 'online', 'site', 'live'];

function add(signals: RiskSignal[], label: string, points: number, detail: string, kind: RiskSignal['kind']): void {
  signals.push({ label, points, detail, kind });
}

export function scoreDomain(params: {
  domain: string;
  records: DnsSection;
  email: EmailSecurity;
  whois: WhoisInfo | null;
  ips: IpInfo[];
  subdomainCount: number;
}): DomainRisk {
  const { domain, records, email, whois, ips, subdomainCount } = params;
  let score = 0;
  const signals: RiskSignal[] = [];

  const nxdomain = records.A.length === 0 && records.AAAA.length === 0 && records.NS.length === 0;
  if (nxdomain) {
    score += 25;
    add(signals, 'NXDOMAIN', 25, 'Domain does not resolve — likely parked, dead or flagged', 'infrastructure');
  }

  if (!email.hasSPF) {
    score += 12;
    add(signals, 'No SPF', 12, 'Domain can be spoofed in email (missing Sender Policy Framework)', 'security');
  } else if (email.spfHardFail) {
    score -= 3;
    add(signals, 'SPF hard fail', -3, 'Strict SPF (-all) reduces spoofing surface', 'security');
  }

  if (!email.hasDMARC) {
    score += 12;
    add(signals, 'No DMARC', 12, 'Domain can be impersonated — no DMARC policy to quarantine/reject', 'security');
  } else if (email.dmarcPolicy === 'reject') {
    score -= 3;
    add(signals, 'DMARC reject', -3, 'Strong DMARC policy configured', 'security');
  }

  if (!email.hasDKIM) {
    score += 6;
    add(signals, 'No DKIM', 6, 'No common DKIM selector found', 'security');
  }

  // WHOIS age / expiry
  const createdDays = whois ? daysSince(whois.created) : null;
  if (createdDays === null) {
    score += 5;
    add(signals, 'No WHOIS age', 5, 'WHOIS unavailable — cannot verify domain age', 'age');
  } else if (createdDays < 30) {
    score += 20;
    add(signals, 'Very young domain', 20, `Registered only ${createdDays} days ago (${whois!.created?.slice(0, 10)})`, 'age');
  } else if (createdDays < 180) {
    score += 8;
    add(signals, 'Young domain', 8, `Registered ${createdDays} days ago`, 'age');
  } else if (createdDays > 3650) {
    score -= 5;
    add(signals, 'Aged domain', -5, `Registered ${Math.floor(createdDays / 365)} years ago`, 'age');
  }

  const expiryDays = whois ? daysUntil(whois.expires) : null;
  if (expiryDays !== null && expiryDays < 30) {
    score += 8;
    add(signals, 'Expiring soon', 8, `Domain expires in ${expiryDays} days — common in squatting`, 'age');
  }

  // TLD reputation
  const tld = domain.split('.').pop()?.toLowerCase() || '';
  if (HIGH_RISK_TLDS.includes(tld)) {
    score += 10;
    add(signals, 'High-risk TLD', 10, `TLD .${tld} is over-represented in phishing campaigns`, 'reputation');
  }

  // Hyphens / punycode / digits — typosquat tell-tales
  const registrable = domain.split('.').slice(-2)[0] || domain;
  if (registrable.includes('-')) {
    score += 5;
    add(signals, 'Hyphenated label', 5, 'Hyphens in the registrable label are common in lookalike domains', 'reputation');
  }
  if (domain.startsWith('xn--')) {
    score += 10;
    add(signals, 'Punycode', 10, 'IDN/punycode domain — frequent in homograph phishing', 'reputation');
  }
  if (/\d/.test(registrable)) {
    score += 4;
    add(signals, 'Digits in label', 4, 'Numeric characters in label (e.g. paypa1) can indicate lookalike', 'reputation');
  }

  // Infrastructure flags
  const hostingCount = ips.filter((i) => i.hosting).length;
  if (hostingCount > 0) {
    score += 5;
    add(signals, 'Hosting IP', 5, `${hostingCount} IP(s) hosted on cloud/data-center ranges`, 'infrastructure');
  }
  const proxyCount = ips.filter((i) => i.proxy).length;
  if (proxyCount > 0) {
    score += 8;
    add(signals, 'Proxy/VPN IP', 8, `${proxyCount} IP(s) flagged as proxy/VPN/anonymizer`, 'infrastructure');
  }
  const sharedAsn = ips.some((i) => i.asn) && ips.filter((i) => i.asn).length === 1;
  if (sharedAsn && ips.length > 1) {
    // All infra under one ASN is normal; no penalty.
  }

  if (subdomainCount >= 30) {
    score += 4;
    add(signals, 'Large attack surface', 4, `${subdomainCount} subdomains discovered`, 'infrastructure');
  }

  score = Math.max(0, Math.min(100, score));
  const level: DomainRisk['level'] = score >= 70 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';

  const recommendations: string[] = [];
  if (score >= 50) {
    recommendations.push('Do NOT visit or interact with this domain without isolation');
    recommendations.push('Block at DNS/perimeter level and monitor for internal access attempts');
    recommendations.push('Report to abuse registrars (abusedlookup via APWG / registrar abuse desk)');
  } else if (score >= 25) {
    recommendations.push('Treat email from this domain with caution — verify sender identity independently');
    recommendations.push('Monitor for internal lookups and login attempts');
  } else {
    recommendations.push('Low risk posture — standard monitoring applies');
  }
  if (!email.hasSPF || !email.hasDMARC) {
    recommendations.push('Domain has no authenticated email — any message claiming to be from it may be spoofed');
  }

  const verdict =
    score >= 70
      ? 'High-confidence malicious/squatting indicators — escalate immediately.'
      : score >= 50
        ? 'Multiple suspicious indicators — treat as untrusted until proven otherwise.'
        : score >= 25
          ? 'Some caution indicators present — review before trusting.'
          : 'No significant suspicious indicators detected.';

  return { score, level, verdict, signals, recommendations };
}
