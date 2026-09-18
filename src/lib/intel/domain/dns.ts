// DNS resolution + email-security analysis for the Domain Intel module.
// Uses Google DoH (dns.google) — free, no API key, JSON over HTTPS.

import type { DnsSection, DnsRecord, EmailSecurity } from './types';

const DOH = 'https://dns.google/resolve';
const QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'] as const;

export async function resolveType(domain: string, type: string): Promise<DnsRecord[]> {
  try {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    if (data.Status !== 0) return [];
    return (data.Answer || []).map((a: any) => ({
      name: a.name || domain,
      type,
      ttl: a.TTL ?? 0,
      data: String(a.data || ''),
      ...(type === 'MX' ? { priority: a.priority ?? 0 } : {}),
    }));
  } catch {
    return [];
  }
}

export async function resolveDns(domain: string): Promise<DnsSection> {
  const settled = await Promise.allSettled(QUERY_TYPES.map((t) => resolveType(domain, t)));
  const result = {} as DnsSection;
  QUERY_TYPES.forEach((t, i) => {
    result[t] = settled[i].status === 'fulfilled' ? settled[i].value : [];
  });
  return result;
}

// DKIM selectors commonly seen in the wild (Google, Microsoft, Amazon SES...).
const DKIM_SELECTORS = ['google', 'k1', 'selector1', 'selector2', 's1', 's2', 'default', 'dkim', 'mail', 'mxvault', 'zoho', 'amazonses', 'mailchimp', 'smtp', 'ems', 'mandrill', 'spf', 'm1', 'm2', 'protonmail'];

export async function analyzeEmailSecurity(domain: string): Promise<EmailSecurity> {
  const result: EmailSecurity = {
    hasSPF: false,
    spfRaw: null,
    spfMechanisms: [],
    spfHardFail: false,
    hasDMARC: false,
    dmarcRaw: null,
    dmarcPolicy: null,
    hasDKIM: false,
    dkimSelectors: [],
    riskLevel: 'MEDIUM',
    findings: [],
  };

  const txt = await resolveType(domain, 'TXT');
  const spf = txt.find((r) => /^v=spf1\b/i.test(r.data));
  if (spf) {
    result.hasSPF = true;
    result.spfRaw = spf.data;
    result.spfMechanisms = spf.data.split(/\s+/);
    const all = result.spfMechanisms.find((m) => /^[+~?-]?all$/.test(m)) || '';
    result.spfHardFail = all === '-all';
    result.findings.push(
      result.spfHardFail
        ? 'SPF with hard fail (-all) — strict email spoofing protection'
        : all === '~all'
          ? 'SPF soft fail (~all) — spoofing protection weakened'
          : 'SPF present but no enforce-all mechanism'
    );
  } else {
    result.findings.push('No SPF record detected — email spoofing possible');
  }

  const dmarc = await resolveType(`_dmarc.${domain}`, 'TXT');
  const dmarcRec = dmarc.find((r) => /^v=DMARC1/i.test(r.data));
  if (dmarcRec) {
    result.hasDMARC = true;
    result.dmarcRaw = dmarcRec.data;
    const policy = dmarcRec.data.match(/p=(\w+)/i);
    result.dmarcPolicy = policy ? policy[1].toLowerCase() : null;
    const pct = dmarcRec.data.match(/pct=(\d+)/i);
    const pctVal = pct ? parseInt(pct[1], 10) : 100;
    result.findings.push(
      result.dmarcPolicy === 'reject'
        ? 'DMARC reject policy — strong'
        : result.dmarcPolicy === 'quarantine'
          ? 'DMARC quarantine policy — moderate'
          : `DMARC ${result.dmarcPolicy || 'none'} (${pctVal}% applied) — weak`
    );
  } else {
    result.findings.push('No DMARC record detected — domain can be impersonated in email');
  }

  const selectors = await Promise.allSettled(
    DKIM_SELECTORS.map((s) =>
      resolveType(`${s}._domainkey.${domain}`, 'TXT').then((recs) =>
        recs.some((r) => r.data.includes('v=DKIM1') || /p=/.test(r.data)) ? s : null
      )
    )
  );
  selectors.forEach((s) => {
    if (s.status === 'fulfilled' && s.value) result.dkimSelectors.push(s.value);
  });
  result.hasDKIM = result.dkimSelectors.length > 0;
  if (result.hasDKIM) {
    result.findings.push(`DKIM found (selectors: ${result.dkimSelectors.join(', ')})`);
  } else {
    result.findings.push('No common DKIM selector found');
  }

  const failures = result.findings.filter((f) => /no|weak|missing/i.test(f)).length;
  result.riskLevel = failures >= 2 ? 'HIGH' : failures === 1 ? 'MEDIUM' : 'LOW';

  return result;
}
