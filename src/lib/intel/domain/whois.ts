// WHOIS / RDAP lookup for the Domain Intel module.
// Uses the RDAP bootstrap (rdap.org) with JCard parsing. Free, no API key.

import type { WhoisInfo } from './types';

export async function lookupWhois(domain: string): Promise<WhoisInfo | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const rd = await res.json();

    const events = (rd.events || []) as any[];
    const eventDate = (action: string) => {
      const e = events.find((ev: any) => ev.eventAction === action);
      return e?.eventDate || null;
    };

    const entities = (rd.entities || []) as any[];
    const findVcard = (fn: string) => {
      for (const entity of entities) {
        const rows = entity?.vcardArray?.[1] || [];
        const match = rows.find((row: any) => String(row[1]).toLowerCase() === fn);
        if (match) return match[3];
      }
      return null;
    };
    const registrantCountry = (() => {
      for (const entity of entities) {
        const rows = entity?.vcardArray?.[1] || [];
        const adr = rows.find((row: any) => String(row[1]).toLowerCase() === 'adr');
        if (adr && Array.isArray(adr[3])) return adr[3][6] || null;
      }
      return null;
    })();

    return {
      registrar: findVcard('fn') || null,
      created: eventDate('registration'),
      updated: eventDate('last changed'),
      expires: eventDate('expiration'),
      nameservers: (rd.nameservers || []).map((n: any) => n.ldhName || n.unicodeName).filter(Boolean),
      status: rd.status || [],
      registrantOrg: findVcard('org') || null,
      registrantCountry,
    };
  } catch {
    return null;
  }
}

export function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86400000));
}

export function daysUntil(iso: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((t - Date.now()) / 86400000));
}
