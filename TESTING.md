# Testing — NEXUS INTEL / MONITOR-THREAT

This document covers how to validate the platform, both automatically and manually, before shipping.

## Prerequisites

- Node.js 20+ or bun (the repo uses bun, but any Node runtime works)
- `bun install` (or `npm install`)

## Automated API tests

The API test suite exercises every module against a running server and verifies
the contract of each endpoint (status codes, response shape, persistence).

```bash
# 1. Start the dev server in one terminal
bun run dev

# 2. In another terminal, run the suite (defaults to http://localhost:3000)
node tests/api-tests.mjs

# or with a custom base URL
node tests/api-tests.mjs http://localhost:3001
```

Coverage:

- IP Intelligence (live ip-api.com lookup + validation)
- Domain Intelligence (Google DoH DNS)
- URL Scanner (risk scoring)
- Hash Lookup (MalwareBazaar / VirusTotal)
- CVE Database (NIST NVD)
- Threat Feeds (CISA KEV, MalwareBazaar, Abuse.ch)
- Dark Web Intel (OSINT reference matching + optional AI)
- AI Analyst (status + POST analysis; works in rule-based fallback without a key)
- IOC Manager (full CRUD: create, list, update, delete)
- Export (JSON, CSV, STIX 2.1 bundle)
- Reports (generate, list, HTML download)
- Intelligence Sources (list, health, add custom source)
- Forensics & Mobile (list + analysis)

### Manual API smoke tests

Quick curl checks while the server runs:

```bash
curl -s "http://localhost:3000/api/osint/ip?ip=8.8.8.8" | head -c 400
curl -s "http://localhost:3000/api/osint/domain?domain=google.com" | head -c 400
curl -s "http://localhost:3000/api/osint/threats?limit=5" | head -c 400
curl -s "http://localhost:3000/api/osint/export?format=stix" | head -c 400
```

## Frontend manual test checklist

Open http://localhost:3000 (or the Vercel deployment) and verify:

1. **Dashboard** — charts render, timeline ticks every 5s, stat cards show counts.
2. **IP Intel** — enter `8.8.8.8` → live geo/country data + "Add to IOCs" works.
3. **Domain Intel** — enter `google.com` → A/MX/NS/TXT records + SPF/DMARC badges.
4. **URL Scanner** — enter `https://example.com` → risk score and recommendations.
5. **Hash Lookup** — enter a 64-char hash → no crash, clean "not found" message.
6. **CVE Database** — search `log4j` → results table with CVSS severity.
7. **Threat Feeds** — load CISA KEV → live vulnerabilities table.
8. **Dark Web Intel** — search `acme` → matches + risk level.
9. **AI Analyst** — run an analysis; note `aiEnabled` badge. Without `GROQ_API_KEY`
   the result is labeled as rule-based; with a key it uses Llama 3.3 via Groq.
10. **IOC Manager** — add/edit/delete an IOC; restart the server → data persists
    only if KV env vars are configured (in-memory fallback otherwise).
11. **Export** — JSON / CSV / STIX downloads all return files.
12. **Reports** — generate a report, then open the "Generated Reports" history
    and download JSON/CSV/HTML.
13. **Intelligence Sources** — built-in sources listed, "Test" works, custom
    source can be added.
14. **Mobile / Forensics** — analyze `test.apk` and run forensics on a domain.

## CI-friendly commands

```bash
bunx tsc --noEmit     # type check
bun run lint          # eslint
bun run build         # production build
node tests/api-tests.mjs  # API contract tests (server must be running)
```

## Known behavior in "demo mode" (no env keys)

- **AI**: `aiEnabled=false`; analysis falls back to rule-based engines and is
  clearly labeled. Set `GROQ_API_KEY` (or `AI_API_KEY`) to enable real LLM
  analysis.
- **Persistence**: falls back to an in-memory store — data resets between
  cold starts. Configure Vercel KV (`KV_REST_API_URL`, `KV_REST_API_TOKEN`) to
  persist across serverless invocations.
- **NVD / VirusTotal**: optional API keys (`NVD_API_KEY`, `VIRUSTOTAL_API_KEY`)
  enable higher rate limits / richer data.
