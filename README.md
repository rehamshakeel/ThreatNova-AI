# ThreatNova AI

ThreatNova AI is a desktop-first cybersecurity investigation interface demo built with
Next.js App Router, React, TypeScript, Tailwind CSS, D3, and Lucide React.

## Run locally

Install dependencies and start the development server:

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Enter a display name to use the
local demo workspace, then submit a sample IP address, domain, URL, or file hash to
preview the simulated investigation workflow.

## Demo boundaries

- The analyst profile is a local display preference; there is no real authentication.
- Indicator validation is format-only. The scanning screen simulates six processing
  stages and makes no network requests or external API calls.
- Dashboard findings, relationships, confidence values, and risk scores are static
  demonstration data. Higher sample risk scores indicate higher estimated risk only
  within the illustrative dataset.
- Do not enter credentials, secrets, or sensitive indicators.

## Main routes and data

- `/` — analyst display-name entry.
- `/dashboard` — investigation form and overview dashboard.
- `/scanning` — local simulated workflow, reached from the dashboard form.
- `/graph` — interactive D3 sample relationship graph.
- `/findings` — demonstration findings with separate interpretation and sample evidence.
- `/intelligence` — static DNS, WHOIS, SSL/TLS, IP, and reputation fixtures.
- `/history` — searchable, filterable built-in sample investigation records.
- `/alerts` — sample alerts with locally saved reviewed status.
- `/settings` — analyst display name, local interface preferences, and demo reset.
- `lib/demo-data.ts` — static, clearly labeled demonstration records.
- `lib/indicators.ts` — indicator type labels and client/server format validation.
- `lib/integrations/contracts.ts` — frontend-facing interfaces for future data,
  enrichment, and explanation providers; no provider implementation is connected.

Python/FastAPI, SQLite, VirusTotal, and LLM services are not installed or called by
this frontend. No API keys or secrets are used.

## Checks

```bash
npm run lint
npm run build
```
