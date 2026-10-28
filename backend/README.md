# ThreatNova AI - FastAPI Backend Service

Autonomous threat investigation orchestration, multi-source intelligence correlation, VirusTotal v3 querying, explainable risk scoring, and D3 graph topology generation for the ThreatNova AI investigation platform.

---

## 🛡️ Architecture & Features

- **FastAPI Framework**: High-performance asynchronous REST API with auto-generated OpenAPI documentation (`/docs` and `/redoc`).
- **SQLite with SQLAlchemy ORM**: Lightweight, zero-config local persistence storing investigations, granular risk factors, findings evidence, and graph relationships.
- **Reliable Configuration Discovery**: Automatically resolves `backend/.env` regardless of whether execution is initiated from the project root or the `backend` folder.
- **VirusTotal v3 Integration**: Real-time indicator reputation lookups using official `x-apikey` authentication with strict request timeouts, rate-limit defense, and automatic fallback to verified demo intelligence fixtures when no API key is supplied.
- **Autonomous AI Analysis**: Synthesizes structured executive summaries and actionable defensive recommendations via OpenAI, Anthropic, or Gemini, with an autonomous rule-based heuristic reasoning fallback when keys are omitted.
- **Provider Status & Verification**: Dedicated `/health` and `/api/health/integrations` diagnostics that clearly distinguish between missing keys, unverified configurations, successful authentications, unauthorized keys, and rate limits without exposing secrets.
- **Explainable Risk Scoring Engine**: Deterministic, mathematical risk scoring (0–100) that produces itemized, human-auditable risk factors rather than black-box numbers.
- **Multi-Source Enrichment**: DNS record resolution, WHOIS registration timeline inspection, TLS/SSL certificate verification, and IP Geolocation / ASN classification.
- **D3 Graph Topology Generator**: Automatic transformation of indicators, domains, IPs, ASNs, and threat actors into force-directed graph nodes and links for interactive visual correlation.
- **CORS Configured**: Pre-configured whitelist for Next.js frontend running on `http://localhost:3000`, `http://localhost:3001`, and `http://localhost:3002`.

---

## 📁 Directory Structure

```text
backend/
├── app/
│   ├── models/
│   │   ├── __init__.py
│   │   └── investigation.py      # SQLAlchemy DB models (investigations, findings)
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── health.py             # Health check & integration diagnostics (/health, /api/health/integrations)
│   │   ├── indicators.py         # On-demand indicator lookup (/api/indicators/{type}/{value})
│   │   └── investigations.py     # Investigation CRUD, graph, and analysis endpoints
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── investigation.py      # Pydantic schemas aligned with frontend lib/types.ts
│   ├── services/
│   │   ├── __init__.py
│   │   ├── correlator.py         # D3 force-directed threat graph generator
│   │   ├── enrichment.py         # DNS, WHOIS, TLS, and GeoIP enrichment
│   │   ├── integration_status.py # Safe provider authentication verification
│   │   ├── llm_analysis.py       # OpenAI, Anthropic, Gemini & heuristic synthesis
│   │   ├── risk_scorer.py        # Transparent, explainable risk calculation
│   │   ├── validator.py          # Input validation & indicator normalization
│   │   └── virustotal.py         # VirusTotal v3 client with demo fixtures
│   ├── config.py                 # Pydantic BaseSettings loading backend/.env
│   ├── database.py               # SQLite engine, session, and table initialization
│   └── main.py                   # Application entrypoint & CORS middleware
├── tests/
│   ├── conftest.py               # Pytest DB setup fixtures
│   ├── test_config_and_integrations.py # Mocked integration status & error tests
│   ├── test_health.py            # Health and root endpoint verification
│   ├── test_investigations.py    # CRUD, graph, analysis, and validation tests
│   ├── test_risk_scorer.py       # Deterministic risk engine scoring tests
│   └── test_validation.py        # Multi-type indicator normalization tests
├── .env.example                  # Environment configuration template
├── .gitignore                    # Python artifacts and database ignores
├── requirements.txt              # Production and test dependencies
└── README.md                     # Backend documentation
```

---

## ⚙️ Environment Configuration (`backend/.env`)

Copy `.env.example` to `.env` in the `backend/` directory:

```powershell
# Windows PowerShell
cd backend
Copy-Item .env.example .env
```

### 1. VirusTotal v3 Configuration

* **Environment Variable**: `VIRUSTOTAL_API_KEY`
* **Format**: 64-character hexadecimal API key
* **Source**: Obtain from [VirusTotal API Key Settings](https://www.virustotal.com/gui/my-apikey)
* **Authentication**: Sent via `x-apikey: <key>` header on all requests
* **Supported Indicators**:
  * IP Addresses: `GET /api/v3/ip_addresses/{ip}`
  * Domains: `GET /api/v3/domains/{domain}`
  * File Hashes (MD5, SHA-1, SHA-256): `GET /api/v3/files/{hash}`
  * URLs: `GET /api/v3/urls/{base64_url_no_padding}`
* **Fallback**: If omitted or blank, ThreatNova AI operates safely in demonstration mode (`isDemo: true`), returning verified threat intelligence fixtures without making external requests.

### 2. LLM Provider Configuration

ThreatNova AI supports three major external LLM providers and an autonomous local heuristic engine:

| `LLM_PROVIDER` | `LLM_API_KEY` Format | Recommended `LLM_MODEL` | Official Endpoint |
|---|---|---|---|
| `none` *(default)* | *(leave blank)* | *(leave blank)* | Local deterministic heuristic engine (0 external calls, 0 cost) |
| `openai` | `sk-...` or `sk-proj-...` | `gpt-4o-mini` *(or `gpt-4o`, `gpt-4-turbo`)* | `POST https://api.openai.com/v1/chat/completions` |
| `anthropic` | `sk-ant-...` | `claude-3-5-sonnet-20241022` *(or `claude-3-5-haiku-20241022`)* | `POST https://api.anthropic.com/v1/messages` |
| `gemini` | `AIzaSy...` | `gemini-1.5-flash` *(or `gemini-2.0-flash`, `gemini-1.5-pro`)* | `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` |

#### Example: OpenAI Configuration
```ini
LLM_PROVIDER=openai
LLM_API_KEY=sk-proj-your-actual-openai-api-key-here
LLM_MODEL=gpt-4o-mini
```

#### Example: Google Gemini Configuration
```ini
LLM_PROVIDER=gemini
LLM_API_KEY=AIzaSyYourActualGeminiApiKeyHere
LLM_MODEL=gemini-1.5-flash
```

#### Example: Local Heuristic Fallback (Zero Credentials)
```ini
LLM_PROVIDER=none
LLM_API_KEY=
LLM_MODEL=
```

---

## 🔍 Integration Health & Authentication Diagnostics

ThreatNova AI strictly separates configured status from verified upstream authentication.

### Status Classifications

| Status Label | Meaning |
|---|---|
| `KEY MISSING` | Variable is unset, empty, or whitespace. Backend safely uses local demonstration fixtures or heuristic analysis. |
| `KEY CONFIGURED, NOT VERIFIED` | Key is present in `backend/.env`, but no live upstream verification ping was requested yet. |
| `AUTHENTICATION SUCCESSFUL` | Minimal read-only ping succeeded with HTTP 200 against provider API. |
| `INVALID KEY / UNAUTHORIZED` | Provider rejected credentials with HTTP 401 / 403. |
| `QUOTA OR RATE LIMIT EXCEEDED` | Provider returned HTTP 429 (rate limit or credit exhaustion). |
| `NETWORK OR PROVIDER ERROR` | Connection timeout or upstream provider connectivity failure. |

### Diagnostic Endpoints

* **Standard Health Check**: `GET /health` or `GET /api/health`
  Returns current system health and integration status without making external calls.
* **Live Authentication Check**: `GET /health?verify=true` or `GET /api/health/integrations?verify=true`
  Executes a minimal, safe, read-only authentication check against configured providers:
  * VirusTotal: `GET /api/v3/ip_addresses/8.8.8.8`
  * OpenAI: `GET /v1/models` (0 tokens, read-only model list)
  * Anthropic: `GET /v1/models`
  * Gemini: `GET /v1beta/models`

#### Sample Response (`GET /health` with keys unconfigured):
```json
{
  "status": "ok",
  "version": "1.0.0",
  "database": "connected",
  "virustotalConfigured": false,
  "llmConfigured": false,
  "llmProvider": "none",
  "timestamp": "2026-10-27T09:23:51.165985+00:00",
  "integrations": {
    "virustotal": {
      "status": "KEY MISSING",
      "configured": false,
      "authenticated": false,
      "mode": "demo_fixture",
      "detail": "VIRUSTOTAL_API_KEY is not configured. ThreatNova AI is utilizing verified demonstration fixtures.",
      "provider": "virustotal"
    },
    "llm": {
      "status": "KEY MISSING",
      "configured": false,
      "authenticated": false,
      "mode": "heuristic_fallback",
      "detail": "No external LLM credentials configured. ThreatNova AI autonomous rule-based heuristic reasoning engine is active.",
      "provider": "none"
    }
  }
}
```

---

## 🧪 Automated Testing

Run the full pytest suite:

```powershell
cd backend
python -m pytest -v
```

All 29 tests validate:
* Empty string normalization to `None` and case-insensitive provider normalization.
* Missing credentials handling (graceful demo fixture and heuristic fallback).
* Mocked provider responses: `AUTHENTICATION SUCCESSFUL` (200), `INVALID KEY / UNAUTHORIZED` (401), `QUOTA OR RATE LIMIT EXCEEDED` (429), and network timeouts.
* **Zero paid requests**: Automated tests mock all upstream HTTP calls, ensuring no API quota or tokens are consumed during tests.
* Full investigation CRUD, D3 graph, risk calculation, and multi-indicator canonicalization.

---

## 🚀 Running the Backend Server

```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

* **Interactive Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **ReDoc Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
* **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)
* **Integration Verification**: [http://localhost:8000/api/health/integrations?verify=true](http://localhost:8000/api/health/integrations?verify=true)
