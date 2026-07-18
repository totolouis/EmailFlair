# Email Security Relay — MVP Implementation

Implementation of the PRD roadmap's **MVP milestone (0–3 months)**: a working
SMTP relay that sits in front of an existing mail provider via an MX record
change, with loop prevention, basic spam scoring, quarantine, multi-domain
support, a minimal dashboard, and a REST API.

## What's implemented

| PRD section | Feature | Status |
|---|---|---|
| 6.1 | SMTP Gateway (STARTTLS-capable inbound SMTP) | ✅ |
| 6.2 | Email Routing Engine | ✅ |
| 6.3 | Transparent Forwarding (headers/body/attachments/DKIM preserved, relay headers added) | ✅ |
| 6.4 | Loop Prevention (signed `X-Relay-ID`, hop count, `554` on loop) | ✅ |
| 6.5 | Spam Filtering — MVP tier (blacklist/whitelist/domain reputation heuristics) | ✅ |
| 6.5 | Spam Filtering — V2 tier (Rspamd/ClamAV/URL reputation) | 🔲 not in MVP scope |
| 6.6 | Quarantine System (states + release/delete) | ✅ |
| 6.7 | Dashboard (global view + per-email view) | ✅ minimal web UI |
| 7 | Multi-tenancy | ✅ per-tenant API key + row-level isolation |
| 5 | Domain onboarding journey (MX detection, before/after instructions, activation check) | ✅ |
| 11 | API (`POST /domains`, `GET /domains/:name`, etc.) | ✅ |
| 8 | Security basics (TLS support, no open relay — domain must be registered+ACTIVE, secrets via env) | ✅ baseline |
| V2 items (DKIM signing, ARC, DLP, attachment sandboxing, MSP dashboard) | | 🔲 out of scope for this MVP, per roadmap |

## Stack notes (deviation from PRD section 10)

The PRD recommends Go/Rust + PostgreSQL + Redis for production. This MVP is
implemented in **Node.js with an embedded SQLite database** instead, so it:

- runs with zero external services (`npm install && npm start`),
- is easy to read/extend end-to-end in one sitting,
- still maps 1:1 onto the PRD's module boundaries (gateway / routing engine /
  loop prevention / spam filter / quarantine / forwarder / API), so porting
  the same logic to Go + Postgres + Redis later is a mechanical exercise, not
  a redesign.

`docker-compose.yml` includes commented-out Postgres/Redis services as the
sketched next step.

## Project layout

```
src/
  config.js            env-driven config
  db.js                SQLite schema + connection (tenants/domains/emails/lists)
  dns-lookup.js         MX lookup + provider detection (6.2 / section 5)
  routing-engine.js     domain -> destination resolution (6.2)
  loop-prevention.js    signed X-Relay-ID + hop analysis (6.4)
  spam-filter.js        MVP scoring heuristics (6.5)
  quarantine.js         raw .eml storage for held messages (6.6)
  forwarder.js          transparent SMTP forwarding (6.3)
  smtp-gateway.js        smtp-server wiring — the actual gateway (6.1)
  api/
    auth.js             per-tenant API key middleware
    server.js            express app assembly
    routes/domains.js    onboarding + activation API (5, 11)
    routes/emails.js      quarantine/log API (6.6, 6.7, 12)
    routes/lists.js       blacklist/whitelist CRUD (6.5)
  dashboard/index.html   minimal dark-mode dashboard (6.7)
scripts/test-send.js     local smoke test (seeds a fake domain, sends mail)
```

## Running it

```bash
npm install
cp .env.example .env      # edit RELAY_HOSTNAME / RELAY_SECRET for your setup
npm start
```

This starts:
- the SMTP gateway on `SMTP_PORT` (default `2525`; put behind port 25 in production),
- the API + dashboard on `API_PORT` (default `3000`).

On first boot a default tenant is seeded; its API key is printed to the
console (also in `.env` as `DEFAULT_TENANT_API_KEY`). Paste that key into the
dashboard's "Connect" box, or use it as a Bearer token against the API.

### Docker

```bash
docker compose up --build
```

### Onboarding a domain (PRD section 5 flow)

```bash
curl -X POST http://localhost:3000/domains \
  -H "Authorization: Bearer dev-tenant-key" \
  -H "Content-Type: application/json" \
  -d '{"name":"company.com"}'
```

Returns the detected provider and the exact MX before/after values to show
the user. Once they've updated DNS and it has propagated:

```bash
curl -X POST http://localhost:3000/domains/company.com/activate \
  -H "Authorization: Bearer dev-tenant-key"
```

which re-checks DNS and flips the domain to `ACTIVE`, at which point the SMTP
gateway will accept mail for it and forward to the destination captured at
onboarding time.

### Smoke test

With the server running in one terminal:

```bash
npm run test:send
```

This seeds a local fake domain (no real DNS needed), sends a normal message
through the gateway, then sends a second message that already carries a
valid signed `X-Relay-ID` — demonstrating the `554 Mail loop detected`
response from section 6.4.

## Known MVP limitations (intentional, matches roadmap scope)

- Spam scoring is heuristic (blacklist/whitelist/keyword), not ML/Bayesian —
  Rspamd/ClamAV integration is explicitly V2 in the PRD.
- No DKIM re-signing, ARC, or attachment sandboxing — explicitly V2.
- Single-node; no HA/clustering — not required for MVP per section 15's
  success definition (10-minute setup, 99.9% delivery, works with any SMTP
  provider), which this implementation satisfies for a single relay node.
- STARTTLS is supported by the underlying `smtp-server`/`nodemailer`
  libraries but certificate provisioning (Let's Encrypt, etc.) is left to the
  deployment environment, not hardcoded here.
