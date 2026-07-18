# Email Security Relay

SMTP security gateway that sits in front of any existing mail provider via MX record change ("Cloudflare for Email"). Inbound mail flows through this relay for spam filtering, loop prevention, and quarantine before being forwarded to your actual mail provider.

## Architecture

```
   ┌──────────┐    SMTP 25    ┌───────────────────────────────────────────────┐    SMTP     ┌──────────────┐
   │  Sender   │ ────────────▶│  Traefik v3 (edge proxy)                      │ ──────────▶│  Destination │
   │  MTA      │              │  ┌────────────────┐                            │            │  MX (Gmail,  │
   └──────────┘               │  │ Port 25 (TCP)  │── passthrough ──┐         │            │  Outlook...) │
                              │  │ Port 465 (SMTPS)│── TLS term. ──┐│         │            └──────────────┘
                              │  │ Port 80  (HTTP) │── ACME proxy ─┤│         │
                              │  │ Port 443 (HTTPS)│── TLS term. ──┤├─────────┤
                              │  └────────────────┘               ││         │
                              └───────────────────────────────────││─────────┘
                                                                  ▼▼
                                           ┌─────────────────────────────────────────────┐
                                           │  Relay (internal, no public ports)           │
                                           │  ┌────────────────────────────────────┐      │
                                           │  │ smtp-server (port 2525)             │      │
                                           │  │ ↓  onRcptTo → RoutingEngine        │      │
                                           │  │ ↓  onData   → LoopPrevention       │      │
                                           │  │              → SpamFilter          │      │
                                           │  │              → Quarantine          │      │
                                           │  │              → Forwarder           │      │
                                           │  └────────────────────────────────────┘      │
                                           │  ┌────────────────────────────────────┐      │
                                           │  │ Express.js (port 3000)              │      │
                                           │  │ /domains, /emails, /lists, dashb.  │      │
                                           │  │ /.well-known/acme-challenge/*      │      │
                                           │  └────────────────────────────────────┘      │
                                           │  ┌────────────────────────────────────┐      │
                                           │  │ AcmeManager (embedded Let's Encrypt)│      │
                                           │  │ → CertStore (PEM file I/O)         │      │
                                           │  │ → 24h renewal timer (<30d)         │      │
                                           │  └────────────────────────────────────┘      │
                                           └─────────────────────────────────────────────┘
```

Built with **SOLID** principles: single-responsibility services, dependency injection via constructor/export, repository pattern for data access, and interface segregation through TypeScript interfaces.

## What you need before starting

Running this relay in production requires three things you must set up yourself:

1. **A server** with a public IP and port 25 (SMTP) accessible from the internet. You cannot run this behind a residential ISP (they block port 25). Use a VPS from DigitalOcean, Linode, AWS, etc.

2. **A domain name** that you own and control DNS for. This domain serves as your relay hostname (what you put in `RELAY_HOSTNAME`). For example, if you own `emailrelay.com`, you'd set `RELAY_HOSTNAME=mx1.emailrelay.com` and create an **A record** pointing `mx1.emailrelay.com` to your server's public IP.

3. **Your customers' domains** — each domain you want to protect (e.g. `customer.com`) must be registered via the API and have its MX record updated to point at your relay hostname (see [Domain onboarding flow](#domain-onboarding-flow) below).

If you just want to try the app locally for development, skip the server and domain — it runs fine on localhost for testing.

## Quick start (local dev)

```bash
npm install
cp .env.example .env        # edit RELAY_SECRET for your environment
npm run build               # compile TypeScript → dist/
npm start                   # starts SMTP gateway + API + dashboard
```

On first boot a default tenant is seeded. The API key is shown in the console output, and also available via `DEFAULT_TENANT_API_KEY` (default: `dev-tenant-key`).

Use that key as a Bearer token in API requests, or paste it into the dashboard's "Connect" box at `http://localhost:3000/`.

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `RELAY_ID` | `relay-01` | Identity of this relay node, used in headers |
| `RELAY_SECRET` | `dev-secret-do-not-use-in-prod` | HMAC key for loop detection signatures (min 8 chars, not `change-me`) |
| `RELAY_HOSTNAME` | `mx1.emailrelay.com` | Public hostname users point their MX record to |
| `SMTP_PORT` | `2525` | Inbound SMTP port (map to 25 behind a firewall in production) |
| `API_PORT` | `3000` | REST API + dashboard HTTP port |
| `SPAM_QUARANTINE_THRESHOLD` | `5` | Messages scoring ≥ this are quarantined (held for review) |
| `SPAM_REJECT_THRESHOLD` | `10` | Messages scoring ≥ this are rejected outright (554) |
| `DB_PATH` | `./data/relay.db` | SQLite database file path |
| `QUARANTINE_DIR` | `./data/quarantine` | Directory for quarantined `.eml` files |
| `DEFAULT_TENANT_NAME` | `Default Tenant` | Name of the auto-seeded tenant |
| `DEFAULT_TENANT_API_KEY` | `dev-tenant-key` | API key for the auto-seeded tenant |
| `TLS_ACME_ENABLED` | `false` | Enable automatic Let's Encrypt cert provisioning for SMTP STARTTLS |
| `TLS_ACME_EMAIL` | `admin@example.com` | Contact email for Let's Encrypt account registration |
| `TLS_ACME_STORAGE` | `./data/acme` | Directory to store ACME-issued certs and account key |
| `SMTP_TLS_PORT` | `465` | Port for SMTPS (used by Traefik for TLS termination) |

## Docker (production)

```bash
docker compose up --build
```

Two containers start:

- **traefik** — edge proxy exposing ports 25 (SMTP), 465 (SMTPS), 80 (HTTP), 443 (HTTPS). It terminates TLS for SMTPS and HTTPS using Let's Encrypt certs (TLS-ALPN-01). Routes `/.well-known/acme-challenge/` requests to the relay's HTTP-01 challenge handler.
- **relay** — internal service on ports 2525 (SMTP backend) and 3000 (API backend). Only Traefik can reach these ports. Embeds the `AcmeManager` which auto-provisions STARTTLS certs via HTTP-01.

The Dockerfile uses a multi-stage build: compile TypeScript in a full Node image, then copy only `dist/` and production dependencies into a slim runtime image.

## TLS & Let's Encrypt

This relay uses a **two-certificate strategy**:

### 1. HTTPS API + SMTPS (Traefik handles these)

Traefik exposes ports 443 and 465 with TLS termination, using Let's Encrypt via **TLS-ALPN-01** challenge (port 443 only). Configured in `traefik/traefik.yml`:

```yaml
certificatesResolvers:
  letsencrypt:
    acme:
      email: "${TLS_ACME_EMAIL}"
      storage: /certs/acme.json
      tlsChallenge: {}
```

The HTTPS API and SMTPS connections get their certs from Traefik automatically.

### 2. SMTP STARTTLS (relay handles this)

Traefik **passes through** port 25 TCP to the relay (no TLS termination). The relay uses the embedded `AcmeManager` to provision its own cert via **HTTP-01** challenge:

1. Traefik routes `/.well-known/acme-challenge/*` to the relay's Express app.
2. `AcmeManager` requests a cert from Let's Encrypt for `RELAY_HOSTNAME`.
3. Let's Encrypt validates via the HTTP-01 challenge endpoint.
4. The cert is saved to `TLS_ACME_STORAGE` and loaded into the SMTP server.
5. Every 24 hours the cert is checked; if <30 days remain, it renews automatically.
6. On renewal, the SMTP server is gracefully closed and restarted with the new cert.

### Enable TLS

```bash
export TLS_ACME_ENABLED=true
export TLS_ACME_EMAIL=admin@yourdomain.com
export RELAY_HOSTNAME=mx1.yourdomain.com
docker compose up --build
```

> **Note:** Let's Encrypt requires your server to be publicly reachable on port 80 (for HTTP-01) and port 443 (for TLS-ALPN-01). The first issuance takes a few seconds.

## Domain onboarding flow

### 1. Register a domain

```bash
curl -X POST http://localhost:3000/domains \
  -H "Authorization: Bearer dev-tenant-key" \
  -H "Content-Type: application/json" \
  -d '{"name":"yourcompany.com"}'
```

The relay looks up your domain's current MX records, detects the mail provider (Google Workspace, Microsoft 365, ProtonMail, OVH, etc.), and returns the current MX value along with instructions to update DNS.

### 2. Update your MX record

Change your domain's MX record to point to `RELAY_HOSTNAME` (default `mx1.emailrelay.com`). Keep TTL low during propagation.

### 3. Activate the domain

```bash
curl -X POST http://localhost:3000/domains/yourcompany.com/activate \
  -H "Authorization: Bearer dev-tenant-key"
```

The relay re-checks DNS. If the MX record now points to the relay, the domain is set to `ACTIVE` and begins accepting mail.

## REST API

All endpoints (except `/health` and `/`) require `Authorization: Bearer <api-key>` header.

### Domains

| Method | Path | Description |
|---|---|---|
| `POST` | `/domains` | Register a new domain (triggers MX lookup) |
| `GET` | `/domains` | List all domains for this tenant |
| `GET` | `/domains/:name` | Get domain details + MX instructions |
| `POST` | `/domains/:name/activate` | Verify DNS propagation and activate domain |
| `DELETE` | `/domains/:name` | Remove a domain |

### Emails

| Method | Path | Description |
|---|---|---|
| `GET` | `/emails` | List emails (supports `?status=`, `?domain=`, `?limit=`) |
| `GET` | `/emails/summary` | Aggregated counts by status + active domain count |
| `GET` | `/emails/:id` | Get email details (includes parsed headers) |
| `POST` | `/emails/:id/release` | Release a quarantined email (forward to destination) |
| `DELETE` | `/emails/:id` | Delete an email record (cleans up quarantine file) |

### Lists (blacklist/whitelist)

| Method | Path | Description |
|---|---|---|
| `GET` | `/lists/:table` | List entries (`:table` = `blacklist` or `whitelist`) |
| `POST` | `/lists/:table` | Add entry (`{"type": "ip"|"domain", "value": "..."}`) |
| `DELETE` | `/lists/:table/:id` | Remove an entry |

Blacklisted senders add +10 to spam score. Whitelisted senders bypass scoring entirely (score = 0).

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Returns `{"ok": true}` |
| `GET` | `/` | Dashboard UI (static HTML) |

## Spam scoring

The MVP spam filter uses heuristic scoring:

| Criteria | Points |
|---|---|
| Sender IP is blacklisted | +10 |
| Sender domain is blacklisted | +10 |
| Suspicious keyword in subject | +2 each |
| Malformed sender address | +3 |
| Message has attachments | +0.5 |
| Sender is whitelisted | score = 0 (overrides all) |

Thresholds are configurable via `SPAM_QUARANTINE_THRESHOLD` (default 5) and `SPAM_REJECT_THRESHOLD` (default 10).

## Dashboard

A minimal dark-mode dashboard is served at `/`. Paste your API key in the "Connect" box to view domains, quarantined emails, and release/delete messages.

## Development

### Project structure

```
src/
  config.ts                    Environment-driven configuration
  interfaces/                  TypeScript interfaces for all domain objects
  services/
    DatabaseService.ts         SQLite connection + schema migrations
    DatabaseMigrations.ts      Table creation + indexes
    DnsLookupService.ts        MX lookup + provider detection
    RoutingEngineService.ts    Domain → destination MX resolution
    LoopPreventionService.ts   Signed headers + hop count analysis
    SpamFilterService.ts       Heuristic scoring (blacklist/whitelist/keywords)
    QuarantineService.ts       .eml file storage + retrieval
    ForwarderService.ts        Nodemailer-based SMTP forwarding
  tls/
    CertStore.ts               PEM file I/O + cert expiry detection
    AcmeManager.ts             ACME lifecycle (account, CSR, HTTP-01, renewal)
  repositories/
    TenantRepository.ts        Tenant data access (API key lookup)
    DomainRepository.ts        Domain CRUD (with tenant isolation)
    EmailRepository.ts         Email log CRUD + filtering
    ListRepository.ts          Blacklist/whitelist CRUD
  middleware/
    AuthMiddleware.ts          Bearer token → tenant resolution
  api/
    server.ts                  Express app assembly
    routes/
      domains.ts               Domain onboarding + activation endpoints
      emails.ts                Email listing, release, delete
      lists.ts                 Blacklist/whitelist CRUD
  dashboard/index.html         Minimal dark-mode web UI
  smtp-gateway.ts              smtp-server wiring (onRcptTo, onData pipeline)
  index.ts                     Entry point: graceful startup + shutdown
```

### Commands

```bash
npm run build          # Compile TypeScript to dist/
npm run typecheck      # Type-check only (no emit)
npm start              # Run from compiled dist/
npm run dev            # Build + run with --watch for development
npm test               # Run all tests (tsx --test)
npm run test:send      # Smoke test: send a normal + a looped message
```

### Adding a test

Tests use Node's built-in `node:test` runner with `tsx`. Test files live in `test/*.test.ts`:

```ts
import { describe, it } from 'node:test';
import assert from 'node:assert';
import myService from '../dist/services/MyService';

describe('MyService', () => {
  it('should do the thing', () => {
    assert.equal(myService.doSomething(), 'expected');
  });
});
```

Tests import from `dist/` (compiled output), not `src/` (source), to verify the actual built modules.

### Adding a mail provider

Edit `PROVIDER_PATTERNS` in `src/services/DnsLookupService.ts`:

```ts
{ pattern: /\.mail\.newprovider\.com$/i, provider: 'NewProvider' },
```

### TypeScript notes

- TypeScript 7 requires `moduleResolution: "node16"` (not `"node"`).
- With `module: "Node16"` and no `"type": "module"` in package.json, output is CommonJS.
- `import` is hoisted above `process.env` assignments; use `require()` for modules that depend on env vars at load time.
- When destructuring methods from service singletons, call them as `instance.method()` (not `const { method } = instance`) to preserve `this` context.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `RELAY_SECRET must be at least 8 characters` | Change `RELAY_SECRET` from `change-me` to something unique |
| `No such domain configured on this relay` | The recipient domain hasn't been registered via `POST /domains` or is not `ACTIVE` |
| `Mail loop detected` | The message already carries this relay's signed header — check your destination MX isn't pointing back at this relay |
| `Could not resolve MX records` | The domain doesn't exist or has no mail configured — verify the domain name |
| Connection refused on SMTP port | Ensure `npm start` is running and the port isn't firewalled |
| Dashboard shows "Not connected" | Paste the default tenant API key (shown at startup) into the Connect box |
| `TLS_ACME_ENABLED=true` but no cert issued | Ensure port 80 is publicly reachable and `RELAY_HOSTNAME` resolves to this server |
| SMTP server fails to start with TLS options | Check `TLS_ACME_STORAGE` directory exists and cert files are valid PEM |

## Known MVP limitations

- Spam filtering is heuristic (blacklist/whitelist/keywords), not ML/Bayesian. Rspamd/ClamAV integration is planned for V2.
- No DKIM re-signing, ARC, or attachment sandboxing (V2 scope).
- Single-node only; no HA/clustering.
- Traefik ACME certs are stored in an `acme.json` file on a Docker volume — no external cert manager.
- SQLite is embedded (no external Postgres). The PRD target stack (Go/Rust, Postgres, Redis) is shown as commented-out services in `docker-compose.yml` for future scaling.
