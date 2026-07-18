const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { v4: uuid } = require('uuid');
const config = require('./config');

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
fs.mkdirSync(config.quarantineDir, { recursive: true });

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL UNIQUE,
  provider TEXT,
  origin_mx TEXT,
  destination_mx TEXT,
  relay_target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING_DNS', -- PENDING_DNS | ACTIVE | SUSPENDED
  created_at TEXT NOT NULL,
  activated_at TEXT
);

CREATE TABLE IF NOT EXISTS emails (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  domain TEXT NOT NULL,
  sender TEXT,
  recipient TEXT,
  subject TEXT,
  remote_ip TEXT,
  spam_score REAL DEFAULT 0,
  decision TEXT,                 -- FORWARDED | QUARANTINED | REJECTED
  status TEXT NOT NULL,          -- RECEIVED | ANALYZING | FORWARDED | QUARANTINED | REJECTED
  relay_id TEXT,
  reason TEXT,
  headers_json TEXT,
  size_bytes INTEGER,
  eml_path TEXT,
  received_at TEXT NOT NULL,
  processed_at TEXT
);

CREATE TABLE IF NOT EXISTS blacklist (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  type TEXT NOT NULL,   -- ip | domain
  value TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  type TEXT NOT NULL,   -- ip | domain
  value TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_emails_domain ON emails(domain);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains(tenant_id);
`);

// Seed a default tenant so the API/dashboard work out of the box.
function seedDefaultTenant() {
  const existing = db.prepare('SELECT * FROM tenants WHERE api_key = ?').get(config.defaultTenantApiKey);
  if (existing) return existing;
  const tenant = {
    id: uuid(),
    name: config.defaultTenantName,
    api_key: config.defaultTenantApiKey,
    created_at: new Date().toISOString(),
  };
  db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (@id, @name, @api_key, @created_at)').run(tenant);
  return tenant;
}

const defaultTenant = seedDefaultTenant();

module.exports = { db, uuid, defaultTenant };
