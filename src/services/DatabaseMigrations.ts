import Database from 'better-sqlite3';
import crypto from 'crypto';

function sha256hex(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export default function runMigrations(db: Database.Database): void {
  db.exec(`
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL UNIQUE,
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
  status TEXT NOT NULL DEFAULT 'PENDING_DNS',
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
  decision TEXT,
  status TEXT NOT NULL,
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
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_emails_domain ON emails(domain);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains(tenant_id);
`);

  // Migration: rename api_key → api_key_hash for existing DBs
  const columns = db.prepare("PRAGMA table_info(tenants)").all() as { name: string }[];
  const hasOldColumn = columns.some(c => c.name === 'api_key');
  const hasNewColumn = columns.some(c => c.name === 'api_key_hash');

  if (hasOldColumn && !hasNewColumn) {
    db.exec(`ALTER TABLE tenants RENAME COLUMN api_key TO api_key_hash`);
    // Re-hash any plaintext keys that were stored before the migration
    const rows = db.prepare('SELECT id, api_key_hash FROM tenants').all() as { id: string; api_key_hash: string }[];
    const update = db.prepare('UPDATE tenants SET api_key_hash = ? WHERE id = ?');
    for (const row of rows) {
      // Only hash if it doesn't look like a SHA-256 hex string (64 hex chars)
      if (row.api_key_hash.length !== 64 || !/^[0-9a-f]{64}$/.test(row.api_key_hash)) {
        update.run(sha256hex(row.api_key_hash), row.id);
      }
    }
  }
}
