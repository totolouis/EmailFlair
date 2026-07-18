const { initDb, closeDb, uuid, getDb } = require('../src/db');
const config = require('../src/config');
const path = require('path');
const fs = require('fs');

const TEST_QUARANTINE_DIR = path.join(__dirname, '..', 'data', 'test-quarantine');

function setupTestDb() {
  initDb(':memory:');
  fs.mkdirSync(TEST_QUARANTINE_DIR, { recursive: true });
  config.quarantineDir = TEST_QUARANTINE_DIR;
  return getDb();
}

function seedTestTenant() {
  const db = getDb();
  const tenant = {
    id: uuid(),
    name: 'Test Tenant',
    api_key: 'test-api-key',
    created_at: new Date().toISOString(),
  };
  db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (@id, @name, @api_key, @created_at)').run(tenant);
  return tenant;
}

function seedTestDomain(tenantId, overrides = {}) {
  const db = getDb();
  const row = {
    id: uuid(),
    tenant_id: tenantId,
    name: 'test-domain.com',
    provider: 'GoogleWorkspace',
    origin_mx: 'aspmx.l.google.com',
    destination_mx: 'mx.test-domain.com',
    relay_target: 'mx1.emailrelay.com',
    status: 'ACTIVE',
    created_at: new Date().toISOString(),
    activated_at: new Date().toISOString(),
    ...overrides,
  };
  db.prepare(`
    INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
    VALUES (@id, @tenant_id, @name, @provider, @origin_mx, @destination_mx, @relay_target, @status, @created_at, @activated_at)
  `).run(row);
  return row;
}

function createTestRawEmail() {
  return Buffer.from(
    'From: sender@example.com\r\n' +
    'To: user@test-domain.com\r\n' +
    'Subject: Test Message\r\n' +
    'Message-ID: <test@example.com>\r\n' +
    '\r\n' +
    'Hello, this is a test message.\r\n'
  );
}

function cleanupTestDir() {
  if (fs.existsSync(TEST_QUARANTINE_DIR)) {
    fs.rmSync(TEST_QUARANTINE_DIR, { recursive: true, force: true });
  }
}

module.exports = {
  setupTestDb,
  seedTestTenant,
  seedTestDomain,
  createTestRawEmail,
  cleanupTestDir,
  TEST_QUARANTINE_DIR,
};