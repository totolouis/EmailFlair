const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');

process.env.DB_PATH = ':memory:';

delete require.cache[require.resolve('../src/config')];
delete require.cache[require.resolve('../src/db')];
delete require.cache[require.resolve('../src/routing-engine')];

const { initDb, closeDb, getDb, uuid } = require('../src/db');
const { resolveDestination } = require('../src/routing-engine');

describe('routing-engine', () => {
  let tenantId;

  before(() => {
    initDb(':memory:');
    const db = getDb();
    tenantId = uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', 'test-key', new Date().toISOString());
  });

  after(() => {
    closeDb();
  });

  const domainData = {
    id: uuid(),
    tenant_id: null,
    name: 'example.com',
    provider: 'GoogleWorkspace',
    origin_mx: 'aspmx.l.google.com',
    destination_mx: 'aspmx.l.google.com',
    relay_target: 'mx1.emailrelay.com',
    status: 'ACTIVE',
    created_at: new Date().toISOString(),
    activated_at: new Date().toISOString(),
  };

  function seedDomain(overrides = {}) {
    const row = { ...domainData, tenant_id: tenantId, ...overrides, id: uuid() };
    getDb().prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (@id, @tenant_id, @name, @provider, @origin_mx, @destination_mx, @relay_target, @status, @created_at, @activated_at)
    `).run(row);
    return row;
  }

  it('should return domain row for a registered domain', () => {
    seedDomain({ name: 'example.com' });
    const result = resolveDestination('example.com');
    assert.ok(result);
    assert.equal(result.name, 'example.com');
    assert.equal(result.destination_mx, 'aspmx.l.google.com');
  });

  it('should be case-insensitive for domain matching', () => {
    seedDomain({ name: 'UpperCase.COM' });
    const result = resolveDestination('uppercase.com');
    assert.ok(result);
    assert.equal(result.name, 'UpperCase.COM');
  });

  it('should return null for unregistered domain', () => {
    const result = resolveDestination('nonexistent.com');
    assert.strictEqual(result, null);
  });

  it('should return the correct destination MX', () => {
    seedDomain({ name: 'myco.com', destination_mx: 'mx.myco.com' });
    const result = resolveDestination('myco.com');
    assert.equal(result.destination_mx, 'mx.myco.com');
  });

  it('should handle subdomains correctly', () => {
    seedDomain({ name: 'sub.example.com' });
    const result = resolveDestination('sub.example.com');
    assert.ok(result);
    assert.equal(result.name, 'sub.example.com');
  });
});
