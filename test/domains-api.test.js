const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const express = require('express');
const request = require('supertest');

process.env.DB_PATH = ':memory:';

delete require.cache[require.resolve('../src/config')];
delete require.cache[require.resolve('../src/db')];
delete require.cache[require.resolve('../src/dns-lookup')];
delete require.cache[require.resolve('../src/api/auth')];
delete require.cache[require.resolve('../src/api/routes/domains')];

const { initDb, closeDb, getDb, uuid } = require('../src/db');
const { requireTenant } = require('../src/api/auth');
const domainsRouter = require('../src/api/routes/domains');

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/domains', requireTenant, domainsRouter);
  return app;
}

function getTestTenantId(apiKey) {
  return getDb().prepare('SELECT id FROM tenants WHERE api_key = ?').get(apiKey).id;
}

function insertDomain(tenantId, overrides = {}) {
  const db = getDb();
  const row = {
    id: uuid(),
    tenant_id: tenantId,
    name: 'test-' + Date.now() + '-' + Math.random().toString(36).slice(2) + '.com',
    provider: 'Test',
    origin_mx: 'mx.test.com',
    destination_mx: 'mx.test.com',
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

describe('domains API', () => {
  let app;
  let testApiKey;
  let tenantId;

  before(() => {
    initDb(':memory:');
    const db = getDb();
    testApiKey = 'test-domains-key';
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(uuid(), 'Test', testApiKey, new Date().toISOString());
    tenantId = getTestTenantId(testApiKey);
    app = buildApp();
  });

  after(() => {
    closeDb();
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  describe('POST /domains', () => {
    it('should return 400 for missing name', async () => {
      const res = await request(app).post('/domains').set(auth()).send({});
      assert.equal(res.status, 400);
      assert.ok(res.body.error.includes('name'));
    });

    it('should return 400 for non-string name', async () => {
      const res = await request(app).post('/domains').set(auth()).send({ name: 123 });
      assert.equal(res.status, 400);
    });

    it('should return 400 for invalid domain format', async () => {
      const res = await request(app).post('/domains').set(auth()).send({ name: 'not-a-valid-domain!' });
      assert.equal(res.status, 400);
      assert.ok(res.body.error.includes('not a valid domain'));
    });

    it('should return 422 when MX lookup fails (domain does not exist)', async () => {
      const res = await request(app).post('/domains').set(auth()).send({ name: 'thisdomaindefinitelydoesnotexist12345.com' });
      assert.equal(res.status, 422);
      assert.ok(res.body.error.includes('MX records'));
    });

    it('should return 409 for duplicate domain', async () => {
      const existingDomain = insertDomain(tenantId, { name: 'duplicate.com' });
      const res = await request(app).post('/domains').set(auth()).send({ name: 'duplicate.com' });
      assert.equal(res.status, 409);
      assert.ok(res.body.error.includes('already registered'));
    });
  });

  describe('GET /domains', () => {
    it('should return empty list when no domains for this tenant', async () => {
      const emptyKey = 'empty-tenant-key-' + Date.now();
      getDb().prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(uuid(), 'Empty', emptyKey, new Date().toISOString());
      const res = await request(app).get('/domains').set({ Authorization: `Bearer ${emptyKey}` });
      assert.equal(res.status, 200);
      assert.equal(res.body.domains.length, 0);
    });

    it('should return domains for current tenant', async () => {
      insertDomain(tenantId, { name: 'tenant-specific-test.com' });
      const res = await request(app).get('/domains').set(auth());
      assert.equal(res.status, 200);
      const names = res.body.domains.map(d => d.name);
      assert.ok(names.includes('tenant-specific-test.com'));
    });

    it('should not show other tenants domains', async () => {
      const otherId = uuid();
      getDb().prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(otherId, 'Other', 'other-key-' + Date.now(), new Date().toISOString());
      insertDomain(otherId, { name: 'other-tenant-domain.com' });

      const res = await request(app).get('/domains').set(auth());
      const names = res.body.domains.map(d => d.name);
      assert.ok(!names.includes('other-tenant-domain.com'));
    });
  });

  describe('GET /domains/:name', () => {
    it('should return 404 for unknown domain', async () => {
      const res = await request(app).get('/domains/unknown.com').set(auth());
      assert.equal(res.status, 404);
    });

    it('should return domain details with instructions', async () => {
      const domain = insertDomain(tenantId, { name: 'detail-check.com' });
      const res = await request(app).get(`/domains/${domain.name}`).set(auth());
      assert.equal(res.status, 200);
      assert.equal(res.body.domain.name, domain.name);
      assert.ok(res.body.instructions);
      assert.ok(res.body.instructions.before);
      assert.ok(res.body.instructions.after);
    });

    it('should return 404 for other tenant domain', async () => {
      const otherId = uuid();
      getDb().prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(otherId, 'Other2', 'other-key-2', new Date().toISOString());
      const otherDomain = insertDomain(otherId, { name: 'not-my-domain.com' });
      const res = await request(app).get(`/domains/${otherDomain.name}`).set(auth());
      assert.equal(res.status, 404);
    });
  });

  describe('DELETE /domains/:name', () => {
    it('should return 404 for unknown domain', async () => {
      const res = await request(app).delete('/domains/unknown.com').set(auth());
      assert.equal(res.status, 404);
    });

    it('should delete own domain', async () => {
      const domain = insertDomain(tenantId, { name: 'delete-me-test.com' });
      const res = await request(app).delete(`/domains/${domain.name}`).set(auth());
      assert.equal(res.status, 204);

      const deleted = getDb().prepare('SELECT * FROM domains WHERE id = ?').get(domain.id);
      assert.ok(!deleted);
    });

    it('should return 404 for other tenant domain', async () => {
      const otherId = uuid();
      getDb().prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(otherId, 'Other3', 'other-key-3', new Date().toISOString());
      const otherDomain = insertDomain(otherId, { name: 'cant-delete.com' });
      const res = await request(app).delete(`/domains/${otherDomain.name}`).set(auth());
      assert.equal(res.status, 404);
    });
  });

  describe('auth', () => {
    it('should return 401 without auth header', async () => {
      const res = await request(app).get('/domains');
      assert.equal(res.status, 401);
    });

    it('should return 401 with invalid auth header', async () => {
      const res = await request(app).get('/domains').set({ Authorization: 'Bearer invalid' });
      assert.equal(res.status, 401);
    });
  });
});
