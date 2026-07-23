import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import databaseService from '../dist/services/DatabaseService';
import { requireTenant } from '../dist/middleware/AuthMiddleware';
import domainsRouter from '../dist/api/routes/domains';
import { hashApiKey } from './helpers';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/domains', requireTenant, domainsRouter);
  return app;
}

function getTestTenantId(apiKey: string): string {
  const hashed = hashApiKey(apiKey);
  const row = databaseService.getDb().prepare('SELECT id FROM tenants WHERE api_key_hash = ?').get(hashed) as { id: string } | undefined;
  return row!.id;
}

function insertDomain(tenantId: string, overrides: Record<string, unknown> = {}) {
  const db = databaseService.getDb();
  const row: Record<string, unknown> = {
    id: databaseService.uuid(),
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
  let app: express.Application;
  let testApiKey: string;
  let tenantId: string;

  before(() => {
    databaseService.init(':memory:');
    const db = databaseService.getDb();
    testApiKey = 'test-domains-key';
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(databaseService.uuid(), 'Test', hashApiKey(testApiKey), new Date().toISOString());
    tenantId = getTestTenantId(testApiKey);
    app = buildApp();
  });

  after(() => {
    databaseService.close();
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  describe('POST /domains', () => {
    it('should return 400 for missing name', async () => {
      const res = await request(app).post('/domains').set(auth()).send({});
      assert.equal(res.status, 400);
      assert.ok((res.body.error as string).includes('name'));
    });

    it('should return 400 for non-string name', async () => {
      const res = await request(app).post('/domains').set(auth()).send({ name: 123 });
      assert.equal(res.status, 400);
    });

    it('should return 400 for invalid domain format', async () => {
      const res = await request(app).post('/domains').set(auth()).send({ name: 'not-a-valid-domain!' });
      assert.equal(res.status, 400);
      assert.ok((res.body.error as string).includes('not a valid domain'));
    });

    it('should return 422 when MX lookup fails (domain does not exist)', async () => {
      const res = await request(app).post('/domains').set(auth()).send({ name: 'thisdomaindefinitelydoesnotexist12345.com' });
      assert.equal(res.status, 422);
      assert.ok((res.body.error as string).includes('MX records'));
    });

    it('should return 409 for duplicate domain', async () => {
      insertDomain(tenantId, { name: 'duplicate.com' });
      const res = await request(app).post('/domains').set(auth()).send({ name: 'duplicate.com' });
      assert.equal(res.status, 409);
      assert.ok((res.body.error as string).includes('already registered'));
    });
  });

  describe('GET /domains', () => {
    it('should return empty list when no domains for this tenant', async () => {
      const emptyKey = 'empty-tenant-key-' + Date.now();
      databaseService.getDb().prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(databaseService.uuid(), 'Empty', hashApiKey(emptyKey), new Date().toISOString());
      const res = await request(app).get('/domains').set({ Authorization: `Bearer ${emptyKey}` });
      assert.equal(res.status, 200);
      assert.equal(res.body.domains.length, 0);
    });

    it('should return domains for current tenant', async () => {
      insertDomain(tenantId, { name: 'tenant-specific-test.com' });
      const res = await request(app).get('/domains').set(auth());
      assert.equal(res.status, 200);
      const names: string[] = res.body.domains.map((d: { name: string }) => d.name);
      assert.ok(names.includes('tenant-specific-test.com'));
    });

    it('should not show other tenants domains', async () => {
      const otherId = databaseService.uuid();
      databaseService.getDb().prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(otherId, 'Other', hashApiKey('other-key-' + Date.now()), new Date().toISOString());
      insertDomain(otherId, { name: 'other-tenant-domain.com' });

      const res = await request(app).get('/domains').set(auth());
      const names: string[] = res.body.domains.map((d: { name: string }) => d.name);
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
      const otherId = databaseService.uuid();
      databaseService.getDb().prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(otherId, 'Other2', hashApiKey('other-key-2'), new Date().toISOString());
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

      const deleted = databaseService.getDb().prepare('SELECT * FROM domains WHERE id = ?').get(domain.id);
      assert.ok(!deleted);
    });

    it('should return 404 for other tenant domain', async () => {
      const otherId = databaseService.uuid();
      databaseService.getDb().prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(otherId, 'Other3', hashApiKey('other-key-3'), new Date().toISOString());
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
