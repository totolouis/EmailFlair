import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import databaseService from '../dist/services/DatabaseService';
import { requireTenant } from '../dist/middleware/AuthMiddleware';
import listsRouter from '../dist/api/routes/lists';
import { hashApiKey } from './helpers';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/lists', requireTenant, listsRouter);
  return app;
}

describe('lists API (blacklist/whitelist)', () => {
  let app: express.Application;
  let tenantId: string;
  let testApiKey: string;

  before(() => {
    databaseService.init(':memory:');
    const db = databaseService.getDb();
    testApiKey = 'test-lists-key';
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', hashApiKey(testApiKey), new Date().toISOString());
    app = buildApp();
  });

  after(() => {
    databaseService.close();
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  describe('blacklist', () => {
    const BASE = '/lists/blacklist';

    it('should start empty', async () => {
      const res = await request(app).get(BASE).set(auth());
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.blacklist));
    });

    it('should add an IP entry', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ type: 'ip', value: '10.0.0.50' });
      assert.equal(res.status, 201);
      assert.equal(res.body.entry.type, 'ip');
      assert.equal(res.body.entry.value, '10.0.0.50');
    });

    it('should add a domain entry', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ type: 'domain', value: 'spam-domain.com' });
      assert.equal(res.status, 201);
      assert.equal(res.body.entry.type, 'domain');
      assert.equal(res.body.entry.value, 'spam-domain.com');
    });

    it('should store values lowercased', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ type: 'domain', value: 'EVIL.COM' });
      assert.equal(res.status, 201);
      assert.equal(res.body.entry.value, 'evil.com');
    });

    it('should return 400 for missing type', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ value: '1.2.3.4' });
      assert.equal(res.status, 400);
    });

    it('should return 400 for invalid type', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ type: 'email', value: 'test@test.com' });
      assert.equal(res.status, 400);
    });

    it('should return 400 for missing value', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ type: 'ip' });
      assert.equal(res.status, 400);
    });

    it('should list entries', async () => {
      const res = await request(app).get(BASE).set(auth());
      assert.equal(res.status, 200);
      assert.ok(res.body.blacklist.length >= 3);
    });

    it('should delete an entry', async () => {
      const list = await request(app).get(BASE).set(auth());
      if (list.body.blacklist.length > 0) {
        const id = list.body.blacklist[0].id;
        const delRes = await request(app).delete(`${BASE}/${id}`).set(auth());
        assert.equal(delRes.status, 204);

        const verify = await request(app).get(BASE).set(auth());
        const ids: string[] = verify.body.blacklist.map((e: { id: string }) => e.id);
        assert.ok(!ids.includes(id));
      }
    });

    it('should return 404 when deleting non-existent entry', async () => {
      const res = await request(app).delete(`${BASE}/nonexistent-id`).set(auth());
      assert.equal(res.status, 404);
    });
  });

  describe('whitelist', () => {
    const BASE = '/lists/whitelist';

    it('should start empty', async () => {
      const res = await request(app).get(BASE).set(auth());
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.whitelist));
    });

    it('should add an entry', async () => {
      const res = await request(app).post(BASE).set(auth()).send({ type: 'ip', value: '192.168.1.1' });
      assert.equal(res.status, 201);
    });

    it('should not mix blacklist and whitelist entries', async () => {
      const bl = await request(app).get('/lists/blacklist').set(auth());
      const wl = await request(app).get(BASE).set(auth());
      const blValues: string[] = bl.body.blacklist.map((e: { value: string }) => e.value);
      const wlValues: string[] = wl.body.whitelist.map((e: { value: string }) => e.value);
      const overlap = blValues.filter((v) => wlValues.includes(v));
      assert.equal(overlap.length, 0);
    });
  });

  describe('auth isolation', () => {
    it('should not show entries across tenants', async () => {
      const otherApiKey = 'other-tenant-key';
      databaseService.getDb().prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(databaseService.uuid(), 'Other', hashApiKey(otherApiKey), new Date().toISOString());

      const res = await request(app).get('/lists/blacklist').set({ Authorization: `Bearer ${otherApiKey}` });
      assert.equal(res.status, 200);
      assert.equal(res.body.blacklist.length, 0);
    });
  });
});
