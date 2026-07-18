import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import databaseService from '../dist/services/DatabaseService';
import { requireTenant } from '../dist/middleware/AuthMiddleware';
import domainsRouter from '../dist/api/routes/domains';
import emailsRouter from '../dist/api/routes/emails';
import config from '../dist/config';

function buildDomainsApp() {
  const app = express();
  app.use(express.json());
  app.use('/domains', requireTenant, domainsRouter);
  return app;
}

function buildEmailsApp() {
  const app = express();
  app.use(express.json());
  app.use('/emails', requireTenant, emailsRouter);
  return app;
}

describe('additional API edge cases', () => {
  let app: express.Application;
  let tenantId: string;
  let testApiKey: string;
  let db: ReturnType<typeof databaseService.getDb>;

  before(() => {
    databaseService.init(':memory:');
    db = databaseService.getDb();
    testApiKey = 'additional-test-key';
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Additional Test', testApiKey, new Date().toISOString());
  });

  after(() => {
    databaseService.close();
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  describe('email release with domain without destination', () => {
    it('should return 500 when domain has no destination_mx', async () => {
      const emailApp = buildEmailsApp();

      const domainId = databaseService.uuid();
      db.prepare(`
        INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(domainId, tenantId, 'no-mx-domain.com', 'Test', 'mx.test.com', null, config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

      const emailId = databaseService.uuid();
      db.prepare(`
        INSERT INTO emails (id, tenant_id, domain, sender, recipient, subject, remote_ip,
          spam_score, decision, status, relay_id, reason, headers_json,
          size_bytes, eml_path, received_at, processed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(emailId, tenantId, 'no-mx-domain.com', 'sender@test.com', 'user@test.com', 'Release Test', '1.2.3.4', 6, 'QUARANTINED', 'QUARANTINED', 'relay-01', null, null, 100, '/tmp/test.eml', new Date().toISOString(), new Date().toISOString());

      const res = await request(emailApp).post(`/emails/${emailId}/release`).set(auth());
      assert.equal(res.status, 500);
      assert.ok((res.body.error as string).includes('destination') || (res.body.error as string).includes('configured'));
    });
  });

  describe('domain activation', () => {
    it('should return 404 for domain not found', async () => {
      const domainsApp = buildDomainsApp();
      const res = await request(domainsApp).post('/domains/nonexistent.com/activate').set(auth());
      assert.equal(res.status, 404);
    });
  });

  describe('loop prevent multi-value headers', () => {
    it('should handle Map with mixed case header names', async () => {
      const { default: loopPreventionService } = require('../dist/services/LoopPreventionService');
      const sig = loopPreventionService.signRelayId(config.relayId, config.relaySecret);
      const headers = new Map<string, unknown>();
      headers.set('X-RELAY-ID', config.relayId);
      headers.set('X-RELAY-SIGNATURE', sig);
      const result = loopPreventionService.detectLoop(headers);
      // Map.get is case-sensitive, so this won't match unless we normalize
      assert.equal(result.isLoop, false);
    });
  });

  describe('null/undefined edge cases', () => {
    it('should handle empty email list for new tenant', async () => {
      const emptyKey = 'empty-tenant-' + Date.now();
      db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(databaseService.uuid(), 'Empty', emptyKey, new Date().toISOString());
      const emailApp = buildEmailsApp();
      const res = await request(emailApp).get('/emails').set({ Authorization: `Bearer ${emptyKey}` });
      assert.equal(res.status, 200);
      assert.equal(res.body.emails.length, 0);
    });
  });
});
