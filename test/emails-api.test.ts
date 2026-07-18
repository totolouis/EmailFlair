import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import path from 'path';
import fs from 'fs';

const TEST_DIR = path.join(__dirname, '..', 'data', 'test-emails-' + process.pid);

import databaseService from '../dist/services/DatabaseService';
import config from '../dist/config';
import { requireTenant } from '../dist/middleware/AuthMiddleware';
import emailsRouter from '../dist/api/routes/emails';

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/emails', requireTenant, emailsRouter);
  return app;
}

describe('emails API', () => {
  let app: express.Application;
  let tenantId: string;
  let testApiKey: string;

  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;

    databaseService.init(':memory:');
    const db = databaseService.getDb();
    testApiKey = 'test-emails-key';
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', testApiKey, new Date().toISOString());
    app = buildApp();
  });

  after(() => {
    databaseService.close();
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  function insertEmail(overrides: Record<string, unknown> = {}) {
    const db = databaseService.getDb();
    const email: Record<string, unknown> = {
      id: (overrides.id as string) || databaseService.uuid(),
      tenant_id: (overrides.tenant_id as string) || tenantId,
      domain: (overrides.domain as string) || 'test.com',
      sender: (overrides.sender as string) || 'sender@example.com',
      recipient: (overrides.recipient as string) || 'user@test.com',
      subject: (overrides.subject as string) || 'Test Subject',
      remote_ip: (overrides.remote_ip as string) || '1.2.3.4',
      spam_score: (overrides.spam_score as number) || 0,
      decision: (overrides.decision as string) || 'FORWARDED',
      status: (overrides.status as string) || 'FORWARDED',
      relay_id: (overrides.relay_id as string) || 'relay-01',
      reason: (overrides.reason as string) || null,
      headers_json: (overrides.headers_json as string) || null,
      size_bytes: (overrides.size_bytes as number) || 100,
      eml_path: (overrides.eml_path as string) || null,
      received_at: (overrides.received_at as string) || new Date().toISOString(),
      processed_at: (overrides.processed_at as string) || new Date().toISOString(),
    };

    db.prepare(`
      INSERT INTO emails (id, tenant_id, domain, sender, recipient, subject, remote_ip,
        spam_score, decision, status, relay_id, reason, headers_json,
        size_bytes, eml_path, received_at, processed_at)
      VALUES (@id, @tenant_id, @domain, @sender, @recipient, @subject, @remote_ip,
        @spam_score, @decision, @status, @relay_id, @reason, @headers_json,
        @size_bytes, @eml_path, @received_at, @processed_at)
    `).run(email);

    return email;
  }

  describe('GET /emails', () => {
    it('should return empty list when no emails', async () => {
      const res = await request(app).get('/emails').set(auth());
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.body.emails));
    });

    it('should list emails for the tenant', async () => {
      insertEmail({ subject: 'Test Email 1' });
      insertEmail({ subject: 'Test Email 2' });

      const res = await request(app).get('/emails').set(auth());
      assert.equal(res.status, 200);
      assert.ok(res.body.emails.length >= 2);
    });

    it('should filter by status', async () => {
      insertEmail({ subject: 'Quarantined', status: 'QUARANTINED', decision: 'QUARANTINED' });
      const res = await request(app).get('/emails?status=QUARANTINED').set(auth());
      assert.equal(res.status, 200);
      res.body.emails.forEach((e: { status: string }) => assert.equal(e.status, 'QUARANTINED'));
    });

    it('should filter by domain', async () => {
      insertEmail({ subject: 'From other domain', domain: 'other.com' });
      const res = await request(app).get('/emails?domain=other.com').set(auth());
      assert.equal(res.status, 200);
      res.body.emails.forEach((e: { domain: string }) => assert.equal(e.domain, 'other.com'));
    });

    it('should respect limit parameter', async () => {
      const res = await request(app).get('/emails?limit=1').set(auth());
      assert.equal(res.status, 200);
      assert.ok(res.body.emails.length <= 1);
    });

    it('should not show other tenants emails', async () => {
      const otherTenantId = databaseService.uuid();
      databaseService.getDb().prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(otherTenantId, 'Other', 'other-key', new Date().toISOString());
      insertEmail({ tenant_id: otherTenantId, subject: 'Other tenant email' });

      const res = await request(app).get('/emails').set(auth());
      const subjects: string[] = res.body.emails.map((e: { subject: string }) => e.subject);
      assert.ok(!subjects.includes('Other tenant email'));
    });
  });

  describe('GET /emails/summary', () => {
    it('should return summary counts', async () => {
      const res = await request(app).get('/emails/summary').set(auth());
      assert.equal(res.status, 200);
      assert.ok(res.body.totals);
      assert.ok('FORWARDED' in res.body.totals);
      assert.ok('QUARANTINED' in res.body.totals);
      assert.ok('REJECTED' in res.body.totals);
    });
  });

  describe('GET /emails/:id', () => {
    it('should return 404 for unknown email', async () => {
      const res = await request(app).get('/emails/nonexistent-id').set(auth());
      assert.equal(res.status, 404);
    });

    it('should return email details', async () => {
      const email = insertEmail({ subject: 'Detail View Test' });
      const res = await request(app).get(`/emails/${email.id}`).set(auth());
      assert.equal(res.status, 200);
      assert.equal(res.body.email.subject, 'Detail View Test');
    });
  });

  describe('DELETE /emails/:id', () => {
    it('should return 404 for unknown email', async () => {
      const res = await request(app).delete('/emails/nonexistent-id').set(auth());
      assert.equal(res.status, 404);
    });

    it('should delete an email record', async () => {
      const email = insertEmail({ status: 'QUARANTINED', decision: 'QUARANTINED' });
      const res = await request(app).delete(`/emails/${email.id}`).set(auth());
      assert.equal(res.status, 204);

      const dbEmail = databaseService.getDb().prepare('SELECT * FROM emails WHERE id = ?').get(email.id);
      assert.ok(!dbEmail, 'email should be deleted from DB');
    });
  });

  describe('POST /emails/:id/release', () => {
    it('should return 404 for unknown email', async () => {
      const res = await request(app).post('/emails/nonexistent-id/release').set(auth());
      assert.equal(res.status, 404);
    });

    it('should return 409 for non-quarantined email', async () => {
      const email = insertEmail({ status: 'FORWARDED', decision: 'FORWARDED' });
      const res = await request(app).post(`/emails/${email.id}/release`).set(auth());
      assert.equal(res.status, 409);
      assert.ok((res.body.error as string).includes('not quarantined'));
    });

    it('should return 500 if no eml_path stored', async () => {
      const email = insertEmail({ status: 'QUARANTINED', decision: 'QUARANTINED', eml_path: null });
      const res = await request(app).post(`/emails/${email.id}/release`).set(auth());
      assert.equal(res.status, 500);
      assert.ok((res.body.error as string).includes('no stored content'));
    });
  });
});
