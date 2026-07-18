const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const express = require('express');
const request = require('supertest');
const path = require('path');
const fs = require('fs');

process.env.DB_PATH = ':memory:';

delete require.cache[require.resolve('../src/config')];
delete require.cache[require.resolve('../src/db')];
delete require.cache[require.resolve('../src/api/auth')];
delete require.cache[require.resolve('../src/api/routes/emails')];
delete require.cache[require.resolve('../src/routing-engine')];

const { initDb, closeDb, getDb, uuid } = require('../src/db');
const config = require('../src/config');
const { requireTenant } = require('../src/api/auth');
const emailsRouter = require('../src/api/routes/emails');

const TEST_DIR = path.join(__dirname, '..', 'data', 'test-emails-' + process.pid);

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/emails', requireTenant, emailsRouter);
  return app;
}

describe('emails API', () => {
  let app;
  let tenantId;
  let testApiKey;

  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;

    initDb(':memory:');
    const db = getDb();
    testApiKey = 'test-emails-key';
    tenantId = uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', testApiKey, new Date().toISOString());
    app = buildApp();
  });

  after(() => {
    closeDb();
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  function insertEmail(overrides = {}) {
    const db = getDb();
    const email = {
      id: overrides.id || uuid(),
      tenant_id: overrides.tenant_id || tenantId,
      domain: overrides.domain || 'test.com',
      sender: overrides.sender || 'sender@example.com',
      recipient: overrides.recipient || 'user@test.com',
      subject: overrides.subject || 'Test Subject',
      remote_ip: overrides.remote_ip || '1.2.3.4',
      spam_score: overrides.spam_score || 0,
      decision: overrides.decision || 'FORWARDED',
      status: overrides.status || 'FORWARDED',
      relay_id: overrides.relay_id || 'relay-01',
      reason: overrides.reason || null,
      headers_json: overrides.headers_json || null,
      size_bytes: overrides.size_bytes || 100,
      eml_path: overrides.eml_path || null,
      received_at: overrides.received_at || new Date().toISOString(),
      processed_at: overrides.processed_at || new Date().toISOString(),
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
      res.body.emails.forEach(e => assert.equal(e.status, 'QUARANTINED'));
    });

    it('should filter by domain', async () => {
      insertEmail({ subject: 'From other domain', domain: 'other.com' });
      const res = await request(app).get('/emails?domain=other.com').set(auth());
      assert.equal(res.status, 200);
      res.body.emails.forEach(e => assert.equal(e.domain, 'other.com'));
    });

    it('should respect limit parameter', async () => {
      const res = await request(app).get('/emails?limit=1').set(auth());
      assert.equal(res.status, 200);
      assert.ok(res.body.emails.length <= 1);
    });

    it('should not show other tenants emails', async () => {
      const otherTenantId = uuid();
      getDb().prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
        .run(otherTenantId, 'Other', 'other-key', new Date().toISOString());
      insertEmail({ tenant_id: otherTenantId, subject: 'Other tenant email' });

      const res = await request(app).get('/emails').set(auth());
      const subjects = res.body.emails.map(e => e.subject);
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

      const dbEmail = getDb().prepare('SELECT * FROM emails WHERE id = ?').get(email.id);
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
      assert.ok(res.body.error.includes('not quarantined'));
    });

    it('should return 500 if no eml_path stored', async () => {
      const email = insertEmail({ status: 'QUARANTINED', decision: 'QUARANTINED', eml_path: null });
      const res = await request(app).post(`/emails/${email.id}/release`).set(auth());
      assert.equal(res.status, 500);
      assert.ok(res.body.error.includes('no stored content'));
    });
  });
});
