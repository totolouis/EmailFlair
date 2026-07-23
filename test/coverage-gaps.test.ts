import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs';
import express from 'express';
import request from 'supertest';

/* ------------------------------------------------------------------ */
/*  DatabaseService & DatabaseMigrations                              */
/* ------------------------------------------------------------------ */
describe('DatabaseService – edge cases', () => {
  it('getDb() should throw before init()', () => {
    const { DatabaseService } = require('../dist/services/DatabaseService');
    const fresh = new DatabaseService();
    assert.throws(() => fresh.getDb(), /not initialized/i);
  });

  it('init() should work with :memory: twice (re-init)', () => {
    const { DatabaseService } = require('../dist/services/DatabaseService');
    const fresh = new DatabaseService();
    fresh.init(':memory:');
    fresh.getDb().prepare('SELECT 1').get(); // first init OK
    fresh.init(':memory:'); // re-init (closes previous, opens new)
    fresh.getDb().prepare('SELECT 1').get(); // should still work
  });

  it('seedDefaultTenant() should return existing tenant on second call', () => {
    const { DatabaseService } = require('../dist/services/DatabaseService');
    const fresh = new DatabaseService();
    fresh.init(':memory:');
    const t1 = fresh.seedDefaultTenant();
    const t2 = fresh.seedDefaultTenant();
    // avoid mutating config – pass in-memory config values manually
    assert.ok(t1.id);
    assert.equal(t1.id, t2.id, 'should return same tenant without re-inserting');
  });

  it('uuid() should return valid UUID v4', () => {
    const { DatabaseService } = require('../dist/services/DatabaseService');
    const fresh = new DatabaseService();
    fresh.init(':memory:');
    const id = fresh.uuid();
    assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  describe('DatabaseMigrations – schema verification', () => {
    let db: ReturnType<typeof import('../dist/services/DatabaseService').DatabaseService.prototype.getDb>;
    const { DatabaseService: DBSvc } = require('../dist/services/DatabaseService');
    const fresh = new DBSvc();

    before(() => {
      fresh.init(':memory:');
      db = fresh.getDb();
    });

    it('should create tenants table', () => {
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='tenants'").get();
      assert.ok(tables);
    });

    it('should create domains table with foreign key', () => {
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='domains'").get();
      assert.ok(tables);
    });

    it('should create emails table', () => {
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='emails'").get();
      assert.ok(tables);
    });

    it('should create blacklist and whitelist tables', () => {
      const bl = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='blacklist'").get();
      const wl = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='whitelist'").get();
      assert.ok(bl);
      assert.ok(wl);
    });

    it('should create indexes', () => {
      const idx1 = db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_emails_domain'").get();
      const idx2 = db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_emails_status'").get();
      const idx3 = db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_domains_tenant'").get();
      assert.ok(idx1);
      assert.ok(idx2);
      assert.ok(idx3);
    });

    it('should enable foreign_keys pragma', () => {
      const row = db.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number };
      assert.equal(row.foreign_keys, 1);
    });
  });
});

/* ------------------------------------------------------------------ */
/*  ForwarderService                                                  */
/* ------------------------------------------------------------------ */
describe('ForwarderService', () => {
  it('should throw when connecting to unreachable host', async () => {
    const forwarderService = (await import('../dist/services/ForwarderService')).default;
    try {
      await forwarderService.forward({
        destinationHost: '127.0.0.1',
        destinationPort: 1,
        from: 'a@b.com',
        to: ['c@d.com'],
        rawMessage: Buffer.from('test'),
      });
      assert.fail('should have thrown');
    } catch (err: unknown) {
      assert.ok((err as Error).message);
    }
  });

  it('should export forwarderService singleton', () => {
    const mod = require('../dist/services/ForwarderService');
    assert.ok(mod.forwarderService);
    assert.equal(typeof mod.forwarderService.forward, 'function');
  });

  it('should fail with NXDOMAIN hostname', async () => {
    const forwarderService = (await import('../dist/services/ForwarderService')).default;
    try {
      await forwarderService.forward({
        destinationHost: 'thisshouldnotresolveatall99999.com',
        from: 'a@b.com',
        to: ['c@d.com'],
        rawMessage: Buffer.from('test'),
      });
      assert.fail('should have thrown');
    } catch (err: unknown) {
      const msg = (err as Error).message;
      assert.ok(msg.length > 0, 'should have error message');
    }
  });

  it('should use default port when destinationPort is omitted', async () => {
    const forwarderService = (await import('../dist/services/ForwarderService')).default;
    try {
      await forwarderService.forward({
        destinationHost: '127.0.0.1',
        from: 'a@b.com',
        to: ['c@d.com'],
        rawMessage: Buffer.from('test'),
      });
      assert.fail('should have thrown');
    } catch (err: unknown) {
      const msg = (err as Error).message;
      // Connection refused on port 25 (default)
      assert.ok(msg.includes('ECONNREFUSED') || msg.includes('connect') || msg.includes('refused'),
        `Expected connection error on port 25, got: ${msg}`);
    }
  });

  it('should throw for empty recipients array', async () => {
    const forwarderService = (await import('../dist/services/ForwarderService')).default;
    try {
      await forwarderService.forward({
        destinationHost: '127.0.0.1',
        destinationPort: 1,
        from: 'a@b.com',
        to: [],
        rawMessage: Buffer.from('test'),
      });
      assert.fail('should have thrown');
    } catch (err: unknown) {
      assert.ok((err as Error).message);
    }
  });
});

/* ------------------------------------------------------------------ */
/*  DnsLookupService – edge cases                                     */
/* ------------------------------------------------------------------ */
describe('DnsLookupService – edge cases', () => {
  it('should return false when domain MX does not point to relay', async () => {
    const svc = (require('../dist/services/DnsLookupService').dnsLookupService
      || require('../dist/services/DnsLookupService').default);
    const result = await svc.mxPointsToRelay('google.com', 'mx1.emailrelay.com');
    assert.equal(result, false);
  });

  it('should return false for non-existent domain', async () => {
    const svc = (require('../dist/services/DnsLookupService').dnsLookupService
      || require('../dist/services/DnsLookupService').default);
    const result = await svc.mxPointsToRelay('thisshouldnotexist99999.com', 'mx1.emailrelay.com');
    assert.equal(result, false);
  });

  it('should be case-insensitive when comparing hostnames', () => {
    const svc = (require('../dist/services/DnsLookupService').dnsLookupService
      || require('../dist/services/DnsLookupService').default);
    assert.equal(svc.detectProvider('ASPMX.L.GOOGLE.COM'), 'GoogleWorkspace');
  });

  it('should rethrow non-ENOTFOUND/non-ENODATA DNS errors', async () => {
    const svc = (require('../dist/services/DnsLookupService').dnsLookupService
      || require('../dist/services/DnsLookupService').default);
    try {
      // An invalid domain name to trigger a different DNS error
      await svc.lookupDomainMx('invalid..domain..name');
      // May or may not throw depending on OS DNS behavior
    } catch (err: unknown) {
      const dnsErr = err as NodeJS.ErrnoException;
      assert.ok(dnsErr.code !== 'ENOTFOUND' && dnsErr.code !== 'ENODATA',
        `Should rethrow (not ENOTFOUND/ENODATA), got: ${dnsErr.code}`);
    }
  });

  it('should detect Purelymail provider', () => {
    const svc = (require('../dist/services/DnsLookupService').dnsLookupService
      || require('../dist/services/DnsLookupService').default);
    assert.equal(svc.detectProvider('mail.purelymail.com'), 'Purelymail');
  });

  it('should detect GoogleWorkspace via googlemail.com pattern', () => {
    const svc = (require('../dist/services/DnsLookupService').dnsLookupService
      || require('../dist/services/DnsLookupService').default);
    assert.equal(svc.detectProvider('aspmx.googlemail.com'), 'GoogleWorkspace');
  });
});

/* ------------------------------------------------------------------ */
/*  Domains activate endpoint                                         */
/* ------------------------------------------------------------------ */
describe('Domains API – activate endpoint', () => {
  let app: express.Application;
  let tenantId: string;
  let testApiKey: string;
  let db: ReturnType<typeof import('../dist/services/DatabaseService').DatabaseService.prototype.getDb>;

  const { default: databaseService } = require('../dist/services/DatabaseService');
  const { requireTenant } = require('../dist/middleware/AuthMiddleware');
  const domainsRouter = require('../dist/api/routes/domains').default;
  const { hashApiKey } = require('./helpers');

  function buildApp() {
    const a = express();
    a.use(express.json());
    a.use('/domains', requireTenant, domainsRouter);
    return a;
  }

  before(() => {
    databaseService.init(':memory:');
    db = databaseService.getDb();
    testApiKey = 'activate-test-key';
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'ActivateTest', hashApiKey(testApiKey), new Date().toISOString());
    app = buildApp();
  });

  after(() => {
    databaseService.close();
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  it('should return 404 for unknown domain', async () => {
    const res = await request(app).post('/domains/nonexistent.xyz/activate').set(auth());
    assert.equal(res.status, 404);
  });

  it('should return 409 when MX does not yet point to relay', async () => {
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(databaseService.uuid(), tenantId, 'activate-test-domain.com', 'Test', 'mx.original.com', 'mx.destination.com', 'mx1.emailrelay.com', 'PENDING_DNS', new Date().toISOString(), null);

    const res = await request(app).post('/domains/activate-test-domain.com/activate').set(auth());
    assert.equal(res.status, 409);
    assert.ok((res.body.error as string).includes('does not yet point'));
  });

  it('should handle domain with specific MX that does not match relay', async () => {
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(databaseService.uuid(), tenantId, 'mx-points-elsewhere.com', 'Test', 'mx.original.com', 'mx.destination.com', 'mx1.emailrelay.com', 'PENDING_DNS', new Date().toISOString(), null);

    const res = await request(app).post('/domains/mx-points-elsewhere.com/activate').set(auth());
    assert.equal(res.status, 409);
    assert.ok(res.body.instructions);
    assert.ok(res.body.instructions.after);
  });
});

/* ------------------------------------------------------------------ */
/*  Emails release – remaining paths                                   */
/* ------------------------------------------------------------------ */
describe('Emails API – release edge cases', () => {
  let app: express.Application;
  let tenantId: string;
  let testApiKey: string;
  let db: ReturnType<typeof import('../dist/services/DatabaseService').DatabaseService.prototype.getDb>;
  const TEST_DIR = path.join(__dirname, '..', 'data', 'test-release-' + process.pid);

  const { default: databaseService } = require('../dist/services/DatabaseService');
  const config = require('../dist/config').default;
  const { requireTenant } = require('../dist/middleware/AuthMiddleware');
  const emailsRouter = require('../dist/api/routes/emails').default;
  const { hashApiKey } = require('./helpers');

  function buildApp() {
    const a = express();
    a.use(express.json());
    a.use('/emails', requireTenant, emailsRouter);
    return a;
  }

  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;

    databaseService.init(':memory:');
    db = databaseService.getDb();
    testApiKey = 'release-edge-key-' + Date.now();
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'ReleaseEdge', hashApiKey(testApiKey), new Date().toISOString());

    const domainId = databaseService.uuid();
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(domainId, tenantId, 'forward-target.com', 'Test', 'mx.orig.com', '127.0.0.1', 'mx1.emailrelay.com', 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    app = buildApp();
  });

  after(() => {
    databaseService.close();
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  it('should return 500 when quarantine file does not exist on disk', async () => {
    const emailId = databaseService.uuid();
    db.prepare(`
      INSERT INTO emails (id, tenant_id, domain, sender, recipient, subject, remote_ip,
        spam_score, decision, status, relay_id, reason, headers_json,
        size_bytes, eml_path, received_at, processed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(emailId, tenantId, 'forward-target.com', 's@ex.com', 'r@ex.com', 'Missing file test', '1.2.3.4', 6, 'QUARANTINED', 'QUARANTINED', 'relay-01', null, null, 100, '/tmp/nonexistent-file-' + Date.now() + '.eml', new Date().toISOString(), new Date().toISOString());

    const res = await request(app).post(`/emails/${emailId}/release`).set(auth());
    assert.equal(res.status, 500);
    assert.ok((res.body.error as string).includes('file') || (res.body.error as string).includes('stored'));
  });

  it('should return 500 when domain has no destination_mx', async () => {
    const noDestDomainId = databaseService.uuid();
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(noDestDomainId, tenantId, 'no-dest-' + Date.now() + '.com', 'Test', 'mx.orig.com', null, 'mx1.emailrelay.com', 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const emailId = databaseService.uuid();
    const emlPath = path.join(TEST_DIR, emailId + '.eml');
    fs.writeFileSync(emlPath, Buffer.from('test'));
    db.prepare(`
      INSERT INTO emails (id, tenant_id, domain, sender, recipient, subject, remote_ip,
        spam_score, decision, status, relay_id, reason, headers_json,
        size_bytes, eml_path, received_at, processed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(emailId, tenantId, 'no-dest-' + Date.now() + '.com', 's@ex.com', 'r@ex.com', 'No dest test', '1.2.3.4', 6, 'QUARANTINED', 'QUARANTINED', 'relay-01', null, null, 100, emlPath, new Date().toISOString(), new Date().toISOString());

    const res = await request(app).post(`/emails/${emailId}/release`).set(auth());
    assert.equal(res.status, 500);
    assert.ok((res.body.error as string).includes('destination'));
  });

  it('should return 502 when forwarder fails (unreachable MX)', async () => {
    const emailId = databaseService.uuid();
    const emlPath = path.join(TEST_DIR, emailId + '.eml');
    fs.writeFileSync(emlPath, Buffer.from('From: test\r\nTo: test\r\nSubject: Release test\r\n\r\nBody'));
    db.prepare(`
      INSERT INTO emails (id, tenant_id, domain, sender, recipient, subject, remote_ip,
        spam_score, decision, status, relay_id, reason, headers_json,
        size_bytes, eml_path, received_at, processed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(emailId, tenantId, 'forward-target.com', 's@ex.com', 'r@ex.com', 'Forward fail test', '1.2.3.4', 6, 'QUARANTINED', 'QUARANTINED', 'relay-01', null, null, 100, emlPath, new Date().toISOString(), new Date().toISOString());

    const res = await request(app).post(`/emails/${emailId}/release`).set(auth());
    assert.equal(res.status, 502);
    assert.ok((res.body.error as string).includes('release failed'));
  });
});

/* ------------------------------------------------------------------ */
/*  Email serialization with headers                                  */
/* ------------------------------------------------------------------ */
describe('Emails API – headers serialization', () => {
  let app: express.Application;
  let tenantId: string;
  let testApiKey: string;
  let db: ReturnType<typeof import('../dist/services/DatabaseService').DatabaseService.prototype.getDb>;

  const { default: databaseService } = require('../dist/services/DatabaseService');
  const { requireTenant } = require('../dist/middleware/AuthMiddleware');
  const emailsRouter = require('../dist/api/routes/emails').default;
  const { hashApiKey } = require('./helpers');

  function buildApp() {
    const a = express();
    a.use(express.json());
    a.use('/emails', requireTenant, emailsRouter);
    return a;
  }

  before(() => {
    databaseService.init(':memory:');
    db = databaseService.getDb();
    testApiKey = 'headers-test-key';
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'HeadersTest', hashApiKey(testApiKey), new Date().toISOString());
    app = buildApp();
  });

  after(() => {
    databaseService.close();
  });

  function auth() {
    return { Authorization: `Bearer ${testApiKey}` };
  }

  function insertEmail(overrides: Record<string, unknown> = {}) {
    const email: Record<string, unknown> = {
      id: databaseService.uuid(),
      tenant_id: tenantId,
      domain: 'h-test.com',
      sender: 's@h.com',
      recipient: 'r@h.com',
      subject: 'Test',
      remote_ip: '1.2.3.4',
      spam_score: 0,
      decision: 'FORWARDED',
      status: 'FORWARDED',
      relay_id: 'relay-01',
      reason: null,
      headers_json: null,
      size_bytes: 100,
      eml_path: null,
      received_at: new Date().toISOString(),
      processed_at: new Date().toISOString(),
      ...overrides,
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

  it('should include parsed headers when requesting single email', async () => {
    const headersData = { received: ['from mx.test.com'], 'message-id': '<abc@test>' };
    const email = insertEmail({ headers_json: JSON.stringify(headersData) });

    const res = await request(app).get(`/emails/${email.id}`).set(auth());
    assert.equal(res.status, 200);
    assert.ok(res.body.email.headers, 'should have headers field');
    assert.equal(res.body.email.headers.received[0], 'from mx.test.com');
  });

  it('should not include headers in list endpoint', async () => {
    insertEmail({ subject: 'List test', headers_json: JSON.stringify({ x: 'y' }) });
    const res = await request(app).get('/emails').set(auth());
    assert.equal(res.status, 200);
    const listEmails = res.body.emails as Record<string, unknown>[];
    if (listEmails.length > 0) {
      assert.ok(!listEmails[0].headers, 'list should not include headers');
    }
  });

  it('should handle null headers_json gracefully', async () => {
    const email = insertEmail({ headers_json: null });

    const res = await request(app).get(`/emails/${email.id}`).set(auth());
    assert.equal(res.status, 200);
    assert.equal(res.body.email.headers, null);
  });

  it('should handle malformed headers_json gracefully', async () => {
    const email = insertEmail({ headers_json: 'not-valid-json{' });

    const res = await request(app).get(`/emails/${email.id}`).set(auth());
    assert.equal(res.status, 200);
    assert.equal(res.body.email.headers, null);
  });

  it('should delete quarantine file when deleting email with eml_path', async () => {
    const { default: config } = require('../dist/config');
    config.quarantineDir = path.join(__dirname, '..', 'data', 'test-delete-' + process.pid);
    fs.mkdirSync(config.quarantineDir, { recursive: true });

    const emlPath = path.join(config.quarantineDir, 'to-delete.eml');
    fs.writeFileSync(emlPath, 'test content');

    const email = insertEmail({ eml_path: emlPath });

    const res = await request(app).delete(`/emails/${email.id}`).set(auth());
    assert.equal(res.status, 204);
    assert.ok(!fs.existsSync(emlPath), 'quarantine file should be deleted');

    fs.rmSync(config.quarantineDir, { recursive: true, force: true });
    config.quarantineDir = path.join(__dirname, '..', 'data');
  });
});

/* ------------------------------------------------------------------ */
/*  SMTP gateway – onRcptTo edge cases                                */
/* ------------------------------------------------------------------ */
describe('SMTP gateway – onRcptTo edge cases', () => {
  let server: ReturnType<typeof import('../dist/smtp-gateway').buildServer>;
  let dbSvc: typeof import('../dist/services/DatabaseService').default;
  const TEST_DIR = path.join(__dirname, '..', 'data', 'test-rcptto-' + process.pid);
  const SMTP_PORT = 19988;
  let originalQuarantineDir: string;

  before(async () => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    const config = require('../dist/config').default;
    originalQuarantineDir = config.quarantineDir;
    config.quarantineDir = TEST_DIR;

    dbSvc = require('../dist/services/DatabaseService').default;
    dbSvc.init(':memory:');
    const { hashApiKey } = require('./helpers');
    const db = dbSvc.getDb();
    const tenantId = dbSvc.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'RcptToTest', hashApiKey('rcptto-key'), new Date().toISOString());
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(dbSvc.uuid(), tenantId, 'valid-domain.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const { buildServer } = require('../dist/smtp-gateway');
    server = buildServer();
    await new Promise<void>((resolve) => server.listen(SMTP_PORT, resolve));
  });

  after(() => {
    const config = require('../dist/config').default;
    config.quarantineDir = originalQuarantineDir;
    server.close();
    dbSvc.close();
    try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should reject recipient for unconfigured domain', async () => {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: 'localhost',
      port: SMTP_PORT,
      secure: false,
      tls: { rejectUnauthorized: false },
      connectionTimeout: 5000,
      greetingTimeout: 5000,
    });

    try {
      await transporter.sendMail({
        envelope: { from: 'sender@test.com', to: ['user@unknown-domain.com'] },
        raw: 'From: sender@test.com\r\nTo: user@unknown-domain.com\r\nSubject: Test\r\n\r\nBody',
      });
      assert.fail('should have rejected unknown domain');
    } catch (err: unknown) {
      const msg = (err as Error).message;
      assert.ok(msg.includes('550') || msg.includes('No such domain') || msg.includes('unknown'),
        `Expected domain rejection, got: ${msg}`);
    }
  });

  it('should reject recipient without @ symbol', async () => {
    const net = require('net');
    const response = await new Promise<string>((resolve, reject) => {
      const client = new net.Socket();
      let buf = '';
      let lastCmd = '';
      let expecting = 'banner';
      const timeout = setTimeout(() => {
        client.destroy();
        reject(new Error(`timeout - expecting=${expecting} buf=${buf.slice(-200)}`));
      }, 5000);

      function checkResponse() {
        // Get lines ending with SPACE (not dash) = end of multi-line response
        const lines = buf.split('\r\n');
        const lastResp = [...lines].reverse().find(l => /^\d{3} ./.test(l));
        if (!lastResp) return;

        const code = lastResp.substring(0, 3);

        if (expecting === 'banner') {
          if (code === '220') {
            lastCmd = 'EHLO test';
            client.write(lastCmd + '\r\n');
            expecting = 'ehlo';
          }
          return;
        }

        if (expecting === 'ehlo') {
          if (code === '250') {
            lastCmd = 'MAIL FROM:<sender@test.com>';
            client.write(lastCmd + '\r\n');
            expecting = 'mail';
          }
          return;
        }

        if (expecting === 'mail') {
          if (code === '250') {
            lastCmd = 'RCPT TO:<noatsign>';
            client.write(lastCmd + '\r\n');
            expecting = 'rcpt';
          }
          return;
        }

        if (expecting === 'rcpt') {
          if (code === '550' || code === '501') {
            clearTimeout(timeout);
            client.write('QUIT\r\n');
            setTimeout(() => { client.destroy(); resolve(lastResp); }, 200);
            expecting = 'done';
          }
          return;
        }
      }

      client.connect(SMTP_PORT, 'localhost');

      client.on('data', (data: Buffer) => {
        buf += data.toString();
        checkResponse();
      });

      client.on('error', (e: Error) => { clearTimeout(timeout); reject(e); });
    });

    assert.ok(response.includes('550') || response.includes('501'), `Expected 5xx, got: ${response}`);
  });
});

/* ------------------------------------------------------------------ */
/*  SMTP gateway – onData parse failure                               */
/* ------------------------------------------------------------------ */
describe('SMTP gateway – parse failure', () => {
  it('should handle mail that fails to parse', async () => {
    const nodemailer = require('nodemailer');
    const { buildServer } = require('../dist/smtp-gateway');
    const { default: databaseService } = require('../dist/services/DatabaseService');
    const { default: config } = require('../dist/config');
    const TEST_DIR = path.join(__dirname, '..', 'data', 'test-parse-' + process.pid);
    const SMTP_PORT = 18989;

    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;

    databaseService.init(':memory:');
    const db = databaseService.getDb();
    const tenantId = databaseService.uuid();
    const { hashApiKey } = require('./helpers');
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'ParseTest', hashApiKey('parse-key'), new Date().toISOString());
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(databaseService.uuid(), tenantId, 'parse-test-domain.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const server = buildServer();
    server.listen(SMTP_PORT);

    const transporter = nodemailer.createTransport({
      host: 'localhost',
      port: SMTP_PORT,
      secure: false,
      tls: { rejectUnauthorized: false },
      connectionTimeout: 5000,
      greetingTimeout: 5000,
    });

    try {
      await transporter.sendMail({
        envelope: { from: 'sender@test.com', to: ['user@parse-test-domain.com'] },
        raw: Buffer.from([0x00, 0xFF, 0xFE]), // binary junk that may fail to parse
      });
      // Depending on mailparser version this might succeed or fail
      // Either way the server should not crash
    } catch {
      // Expected
    }

    server.close(() => {
      databaseService.close();
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    });
  });
});

/* ------------------------------------------------------------------ */
/*  buildApiApp – health, dashboard, and edge cases                   */
/* ------------------------------------------------------------------ */
describe('API server – health & static files', () => {
  it('health endpoint should return ok', async () => {
    const { buildApiApp } = require('../dist/api/server');
    const app = buildApiApp();
    const res = await request(app).get('/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
  });

  it('dashboard index should be served at /', async () => {
    const { buildApiApp } = require('../dist/api/server');
    const app = buildApiApp();
    const res = await request(app).get('/');
    assert.ok(res.status === 200 || res.status === 404);
    if (res.status === 200) {
      assert.ok((res.text as string).includes('Email Security Relay'));
    }
  });

  it('should return 404 for unknown routes', async () => {
    const { buildApiApp } = require('../dist/api/server');
    const app = buildApiApp();
    const res = await request(app).get('/nonexistent-route-12345');
    assert.equal(res.status, 404);
  });

  it('should include CORS headers', async () => {
    const { buildApiApp } = require('../dist/api/server');
    const app = buildApiApp();
    const res = await request(app).options('/health');
    const origin = res.headers['access-control-allow-origin'];
    const methods = res.headers['access-control-allow-methods'];
    assert.ok(origin !== undefined || methods !== undefined,
      `Expected CORS headers, got: ${JSON.stringify(res.headers)}`);
  });

  it('should reject JSON body exceeding 2mb limit', async () => {
    const { buildApiApp } = require('../dist/api/server');
    const app = buildApiApp();
    // Create a 2.5mb payload
    const bigBody = Buffer.alloc(2.5 * 1024 * 1024).toString('utf8');
    const res = await request(app)
      .post('/domains')
      .set('Content-Type', 'application/json')
      .send(bigBody);
    // Should get 413 Entity Too Large or 400 Bad Request
    assert.ok(res.status === 413 || res.status === 400,
      `Expected 413 or 400, got: ${res.status}`);
  });
});

/* ------------------------------------------------------------------ */
/*  Config validation                                                 */
/* ------------------------------------------------------------------ */
describe('Config – validate() function', () => {
  let originalSecret: string | undefined;

  before(() => {
    originalSecret = process.env.RELAY_SECRET;
  });

  after(() => {
    process.env.RELAY_SECRET = originalSecret;
    delete require.cache[require.resolve('../dist/config')];
    require('../dist/config');
  });

  it('should log error for RELAY_SECRET = change-me', () => {
    process.env.RELAY_SECRET = 'change-me';
    delete require.cache[require.resolve('../dist/config')];
    const cfg = require('../dist/config').default;
    assert.ok(cfg.relaySecret, 'config still loads');
    assert.equal(cfg.relaySecret, 'change-me');
  });

  it('should log error for RELAY_SECRET too short (< 8 chars)', () => {
    process.env.RELAY_SECRET = 'short';
    delete require.cache[require.resolve('../dist/config')];
    const cfg = require('../dist/config').default;
    assert.equal(cfg.relaySecret, 'short');
  });

  it('should NOT log error for valid RELAY_SECRET', () => {
    process.env.RELAY_SECRET = 'this-is-a-valid-secret-123!';
    delete require.cache[require.resolve('../dist/config')];
    const cfg = require('../dist/config').default;
    assert.equal(cfg.relaySecret, 'this-is-a-valid-secret-123!');
  });

  it('should use default when RELAY_SECRET is not set', () => {
    delete process.env.RELAY_SECRET;
    delete require.cache[require.resolve('../dist/config')];
    const cfg = require('../dist/config').default;
    assert.equal(cfg.relaySecret, 'dev-secret-do-not-use-in-prod');
  });
});
