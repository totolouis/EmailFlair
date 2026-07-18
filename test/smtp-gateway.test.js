const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

process.env.DB_PATH = ':memory:';

delete require.cache[require.resolve('../src/config')];
delete require.cache[require.resolve('../src/db')];
delete require.cache[require.resolve('../src/routing-engine')];
delete require.cache[require.resolve('../src/loop-prevention')];
delete require.cache[require.resolve('../src/spam-filter')];
delete require.cache[require.resolve('../src/quarantine')];
delete require.cache[require.resolve('../src/forwarder')];
delete require.cache[require.resolve('../src/smtp-gateway')];

const { initDb, closeDb, getDb, uuid } = require('../src/db');
const config = require('../src/config');
const { buildServer } = require('../src/smtp-gateway');
const { signRelayId } = require('../src/loop-prevention');

const TEST_DIR = path.join(__dirname, '..', 'data', 'test-smtp-' + process.pid);
const SMTP_TEST_PORT = 18987;

function createTransporter() {
  return nodemailer.createTransport({
    host: 'localhost',
    port: SMTP_TEST_PORT,
    secure: false,
    tls: { rejectUnauthorized: false },
    connectionTimeout: 5000,
    greetingTimeout: 5000,
  });
}

async function sendTestMessage({ from, to, subject, extraHeaders = '' }) {
  const transporter = createTransporter();
  try {
    const info = await transporter.sendMail({
      envelope: { from: from || 'sender@example.org', to: [to || 'user@test.com'] },
      raw:
        `${extraHeaders}From: ${from || 'sender@example.org'}\r\n` +
        `To: ${to || 'user@test.com'}\r\n` +
        `Subject: ${subject || 'Test'}\r\n` +
        `\r\n${subject || 'Test'} body.\r\n`,
    });
    return { accepted: true, response: info.response };
  } catch (err) {
    const errMsg = err.message || String(err);
    return { accepted: false, message: errMsg };
  }
}

function findSmtpCode(errMsg) {
  const m = errMsg.match(/(\d{3})/);
  return m ? parseInt(m[1], 10) : null;
}

describe('SMTP gateway integration', () => {
  let server;
  let tenantId;
  let db;

  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;

    initDb(':memory:');
    db = getDb();
    tenantId = uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', 'test-key', new Date().toISOString());

    server = buildServer();
    server.listen(SMTP_TEST_PORT);
  });

  after(() => {
    server.close(() => {
      closeDb();
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    });
  });

  it('should reject mail for unknown domain with 550', async () => {
    const result = await sendTestMessage({ to: 'user@unknown-xyz-domain.com', subject: 'Unknown' });
    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message), 550, `Expected 550, got: ${result.message}`);
  });

  it('should reject mail for inactive (PENDING_DNS) domain with 550', async () => {
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(uuid(), tenantId, 'pending-domain.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'PENDING_DNS', new Date().toISOString(), null);

    const result = await sendTestMessage({ to: 'user@pending-domain.com', subject: 'Pending' });
    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message), 550, `Expected 550, got: ${result.message}`);
  });

  it('should process mail for active domain (forwarder may fail in test env)', async () => {
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(uuid(), tenantId, 'active-test.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const result = await sendTestMessage({ to: 'user@active-test.com', subject: 'Process test' });
    // The mail is accepted by the gateway, but the forwarder (127.0.0.1:25) is not running
    // So the SMTP session will report a temporary failure. The email is still logged.
    const emailRecord = db.prepare("SELECT * FROM emails WHERE domain = 'active-test.com' ORDER BY received_at DESC LIMIT 1").get();
    assert.ok(emailRecord, 'Email should be recorded in database');
    assert.equal(emailRecord.recipient, 'user@active-test.com');
  });

  it('should detect loop with code 554 in error message', async () => {
    const sig = signRelayId(config.relayId, config.relaySecret);
    const extraHeaders =
      `X-Relay-ID: ${config.relayId}\r\n` +
      `X-Relay-Signature: ${sig}\r\n`;

    const result = await sendTestMessage({
      to: 'user@active-test.com',
      subject: 'Loop test',
      extraHeaders,
    });

    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message), 554, `Expected 554, got: ${result.message}`);
    assert.ok(result.message.toLowerCase().includes('loop'), `Should mention loop: ${result.message}`);
  });

  it('should quarantine message when spam score exceeds threshold', async () => {
    // Create a dedicated domain for this test
    const quarantineDomainId = uuid();
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(quarantineDomainId, tenantId, 'quarantine-test.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const beforeCount = db.prepare("SELECT COUNT(*) as c FROM emails WHERE decision = 'QUARANTINED' AND domain = 'quarantine-test.com'").get().c;

    // Use subject keywords to trigger quarantine: 3 keywords * 2 = 6 points (between 5 and 10)
    const result = await sendTestMessage({
      from: 'user@example.com',
      to: 'user@quarantine-test.com',
      subject: 'URGENT wire transfer bitcoin needed',
    });

    assert.ok(result.accepted, `Quarantined mail should be accepted, got: ${result.message}`);

    const afterCount = db.prepare("SELECT COUNT(*) as c FROM emails WHERE decision = 'QUARANTINED' AND domain = 'quarantine-test.com'").get().c;
    assert.equal(afterCount, beforeCount + 1, `Quarantined count should increase by 1: ${beforeCount} -> ${afterCount}`);
  });

  it('should reject spam with code 554 when score exceeds reject threshold', async () => {
    const origReject = config.rejectThreshold;
    config.rejectThreshold = 1;

    const result = await sendTestMessage({
      to: 'user@active-test.com',
      subject: 'URGENT wire transfer bitcoin',
    });

    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message), 554, `Expected 554, got: ${result.message}`);

    config.rejectThreshold = origReject;
  });

  it('should record email metadata in database', async () => {
    const email = db.prepare("SELECT * FROM emails WHERE domain = 'active-test.com' ORDER BY received_at DESC LIMIT 1").get();
    assert.ok(email, 'Email record should exist');
    assert.ok(email.sender);
    assert.ok(email.recipient);
    assert.ok(email.subject);
    assert.equal(typeof email.spam_score, 'number');
    assert.ok(email.received_at);
    assert.ok(email.id);
    assert.ok(email.relay_id);
  });

  it('should record looped messages in database as REJECTED', async () => {
    const looped = db.prepare("SELECT * FROM emails WHERE decision = 'REJECTED' AND reason LIKE '%X-Relay-ID%'").all();
    assert.ok(looped.length > 0, 'Should have looped message records');
  });

  it('should track remote IP of incoming messages', async () => {
    const email = db.prepare("SELECT remote_ip FROM emails WHERE domain = 'active-test.com' ORDER BY received_at DESC LIMIT 1").get();
    assert.ok(email, 'Email record should exist');
    assert.ok(email.remote_ip, `Remote IP should be set, got: ${JSON.stringify(email.remote_ip)}`);
  });
});
