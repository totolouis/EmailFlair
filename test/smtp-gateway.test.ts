import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs';
import nodemailer from 'nodemailer';

import config from '../dist/config';
import databaseService from '../dist/services/DatabaseService';
import loopPreventionService from '../dist/services/LoopPreventionService';
import { buildServer } from '../dist/smtp-gateway';
import { hashApiKey } from './helpers';

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

async function sendTestMessage({ from, to, subject, extraHeaders = '' }: {
  from?: string;
  to?: string;
  subject?: string;
  extraHeaders?: string;
}) {
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
    const errMsg = (err as Error).message || String(err);
    return { accepted: false, message: errMsg };
  }
}

function findSmtpCode(errMsg: string): number | null {
  const m = errMsg.match(/(\d{3})/);
  return m ? parseInt(m[1], 10) : null;
}

describe('SMTP gateway integration', () => {
  let server: ReturnType<typeof buildServer>;
  let tenantId: string;
  let db: ReturnType<typeof databaseService.getDb>;

  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;

    databaseService.init(':memory:');
    db = databaseService.getDb();
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', hashApiKey('test-key'), new Date().toISOString());

    server = buildServer();
    server.listen(SMTP_TEST_PORT);
  });

  after(() => {
    server.close(() => {
      databaseService.close();
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    });
  });

  it('should reject mail for unknown domain with 550', async () => {
    const result = await sendTestMessage({ to: 'user@unknown-xyz-domain.com', subject: 'Unknown' });
    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message!), 550, `Expected 550, got: ${result.message}`);
  });

  it('should reject mail for inactive (PENDING_DNS) domain with 550', async () => {
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(databaseService.uuid(), tenantId, 'pending-domain.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'PENDING_DNS', new Date().toISOString(), null);

    const result = await sendTestMessage({ to: 'user@pending-domain.com', subject: 'Pending' });
    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message!), 550, `Expected 550, got: ${result.message}`);
  });

  it('should process mail for active domain (forwarder may fail in test env)', async () => {
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(databaseService.uuid(), tenantId, 'active-test.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const result = await sendTestMessage({ to: 'user@active-test.com', subject: 'Process test' });
    // The mail is accepted by the gateway, but the forwarder (127.0.0.1:25) is not running
    // So the SMTP session will report a temporary failure. The email is still logged.
    const emailRecord = db.prepare("SELECT * FROM emails WHERE domain = 'active-test.com' ORDER BY received_at DESC LIMIT 1").get() as Record<string, unknown> | undefined;
    assert.ok(emailRecord, 'Email should be recorded in database');
    assert.equal(emailRecord!.recipient, 'user@active-test.com');
  });

  it('should detect loop with code 554 in error message', async () => {
    const sig = loopPreventionService.signRelayId(config.relayId, config.relaySecret);
    const extraHeaders =
      `X-Relay-ID: ${config.relayId}\r\n` +
      `X-Relay-Signature: ${sig}\r\n`;

    const result = await sendTestMessage({
      to: 'user@active-test.com',
      subject: 'Loop test',
      extraHeaders,
    });

    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message!), 554, `Expected 554, got: ${result.message}`);
    assert.ok(result.message!.toLowerCase().includes('loop'), `Should mention loop: ${result.message}`);
  });

  it('should quarantine message when spam score exceeds threshold', async () => {
    const quarantineDomainId = databaseService.uuid();
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(quarantineDomainId, tenantId, 'quarantine-test.com', 'Test', 'mx.test.com', '127.0.0.1', config.relayHostname, 'ACTIVE', new Date().toISOString(), new Date().toISOString());

    const beforeCount = (db.prepare("SELECT COUNT(*) as c FROM emails WHERE decision = 'QUARANTINED' AND domain = 'quarantine-test.com'").get() as { c: number }).c;

    // Set thresholds so any positive score quarantines (enhanced filter adds DNS/header scores)
    const origQuarantine = config.quarantineThreshold;
    const origReject = config.rejectThreshold;
    config.quarantineThreshold = 1;
    config.rejectThreshold = 999;

    const result = await sendTestMessage({
      from: 'user@example.com',
      to: 'user@quarantine-test.com',
      subject: 'test message',
    });

    assert.ok(result.accepted, `Quarantined mail should be accepted, got: ${result.message}`);

    const afterCount = (db.prepare("SELECT COUNT(*) as c FROM emails WHERE decision = 'QUARANTINED' AND domain = 'quarantine-test.com'").get() as { c: number }).c;
    assert.equal(afterCount, beforeCount + 1, `Quarantined count should increase by 1: ${beforeCount} -> ${afterCount}`);

    config.quarantineThreshold = origQuarantine;
    config.rejectThreshold = origReject;
  });

  it('should reject spam with code 554 when score exceeds reject threshold', async () => {
    const origReject = config.rejectThreshold;
    config.rejectThreshold = 1;

    const result = await sendTestMessage({
      to: 'user@active-test.com',
      subject: 'URGENT wire transfer bitcoin',
    });

    assert.ok(!result.accepted);
    assert.equal(findSmtpCode(result.message!), 554, `Expected 554, got: ${result.message}`);

    config.rejectThreshold = origReject;
  });

  it('should record email metadata in database', async () => {
    const email = db.prepare("SELECT * FROM emails WHERE domain = 'active-test.com' ORDER BY received_at DESC LIMIT 1").get() as Record<string, unknown> | undefined;
    assert.ok(email, 'Email record should exist');
    assert.ok(email!.sender);
    assert.ok(email!.recipient);
    assert.ok(email!.subject);
    assert.equal(typeof email!.spam_score, 'number');
    assert.ok(email!.received_at);
    assert.ok(email!.id);
    assert.ok(email!.relay_id);
  });

  it('should record looped messages in database as REJECTED', async () => {
    const looped = db.prepare("SELECT * FROM emails WHERE decision = 'REJECTED' AND reason LIKE '%X-Relay-ID%'").all() as Record<string, unknown>[];
    assert.ok(looped.length > 0, 'Should have looped message records');
  });

  it('should track remote IP of incoming messages', async () => {
    const email = db.prepare("SELECT remote_ip FROM emails WHERE domain = 'active-test.com' ORDER BY received_at DESC LIMIT 1").get() as { remote_ip: string | null } | undefined;
    assert.ok(email, 'Email record should exist');
    assert.ok(email!.remote_ip, `Remote IP should be set, got: ${JSON.stringify(email!.remote_ip)}`);
  });
});
