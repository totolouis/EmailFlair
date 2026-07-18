const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');

describe('config', () => {
  let envBackup;

  before(() => {
    envBackup = {};
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('RELAY_') || key.startsWith('SMTP_') || key.startsWith('API_') || key.startsWith('SPAM_') || key.startsWith('DB_') || key.startsWith('QUARANTINE_') || key.startsWith('DEFAULT_')) {
        envBackup[key] = process.env[key];
        delete process.env[key];
      }
    }
  });

  after(() => {
    for (const [key, value] of Object.entries(envBackup)) {
      if (value !== undefined) process.env[key] = value;
    }
  });

  it('should use default values when env vars are not set', () => {
    delete require.cache[require.resolve('../src/config')];
    delete require.cache[require.resolve('../src/db')];
    const config = require('../src/config');
    assert.equal(config.relayId, 'relay-01');
    assert.equal(config.relayHostname, 'mx1.emailrelay.com');
    assert.equal(config.smtpPort, 2525);
    assert.equal(config.apiPort, 3000);
    assert.equal(config.quarantineThreshold, 5);
    assert.equal(config.rejectThreshold, 10);
    assert.equal(config.dbPath, './data/relay.db');
    assert.equal(config.defaultTenantName, 'Default Tenant');
    assert.equal(config.defaultTenantApiKey, 'dev-tenant-key');
  });

  it('should read values from environment', () => {
    process.env.RELAY_ID = 'test-relay';
    process.env.RELAY_SECRET = 'my-super-secret-key';
    process.env.RELAY_HOSTNAME = 'mx.test.com';
    process.env.SMTP_PORT = '25';
    process.env.API_PORT = '8080';
    process.env.SPAM_QUARANTINE_THRESHOLD = '3';
    process.env.SPAM_REJECT_THRESHOLD = '8';
    process.env.DB_PATH = '/tmp/test.db';
    process.env.QUARANTINE_DIR = '/tmp/quarantine';
    process.env.DEFAULT_TENANT_NAME = 'TestCo';
    process.env.DEFAULT_TENANT_API_KEY = 'test-key';

    delete require.cache[require.resolve('../src/config')];
    const config = require('../src/config');

    assert.equal(config.relayId, 'test-relay');
    assert.equal(config.relaySecret, 'my-super-secret-key');
    assert.equal(config.relayHostname, 'mx.test.com');
    assert.equal(config.smtpPort, 25);
    assert.equal(config.apiPort, 8080);
    assert.equal(config.quarantineThreshold, 3);
    assert.equal(config.rejectThreshold, 8);
    assert.equal(config.dbPath, '/tmp/test.db');
    assert.equal(config.quarantineDir, '/tmp/quarantine');
    assert.equal(config.defaultTenantName, 'TestCo');
    assert.equal(config.defaultTenantApiKey, 'test-key');
  });

  it('should parse float thresholds correctly', () => {
    process.env.SPAM_QUARANTINE_THRESHOLD = '4.5';
    process.env.SPAM_REJECT_THRESHOLD = '9.5';
    delete require.cache[require.resolve('../src/config')];
    const config = require('../src/config');
    assert.equal(config.quarantineThreshold, 4.5);
    assert.equal(config.rejectThreshold, 9.5);
  });

  it('should parse port numbers correctly', () => {
    process.env.SMTP_PORT = '465';
    delete require.cache[require.resolve('../src/config')];
    const config = require('../src/config');
    assert.strictEqual(config.smtpPort, 465);
    assert.strictEqual(typeof config.smtpPort, 'number');
  });
});
