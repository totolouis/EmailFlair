const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');

process.env.DB_PATH = ':memory:';

delete require.cache[require.resolve('../src/config')];
delete require.cache[require.resolve('../src/db')];
delete require.cache[require.resolve('../src/spam-filter')];

const { initDb, closeDb, getDb, uuid } = require('../src/db');
const { scoreEmail } = require('../src/spam-filter');

const DEFAULT_SENDER = 'user@example.com';
const DEFAULT_DOMAIN = 'example.com';
const DEFAULT_IP = '1.2.3.4';

function makeParams(overrides = {}) {
  return {
    tenantId: null,
    remoteIp: DEFAULT_IP,
    senderDomain: DEFAULT_DOMAIN,
    senderAddress: DEFAULT_SENDER,
    subject: '',
    hasAttachments: false,
    ...overrides,
  };
}

describe('spam-filter', () => {
  let tenantId;

  before(() => {
    initDb(':memory:');
    const db = getDb();
    tenantId = uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', 'test-key', new Date().toISOString());
  });

  after(() => {
    closeDb();
  });

  function addToList(table, type, value) {
    getDb().prepare(`INSERT INTO ${table} (id, tenant_id, type, value, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(uuid(), tenantId, type, value, new Date().toISOString());
  }

  describe('whitelist', () => {
    it('should return score 0 when sender IP is whitelisted', () => {
      addToList('whitelist', 'ip', '10.0.0.1');
      const result = scoreEmail(makeParams({ tenantId, remoteIp: '10.0.0.1', senderDomain: 'evil.com', subject: 'urgent wire transfer' }));
      assert.equal(result.score, 0);
      assert.ok(result.reasons.includes('sender is whitelisted'));
    });

    it('should return score 0 when sender domain is whitelisted', () => {
      addToList('whitelist', 'domain', 'trusted.com');
      const result = scoreEmail(makeParams({ tenantId, remoteIp: '10.0.0.2', senderDomain: 'trusted.com', subject: 'urgent wire transfer' }));
      assert.equal(result.score, 0);
    });
  });

  describe('blacklist', () => {
    it('should add 10 points for blacklisted IP', () => {
      addToList('blacklist', 'ip', '192.168.1.1');
      const result = scoreEmail(makeParams({ tenantId, remoteIp: '192.168.1.1' }));
      assert.equal(result.score, 10);
    });

    it('should add 10 points for blacklisted domain', () => {
      addToList('blacklist', 'domain', 'spam.com');
      const result = scoreEmail(makeParams({ tenantId, senderDomain: 'spam.com' }));
      assert.equal(result.score, 10);
    });

    it('should add 20 points when both IP and domain are blacklisted', () => {
      addToList('blacklist', 'ip', '5.5.5.5');
      addToList('blacklist', 'domain', 'spam.com');
      const result = scoreEmail(makeParams({ tenantId, remoteIp: '5.5.5.5', senderDomain: 'spam.com' }));
      assert.equal(result.score, 20);
    });
  });

  describe('subject keywords', () => {
    it('should add 2 points for each suspicious keyword', () => {
      const result = scoreEmail(makeParams({ tenantId, subject: 'URGENT wire transfer needed' }));
      assert.equal(result.score, 4);
    });

    it('should handle empty subject', () => {
      const result = scoreEmail(makeParams({ tenantId, subject: '' }));
      assert.equal(result.score, 0);
    });

    it('should not flag normal subject lines', () => {
      const result = scoreEmail(makeParams({ tenantId, subject: 'Meeting tomorrow at 3pm' }));
      assert.equal(result.score, 0);
    });

    it('should be case-insensitive for keyword matching', () => {
      const result = scoreEmail(makeParams({ tenantId, subject: 'BITCOIN GIFT CARD' }));
      assert.equal(result.score, 4);
    });

    it('should accumulate points per keyword', () => {
      const result = scoreEmail(makeParams({ tenantId, subject: 'verify your account urgent act now bitcoin' }));
      assert.equal(result.score, 8);
    });
  });

  describe('sender validation', () => {
    it('should add 3 points for malformed sender', () => {
      const result = scoreEmail(makeParams({ tenantId, senderAddress: 'not-an-email' }));
      assert.equal(result.score, 3);
    });

    it('should add 3 points for missing sender', () => {
      const result = scoreEmail(makeParams({ tenantId, senderAddress: null }));
      assert.equal(result.score, 3);
    });

    it('should not penalize valid sender address', () => {
      const result = scoreEmail(makeParams({ tenantId, senderAddress: 'user@example.com' }));
      assert.equal(result.score, 0);
    });
  });

  describe('attachments', () => {
    it('should add 0.5 points for messages with attachments', () => {
      const result = scoreEmail(makeParams({ tenantId, hasAttachments: true }));
      assert.equal(result.score, 0.5);
    });

    it('should not add points for messages without attachments', () => {
      const result = scoreEmail(makeParams({ tenantId, hasAttachments: false }));
      assert.equal(result.score, 0);
    });
  });

  describe('whitelist overrides blacklist', () => {
    it('should return 0 even if sender is also blacklisted', () => {
      addToList('whitelist', 'ip', '10.0.0.99');
      addToList('blacklist', 'ip', '10.0.0.99');
      const result = scoreEmail(makeParams({ tenantId, remoteIp: '10.0.0.99', subject: 'urgent' }));
      assert.equal(result.score, 0);
    });
  });
});
