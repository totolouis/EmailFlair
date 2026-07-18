const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');

process.env.DB_PATH = ':memory:';

delete require.cache[require.resolve('../src/config')];
delete require.cache[require.resolve('../src/db')];
delete require.cache[require.resolve('../src/api/auth')];

const { initDb, closeDb, getDb, uuid } = require('../src/db');
const { requireTenant } = require('../src/api/auth');

function mockReqRes(token) {
  const req = { headers: { authorization: token ? `Bearer ${token}` : '' }, query: {} };
  const res = { statusCode: null, body: null, status(code) { this.statusCode = code; return this; }, json(obj) { this.body = obj; } };
  const nextCalled = { called: false };
  const next = () => { nextCalled.called = true; };
  return { req, res, next, nextCalled };
}

describe('auth middleware', () => {
  let testTenantKey;

  before(() => {
    initDb(':memory:');
    const db = getDb();
    testTenantKey = 'test-auth-key-12345';
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(uuid(), 'Test', testTenantKey, new Date().toISOString());
  });

  after(() => {
    closeDb();
  });

  it('should attach tenant to req for valid API key', () => {
    const { req, res, next, nextCalled } = mockReqRes(testTenantKey);
    requireTenant(req, res, next);
    assert.ok(nextCalled.called);
    assert.ok(req.tenant);
    assert.equal(req.tenant.api_key, testTenantKey);
  });

  it('should return 401 for missing Authorization header', () => {
    const { req, res, next, nextCalled } = mockReqRes(null);
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
    assert.ok(res.body.error.includes('Missing API key'));
  });

  it('should return 401 for invalid API key', () => {
    const { req, res, next, nextCalled } = mockReqRes('invalid-key');
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
    assert.ok(res.body.error.includes('Invalid API key'));
  });

  it('should return 401 for empty Bearer token', () => {
    const { req, res, next, nextCalled } = mockReqRes('');
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
  });

  it('should not accept query param as fallback', () => {
    const req = { headers: {}, query: { api_key: testTenantKey } };
    const res = { statusCode: null, body: null, status(code) { this.statusCode = code; return this; }, json(obj) { this.body = obj; } };
    const nextCalled = { called: false };
    const next = () => { nextCalled.called = true; };
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
  });
});
