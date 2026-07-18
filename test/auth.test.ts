import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { Request, Response, NextFunction } from 'express';
import databaseService from '../dist/services/DatabaseService';
import { requireTenant, AuthenticatedRequest } from '../dist/middleware/AuthMiddleware';

function mockReqRes(token?: string | null) {
  const req = { headers: { authorization: token ? `Bearer ${token}` : '' }, query: {} } as AuthenticatedRequest;
  const res = {
    statusCode: null as number | null,
    body: null as Record<string, unknown> | null,
    status(code: number) { this.statusCode = code; return this; },
    json(obj: Record<string, unknown>) { this.body = obj; },
  } as unknown as Response;
  const nextCalled = { called: false };
  const next = (() => { nextCalled.called = true; }) as NextFunction;
  return { req, res, next, nextCalled };
}

describe('auth middleware', () => {
  let testTenantKey: string;

  before(() => {
    require.cache = require.cache || {};
    databaseService.init(':memory:');
    const db = databaseService.getDb();
    testTenantKey = 'test-auth-key-12345';
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(databaseService.uuid(), 'Test', testTenantKey, new Date().toISOString());
  });

  after(() => {
    databaseService.close();
  });

  it('should attach tenant to req for valid API key', () => {
    const { req, res, next, nextCalled } = mockReqRes(testTenantKey);
    requireTenant(req, res, next);
    assert.ok(nextCalled.called);
    assert.ok(req.tenant);
    assert.equal(req.tenant!.api_key, testTenantKey);
  });

  it('should return 401 for missing Authorization header', () => {
    const { req, res, next, nextCalled } = mockReqRes(null);
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
    assert.ok(res.body!.error!.toString().includes('Missing API key'));
  });

  it('should return 401 for invalid API key', () => {
    const { req, res, next, nextCalled } = mockReqRes('invalid-key');
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
    assert.ok(res.body!.error!.toString().includes('Invalid API key'));
  });

  it('should return 401 for empty Bearer token', () => {
    const { req, res, next, nextCalled } = mockReqRes('');
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
  });

  it('should not accept query param as fallback', () => {
    const req = { headers: {}, query: { api_key: testTenantKey } } as unknown as AuthenticatedRequest;
    const res = {
      statusCode: null as number | null,
      body: null as Record<string, unknown> | null,
      status(code: number) { this.statusCode = code; return this; },
      json(obj: Record<string, unknown>) { this.body = obj; },
    } as unknown as Response;
    const nextCalled = { called: false };
    const next = (() => { nextCalled.called = true; }) as NextFunction;
    requireTenant(req, res, next);
    assert.ok(!nextCalled.called);
    assert.equal(res.statusCode, 401);
  });
});
