import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import databaseService from '../dist/services/DatabaseService';
import routingEngineService from '../dist/services/RoutingEngineService';
import { hashApiKey } from './helpers';

describe('routing-engine', () => {
  let tenantId: string;

  before(() => {
    databaseService.init(':memory:');
    const db = databaseService.getDb();
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', hashApiKey('test-key'), new Date().toISOString());
  });

  after(() => {
    databaseService.close();
  });

  function seedDomain(overrides: Record<string, unknown> = {}) {
    const db = databaseService.getDb();
    const row = {
      id: databaseService.uuid(),
      tenant_id: tenantId,
      name: 'example.com',
      provider: 'GoogleWorkspace',
      origin_mx: 'aspmx.l.google.com',
      destination_mx: 'aspmx.l.google.com',
      relay_target: 'mx1.emailrelay.com',
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      activated_at: new Date().toISOString(),
      ...overrides,
    };
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (@id, @tenant_id, @name, @provider, @origin_mx, @destination_mx, @relay_target, @status, @created_at, @activated_at)
    `).run(row);
    return row;
  }

  it('should return domain row for a registered domain', () => {
    seedDomain({ name: 'example.com' });
    const result = routingEngineService.resolveDestination('example.com');
    assert.ok(result);
    assert.equal(result!.name, 'example.com');
    assert.equal(result!.destination_mx, 'aspmx.l.google.com');
  });

  it('should be case-insensitive for domain matching', () => {
    seedDomain({ name: 'UpperCase.COM' });
    const result = routingEngineService.resolveDestination('uppercase.com');
    assert.ok(result);
    assert.equal(result!.name, 'UpperCase.COM');
  });

  it('should return null for unregistered domain', () => {
    const result = routingEngineService.resolveDestination('nonexistent.com');
    assert.strictEqual(result, null);
  });

  it('should return the correct destination MX', () => {
    seedDomain({ name: 'myco.com', destination_mx: 'mx.myco.com' });
    const result = routingEngineService.resolveDestination('myco.com');
    assert.equal(result!.destination_mx, 'mx.myco.com');
  });

  it('should handle subdomains correctly', () => {
    seedDomain({ name: 'sub.example.com' });
    const result = routingEngineService.resolveDestination('sub.example.com');
    assert.ok(result);
    assert.equal(result!.name, 'sub.example.com');
  });
});
