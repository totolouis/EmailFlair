import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import databaseService from '../dist/services/DatabaseService';
import tenantRepository from '../dist/repositories/TenantRepository';
import domainRepository from '../dist/repositories/DomainRepository';
import emailRepository from '../dist/repositories/EmailRepository';
import listRepository from '../dist/repositories/ListRepository';

describe('repositories', () => {
  let tenantId: string;
  let otherTenantId: string;

  before(() => {
    databaseService.init(':memory:');
    const db = databaseService.getDb();
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test Tenant', 'test-key-repo', new Date().toISOString());
    otherTenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key, created_at) VALUES (?, ?, ?, ?)')
      .run(otherTenantId, 'Other Tenant', 'other-key-repo', new Date().toISOString());
  });

  after(() => {
    databaseService.close();
  });

  describe('TenantRepository', () => {
    it('should find tenant by API key', () => {
      const tenant = tenantRepository.findByApiKey('test-key-repo');
      assert.ok(tenant);
      assert.equal(tenant!.name, 'Test Tenant');
    });

    it('should return null for unknown API key', () => {
      const tenant = tenantRepository.findByApiKey('nonexistent-key');
      assert.strictEqual(tenant, null);
    });

    it('should find tenant by ID', () => {
      const tenant = tenantRepository.findById(tenantId);
      assert.ok(tenant);
      assert.equal(tenant!.api_key, 'test-key-repo');
    });

    it('should return null for unknown ID', () => {
      const tenant = tenantRepository.findById('nonexistent-id');
      assert.strictEqual(tenant, null);
    });
  });

  describe('DomainRepository', () => {
    let domainId: string;
    const domainName = 'repo-test-' + Date.now() + '.com';

    before(() => {
      domainId = databaseService.uuid();
      domainRepository.create({
        id: domainId,
        tenant_id: tenantId,
        name: domainName,
        provider: 'TestProvider',
        origin_mx: 'mx.original.com',
        destination_mx: 'mx.destination.com',
        relay_target: 'mx1.emailrelay.com',
        status: 'PENDING_DNS',
        created_at: new Date().toISOString(),
        activated_at: null,
      });
    });

    it('should find domain by name', () => {
      const domain = domainRepository.findByName(domainName);
      assert.ok(domain);
      assert.equal(domain!.tenant_id, tenantId);
    });

    it('should be case-insensitive for find by name', () => {
      const domain = domainRepository.findByName(domainName.toUpperCase());
      assert.ok(domain);
    });

    it('should find domain by tenant and name', () => {
      const domain = domainRepository.findByTenantAndName(tenantId, domainName);
      assert.ok(domain);
      assert.equal(domain!.status, 'PENDING_DNS');
    });

    it('should return null for other tenant domain', () => {
      const domain = domainRepository.findByTenantAndName(otherTenantId, domainName);
      assert.strictEqual(domain, null);
    });

    it('should find all domains by tenant', () => {
      const domains = domainRepository.findAllByTenant(tenantId);
      assert.ok(domains.length >= 1);
      assert.ok(domains.some((d: { id: string }) => d.id === domainId));
    });

    it('should not include other tenant domains', () => {
      const otherDomainId = databaseService.uuid();
      domainRepository.create({
        id: otherDomainId,
        tenant_id: otherTenantId,
        name: 'other-' + domainName,
        provider: null,
        origin_mx: null,
        destination_mx: 'mx.other.com',
        relay_target: 'mx1.emailrelay.com',
        status: 'ACTIVE',
        created_at: new Date().toISOString(),
        activated_at: new Date().toISOString(),
      });
      const domains = domainRepository.findAllByTenant(tenantId);
      assert.ok(!domains.some((d: { id: string }) => d.id === otherDomainId));
    });

    it('should update status', () => {
      domainRepository.updateStatus(domainId, 'ACTIVE', new Date().toISOString());
      const updated = domainRepository.findByName(domainName);
      assert.equal(updated!.status, 'ACTIVE');
      assert.ok(updated!.activated_at);
    });

    it('should count active domains by tenant', () => {
      const count = domainRepository.countActiveByTenant(tenantId);
      assert.equal(typeof count, 'number');
      assert.ok(count >= 1);
    });

    it('should delete domain', () => {
      const deleteId = databaseService.uuid();
      domainRepository.create({
        id: deleteId,
        tenant_id: tenantId,
        name: 'to-delete-' + Date.now() + '.com',
        provider: null,
        origin_mx: null,
        destination_mx: 'mx.test.com',
        relay_target: 'mx1.emailrelay.com',
        status: 'ACTIVE',
        created_at: new Date().toISOString(),
        activated_at: new Date().toISOString(),
      });
      domainRepository.delete(deleteId);
      const deleted = domainRepository.findByName('to-delete-*');
      // Use direct DB query since findByName won't find by pattern
      const row = databaseService.getDb().prepare('SELECT * FROM domains WHERE id = ?').get(deleteId);
      assert.ok(!row);
    });
  });

  describe('EmailRepository', () => {
    let emailId: string;

    before(() => {
      emailId = databaseService.uuid();
      emailRepository.create({
        id: emailId,
        tenant_id: tenantId,
        domain: 'test-email-domain.com',
        sender: 'sender@example.com',
        recipient: 'recip@example.com',
        subject: 'Repository Test',
        remote_ip: '10.0.0.1',
        spam_score: 0,
        decision: 'FORWARDED',
        status: 'FORWARDED',
        relay_id: 'relay-01',
        reason: null,
        headers_json: JSON.stringify({ received: 'from test' }),
        size_bytes: 500,
        eml_path: null,
        received_at: new Date().toISOString(),
        processed_at: new Date().toISOString(),
      });
      emailRepository.create({
        id: databaseService.uuid(),
        tenant_id: tenantId,
        domain: 'quarantine-domain.com',
        sender: 'spam@example.com',
        recipient: 'user@quarantine-domain.com',
        subject: 'Quarantine Test',
        remote_ip: '10.0.0.2',
        spam_score: 6,
        decision: 'QUARANTINED',
        status: 'QUARANTINED',
        relay_id: 'relay-01',
        reason: 'suspicious keywords',
        headers_json: null,
        size_bytes: 300,
        eml_path: '/tmp/test.eml',
        received_at: new Date().toISOString(),
        processed_at: new Date().toISOString(),
      });
    });

    it('should find all emails with filtering', () => {
      const emails = emailRepository.findAll({ tenantId });
      assert.ok(emails.length >= 2);
    });

    it('should filter by status', () => {
      const qEmails = emailRepository.findAll({ tenantId, status: 'QUARANTINED' });
      assert.ok(qEmails.every((e: { status: string }) => e.status === 'QUARANTINED'));
    });

    it('should filter by domain', () => {
      const dEmails = emailRepository.findAll({ tenantId, domain: 'quarantine-domain.com' });
      assert.ok(dEmails.every((e: { domain: string }) => e.domain === 'quarantine-domain.com'));
    });

    it('should respect limit', () => {
      const limited = emailRepository.findAll({ tenantId, limit: 1 });
      assert.ok(limited.length <= 1);
    });

    it('should find by ID', () => {
      const email = emailRepository.findById(tenantId, emailId);
      assert.ok(email);
      assert.equal(email!.sender, 'sender@example.com');
    });

    it('should return null for unknown ID', () => {
      const email = emailRepository.findById(tenantId, 'nonexistent');
      assert.strictEqual(email, null);
    });

    it('should not show other tenant emails', () => {
      const email = emailRepository.findById(otherTenantId, emailId);
      assert.strictEqual(email, null);
    });

    it('should get status summary', () => {
      const summary = emailRepository.getStatusSummary(tenantId);
      assert.ok('FORWARDED' in summary);
      assert.ok('QUARANTINED' in summary);
      assert.equal(typeof summary.FORWARDED, 'number');
    });

    it('should update status', () => {
      emailRepository.updateStatus(emailId, 'REJECTED', 'REJECTED', new Date().toISOString());
      const updated = emailRepository.findById(tenantId, emailId);
      assert.equal(updated!.status, 'REJECTED');
    });

    it('should delete an email', () => {
      const deleteId = databaseService.uuid();
      emailRepository.create({
        id: deleteId,
        tenant_id: tenantId,
        domain: 'delete-test.com',
        sender: 'del@example.com',
        recipient: 'del-user@example.com',
        subject: 'Delete Me',
        remote_ip: null,
        spam_score: 0,
        decision: 'FORWARDED',
        status: 'FORWARDED',
        relay_id: null,
        reason: null,
        headers_json: null,
        size_bytes: 100,
        eml_path: null,
        received_at: new Date().toISOString(),
        processed_at: new Date().toISOString(),
      });
      emailRepository.delete(deleteId);
      const found = emailRepository.findById(tenantId, deleteId);
      assert.strictEqual(found, null);
    });
  });

  describe('ListRepository', () => {
    let listEntryId: string;

    before(() => {
      listEntryId = databaseService.uuid();
      listRepository.create({
        id: listEntryId,
        tenant_id: tenantId,
        type: 'ip',
        value: '10.0.0.100',
        created_at: new Date().toISOString(),
      }, 'blacklist');
      listRepository.create({
        id: databaseService.uuid(),
        tenant_id: tenantId,
        type: 'domain',
        value: 'evil.com',
        created_at: new Date().toISOString(),
      }, 'blacklist');
      listRepository.create({
        id: databaseService.uuid(),
        tenant_id: tenantId,
        type: 'ip',
        value: '192.168.1.1',
        created_at: new Date().toISOString(),
      }, 'whitelist');
    });

    it('should find all blacklist entries for tenant', () => {
      const entries = listRepository.findAll(tenantId, 'blacklist');
      assert.ok(entries.length >= 2);
    });

    it('should find all whitelist entries for tenant', () => {
      const entries = listRepository.findAll(tenantId, 'whitelist');
      assert.ok(entries.length >= 1);
    });

    it('should not mix blacklist and whitelist', () => {
      const bl = listRepository.findAll(tenantId, 'blacklist');
      const wl = listRepository.findAll(tenantId, 'whitelist');
      const blValues = bl.map((e: { value: string }) => e.value);
      const wlValues = wl.map((e: { value: string }) => e.value);
      const overlap = blValues.filter((v: string) => wlValues.includes(v));
      assert.equal(overlap.length, 0);
    });

    it('should find by ID', () => {
      const entry = listRepository.findById(tenantId, listEntryId, 'blacklist');
      assert.ok(entry);
      assert.equal(entry!.value, '10.0.0.100');
    });

    it('should return null for wrong table', () => {
      const entry = listRepository.findById(tenantId, listEntryId, 'whitelist');
      assert.strictEqual(entry, null);
    });

    it('should throw for invalid table name', () => {
      assert.throws(() => listRepository.findAll(tenantId, 'invalid_table'));
      assert.throws(() => listRepository.create({
        id: 'x',
        tenant_id: tenantId,
        type: 'ip',
        value: '1.2.3.4',
        created_at: new Date().toISOString(),
      }, 'invalid_table'));
      assert.throws(() => listRepository.findById(tenantId, 'x', 'invalid_table'));
      assert.throws(() => listRepository.delete('x', 'invalid_table'));
    });

    it('should delete an entry', () => {
      listRepository.delete(listEntryId, 'blacklist');
      const entry = listRepository.findById(tenantId, listEntryId, 'blacklist');
      assert.strictEqual(entry, null);
    });
  });
});
