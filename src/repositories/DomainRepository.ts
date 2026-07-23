import databaseService from '../services/DatabaseService';
import { IDomain, IDomainCreate } from '../interfaces';

class DomainRepository {
  findByName(name: string): IDomain | null {
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM domains WHERE lower(name) = lower(?)')
      .get(name) as IDomain | undefined;

    return row || null;
  }

  findByTenantAndName(tenantId: string, name: string): IDomain | null {
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM domains WHERE tenant_id = ? AND name = ?')
      .get(tenantId, name) as IDomain | undefined;

    return row || null;
  }

  findAllByTenant(tenantId: string): IDomain[] {
    return databaseService
      .getDb()
      .prepare('SELECT * FROM domains WHERE tenant_id = ? ORDER BY created_at DESC')
      .all(tenantId) as IDomain[];
  }

  create(domain: IDomainCreate): void {
    databaseService
      .getDb()
      .prepare(
        `INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
         VALUES (@id, @tenant_id, @name, @provider, @origin_mx, @destination_mx, @relay_target, @status, @created_at, @activated_at)`
      )
      .run(domain);
  }

  updateStatus(id: string, status: string, activatedAt: string): void {
    databaseService
      .getDb()
      .prepare('UPDATE domains SET status = ?, activated_at = ? WHERE id = ?')
      .run(status, activatedAt, id);
  }

  updateDestinationMx(id: string, destinationMx: string): void {
    databaseService
      .getDb()
      .prepare('UPDATE domains SET destination_mx = ? WHERE id = ?')
      .run(destinationMx, id);
  }

  delete(id: string): void {
    databaseService.getDb().prepare('DELETE FROM domains WHERE id = ?').run(id);
  }

  countActiveByTenant(tenantId: string): number {
    const row = databaseService
      .getDb()
      .prepare('SELECT COUNT(*) as c FROM domains WHERE tenant_id = ? AND status = ?')
      .get(tenantId, 'ACTIVE') as { c: number };

    return row.c;
  }
}

const domainRepository = new DomainRepository();
export { domainRepository, DomainRepository };
export default domainRepository;
