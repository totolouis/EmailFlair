import databaseService from '../services/DatabaseService';
import { IListEntry } from '../interfaces';

const ALLOWED_TABLES = new Set(['blacklist', 'whitelist']);

class ListRepository {
  private validateTable(table: string): void {
    if (!ALLOWED_TABLES.has(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
  }

  findAll(tenantId: string, table: string): IListEntry[] {
    this.validateTable(table);
    return databaseService
      .getDb()
      .prepare(`SELECT * FROM ${table} WHERE tenant_id = ? ORDER BY created_at DESC`)
      .all(tenantId) as IListEntry[];
  }

  create(entry: IListEntry, table: string): void {
    this.validateTable(table);
    databaseService
      .getDb()
      .prepare(
        `INSERT INTO ${table} (id, tenant_id, type, value, created_at)
         VALUES (@id, @tenant_id, @type, @value, @created_at)`
      )
      .run(entry);
  }

  findById(tenantId: string, id: string, table: string): IListEntry | null {
    this.validateTable(table);
    const row = databaseService
      .getDb()
      .prepare(`SELECT * FROM ${table} WHERE tenant_id = ? AND id = ?`)
      .get(tenantId, id) as IListEntry | undefined;

    return row || null;
  }

  delete(id: string, table: string): void {
    this.validateTable(table);
    databaseService.getDb().prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
  }
}

const listRepository = new ListRepository();
export { listRepository, ListRepository };
export default listRepository;
