import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { v4 as uuid } from 'uuid';
import config from '../config';
import runMigrations from './DatabaseMigrations';

class DatabaseService {
  private db: Database.Database | null = null;

  init(dbPath: string): Database.Database {
    if (this.db) {
      this.db.close();
    }

    const isMemory = dbPath === ':memory:';
    if (!isMemory) {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }

    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    runMigrations(this.db);
    return this.getDb();
  }

  getDb(): Database.Database {
    if (!this.db) {
      throw new Error('Database not initialized. Call init() first.');
    }
    return this.db;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  seedDefaultTenant(): {
    id: string;
    name: string;
    api_key: string;
    created_at: string;
  } {
    const existing = this.getDb()
      .prepare('SELECT * FROM tenants WHERE api_key = ?')
      .get(config.defaultTenantApiKey) as { id: string; name: string; api_key: string; created_at: string } | undefined;

    if (existing) return existing;

    const tenant = {
      id: uuid(),
      name: config.defaultTenantName,
      api_key: config.defaultTenantApiKey,
      created_at: new Date().toISOString(),
    };

    this.getDb()
      .prepare(
        'INSERT INTO tenants (id, name, api_key, created_at) VALUES (@id, @name, @api_key, @created_at)'
      )
      .run(tenant);

    return tenant;
  }

  uuid(): string {
    return uuid();
  }
}

const databaseService = new DatabaseService();
export { databaseService, DatabaseService };
export default databaseService;
