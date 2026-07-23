import databaseService from '../services/DatabaseService';
import { ITenant } from '../interfaces';
import { hashApiKey } from '../utils/crypto';

class TenantRepository {
  findByApiKey(apiKey: string): ITenant | null {
    const hashed = hashApiKey(apiKey);
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM tenants WHERE api_key_hash = ?')
      .get(hashed) as ITenant | undefined;

    return row || null;
  }

  findById(id: string): ITenant | null {
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM tenants WHERE id = ?')
      .get(id) as ITenant | undefined;

    return row || null;
  }
}

const tenantRepository = new TenantRepository();
export { tenantRepository, TenantRepository };
export default tenantRepository;
