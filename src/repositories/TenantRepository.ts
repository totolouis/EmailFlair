import databaseService from '../services/DatabaseService';
import { ITenant } from '../interfaces';

class TenantRepository {
  findByApiKey(apiKey: string): ITenant | null {
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM tenants WHERE api_key = ?')
      .get(apiKey) as ITenant | undefined;

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
