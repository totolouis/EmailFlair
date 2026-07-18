import databaseService from './DatabaseService';
import { IDomain } from '../interfaces';

class RoutingEngineService {
  resolveDestination(recipientDomain: string): IDomain | null {
    const row = databaseService
      .getDb()
      .prepare('SELECT * FROM domains WHERE lower(name) = lower(?)')
      .get(recipientDomain) as IDomain | undefined;

    return row || null;
  }
}

const routingEngineService = new RoutingEngineService();
export { routingEngineService, RoutingEngineService };
export default routingEngineService;
