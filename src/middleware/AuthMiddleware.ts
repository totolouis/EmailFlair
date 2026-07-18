import { Request, Response, NextFunction } from 'express';
import tenantRepository from '../repositories/TenantRepository';

interface AuthenticatedRequest extends Request {
  tenant?: { id: string; name: string; api_key: string; created_at: string };
}

function requireTenant(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    res.status(401).json({ error: 'Missing API key (Authorization: Bearer <key>)' });
    return;
  }
  const tenant = tenantRepository.findByApiKey(token);
  if (!tenant) {
    res.status(401).json({ error: 'Invalid API key' });
    return;
  }
  req.tenant = tenant;
  next();
}

export { requireTenant, AuthenticatedRequest };
