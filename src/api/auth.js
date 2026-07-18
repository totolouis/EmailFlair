const { db } = require('../db');

/**
 * Very small API-key auth: `Authorization: Bearer <tenant api key>`.
 * Attaches req.tenant so every route below is automatically scoped/isolated
 * per tenant, per PRD section 7 (Multi-tenancy -> Isolation: config/logs/quarantine/secrets).
 */
function requireTenant(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (req.query.api_key || '');
  if (!token) {
    return res.status(401).json({ error: 'Missing API key (Authorization: Bearer <key>)' });
  }
  const tenant = db.prepare('SELECT * FROM tenants WHERE api_key = ?').get(token);
  if (!tenant) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  req.tenant = tenant;
  next();
}

module.exports = { requireTenant };
