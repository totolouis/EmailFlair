const express = require('express');
const { db, uuid } = require('../../db');
const config = require('../../config');
const { lookupDomainMx, mxPointsToRelay } = require('../../dns-lookup');

const router = express.Router();

// POST /domains  { "name": "company.com" }
// Detects the current provider via MX lookup, stores it as the future
// forwarding destination, and returns the DNS change instructions shown
// to the user in PRD section 5 ("Changez votre MX: Avant / Après").
router.post('/', async (req, res) => {
  const { name } = req.body || {};
  if (!name || typeof name !== 'string') {
    return res.status(400).json({ error: 'body must include "name" (domain)' });
  }
  const domainName = name.trim().toLowerCase();

  const existing = db.prepare('SELECT * FROM domains WHERE name = ?').get(domainName);
  if (existing) {
    return res.status(409).json({ error: `domain ${domainName} is already registered`, domain: serialize(existing) });
  }

  const mx = await lookupDomainMx(domainName);
  if (!mx) {
    return res.status(422).json({ error: `could not resolve MX records for ${domainName}. Verify the domain has mail configured.` });
  }

  const row = {
    id: uuid(),
    tenant_id: req.tenant.id,
    name: domainName,
    provider: mx.provider,
    origin_mx: mx.mxHost,
    destination_mx: mx.mxHost, // captured now, while it still points at the real provider
    relay_target: config.relayHostname,
    status: 'PENDING_DNS',
    created_at: new Date().toISOString(),
    activated_at: null,
  };

  db.prepare(`
    INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
    VALUES (@id, @tenant_id, @name, @provider, @origin_mx, @destination_mx, @relay_target, @status, @created_at, @activated_at)
  `).run(row);

  res.status(201).json({ domain: serialize(row), instructions: mxInstructions(row) });
});

// GET /domains  — list all domains for the caller's tenant
router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM domains WHERE tenant_id = ? ORDER BY created_at DESC').all(req.tenant.id);
  res.json({ domains: rows.map(serialize) });
});

// GET /domains/:name
router.get('/:name', (req, res) => {
  const row = db.prepare('SELECT * FROM domains WHERE tenant_id = ? AND name = ?').get(req.tenant.id, req.params.name.toLowerCase());
  if (!row) return res.status(404).json({ error: 'domain not found' });
  res.json({ domain: serialize(row), instructions: mxInstructions(row) });
});

// POST /domains/:name/activate — verify the MX has actually been switched, then flip to ACTIVE
router.post('/:name/activate', async (req, res) => {
  const row = db.prepare('SELECT * FROM domains WHERE tenant_id = ? AND name = ?').get(req.tenant.id, req.params.name.toLowerCase());
  if (!row) return res.status(404).json({ error: 'domain not found' });

  const pointsToRelay = await mxPointsToRelay(row.name, config.relayHostname);
  if (!pointsToRelay) {
    return res.status(409).json({
      error: `MX for ${row.name} does not yet point to ${config.relayHostname}. DNS may still be propagating.`,
      instructions: mxInstructions(row),
    });
  }

  db.prepare('UPDATE domains SET status = ?, activated_at = ? WHERE id = ?')
    .run('ACTIVE', new Date().toISOString(), row.id);

  const updated = db.prepare('SELECT * FROM domains WHERE id = ?').get(row.id);
  res.json({ domain: serialize(updated) });
});

// DELETE /domains/:name
router.delete('/:name', (req, res) => {
  const row = db.prepare('SELECT * FROM domains WHERE tenant_id = ? AND name = ?').get(req.tenant.id, req.params.name.toLowerCase());
  if (!row) return res.status(404).json({ error: 'domain not found' });
  db.prepare('DELETE FROM domains WHERE id = ?').run(row.id);
  res.status(204).send();
});

function mxInstructions(row) {
  return {
    before: row.origin_mx,
    after: row.relay_target,
    note: 'Update your domain\'s MX record to point to the "after" value. Keep TTL low until activation is confirmed.',
  };
}

function serialize(row) {
  return {
    id: row.id,
    name: row.name,
    provider: row.provider,
    status: row.status,
    originMx: row.origin_mx,
    destinationMx: row.destination_mx,
    relayTarget: row.relay_target,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
  };
}

module.exports = router;
