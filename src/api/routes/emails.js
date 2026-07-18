const express = require('express');
const { db } = require('../../db');
const { readRaw, deleteRaw } = require('../../quarantine');
const { forward } = require('../../forwarder');
const { resolveDestination } = require('../../routing-engine');

const router = express.Router();

// GET /emails?status=QUARANTINED&domain=company.com&limit=50
router.get('/', (req, res) => {
  const { status, domain, limit = 100 } = req.query;
  let query = 'SELECT * FROM emails WHERE tenant_id = ?';
  const params = [req.tenant.id];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }
  if (domain) {
    query += ' AND domain = ?';
    params.push(domain);
  }
  query += ' ORDER BY received_at DESC LIMIT ?';
  params.push(parseInt(limit, 10));

  const rows = db.prepare(query).all(...params);
  res.json({ emails: rows.map(serialize) });
});

// GET /emails/summary — counts for dashboard KPIs (PRD 12 - Metrics Business)
router.get('/summary', (req, res) => {
  const rows = db.prepare('SELECT status, COUNT(*) as count FROM emails WHERE tenant_id = ? GROUP BY status').all(req.tenant.id);
  const totals = { RECEIVED: 0, FORWARDED: 0, QUARANTINED: 0, REJECTED: 0 };
  rows.forEach((r) => { totals[r.status] = r.count; });
  const domainCount = db.prepare('SELECT COUNT(*) as c FROM domains WHERE tenant_id = ? AND status = ?').get(req.tenant.id, 'ACTIVE').c;
  res.json({ totals, activeDomains: domainCount });
});

// GET /emails/:id
router.get('/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM emails WHERE tenant_id = ? AND id = ?').get(req.tenant.id, req.params.id);
  if (!row) return res.status(404).json({ error: 'email not found' });
  res.json({ email: serialize(row, true) });
});

// POST /emails/:id/release — release a QUARANTINED message: forward it now
router.post('/:id/release', async (req, res) => {
  const row = db.prepare('SELECT * FROM emails WHERE tenant_id = ? AND id = ?').get(req.tenant.id, req.params.id);
  if (!row) return res.status(404).json({ error: 'email not found' });
  if (row.status !== 'QUARANTINED') return res.status(409).json({ error: `email is not quarantined (status=${row.status})` });
  if (!row.eml_path) return res.status(500).json({ error: 'quarantined message has no stored content' });

  const domainRow = resolveDestination(row.domain);
  if (!domainRow || !domainRow.destination_mx) {
    return res.status(500).json({ error: 'no destination configured for this domain' });
  }

  try {
    const raw = readRaw(row.eml_path);
    await forward({ destinationHost: domainRow.destination_mx, from: row.sender, to: [row.recipient], rawMessage: raw });
    db.prepare('UPDATE emails SET status = ?, decision = ?, processed_at = ? WHERE id = ?')
      .run('FORWARDED', 'FORWARDED', new Date().toISOString(), row.id);
    deleteRaw(row.eml_path);
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: `release failed: ${err.message}` });
  }
});

// DELETE /emails/:id — permanently discard a quarantined/rejected message
router.delete('/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM emails WHERE tenant_id = ? AND id = ?').get(req.tenant.id, req.params.id);
  if (!row) return res.status(404).json({ error: 'email not found' });
  if (row.eml_path) deleteRaw(row.eml_path);
  db.prepare('UPDATE emails SET status = ? WHERE id = ?').run('REJECTED', row.id);
  res.status(204).send();
});

function serialize(row, includeHeaders = false) {
  const out = {
    id: row.id,
    domain: row.domain,
    sender: row.sender,
    recipient: row.recipient,
    subject: row.subject,
    remoteIp: row.remote_ip,
    spamScore: row.spam_score,
    decision: row.decision,
    status: row.status,
    reason: row.reason,
    sizeBytes: row.size_bytes,
    receivedAt: row.received_at,
    processedAt: row.processed_at,
  };
  if (includeHeaders && row.headers_json) {
    try { out.headers = JSON.parse(row.headers_json); } catch (e) { out.headers = null; }
  }
  return out;
}

module.exports = router;
