const express = require('express');
const { db, uuid } = require('../../db');

const router = express.Router();

function makeListRoutes(table) {
  const r = express.Router();

  r.get('/', (req, res) => {
    const rows = db.prepare(`SELECT * FROM ${table} WHERE tenant_id = ? ORDER BY created_at DESC`).all(req.tenant.id);
    res.json({ [table]: rows.map((row) => ({ id: row.id, type: row.type, value: row.value, createdAt: row.created_at })) });
  });

  r.post('/', (req, res) => {
    const { type, value } = req.body || {};
    if (!type || !['ip', 'domain'].includes(type) || !value) {
      return res.status(400).json({ error: 'body must include type ("ip"|"domain") and value' });
    }
    const row = { id: uuid(), tenant_id: req.tenant.id, type, value: value.trim().toLowerCase(), created_at: new Date().toISOString() };
    db.prepare(`INSERT INTO ${table} (id, tenant_id, type, value, created_at) VALUES (@id, @tenant_id, @type, @value, @created_at)`).run(row);
    res.status(201).json({ entry: { id: row.id, type: row.type, value: row.value, createdAt: row.created_at } });
  });

  r.delete('/:id', (req, res) => {
    const row = db.prepare(`SELECT * FROM ${table} WHERE tenant_id = ? AND id = ?`).get(req.tenant.id, req.params.id);
    if (!row) return res.status(404).json({ error: 'entry not found' });
    db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(row.id);
    res.status(204).send();
  });

  return r;
}

router.use('/blacklist', makeListRoutes('blacklist'));
router.use('/whitelist', makeListRoutes('whitelist'));

module.exports = router;
