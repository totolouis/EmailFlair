const path = require('path');
const express = require('express');
const cors = require('cors');
const { requireTenant } = require('./auth');
const domainsRouter = require('./routes/domains');
const emailsRouter = require('./routes/emails');
const listsRouter = require('./routes/lists');

function buildApiApp() {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  app.get('/health', (req, res) => res.json({ ok: true }));

  app.use('/domains', requireTenant, domainsRouter);
  app.use('/emails', requireTenant, emailsRouter);
  app.use('/lists', requireTenant, listsRouter);

  // Static dashboard (talks to the API above via fetch, using the API key the user pastes in)
  app.use('/', express.static(path.join(__dirname, '..', 'dashboard')));

  return app;
}

module.exports = { buildApiApp };
