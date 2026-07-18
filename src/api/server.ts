import path from 'path';
import express from 'express';
import cors from 'cors';
import { requireTenant } from '../middleware/AuthMiddleware';
import domainsRouter from './routes/domains';
import emailsRouter from './routes/emails';
import listsRouter from './routes/lists';

function buildApiApp(): express.Application {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.use('/domains', requireTenant, domainsRouter);
  app.use('/emails', requireTenant, emailsRouter);
  app.use('/lists', requireTenant, listsRouter);

  app.use('/', express.static(path.join(__dirname, '..', 'dashboard')));

  return app;
}

export { buildApiApp };
