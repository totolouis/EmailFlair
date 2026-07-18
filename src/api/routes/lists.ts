import { Router, Response } from 'express';
import listRepository from '../../repositories/ListRepository';
import databaseService from '../../services/DatabaseService';
import { AuthenticatedRequest } from '../../middleware/AuthMiddleware';
import { ListType } from '../../interfaces';

const router = Router();

function makeListRoutes(table: string): Router {
  const r = Router();

  r.get('/', (req: AuthenticatedRequest, res: Response) => {
    const rows = listRepository.findAll(req.tenant!.id, table);
    res.json({
      [table]: rows.map((row) => ({
        id: row.id,
        type: row.type,
        value: row.value,
        createdAt: row.created_at,
      })),
    });
  });

  r.post('/', (req: AuthenticatedRequest, res: Response) => {
    const { type, value } = req.body || {};
    if (!type || !['ip', 'domain'].includes(type) || !value) {
      res.status(400).json({ error: 'body must include type ("ip"|"domain") and value' });
      return;
    }
    const entry = {
      id: databaseService.uuid(),
      tenant_id: req.tenant!.id,
      type: type as ListType,
      value: (value as string).trim().toLowerCase(),
      created_at: new Date().toISOString(),
    };
    listRepository.create(entry, table);
    res.status(201).json({
      entry: { id: entry.id, type: entry.type, value: entry.value, createdAt: entry.created_at },
    });
  });

  r.delete('/:id', (req: AuthenticatedRequest, res: Response) => {
    const id = (req.params as Record<string, string>).id;
    const row = listRepository.findById(req.tenant!.id, id, table);
    if (!row) {
      res.status(404).json({ error: 'entry not found' });
      return;
    }
    listRepository.delete(row.id, table);
    res.status(204).send();
  });

  return r;
}

router.use('/blacklist', makeListRoutes('blacklist'));
router.use('/whitelist', makeListRoutes('whitelist'));

export default router;
