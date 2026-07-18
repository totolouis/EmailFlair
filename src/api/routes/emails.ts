import { Router, Response } from 'express';
import emailRepository from '../../repositories/EmailRepository';
import domainRepository from '../../repositories/DomainRepository';
import quarantineService from '../../services/QuarantineService';
import forwarderService from '../../services/ForwarderService';
import { AuthenticatedRequest } from '../../middleware/AuthMiddleware';
import { IEmailResponse, EmailDecision, EmailStatus } from '../../interfaces';

const router = Router();

function serializeEmail(row: {
  id: string;
  domain: string;
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  remote_ip: string | null;
  spam_score: number;
  decision: string | null;
  status: string;
  reason: string | null;
  size_bytes: number | null;
  received_at: string;
  processed_at: string | null;
  headers_json: string | null;
}, includeHeaders = false): IEmailResponse {
  const out: IEmailResponse = {
    id: row.id,
    domain: row.domain,
    sender: row.sender,
    recipient: row.recipient,
    subject: row.subject,
    remoteIp: row.remote_ip,
    spamScore: row.spam_score,
    decision: row.decision as EmailDecision | null,
    status: row.status as EmailStatus,
    reason: row.reason,
    sizeBytes: row.size_bytes,
    receivedAt: row.received_at,
    processedAt: row.processed_at,
  };
  if (includeHeaders && row.headers_json) {
    try {
      out.headers = JSON.parse(row.headers_json) as Record<string, unknown>;
    } catch {
      out.headers = null;
    }
  }
  return out;
}

router.get('/', (req: AuthenticatedRequest, res: Response) => {
  const status = typeof req.query.status === 'string' ? req.query.status : undefined;
  const domain = typeof req.query.domain === 'string' ? req.query.domain : undefined;
  const limit = typeof req.query.limit === 'string' ? parseInt(req.query.limit, 10) : 100;
  const rows = emailRepository.findAll({ tenantId: req.tenant!.id, status, domain, limit });
  res.json({ emails: rows.map((r) => serializeEmail(r)) });
});

router.get('/summary', (req: AuthenticatedRequest, res: Response) => {
  const totals = emailRepository.getStatusSummary(req.tenant!.id);
  const activeDomains = domainRepository.countActiveByTenant(req.tenant!.id);
  res.json({ totals, activeDomains });
});

router.get('/:id', (req: AuthenticatedRequest, res: Response) => {
  const id = (req.params as Record<string, string>).id;
  const row = emailRepository.findById(req.tenant!.id, id);
  if (!row) {
    res.status(404).json({ error: 'email not found' });
    return;
  }
  res.json({ email: serializeEmail(row, true) });
});

router.post('/:id/release', async (req: AuthenticatedRequest, res: Response) => {
  const id = (req.params as Record<string, string>).id;
  const row = emailRepository.findById(req.tenant!.id, id);
  if (!row) {
    res.status(404).json({ error: 'email not found' });
    return;
  }
  if (row.status !== 'QUARANTINED') {
    res.status(409).json({ error: `email is not quarantined (status=${row.status})` });
    return;
  }
  if (!row.eml_path) {
    res.status(500).json({ error: 'quarantined message has no stored content' });
    return;
  }

  const domainRow = domainRepository.findByName(row.domain);
  if (!domainRow || !domainRow.destination_mx) {
    res.status(500).json({ error: 'no destination configured for this domain' });
    return;
  }

  try {
    const raw = quarantineService.readRaw(row.eml_path);
    if (!raw) {
      res.status(500).json({ error: 'quarantined message file not found on disk' });
      return;
    }
    await forwarderService.forward({
      destinationHost: domainRow.destination_mx,
      from: row.sender || '',
      to: [row.recipient || ''],
      rawMessage: raw,
    });
    emailRepository.updateStatus(row.id, 'FORWARDED', 'FORWARDED', new Date().toISOString());
    quarantineService.deleteRaw(row.eml_path);
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: `release failed: ${(err as Error).message}` });
  }
});

router.delete('/:id', (req: AuthenticatedRequest, res: Response) => {
  const id = (req.params as Record<string, string>).id;
  const row = emailRepository.findById(req.tenant!.id, id);
  if (!row) {
    res.status(404).json({ error: 'email not found' });
    return;
  }
  if (row.eml_path) quarantineService.deleteRaw(row.eml_path);
  emailRepository.delete(row.id);
  res.status(204).send();
});

export default router;
