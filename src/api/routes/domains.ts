import { Router, Response } from 'express';
import config from '../../config';
import domainRepository from '../../repositories/DomainRepository';
import dnsLookupService from '../../services/DnsLookupService';
import databaseService from '../../services/DatabaseService';
import { AuthenticatedRequest } from '../../middleware/AuthMiddleware';
import { IDomainResponse, IMxInstructions, DomainStatus } from '../../interfaces';

const router = Router();

const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

function serializeDomain(row: {
  id: string;
  name: string;
  provider: string | null;
  origin_mx: string | null;
  destination_mx: string | null;
  relay_target: string;
  status: string;
  created_at: string;
  activated_at: string | null;
}): IDomainResponse {
  return {
    id: row.id,
    name: row.name,
    provider: row.provider,
    status: row.status as DomainStatus,
    originMx: row.origin_mx,
    destinationMx: row.destination_mx,
    relayTarget: row.relay_target,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
  };
}

function mxInstructions(row: {
  origin_mx: string | null;
  relay_target: string;
}): IMxInstructions {
  return {
    before: row.origin_mx,
    after: row.relay_target,
    note: 'Update your domain\'s MX record to point to the "after" value. Keep TTL low until activation is confirmed.',
  };
}

router.post('/', async (req: AuthenticatedRequest, res: Response) => {
  const { name } = req.body || {};
  if (!name || typeof name !== 'string') {
    res.status(400).json({ error: 'body must include "name" (domain)' });
    return;
  }
  const domainName = name.trim().toLowerCase();
  if (!DOMAIN_RE.test(domainName)) {
    res.status(400).json({ error: `"${domainName}" is not a valid domain name` });
    return;
  }

  const existing = domainRepository.findByName(domainName);
  if (existing) {
    res.status(409).json({ error: `domain ${domainName} is already registered`, domain: serializeDomain(existing) });
    return;
  }

  const mx = await dnsLookupService.lookupDomainMx(domainName);
  if (!mx) {
    res.status(422).json({ error: `could not resolve MX records for ${domainName}. Verify the domain has mail configured.` });
    return;
  }

  const row = {
    id: databaseService.uuid(),
    tenant_id: req.tenant!.id,
    name: domainName,
    provider: mx.provider,
    origin_mx: mx.mxHost,
    destination_mx: mx.mxHost,
    relay_target: config.relayHostname,
    status: 'PENDING_DNS' as DomainStatus,
    created_at: new Date().toISOString(),
    activated_at: null,
  };

  domainRepository.create(row);

  res.status(201).json({ domain: serializeDomain(row), instructions: mxInstructions(row) });
});

router.get('/', (req: AuthenticatedRequest, res: Response) => {
  const rows = domainRepository.findAllByTenant(req.tenant!.id);
  res.json({ domains: rows.map(serializeDomain) });
});

router.get('/:name', (req: AuthenticatedRequest, res: Response) => {
  const name = (req.params as Record<string, string>).name.toLowerCase();
  const row = domainRepository.findByTenantAndName(req.tenant!.id, name);
  if (!row) {
    res.status(404).json({ error: 'domain not found' });
    return;
  }
  res.json({ domain: serializeDomain(row), instructions: mxInstructions(row) });
});

router.post('/:name/activate', async (req: AuthenticatedRequest, res: Response) => {
  const name = (req.params as Record<string, string>).name.toLowerCase();
  const row = domainRepository.findByTenantAndName(req.tenant!.id, name);
  if (!row) {
    res.status(404).json({ error: 'domain not found' });
    return;
  }

  const pointsToRelay = await dnsLookupService.mxPointsToRelay(row.name, config.relayHostname);
  if (!pointsToRelay) {
    res.status(409).json({
      error: `MX for ${row.name} does not yet point to ${config.relayHostname}. DNS may still be propagating.`,
      instructions: mxInstructions(row),
    });
    return;
  }

  domainRepository.updateStatus(row.id, 'ACTIVE', new Date().toISOString());
  const updated = domainRepository.findByName(row.name);
  res.json({ domain: serializeDomain(updated!) });
});

router.delete('/:name', (req: AuthenticatedRequest, res: Response) => {
  const name = (req.params as Record<string, string>).name.toLowerCase();
  const row = domainRepository.findByTenantAndName(req.tenant!.id, name);
  if (!row) {
    res.status(404).json({ error: 'domain not found' });
    return;
  }
  domainRepository.delete(row.id);
  res.status(204).send();
});

export default router;
