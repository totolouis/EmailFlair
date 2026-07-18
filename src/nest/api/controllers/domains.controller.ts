import {
  Controller, Get, Post, Delete, Param, Body, UseGuards, HttpCode, HttpStatus
} from '@nestjs/common';
import { TenantGuard } from '../guards/tenant.guard';
import { Tenant, TenantInfo } from '../decorators/tenant.decorator';
import domainRepository from '../../../repositories/DomainRepository';
import dnsLookupService from '../../../services/DnsLookupService';
import databaseService from '../../../services/DatabaseService';
import config from '../../../config';
import { IDomainResponse, IMxInstructions, DomainStatus } from '../../../interfaces';

const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

@Controller('domains')
@UseGuards(TenantGuard)
export class DomainsController {
  private serializeDomain(row: {
    id: string; name: string; provider: string | null; origin_mx: string | null;
    destination_mx: string | null; relay_target: string; status: string;
    created_at: string; activated_at: string | null;
  }): IDomainResponse {
    return {
      id: row.id, name: row.name, provider: row.provider,
      status: row.status as DomainStatus,
      originMx: row.origin_mx, destinationMx: row.destination_mx,
      relayTarget: row.relay_target,
      createdAt: row.created_at, activatedAt: row.activated_at,
    };
  }

  private mxInstructions(row: { origin_mx: string | null; relay_target: string }): IMxInstructions {
    return {
      before: row.origin_mx,
      after: row.relay_target,
      note: 'Update your domain\'s MX record to point to the "after" value. Keep TTL low until activation is confirmed.',
    };
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Tenant() tenant: TenantInfo, @Body('name') name: string) {
    if (!name || typeof name !== 'string') {
      return { statusCode: HttpStatus.BAD_REQUEST, message: 'body must include "name" (domain)' };
    }
    const domainName = name.trim().toLowerCase();
    if (!DOMAIN_RE.test(domainName)) {
      return { statusCode: HttpStatus.BAD_REQUEST, message: `"${domainName}" is not a valid domain name` };
    }

    const existing = domainRepository.findByName(domainName);
    if (existing) {
      return { statusCode: HttpStatus.CONFLICT, message: `domain ${domainName} is already registered`, domain: this.serializeDomain(existing) };
    }

    const mx = await dnsLookupService.lookupDomainMx(domainName);
    if (!mx) {
      return { statusCode: 422, message: `could not resolve MX records for ${domainName}. Verify the domain has mail configured.` };
    }

    const row = {
      id: databaseService.uuid(),
      tenant_id: tenant.id,
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
    return { domain: this.serializeDomain(row), instructions: this.mxInstructions(row) };
  }

  @Get()
  list(@Tenant() tenant: TenantInfo) {
    const rows = domainRepository.findAllByTenant(tenant.id);
    return { domains: rows.map(r => this.serializeDomain(r)) };
  }

  @Get(':name')
  getOne(@Tenant() tenant: TenantInfo, @Param('name') name: string) {
    const row = domainRepository.findByTenantAndName(tenant.id, name.toLowerCase());
    if (!row) return null;
    return { domain: this.serializeDomain(row), instructions: this.mxInstructions(row) };
  }

  @Post(':name/activate')
  @HttpCode(HttpStatus.OK)
  async activate(@Tenant() tenant: TenantInfo, @Param('name') name: string) {
    const row = domainRepository.findByTenantAndName(tenant.id, name.toLowerCase());
    if (!row) return null;

    const pointsToRelay = await dnsLookupService.mxPointsToRelay(row.name, config.relayHostname);
    if (!pointsToRelay) {
      return {
        statusCode: HttpStatus.CONFLICT,
        message: `MX for ${row.name} does not yet point to ${config.relayHostname}. DNS may still be propagating.`,
        instructions: this.mxInstructions(row),
      };
    }

    domainRepository.updateStatus(row.id, 'ACTIVE', new Date().toISOString());
    const updated = domainRepository.findByName(row.name);
    return { domain: this.serializeDomain(updated!) };
  }

  @Delete(':name')
  @HttpCode(HttpStatus.NO_CONTENT)
  delete(@Tenant() tenant: TenantInfo, @Param('name') name: string) {
    const row = domainRepository.findByTenantAndName(tenant.id, name.toLowerCase());
    if (!row) return null;
    domainRepository.delete(row.id);
  }
}