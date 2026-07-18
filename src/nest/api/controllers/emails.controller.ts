import {
  Controller, Get, Post, Delete, Param, Query, Body,
  UseGuards, HttpCode, HttpStatus, UseInterceptors, UploadedFile
} from '@nestjs/common';
import { TenantGuard } from '../guards/tenant.guard';
import { Tenant, TenantInfo } from '../decorators/tenant.decorator';
import emailRepository from '../../../repositories/EmailRepository';
import domainRepository from '../../../repositories/DomainRepository';
import quarantineService from '../../../services/QuarantineService';
import forwarderService from '../../../services/ForwarderService';
import { EmailDecision, EmailStatus, IEmailResponse } from '../../../interfaces';

@Controller('emails')
@UseGuards(TenantGuard)
export class EmailsController {
  private serializeEmail(row: {
    id: string; domain: string; sender: string | null; recipient: string | null;
    subject: string | null; remote_ip: string | null; spam_score: number;
    decision: string | null; status: string; reason: string | null;
    size_bytes: number | null; received_at: string; processed_at: string | null;
    headers_json: string | null;
  }, includeHeaders = false): IEmailResponse {
    const out: IEmailResponse = {
      id: row.id, domain: row.domain, sender: row.sender, recipient: row.recipient,
      subject: row.subject, remoteIp: row.remote_ip, spamScore: row.spam_score,
      decision: row.decision as EmailDecision | null, status: row.status as EmailStatus,
      reason: row.reason, sizeBytes: row.size_bytes,
      receivedAt: row.received_at, processedAt: row.processed_at,
    };
    if (includeHeaders && row.headers_json) {
      try {
        out.headers = JSON.parse(row.headers_json) as Record<string, unknown>;
      } catch { out.headers = null; }
    }
    return out;
  }

  @Get()
  list(
    @Tenant() tenant: TenantInfo,
    @Query('status') status?: string,
    @Query('domain') domain?: string,
    @Query('limit') limit?: string,
  ) {
    const rows = emailRepository.findAll({
      tenantId: tenant.id,
      status: status || undefined,
      domain: domain || undefined,
      limit: limit ? parseInt(limit, 10) : 100,
    });
    return { emails: rows.map(r => this.serializeEmail(r)) };
  }

  @Get('summary')
  summary(@Tenant() tenant: TenantInfo) {
    const totals = emailRepository.getStatusSummary(tenant.id);
    const activeDomains = domainRepository.countActiveByTenant(tenant.id);
    return { totals, activeDomains };
  }

  @Get(':id')
  getOne(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = emailRepository.findById(tenant.id, id);
    if (!row) return null;
    return { email: this.serializeEmail(row, true) };
  }

  @Post(':id/release')
  @HttpCode(HttpStatus.OK)
  async release(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = emailRepository.findById(tenant.id, id);
    if (!row) return { statusCode: HttpStatus.NOT_FOUND, message: 'email not found' };
    if (row.status !== 'QUARANTINED') {
      return { statusCode: HttpStatus.CONFLICT, message: `email is not quarantined (status=${row.status})` };
    }
    if (!row.eml_path) {
      return { statusCode: HttpStatus.INTERNAL_SERVER_ERROR, message: 'quarantined message has no stored content' };
    }

    const domainRow = domainRepository.findByName(row.domain);
    if (!domainRow || !domainRow.destination_mx) {
      return { statusCode: HttpStatus.INTERNAL_SERVER_ERROR, message: 'no destination configured for this domain' };
    }

    const raw = quarantineService.readRaw(row.eml_path);
    if (!raw) {
      return { statusCode: HttpStatus.INTERNAL_SERVER_ERROR, message: 'quarantined message file not found on disk' };
    }

    await forwarderService.forward({
      destinationHost: domainRow.destination_mx,
      from: row.sender || '',
      to: [row.recipient || ''],
      rawMessage: raw,
    });
    emailRepository.updateStatus(row.id, 'FORWARDED', 'FORWARDED', new Date().toISOString());
    quarantineService.deleteRaw(row.eml_path);
    return { ok: true };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  delete(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = emailRepository.findById(tenant.id, id);
    if (!row) return null;
    if (row.eml_path) quarantineService.deleteRaw(row.eml_path);
    emailRepository.delete(row.id);
  }
}