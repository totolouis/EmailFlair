import {
  Controller, Get, Post, Delete, Param, Query,
  UseGuards, NotFoundException, ConflictException,
  InternalServerErrorException, BadGatewayException
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
  }, includeHeaders = false, maskSubject = false): IEmailResponse {
    const out: IEmailResponse = {
      id: row.id, domain: row.domain, sender: row.sender, recipient: row.recipient,
      subject: maskSubject ? this.maskText(row.subject) : row.subject,
      remoteIp: row.remote_ip, spamScore: row.spam_score,
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

  private maskText(text: string | null): string | null {
    if (!text) return null;
    if (text.length <= 3) return '***';
    return text.substring(0, 3) + '***';
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
    return { emails: rows.map(r => this.serializeEmail(r, false, true)) };
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
    if (!row) throw new NotFoundException('email not found');
    return { email: this.serializeEmail(row, true) };
  }

  @Post(':id/release')
  async release(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = emailRepository.findById(tenant.id, id);
    if (!row) throw new NotFoundException('email not found');
    if (row.status !== 'QUARANTINED') {
      throw new ConflictException(`email is not quarantined (status=${row.status})`);
    }
    if (!row.eml_path) {
      throw new InternalServerErrorException('quarantined message has no stored content');
    }

    const domainRow = domainRepository.findByName(row.domain);
    if (!domainRow || !domainRow.destination_mx) {
      throw new InternalServerErrorException('no destination configured for this domain');
    }

    const raw = quarantineService.readRaw(row.eml_path);
    if (!raw) {
      throw new InternalServerErrorException('quarantined message file not found on disk');
    }

    try {
      await forwarderService.forward({
        destinationHost: domainRow.destination_mx,
        from: row.sender || '',
        to: [row.recipient || ''],
        rawMessage: raw,
      });
      emailRepository.updateStatus(row.id, 'FORWARDED', 'FORWARDED', new Date().toISOString());
      quarantineService.deleteRaw(row.eml_path);
      return { ok: true };
    } catch (err) {
      throw new BadGatewayException(`release failed: ${(err as Error).message}`);
    }
  }

  @Delete(':id')
  async delete(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = emailRepository.findById(tenant.id, id);
    if (!row) throw new NotFoundException('email not found');
    if (row.eml_path) quarantineService.deleteRaw(row.eml_path);
    emailRepository.delete(row.id);
  }
}