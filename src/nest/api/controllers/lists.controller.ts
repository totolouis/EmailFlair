import { Controller, Get, Post, Delete, Param, Body, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { TenantGuard } from '../guards/tenant.guard';
import { Tenant, TenantInfo } from '../decorators/tenant.decorator';
import listRepository from '../../../repositories/ListRepository';
import databaseService from '../../../services/DatabaseService';
import { ListType } from '../../../interfaces';

@Controller('lists')
@UseGuards(TenantGuard)
export class ListsController {
  @Get('blacklist')
  getBlacklist(@Tenant() tenant: TenantInfo) {
    const rows = listRepository.findAll(tenant.id, 'blacklist');
    return { blacklist: rows.map(row => ({ id: row.id, type: row.type, value: row.value, createdAt: row.created_at })) };
  }

  @Post('blacklist')
  @HttpCode(HttpStatus.CREATED)
  addBlacklist(@Tenant() tenant: TenantInfo, @Body() body: { type?: string; value?: string }) {
    const { type, value } = body || {};
    if (!type || !['ip', 'domain'].includes(type) || !value) {
      return { statusCode: HttpStatus.BAD_REQUEST, message: 'body must include type ("ip"|"domain") and value' };
    }
    const entry = {
      id: databaseService.uuid(),
      tenant_id: tenant.id,
      type: type as ListType,
      value: (value as string).trim().toLowerCase(),
      created_at: new Date().toISOString(),
    };
    listRepository.create(entry, 'blacklist');
    return { entry: { id: entry.id, type: entry.type, value: entry.value, createdAt: entry.created_at } };
  }

  @Delete('blacklist/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  deleteBlacklist(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = listRepository.findById(tenant.id, id, 'blacklist');
    if (!row) return null;
    listRepository.delete(row.id, 'blacklist');
  }

  @Get('whitelist')
  getWhitelist(@Tenant() tenant: TenantInfo) {
    const rows = listRepository.findAll(tenant.id, 'whitelist');
    return { whitelist: rows.map(row => ({ id: row.id, type: row.type, value: row.value, createdAt: row.created_at })) };
  }

  @Post('whitelist')
  @HttpCode(HttpStatus.CREATED)
  addWhitelist(@Tenant() tenant: TenantInfo, @Body() body: { type?: string; value?: string }) {
    const { type, value } = body || {};
    if (!type || !['ip', 'domain'].includes(type) || !value) {
      return { statusCode: HttpStatus.BAD_REQUEST, message: 'body must include type ("ip"|"domain") and value' };
    }
    const entry = {
      id: databaseService.uuid(),
      tenant_id: tenant.id,
      type: type as ListType,
      value: (value as string).trim().toLowerCase(),
      created_at: new Date().toISOString(),
    };
    listRepository.create(entry, 'whitelist');
    return { entry: { id: entry.id, type: entry.type, value: entry.value, createdAt: entry.created_at } };
  }

  @Delete('whitelist/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  deleteWhitelist(@Tenant() tenant: TenantInfo, @Param('id') id: string) {
    const row = listRepository.findById(tenant.id, id, 'whitelist');
    if (!row) return null;
    listRepository.delete(row.id, 'whitelist');
  }
}