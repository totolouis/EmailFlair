import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { TenantInfo } from '../decorators/tenant.decorator';
import tenantRepository from '../../../repositories/TenantRepository';

@Injectable()
export class TenantGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const header = request.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token) {
      throw new UnauthorizedException('Missing API key (Authorization: Bearer <key>)');
    }
    const tenant = tenantRepository.findByApiKey(token) as TenantInfo | null;
    if (!tenant) {
      throw new UnauthorizedException('Invalid API key');
    }
    (request as Request & { tenant: TenantInfo }).tenant = tenant;
    return true;
  }
}