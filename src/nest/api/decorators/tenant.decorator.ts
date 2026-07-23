import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export interface TenantInfo {
  id: string;
  name: string;
  api_key_hash: string;
  created_at: string;
}

export const Tenant = createParamDecorator(
  (data: keyof TenantInfo | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<Request & { tenant?: TenantInfo }>();
    const tenant = request.tenant;
    if (!tenant) return null;
    return data ? tenant[data] : tenant;
  },
);