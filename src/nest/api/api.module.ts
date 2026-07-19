import { Module } from '@nestjs/common';
import { EmailsController } from './controllers/emails.controller';
import { DomainsController } from './controllers/domains.controller';
import { ListsController } from './controllers/lists.controller';
import { TenantGuard } from './guards/tenant.guard';

@Module({
  controllers: [EmailsController, DomainsController, ListsController],
  providers: [TenantGuard],
})
export class ApiModule {}