import { Module } from '@nestjs/common';
import { EmailsController } from './controllers/emails.controller';
import { DomainsController } from './controllers/domains.controller';
import { ListsController } from './controllers/lists.controller';
import { AcmeChallengeController } from './controllers/acme-challenge.controller';
import { TenantGuard } from './guards/tenant.guard';

@Module({
  controllers: [EmailsController, DomainsController, ListsController, AcmeChallengeController],
  providers: [TenantGuard],
})
export class ApiModule {}