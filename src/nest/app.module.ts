import { Module } from '@nestjs/common';
import { CommonModule } from './common/common.module';
import { ConfigModule } from './config/config.module';
import { ApiModule } from './api/api.module';
import { DatabaseModule } from './database/database.module';
import { TlsModule } from './tls/tls.module';
import { SmtpModule } from './smtp/smtp.module';

@Module({
  imports: [
    CommonModule,
    ConfigModule,
    DatabaseModule,
    ApiModule,
    TlsModule,
    SmtpModule,
  ],
})
export class AppModule {}