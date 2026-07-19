import { Module } from '@nestjs/common';
import { ApiModule } from './api/api.module';
import { CommonModule } from './common/common.module';
import { ConfigModule } from './config/config.module';

@Module({
  imports: [
    CommonModule,
    ConfigModule,
    ApiModule,
  ],
})
export class AppModule {}