import { Module, Global, OnModuleInit } from '@nestjs/common';
import databaseService from '../../services/DatabaseService';

@Global()
@Module({
  providers: [
    {
      provide: databaseService.constructor,
      useValue: databaseService,
    },
  ],
  exports: [databaseService.constructor],
})
export class DatabaseModule implements OnModuleInit {
  onModuleInit() {
    // Database is initialized in AppModule setup before other modules need it
  }
}

export { databaseService };