import { Module, OnModuleInit, Logger, Inject, Optional } from '@nestjs/common';
import { AcmeManager } from '../../tls/AcmeManager';
import { ConfigService } from '../config/config.service';

export const TLS_SERVICE = 'TLS_SERVICE';

@Module({
  providers: [
    {
      provide: TLS_SERVICE,
      useFactory: (configService: ConfigService): AcmeManager | null => {
        if (!configService.tlsAcmeEnabled) return null;
        return new AcmeManager({
          relayHostname: configService.relayHostname,
          tlsAcmeEmail: configService.tlsAcmeEmail,
          tlsAcmeStorage: configService.tlsAcmeStorage,
        } as any);
      },
      inject: [ConfigService],
    },
  ],
  exports: [TLS_SERVICE],
})
export class TlsModule implements OnModuleInit {
  private readonly logger = new Logger('TlsModule');

  constructor(
    // eslint-disable-next-line no-empty-pattern
    @Inject(TLS_SERVICE) private manager: AcmeManager | null,
  ) {}

  getManager(): AcmeManager | null {
    return this.manager;
  }

  onModuleInit() {
    if (!this.manager) {
      this.logger.log('TLS ACME disabled, skipping initialization');
    }
  }
}