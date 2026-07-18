import { Module, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { buildServer } from '../../smtp-gateway';
import type { CertFiles } from '../../tls/CertStore';

@Module({})
export class SmtpModule implements OnModuleInit, OnModuleDestroy {
  private smtpServer: ReturnType<typeof buildServer> | null = null;
  private readonly logger = new Logger('SmtpModule');

  setTlsOptions(opts: CertFiles | undefined) {
    // Called before onModuleInit to set TLS options
  }

  async onModuleInit() {
    const smtpPort = parseInt(process.env.SMTP_PORT || '2525', 10);
    const relayHostname = process.env.RELAY_HOSTNAME || 'mx1.emailrelay.com';
    this.smtpServer = buildServer(undefined);
    this.smtpServer.listen(smtpPort, () => {
      this.logger.log(`SMTP server listening on port ${smtpPort} as ${relayHostname}`);
    });
    this.smtpServer.on('error', (err: Error) => {
      this.logger.error(`SMTP server error: ${err.message}`);
    });
  }

  async onModuleDestroy() {
    if (this.smtpServer) {
      await new Promise<void>((resolve) => this.smtpServer!.close(() => resolve()));
      this.logger.log('SMTP server closed');
    }
  }

  restartWithTls(opts: CertFiles) {
    if (this.smtpServer) {
      const oldPort = parseInt(process.env.SMTP_PORT || '2525', 10);
      this.smtpServer.close(() => {
        this.smtpServer = buildServer(opts);
        this.smtpServer.listen(oldPort, () => {
          this.logger.log(`SMTP server restarted on port ${oldPort} with TLS cert`);
        });
        this.smtpServer.on('error', (err: Error) => {
          this.logger.error(`SMTP server error: ${err.message}`);
        });
      });
    }
  }
}