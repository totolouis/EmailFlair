import { Injectable } from '@nestjs/common';
import dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class ConfigService {
  readonly relayId: string;
  readonly relaySecret: string;
  readonly relayHostname: string;
  readonly smtpPort: number;
  readonly apiPort: number;
  readonly quarantineThreshold: number;
  readonly rejectThreshold: number;
  readonly dbPath: string;
  readonly quarantineDir: string;
  readonly defaultTenantName: string;
  readonly defaultTenantApiKey: string;
  readonly smtpTlsPort: number;
  readonly tlsAcmeEnabled: boolean;
  readonly tlsAcmeEmail: string;
  readonly tlsAcmeStorage: string;

  constructor() {
    this.relayId = process.env.RELAY_ID || 'relay-01';
    this.relaySecret = process.env.RELAY_SECRET || 'dev-secret-do-not-use-in-prod';
    this.relayHostname = process.env.RELAY_HOSTNAME || 'mx1.emailrelay.com';
    this.smtpPort = parseInt(process.env.SMTP_PORT || '2525', 10);
    this.apiPort = parseInt(process.env.API_PORT || '3000', 10);
    this.quarantineThreshold = parseFloat(process.env.SPAM_QUARANTINE_THRESHOLD || '5');
    this.rejectThreshold = parseFloat(process.env.SPAM_REJECT_THRESHOLD || '10');
    this.dbPath = process.env.DB_PATH || './data/relay.db';
    this.quarantineDir = process.env.QUARANTINE_DIR || './data/quarantine';
    this.defaultTenantName = process.env.DEFAULT_TENANT_NAME || 'Default Tenant';
    this.defaultTenantApiKey = process.env.DEFAULT_TENANT_API_KEY || 'dev-tenant-key';
    this.smtpTlsPort = parseInt(process.env.SMTP_TLS_PORT || '465', 10);
    this.tlsAcmeEnabled = process.env.TLS_ACME_ENABLED === 'true';
    this.tlsAcmeEmail = process.env.TLS_ACME_EMAIL || '';
    this.tlsAcmeStorage = process.env.TLS_ACME_STORAGE || './data/acme';
  }

  validate(): string[] {
    const errors: string[] = [];
    if (this.relaySecret === 'change-me' || this.relaySecret.length < 8) {
      errors.push('RELAY_SECRET must be at least 8 characters and not the default value');
    }
    if (this.tlsAcmeEnabled) {
      if (!this.tlsAcmeEmail) {
        errors.push('TLS_ACME_EMAIL is required when TLS_ACME_ENABLED=true');
      }
      if (this.relayHostname === 'mx1.emailrelay.com') {
        errors.push('RELAY_HOSTNAME must be set to a real domain when TLS_ACME_ENABLED=true');
      }
    }
    return errors;
  }
}

export default ConfigService;