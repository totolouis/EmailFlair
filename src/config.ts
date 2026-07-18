import dotenv from 'dotenv';
import { IConfig } from './interfaces';

dotenv.config();

function validate(): void {
  const errors: string[] = [];
  const relaySecret = process.env.RELAY_SECRET;
  if (relaySecret && (relaySecret === 'change-me' || relaySecret.length < 8)) {
    errors.push('RELAY_SECRET must be at least 8 characters and not the default value');
  }
  const acmeEnabled = process.env.TLS_ACME_ENABLED === 'true';
  if (acmeEnabled) {
    if (!process.env.TLS_ACME_EMAIL) {
      errors.push('TLS_ACME_EMAIL is required when TLS_ACME_ENABLED=true');
    }
    const hostname = process.env.RELAY_HOSTNAME || 'mx1.emailrelay.com';
    if (hostname === 'mx1.emailrelay.com') {
      errors.push('RELAY_HOSTNAME must be set to a real domain when TLS_ACME_ENABLED=true');
    }
  }
  if (errors.length) {
    console.error('[config] Invalid configuration:', errors.join('; '));
  }
}

validate();

const config: IConfig = {
  relayId: process.env.RELAY_ID || 'relay-01',
  relaySecret: process.env.RELAY_SECRET || 'dev-secret-do-not-use-in-prod',
  relayHostname: process.env.RELAY_HOSTNAME || 'mx1.emailrelay.com',

  smtpPort: parseInt(process.env.SMTP_PORT || '2525', 10),
  apiPort: parseInt(process.env.API_PORT || '3000', 10),

  quarantineThreshold: parseFloat(process.env.SPAM_QUARANTINE_THRESHOLD || '5'),
  rejectThreshold: parseFloat(process.env.SPAM_REJECT_THRESHOLD || '10'),

  dbPath: process.env.DB_PATH || './data/relay.db',
  quarantineDir: process.env.QUARANTINE_DIR || './data/quarantine',

  defaultTenantName: process.env.DEFAULT_TENANT_NAME || 'Default Tenant',
  defaultTenantApiKey: process.env.DEFAULT_TENANT_API_KEY || 'dev-tenant-key',

  smtpTlsPort: parseInt(process.env.SMTP_TLS_PORT || '465', 10),
  tlsAcmeEnabled: process.env.TLS_ACME_ENABLED === 'true',
  tlsAcmeEmail: process.env.TLS_ACME_EMAIL || '',
  tlsAcmeStorage: process.env.TLS_ACME_STORAGE || './data/acme',
};

export default config;
