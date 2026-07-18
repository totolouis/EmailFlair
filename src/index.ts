import fs from 'fs';
import http from 'http';
import config from './config';
import { buildServer } from './smtp-gateway';
import { buildApiApp } from './api/server';
import databaseService from './services/DatabaseService';
import { AcmeManager } from './tls/AcmeManager';
import type { CertFiles } from './tls/CertStore';

async function main(): Promise<void> {
  fs.mkdirSync(config.quarantineDir, { recursive: true });
  databaseService.init(config.dbPath);
  const defaultTenant = databaseService.seedDefaultTenant();

  /* ---------- TLS / ACME ---------- */
  let acmeManager: AcmeManager | undefined;
  let tlsOptions: CertFiles | undefined;

  if (config.tlsAcmeEnabled) {
    acmeManager = new AcmeManager(config);

    try {
      await acmeManager.init();
      tlsOptions = acmeManager.getServerOptions();
    } catch (err) {
      console.error('[tls] ACME init failed, will retry in background:', (err as Error).message);
      acmeManager.startRetry(30_000);
    }

    if (tlsOptions) {
      console.log('[tls] SMTP STARTTLS enabled');
    } else {
      console.log('[tls] SMTP STARTTLS not available — ACME will retry in background');
    }
  }

  /* ---------- SMTP gateway ---------- */
  let smtpServer = buildServer(tlsOptions);
  smtpServer.listen(config.smtpPort, () => {
    console.log(`[smtp-gateway] listening on port ${config.smtpPort} as ${config.relayHostname} (relay id: ${config.relayId})`);
  });
  smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));

  /* On cert renewal, hot-reload the SMTP server */
  if (acmeManager) {
    const renewHandler = (newCert: CertFiles | undefined) => {
      if (!newCert) return;
      console.log('[tls] Cert obtained/renewed, restarting SMTP server with new cert...');
      const oldPort = config.smtpPort;
      smtpServer.close(() => {
        smtpServer = buildServer(newCert);
        smtpServer.listen(oldPort, () => {
          console.log(`[smtp-gateway] restarted on port ${oldPort} with TLS cert`);
        });
        smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));
      });
    };

    acmeManager.on('renew', renewHandler);

    /* If ACME succeeded on init, schedule normal renewal */
    if (tlsOptions) {
      acmeManager.scheduleRenewal();
    }
  }

  /* ---------- API + dashboard ---------- */
  const apiApp = buildApiApp();

  /* ACME HTTP-01 challenge handler (mounted regardless of ACME status) */
  if (acmeManager) {
    apiApp.get('/.well-known/acme-challenge/:token', (req, res) => {
      const token = (req.params as Record<string, string>).token;
      const keyAuth = acmeManager!.getChallengeResponse(token);
      if (keyAuth) {
        res.end(keyAuth);
      } else {
        res.status(404).end();
      }
    });
  }

  const apiServer = http.createServer(apiApp);
  apiServer.listen(config.apiPort, () => {
    console.log(`[api]           listening on port ${config.apiPort}`);
    console.log(`[dashboard]     http://localhost:${config.apiPort}/`);
    console.log(`[tenant]        default tenant API key: ${defaultTenant.api_key}`);
  });

  /* ---------- Graceful shutdown ---------- */
  function shutdown(signal: string): void {
    console.log(`\n[${signal}] Shutting down gracefully...`);
    if (acmeManager) {
      acmeManager.stopRenewal();
      acmeManager.stopRetry();
    }
    smtpServer.close(() => {
      apiServer.close(() => {
        process.exit(0);
      });
    });
    setTimeout(() => {
      console.error('[shutdown] Forced exit after timeout');
      process.exit(1);
    }, 10000).unref();
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[startup] Fatal error:', err);
  process.exit(1);
});
