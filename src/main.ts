import 'reflect-metadata';
import path from 'path';
import express from 'express';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './nest/app.module';
import config from './config';
import databaseService from './services/DatabaseService';
import { AcmeManager } from './tls/AcmeManager';
import { setAcmeManagerRef } from './nest/api/controllers/acme-challenge.controller';
import type { CertFiles } from './tls/CertStore';
import fs from 'fs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const apiPort = config.apiPort;
  const smtpPort = config.smtpPort;

  databaseService.init(config.dbPath);
  const defaultTenant = databaseService.seedDefaultTenant();
  console.log(`[init] Database initialized. Default tenant API key: ${defaultTenant.api_key}`);

  fs.mkdirSync(config.quarantineDir, { recursive: true });

  /* Serve dashboard and health endpoint on the NestJS Express adapter */
  const adapter = app.getHttpAdapter();
  const instance = adapter.getInstance();
  instance.get('/health', (_req: any, res: any) => res.json({ ok: true }));
  instance.use('/', express.static(path.join(__dirname, 'dashboard')));

  /* Start HTTP server first so ACME challenge endpoint is live for LE validation */
  await app.listen(apiPort);
  console.log(`[api] listening on port ${apiPort}`);
  console.log(`[dashboard] http://localhost:${apiPort}/`);

  /* Start SMTP server (without TLS initially — ACME will supply it) */
  const { buildServer } = require('./smtp-gateway.js');
  let smtpServer = buildServer();
  smtpServer.listen(smtpPort, () => {
    console.log(`[smtp-gateway] listening on port ${smtpPort} as ${config.relayHostname}`);
  });
  smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));

  let acmeManager: AcmeManager | null = null;

  if (config.tlsAcmeEnabled) {
    acmeManager = new AcmeManager({
      relayHostname: config.relayHostname,
      tlsAcmeEmail: config.tlsAcmeEmail,
      tlsAcmeStorage: config.tlsAcmeStorage,
    } as any);

    setAcmeManagerRef(acmeManager);

    acmeManager.on('renew' as any, (newCert: CertFiles | undefined) => {
      if (!newCert) return;
      console.log('[tls] Cert renewed, restarting SMTP server with new cert...');
      smtpServer.close(() => {
        smtpServer = buildServer(newCert);
        smtpServer.listen(smtpPort, () => {
          console.log(`[smtp-gateway] restarted on port ${smtpPort} with TLS cert`);
        });
        smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));
      });
    });

    try {
      await acmeManager.init();
      const tlsOptions = acmeManager.getServerOptions();
      if (tlsOptions) {
        console.log('[tls] SMTP STARTTLS enabled');
        smtpServer.close(() => {
          smtpServer = buildServer(tlsOptions);
          smtpServer.listen(smtpPort, () => {
            console.log(`[smtp-gateway] restarted on port ${smtpPort} with TLS cert`);
          });
          smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));
        });
        acmeManager.scheduleRenewal();
      }
    } catch (err) {
      console.error('[tls] ACME init failed, will retry in background:', (err as Error).message);
      acmeManager.startRetry(30_000);
    }
  }

  function shutdown(signal: string) {
    console.log(`\n[${signal}] Shutting down gracefully...`);
    if (acmeManager) {
      acmeManager.stopRenewal();
      acmeManager.stopRetry();
    }
    smtpServer.close(() => {
      process.exit(0);
    });
    setTimeout(() => {
      console.error('[shutdown] Forced exit after timeout');
      process.exit(1);
    }, 10000).unref();
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

bootstrap().catch((err) => {
  console.error('[startup] Fatal error:', err);
  process.exit(1);
});