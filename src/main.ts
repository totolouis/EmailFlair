import 'reflect-metadata';
import path from 'path';
import express from 'express';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './nest/app.module';
import config from './config';
import databaseService from './services/DatabaseService';
import { CertManager, type CertFiles } from './tls/CertManager';
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

  /* Start SMTP server and init TLS */
  const { buildServer } = require('./smtp-gateway.js');
  let smtpServer: any;
  let tlsServerOptions: CertFiles | undefined;

  const certManager = new CertManager(config.tlsCertDir, config.relayHostname);
  certManager.init();
  tlsServerOptions = certManager.getServerOptions();

  function startSmtpServer(options?: CertFiles) {
    const server = options ? buildServer(options) : buildServer();
    server.listen(smtpPort, () => {
      console.log(`[smtp-gateway] listening on port ${smtpPort} as ${config.relayHostname}`);
    });
    server.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));
    return server;
  }

  if (tlsServerOptions) {
    smtpServer = startSmtpServer(tlsServerOptions);
    console.log('[tls] SMTP STARTTLS enabled');
  } else {
    smtpServer = startSmtpServer();
  }

  certManager.watchForRenewal((newCert) => {
    console.log('[tls] Certbot renewed — restarting SMTP with fresh cert');
    const old = smtpServer;
    old.close(() => {
      smtpServer = startSmtpServer(newCert);
    });
  });

  function shutdown(signal: string) {
    console.log(`\n[${signal}] Shutting down gracefully...`);
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