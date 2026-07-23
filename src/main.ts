import 'reflect-metadata';
import path from 'path';
import express from 'express';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './nest/app.module';
import config from './config';
import databaseService from './services/DatabaseService';
import fs from 'fs';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: [`https://${config.relayHostname}`, `http://${config.relayHostname}`],
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Authorization', 'Content-Type'],
  });

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

  await app.listen(apiPort);
  console.log(`[api] listening on port ${apiPort}`);
  console.log(`[dashboard] http://localhost:${apiPort}/`);

  /* Start SMTP server (plain — Traefik handles TLS termination) */
  const { buildServer } = require('./smtp-gateway.js');
  const smtpServer = buildServer();
  smtpServer.listen(smtpPort, () => {
    console.log(`[smtp-gateway] listening on port ${smtpPort} as ${config.relayHostname}`);
  });
  smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));

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