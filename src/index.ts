import fs from 'fs';
import http from 'http';
import config from './config';
import { buildServer } from './smtp-gateway';
import { buildApiApp } from './api/server';
import databaseService from './services/DatabaseService';

fs.mkdirSync(config.quarantineDir, { recursive: true });
databaseService.init(config.dbPath);
const defaultTenant = databaseService.seedDefaultTenant();

const smtpServer = buildServer();
smtpServer.listen(config.smtpPort, () => {
  console.log(`[smtp-gateway] listening on port ${config.smtpPort} as ${config.relayHostname} (relay id: ${config.relayId})`);
});
smtpServer.on('error', (err: Error) => console.error('[smtp-gateway] error:', err.message));

const apiApp = buildApiApp();
const apiServer = http.createServer(apiApp);
apiServer.listen(config.apiPort, () => {
  console.log(`[api]           listening on port ${config.apiPort}`);
  console.log(`[dashboard]     http://localhost:${config.apiPort}/`);
  console.log(`[tenant]        default tenant API key: ${defaultTenant.api_key}`);
});

function shutdown(signal: string): void {
  console.log(`\n[${signal}] Shutting down gracefully...`);
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
