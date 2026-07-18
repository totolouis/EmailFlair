const config = require('./config');
const { buildServer } = require('./smtp-gateway');
const { buildApiApp } = require('./api/server');
const { defaultTenant } = require('./db');

const smtpServer = buildServer();
smtpServer.listen(config.smtpPort, () => {
  console.log(`[smtp-gateway] listening on port ${config.smtpPort} as ${config.relayHostname} (relay id: ${config.relayId})`);
});
smtpServer.on('error', (err) => console.error('[smtp-gateway] error:', err.message));

const apiServer = buildApiApp();
apiServer.listen(config.apiPort, () => {
  console.log(`[api]           listening on port ${config.apiPort}`);
  console.log(`[dashboard]     http://localhost:${config.apiPort}/`);
  console.log(`[tenant]        default tenant API key: ${defaultTenant.api_key}`);
});

function shutdown(signal) {
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
