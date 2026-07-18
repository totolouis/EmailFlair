const config = require('./config');
const { buildServer } = require('./smtp-gateway');
const { buildApiApp } = require('./api/server');
const { defaultTenant } = require('./db');

const smtpServer = buildServer();
smtpServer.listen(config.smtpPort, () => {
  console.log(`[smtp-gateway] listening on port ${config.smtpPort} as ${config.relayHostname} (relay id: ${config.relayId})`);
});
smtpServer.on('error', (err) => console.error('[smtp-gateway] error:', err.message));

const apiApp = buildApiApp();
apiApp.listen(config.apiPort, () => {
  console.log(`[api]           listening on port ${config.apiPort}`);
  console.log(`[dashboard]     http://localhost:${config.apiPort}/`);
  console.log(`[tenant]        default tenant API key: ${defaultTenant.api_key}`);
});

process.on('SIGINT', () => { console.log('\nShutting down...'); process.exit(0); });
process.on('SIGTERM', () => { process.exit(0); });
