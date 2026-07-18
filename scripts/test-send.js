/* eslint-disable no-console */
// Manual/local smoke test:
//   1. Registers a fake domain directly in the DB (bypassing real DNS) so we
//      can exercise the SMTP pipeline without owning a real domain.
//   2. Sends a message through the SMTP gateway on localhost.
//   3. Sends a second, identical message but with our own X-Relay-ID header
//      already attached, to prove loop detection triggers a 554.
//
// Run with the server already started in another terminal: `npm start`
// Then: `npm run test:send`

const nodemailer = require('nodemailer');
const { db, uuid } = require('../src/db');
const config = require('../src/config');

async function ensureTestDomain() {
  const name = 'test-company.local';
  let row = db.prepare('SELECT * FROM domains WHERE name = ?').get(name);
  if (!row) {
    row = {
      id: uuid(),
      tenant_id: require('../src/db').defaultTenant.id,
      name,
      provider: 'GoogleWorkspace',
      origin_mx: 'aspmx.l.google.com',
      destination_mx: '127.0.0.1', // loop back to a dummy local catch — real forwarding isn't reachable in this sandbox
      relay_target: config.relayHostname,
      status: 'ACTIVE',
      created_at: new Date().toISOString(),
      activated_at: new Date().toISOString(),
    };
    db.prepare(`
      INSERT INTO domains (id, tenant_id, name, provider, origin_mx, destination_mx, relay_target, status, created_at, activated_at)
      VALUES (@id, @tenant_id, @name, @provider, @origin_mx, @destination_mx, @relay_target, @status, @created_at, @activated_at)
    `).run(row);
    console.log(`Seeded test domain: ${name} (status=ACTIVE)`);
  }
  return row;
}

async function sendTestMessage({ extraHeaders = '', label }) {
  const transporter = nodemailer.createTransport({ host: 'localhost', port: config.smtpPort, secure: false, tls: { rejectUnauthorized: false } });
  try {
    const info = await transporter.sendMail({
      envelope: { from: 'sender@example.org', to: ['user@test-company.local'] },
      raw:
        `${extraHeaders}From: Sender <sender@example.org>\r\n` +
        `To: user@test-company.local\r\n` +
        `Subject: ${label}\r\n` +
        `\r\nHello, this is a test message.\r\n`,
    });
    console.log(`[${label}] accepted:`, info.response);
  } catch (err) {
    console.log(`[${label}] rejected as expected/unexpected:`, err.message);
  }
}

(async () => {
  await ensureTestDomain();
  await sendTestMessage({ label: 'normal message' });
  await sendTestMessage({
    label: 'looped message (should be rejected 554)',
    extraHeaders: `X-Relay-ID: ${config.relayId}\r\nX-Relay-Signature: ${require('../src/loop-prevention').signRelayId(config.relayId, config.relaySecret)}\r\n`,
  });
  process.exit(0);
})();
