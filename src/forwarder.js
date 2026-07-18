const nodemailer = require('nodemailer');

/**
 * Forward a raw MIME message to the destination mail server, preserving the
 * original headers/body/attachments/DKIM signature untouched (PRD 6.3:
 * "Transparent Forwarding"). We connect directly to the destination MX on
 * port 25 rather than routing through a smart-host, so nothing is rewritten.
 *
 * `rawMessage` must already include any headers we want to add (X-Relay-ID,
 * X-Filtered-By, X-Spam-Score, X-Processing-Time) — see smtp-gateway.js.
 */
async function forward({ destinationHost, destinationPort = 25, from, to, rawMessage }) {
  const transporter = nodemailer.createTransport({
    host: destinationHost,
    port: destinationPort,
    secure: false,
    tls: { rejectUnauthorized: false }, // opportunistic TLS; many small providers use self-signed/incomplete chains
    connectionTimeout: 15000,
    greetingTimeout: 10000,
  });

  const info = await transporter.sendMail({
    envelope: { from, to },
    raw: rawMessage,
  });

  return info;
}

module.exports = { forward };
