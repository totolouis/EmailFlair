const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const config = require('./config');
const { getDb, uuid, defaultTenant } = require('./db');
const { resolveDestination } = require('./routing-engine');
const { detectLoop, signRelayId } = require('./loop-prevention');
const { scoreEmail } = require('./spam-filter');
const { storeRaw } = require('./quarantine');
const { forward } = require('./forwarder');

/**
 * Insert the relay's own headers right after the top of the raw message,
 * before the original headers, so they read top-to-bottom like a normal
 * mail trace (most-recent-hop-first) without touching anything else
 * (PRD 6.3: preserve original headers/body/attachments/DKIM).
 */
function injectHeaders(rawBuffer, headerLines) {
  const injected = headerLines.map((l) => `${l}\r\n`).join('');
  return Buffer.concat([Buffer.from(injected, 'utf8'), rawBuffer]);
}

function logEmail(record) {
  getDb().prepare(`
    INSERT INTO emails (
      id, tenant_id, domain, sender, recipient, subject, remote_ip,
      spam_score, decision, status, relay_id, reason, headers_json,
      size_bytes, eml_path, received_at, processed_at
    ) VALUES (
      @id, @tenant_id, @domain, @sender, @recipient, @subject, @remote_ip,
      @spam_score, @decision, @status, @relay_id, @reason, @headers_json,
      @size_bytes, @eml_path, @received_at, @processed_at
    )
  `).run(record);
}

function buildServer() {
  const server = new SMTPServer({
    banner: `${config.relayHostname} Email Security Relay`,
    authOptional: true,
    disabledCommands: ['AUTH'], // this is an inbound-only public relay; no client auth in MVP
    logger: false,

    onRcptTo(address, session, callback) {
      const recipientDomain = address.address.split('@')[1];
      const domainRow = resolveDestination(recipientDomain);
      if (!domainRow) {
        const err = new Error(`No such domain configured on this relay: ${recipientDomain}`);
        err.responseCode = 550;
        return callback(err);
      }
      if (domainRow.status !== 'ACTIVE') {
        const err = new Error(`Domain ${recipientDomain} is not yet active on this relay`);
        err.responseCode = 550;
        return callback(err);
      }
      session.envelope._domainRow = domainRow; // stash for onData
      callback();
    },

    onData(stream, session, callback) {
      const startedAt = Date.now();
      const chunks = [];
      let remoteIp = session.remoteAddress;

      stream.on('data', (chunk) => chunks.push(chunk));
      stream.on('error', (err) => {
        console.error('[smtp] stream error:', err.message);
        callback(new Error('451 4.3.0 Temporary error reading message'));
      });

      stream.on('end', async () => {
        const rawBuffer = Buffer.concat(chunks);
        const recipient = (session.envelope.rcptTo[0] || {}).address || 'unknown';
        const domainRow = session.envelope._domainRow || resolveDestination(recipient.split('@')[1]);
        const tenantId = domainRow ? domainRow.tenant_id : defaultTenant.id;
        const emailId = uuid();

        let parsed;
        try {
          parsed = await simpleParser(rawBuffer);
        } catch (err) {
          const parseErr = new Error('Could not parse message');
          parseErr.responseCode = 451;
          return callback(parseErr);
        }

        const senderAddress = (parsed.from && parsed.from.value[0] && parsed.from.value[0].address) || session.envelope.mailFrom.address;
        const senderDomain = (senderAddress || '').split('@')[1] || '';
        const subject = parsed.subject || '';

        // 1. Loop prevention (PRD 6.4)
        const loopCheck = detectLoop(parsed.headers);
        if (loopCheck.isLoop) {
          logEmail({
            id: emailId, tenant_id: tenantId, domain: domainRow ? domainRow.name : recipient.split('@')[1],
            sender: senderAddress, recipient, subject, remote_ip: remoteIp,
            spam_score: 0, decision: 'REJECTED', status: 'REJECTED', relay_id: config.relayId,
            reason: loopCheck.reason, headers_json: null, size_bytes: rawBuffer.length, eml_path: null,
            received_at: new Date(startedAt).toISOString(), processed_at: new Date().toISOString(),
          });
          const loopErr = new Error(`Mail loop detected: ${loopCheck.reason}`);
          loopErr.responseCode = 554;
          return callback(loopErr);
        }

        // 2. Spam / phishing scoring (PRD 6.5)
        const { score, reasons } = scoreEmail({
          tenantId,
          remoteIp,
          senderDomain,
          senderAddress,
          subject,
          hasAttachments: (parsed.attachments || []).length > 0,
        });

        const processingMs = Date.now() - startedAt;
        const relaySignature = signRelayId(config.relayId, config.relaySecret);
        const stampedRaw = injectHeaders(rawBuffer, [
          `X-Relay-ID: ${config.relayId}`,
          `X-Relay-Signature: ${relaySignature}`,
          `X-Filtered-By: EmailSecurityRelay/1.0`,
          `X-Spam-Score: ${score.toFixed(2)}`,
          `X-Processing-Time: ${processingMs}ms`,
        ]);

        const baseRecord = {
          id: emailId,
          tenant_id: tenantId,
          domain: domainRow ? domainRow.name : senderDomain,
          sender: senderAddress,
          recipient,
          subject,
          remote_ip: remoteIp,
          spam_score: score,
          relay_id: config.relayId,
          headers_json: JSON.stringify(Object.fromEntries(parsed.headers)),
          size_bytes: rawBuffer.length,
          received_at: new Date(startedAt).toISOString(),
          processed_at: new Date().toISOString(),
        };

        // 3. Decision: reject / quarantine / forward
        if (score >= config.rejectThreshold) {
          logEmail({ ...baseRecord, decision: 'REJECTED', status: 'REJECTED', reason: reasons.join('; '), eml_path: null });
          const spamErr = new Error('Message rejected as spam/phishing');
          spamErr.responseCode = 554;
          return callback(spamErr);
        }

        if (score >= config.quarantineThreshold) {
          const emlPath = storeRaw(emailId, stampedRaw);
          logEmail({ ...baseRecord, decision: 'QUARANTINED', status: 'QUARANTINED', reason: reasons.join('; '), eml_path: emlPath });
          return callback(); // accepted onto the relay, held in quarantine, not forwarded yet
        }

        // 4. Transparent forward to the original provider (PRD 6.2 / 6.3)
        if (!domainRow || !domainRow.destination_mx) {
          logEmail({ ...baseRecord, decision: 'REJECTED', status: 'REJECTED', reason: 'no destination configured', eml_path: null });
          const destErr = new Error('No destination configured for this domain');
          destErr.responseCode = 451;
          return callback(destErr);
        }

        try {
          await forward({
            destinationHost: domainRow.destination_mx,
            from: session.envelope.mailFrom.address,
            to: session.envelope.rcptTo.map((r) => r.address),
            rawMessage: stampedRaw,
          });
          logEmail({ ...baseRecord, decision: 'FORWARDED', status: 'FORWARDED', reason: reasons.join('; ') || null, eml_path: null });
          callback();
        } catch (err) {
          logEmail({ ...baseRecord, decision: 'REJECTED', status: 'REJECTED', reason: `forwarding failed: ${err.message}`, eml_path: null });
          const fwdErr = new Error('Temporary failure forwarding message');
          fwdErr.responseCode = 451;
          callback(fwdErr);
        }
      });
    },
  });

  return server;
}

module.exports = { buildServer };
