import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import { Readable } from 'stream';
import type { SMTPServerSession, SMTPServerAddress } from 'smtp-server';
import config from './config';
import databaseService from './services/DatabaseService';
import routingEngineService from './services/RoutingEngineService';
import loopPreventionService from './services/LoopPreventionService';
import spamFilterService from './services/SpamFilterService';
import quarantineService from './services/QuarantineService';
import forwarderService from './services/ForwarderService';
import emailRepository from './repositories/EmailRepository';
import { EmailDecision, EmailStatus, IDomain } from './interfaces';

interface ExtendedSession {
  envelope: {
    mailFrom?: SMTPServerAddress | false;
    rcptTo?: SMTPServerAddress[];
    _domainRow?: IDomain;
  };
  remoteAddress?: string;
}

function injectHeaders(rawBuffer: Buffer, headerLines: string[]): Buffer {
  const injected = headerLines.map((l) => `${l}\r\n`).join('');
  return Buffer.concat([Buffer.from(injected, 'utf8'), rawBuffer]);
}

function logEmail(record: {
  id: string;
  tenant_id: string;
  domain: string;
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  remote_ip: string | null;
  spam_score: number;
  decision: EmailDecision | null;
  status: EmailStatus;
  relay_id: string | null;
  reason: string | null;
  headers_json: string | null;
  size_bytes: number;
  eml_path: string | null;
  received_at: string;
  processed_at: string;
}): void {
  emailRepository.create(record);
}

function buildServer(tlsOptions?: { key: Buffer; cert: Buffer; ca?: Buffer }): SMTPServer {
  const server = new SMTPServer({
    banner: `${config.relayHostname} Email Security Relay`,
    authOptional: true,
    disabledCommands: ['AUTH'],
    logger: false,
    ...(tlsOptions ? { key: tlsOptions.key, cert: tlsOptions.cert, ...(tlsOptions.ca ? { ca: tlsOptions.ca } : {}) } : {}),

    onRcptTo(address: { address: string }, session: SMTPServerSession, callback: (err?: Error | null) => void) {
      const recipientDomain = address.address.split('@')[1];
      if (!recipientDomain) {
        const err = new Error('Invalid recipient address');
        (err as { responseCode?: number }).responseCode = 550;
        callback(err);
        return;
      }

      const domainRow = routingEngineService.resolveDestination(recipientDomain);
      if (!domainRow) {
        const err = new Error(`No such domain configured on this relay: ${recipientDomain}`);
        (err as { responseCode?: number }).responseCode = 550;
        callback(err);
        return;
      }
      if (domainRow.status !== 'ACTIVE') {
        const err = new Error(`Domain ${recipientDomain} is not yet active on this relay`);
        (err as { responseCode?: number }).responseCode = 550;
        callback(err);
        return;
      }

      const extSession = session as ExtendedSession;
      extSession.envelope = {
        ...extSession.envelope,
        _domainRow: domainRow,
      };
      callback();
    },

    onData(stream: Readable, session: SMTPServerSession, callback: (err?: Error | null) => void) {
      const startedAt = Date.now();
      const chunks: Buffer[] = [];
      const remoteIp = session.remoteAddress || '';
      const extSession = session as ExtendedSession;

      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('error', () => {
        console.error('[smtp] stream error');
        const err = new Error('Temporary error reading message');
        (err as { responseCode?: number }).responseCode = 451;
        callback(err);
      });

      stream.on('end', async () => {
        const rawBuffer = Buffer.concat(chunks);
        const recipient = (extSession.envelope.rcptTo?.[0]?.address) || 'unknown';
        const domainRow = extSession.envelope._domainRow
          || routingEngineService.resolveDestination(recipient.split('@')[1]) || undefined;
        const tenantId = domainRow ? domainRow.tenant_id : databaseService.seedDefaultTenant().id;
        const emailId = databaseService.uuid();

        let parsed;
        try {
          parsed = await simpleParser(rawBuffer);
        } catch {
          const err = new Error('Could not parse message');
          (err as { responseCode?: number }).responseCode = 451;
          callback(err);
          return;
        }

        const mailFrom = extSession.envelope.mailFrom;
        const mailFromAddress = mailFrom && typeof mailFrom === 'object' ? (mailFrom as SMTPServerAddress).address : '';
        const senderAddress = (parsed.from?.value?.[0]?.address) || mailFromAddress || '';
        const senderDomain = (senderAddress || '').split('@')[1] || '';
        const subject = parsed.subject || '';

        // 1. Loop prevention
        const loopCheck = loopPreventionService.detectLoop(parsed.headers as Map<string, unknown>);
        if (loopCheck.isLoop) {
          logEmail({
            id: emailId,
            tenant_id: tenantId,
            domain: domainRow ? domainRow.name : recipient.split('@')[1],
            sender: senderAddress,
            recipient,
            subject,
            remote_ip: remoteIp,
            spam_score: 0,
            decision: 'REJECTED',
            status: 'REJECTED',
            relay_id: config.relayId,
            reason: loopCheck.reason,
            headers_json: null,
            size_bytes: rawBuffer.length,
            eml_path: null,
            received_at: new Date(startedAt).toISOString(),
            processed_at: new Date().toISOString(),
          });
          const loopErr = new Error(`Mail loop detected: ${loopCheck.reason}`);
          (loopErr as { responseCode?: number }).responseCode = 554;
          callback(loopErr);
          return;
        }

        // 2. Spam scoring
        const { score, reasons } = spamFilterService.scoreEmail({
          tenantId,
          remoteIp,
          senderDomain,
          senderAddress,
          subject,
          hasAttachments: (parsed.attachments || []).length > 0,
        });

        const processingMs = Date.now() - startedAt;
        const relaySignature = loopPreventionService.signRelayId(config.relayId, config.relaySecret);
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
          headers_json: JSON.stringify(Object.fromEntries(parsed.headers as Map<string, unknown>)),
          size_bytes: rawBuffer.length,
          received_at: new Date(startedAt).toISOString(),
          processed_at: new Date().toISOString(),
        };

        // 3. Decision
        if (score >= config.rejectThreshold) {
          logEmail({ ...baseRecord, decision: 'REJECTED' as EmailDecision, status: 'REJECTED' as EmailStatus, reason: reasons.join('; '), eml_path: null });
          const spamErr = new Error('Message rejected as spam/phishing');
          (spamErr as { responseCode?: number }).responseCode = 554;
          callback(spamErr);
          return;
        }

        if (score >= config.quarantineThreshold) {
          const emlPath = quarantineService.storeRaw(emailId, stampedRaw);
          logEmail({ ...baseRecord, decision: 'QUARANTINED' as EmailDecision, status: 'QUARANTINED' as EmailStatus, reason: reasons.join('; '), eml_path: emlPath });
          callback();
          return;
        }

        // 4. Forward
        if (!domainRow || !domainRow.destination_mx) {
          logEmail({ ...baseRecord, decision: 'REJECTED' as EmailDecision, status: 'REJECTED' as EmailStatus, reason: 'no destination configured', eml_path: null });
          const destErr = new Error('No destination configured for this domain');
          (destErr as { responseCode?: number }).responseCode = 451;
          callback(destErr);
          return;
        }

        try {
          await forwarderService.forward({
            destinationHost: domainRow.destination_mx,
            from: mailFromAddress,
            to: (extSession.envelope.rcptTo || []).map((r) => r.address),
            rawMessage: stampedRaw,
          });
          logEmail({ ...baseRecord, decision: 'FORWARDED' as EmailDecision, status: 'FORWARDED' as EmailStatus, reason: reasons.join('; ') || null, eml_path: null });
          callback();
        } catch (err) {
          logEmail({ ...baseRecord, decision: 'REJECTED' as EmailDecision, status: 'REJECTED' as EmailStatus, reason: `forwarding failed: ${(err as Error).message}`, eml_path: null });
          const fwdErr = new Error('Temporary failure forwarding message');
          (fwdErr as { responseCode?: number }).responseCode = 451;
          callback(fwdErr);
        }
      });
    },
  });

  return server;
}

export { buildServer };
