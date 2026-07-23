import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { enhancedSpamFilterService } from '../dist/services/EnhancedSpamFilterService';
import databaseService from '../dist/services/DatabaseService';
import { hashApiKey } from './helpers';

describe('enhanced spam filter', () => {
  let tenantId: string;

  before(() => {
    databaseService.init(':memory:');
    const db = databaseService.getDb();
    tenantId = databaseService.uuid();
    db.prepare('INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(tenantId, 'Test', hashApiKey('test-key'), new Date().toISOString());
  });

  after(() => {
    databaseService.close();
  });

  describe('SPF checks', () => {
    it('should score higher for domain with no SPF record', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '1.2.3.4',
        senderDomain: 'no-spf-domain-xyz-999.com',
        senderAddress: 'user@no-spf-domain-xyz-999.com',
        subject: 'test',
        hasAttachments: false,
      });
      const spfReason = result.reasons.find((r) => r.includes('SPF'));
      assert.ok(spfReason, `Should include SPF reason, got: ${JSON.stringify(result.reasons)}`);
      assert.ok(result.score > 0);
    });

    it('should not penalize whitelisted senders even with bad SPF', async () => {
      const db = databaseService.getDb();
      db.prepare('INSERT INTO whitelist (id, tenant_id, type, value, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(databaseService.uuid(), tenantId, 'ip', '1.2.3.4', new Date().toISOString());

      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '1.2.3.4',
        senderDomain: 'no-spf-domain-xyz-999.com',
        senderAddress: 'user@no-spf-domain-xyz-999.com',
        subject: 'urgent wire transfer',
        hasAttachments: false,
      });
      assert.equal(result.score, 0);
      assert.ok(result.reasons.includes('sender is whitelisted'));
    });
  });

  describe('PTR (reverse DNS) checks', () => {
    it('should score for missing PTR when IP has no reverse DNS', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '192.0.2.1',
        senderDomain: 'example.com',
        senderAddress: 'user@example.com',
        subject: 'hello',
        hasAttachments: false,
      });
      const ptrReason = result.reasons.find((r) => r.includes('reverse DNS'));
      assert.ok(ptrReason, `Should include PTR reason, got: ${JSON.stringify(result.reasons)}`);
    });
  });

  describe('header analysis', () => {
    it('should score for missing Message-ID', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        headers: {},
      });
      const headerReason = result.reasons.find((r) => r.includes('Message-ID'));
      assert.ok(headerReason, `Should include Message-ID reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for Reply-To mismatch', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'legit.com',
        senderAddress: 'user@legit.com',
        subject: 'test',
        hasAttachments: false,
        headers: {
          'from': '"Boss" <user@legit.com>',
          'reply-to': '"Hacker" <hacker@evil.com>',
          'message-id': '<abc@legit.com>',
          'date': 'Mon, 1 Jan 2024 00:00:00 +0000',
          'received': 'from mx.test.com',
        },
      });
      const replyReason = result.reasons.find((r) => r.includes('Reply-To'));
      assert.ok(replyReason, `Should include Reply-To reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for Return-Path mismatch', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'legit.com',
        senderAddress: 'user@legit.com',
        subject: 'test',
        hasAttachments: false,
        headers: {
          'from': '"User" <user@legit.com>',
          'return-path': '<user@evil.com>',
          'message-id': '<abc@legit.com>',
          'date': 'Mon, 1 Jan 2024 00:00:00 +0000',
          'received': 'from mx.test.com',
        },
      });
      const rpReason = result.reasons.find((r) => r.includes('Return-Path'));
      assert.ok(rpReason, `Should include Return-Path reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for missing Date header', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        headers: {
          'message-id': '<abc@test.com>',
          'received': 'from mx.test.com',
        },
      });
      const dateReason = result.reasons.find((r) => r.includes('Date'));
      assert.ok(dateReason, `Should include Date reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for suspicious X-Mailer', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        headers: {
          'message-id': '<abc@test.com>',
          'date': 'Mon, 1 Jan 2024',
          'received': 'from mx.test.com',
          'x-mailer': 'PHPMailer',
        },
      });
      const mailerReason = result.reasons.find((r) => r.includes('X-Mailer'));
      assert.ok(mailerReason, `Should include X-Mailer reason, got: ${JSON.stringify(result.reasons)}`);
    });
  });

  describe('URL analysis', () => {
    it('should score for IP-based URLs', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyHtml: '<a href="http://192.168.1.1/evil">click</a>',
      });
      const urlReason = result.reasons.find((r) => r.includes('IP address'));
      assert.ok(urlReason, `Should include IP URL reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for suspicious TLD URLs', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyText: 'visit http://evil.xyz/free-money',
      });
      const tldReason = result.reasons.find((r) => r.includes('suspicious TLD'));
      assert.ok(tldReason, `Should include suspicious TLD reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for URL shorteners', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyText: 'click here http://bit.ly/abc123',
      });
      const shortReason = result.reasons.find((r) => r.includes('shortener'));
      assert.ok(shortReason, `Should include shortener reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for javascript: URLs', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyHtml: '<a href="javascript:alert(1)">click</a>',
      });
      const jsReason = result.reasons.find((r) => r.includes('javascript:'));
      assert.ok(jsReason, `Should include javascript reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for login-page mimic URLs', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyHtml: '<a href="https://secure-login.evil.com/verify">click</a>',
      });
      const mimicReason = result.reasons.find((r) => r.includes('login/verify'));
      assert.ok(mimicReason, `Should include login/verify reason, got: ${JSON.stringify(result.reasons)}`);
    });
  });

  describe('attachment analysis', () => {
    it('should score for dangerous extensions', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: true,
        attachmentNames: ['invoice.exe'],
      });
      const extReason = result.reasons.find((r) => r.includes('dangerous'));
      assert.ok(extReason, `Should include dangerous attachment reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for double-extension attachments', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: true,
        attachmentNames: ['document.pdf.exe'],
      });
      const dblReason = result.reasons.find((r) => r.includes('double-extension'));
      assert.ok(dblReason, `Should include double-extension reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for many archive attachments', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: true,
        attachmentNames: ['a.zip', 'b.rar', 'c.7z'],
      });
      const archiveReason = result.reasons.find((r) => r.includes('archive'));
      assert.ok(archiveReason, `Should include archive reason, got: ${JSON.stringify(result.reasons)}`);
    });
  });

  describe('content analysis', () => {
    it('should score for iframes in HTML', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyHtml: '<iframe src="http://evil.com/phish"></iframe>',
      });
      const iframeReason = result.reasons.find((r) => r.includes('iframe'));
      assert.ok(iframeReason, `Should include iframe reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for forms in HTML', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyHtml: '<form action="http://evil.com/steal"><input name="password"></form>',
      });
      const formReason = result.reasons.find((r) => r.includes('form'));
      assert.ok(formReason, `Should include form reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for hidden text', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyHtml: '<span style="color: white">hidden1</span><span style="color: #fff">hidden2</span><span style="color: transparent">hidden3</span>',
      });
      const hiddenReason = result.reasons.find((r) => r.includes('hidden text'));
      assert.ok(hiddenReason, `Should include hidden text reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for excessive uppercase', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyText: 'THIS IS AN EXTREMELY URGENT MESSAGE ABOUT YOUR ACCOUNT THAT REQUIRES IMMEDIATE ATTENTION RIGHT NOW',
      });
      const upperReason = result.reasons.find((r) => r.includes('uppercase'));
      assert.ok(upperReason, `Should include uppercase reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should score for 419 scam patterns', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
        bodyText: 'Dear Sir, You have been selected as the next of kin for an inheritance of 5 million dollars. Please provide your bank account for transfer.',
      });
      const scamReason = result.reasons.find((r) => r.includes('419') || r.includes('advance-fee'));
      assert.ok(scamReason, `Should include 419 scam reason, got: ${JSON.stringify(result.reasons)}`);
    });

    it('should not score normal content', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '127.0.0.1',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'meeting tomorrow',
        hasAttachments: false,
        headers: {
          'from': 'user@test.com',
          'message-id': '<abc@test.com>',
          'date': 'Mon, 1 Jan 2024 00:00:00 +0000',
          'received': 'from mx.test.com',
        },
        bodyText: 'Hi, just wanted to confirm our meeting tomorrow at 3pm. Let me know if that works.',
      });
      const contentReasons = result.reasons.filter((r) =>
        !r.includes('SPF') && !r.includes('DMARC') && !r.includes('DNSBL') && !r.includes('reverse DNS'),
      );
      assert.equal(contentReasons.length, 0, `Normal content should not trigger reasons, got: ${JSON.stringify(contentReasons)}`);
    });
  });

  describe('DNSBL checks', () => {
    it('should not crash when remoteIp is null', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: null,
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
      });
      assert.ok(typeof result.score === 'number');
    });

    it('should not crash with empty IP', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '',
        senderDomain: 'test.com',
        senderAddress: 'user@test.com',
        subject: 'test',
        hasAttachments: false,
      });
      assert.ok(typeof result.score === 'number');
    });
  });

  describe('combined scoring', () => {
    it('should accumulate scores from multiple checks', async () => {
      const result = await enhancedSpamFilterService.scoreEmail({
        tenantId,
        remoteIp: '192.0.2.99',
        senderDomain: 'no-spf-domain-xyz-999.com',
        senderAddress: 'user@no-spf-domain-xyz-999.com',
        subject: 'urgent wire transfer',
        hasAttachments: true,
        headers: {},
        bodyHtml: '<a href="http://1.2.3.4/click">click</a><iframe src="http://evil.com"></iframe>',
        attachmentNames: ['virus.exe'],
      });
      assert.ok(result.score >= 10, `Combined score should be high, got: ${result.score}`);
      assert.ok(result.reasons.length >= 5, `Should have multiple reasons, got: ${result.reasons.length}`);
    });
  });
});
