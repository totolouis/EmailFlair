import databaseService from './DatabaseService';
import { ISpamScoreParams, ISpamScoreResult, ListType } from '../interfaces';

const SUSPICIOUS_SUBJECT_WORDS = [
  'urgent', 'wire transfer', 'gift card', 'password expired', 'verify your account',
  'invoice overdue', 'crypto', 'act now', 'bitcoin', 'unusual sign-in',
];

class SpamFilterService {
  private isListed(tenantId: string, table: string, type: ListType, value: string | null): boolean {
    if (!value) return false;
    const row = databaseService
      .getDb()
      .prepare(`SELECT 1 FROM ${table} WHERE tenant_id = ? AND type = ? AND lower(value) = lower(?) LIMIT 1`)
      .get(tenantId, type, value);
    return !!row;
  }

  scoreEmail(params: ISpamScoreParams): ISpamScoreResult {
    const { tenantId, remoteIp, senderDomain, senderAddress, subject, hasAttachments } = params;
    const reasons: string[] = [];

    if (
      this.isListed(tenantId, 'whitelist', 'ip', remoteIp) ||
      this.isListed(tenantId, 'whitelist', 'domain', senderDomain)
    ) {
      return { score: 0, reasons: ['sender is whitelisted'] };
    }

    let score = 0;

    if (this.isListed(tenantId, 'blacklist', 'ip', remoteIp)) {
      score += 10;
      reasons.push(`sending IP ${remoteIp} is blacklisted`);
    }

    if (this.isListed(tenantId, 'blacklist', 'domain', senderDomain)) {
      score += 10;
      reasons.push(`sender domain ${senderDomain} is blacklisted`);
    }

    const subjectLower = (subject || '').toLowerCase();
    const hits = SUSPICIOUS_SUBJECT_WORDS.filter((w) => subjectLower.includes(w));
    if (hits.length) {
      score += hits.length * 2;
      reasons.push(`suspicious subject keywords: ${hits.join(', ')}`);
    }

    if (!senderAddress || !senderAddress.includes('@')) {
      score += 3;
      reasons.push('malformed or missing sender address');
    }

    if (hasAttachments) {
      score += 0.5;
      reasons.push('message has attachments (flagged for informational scoring)');
    }

    return { score, reasons };
  }
}

const spamFilterService = new SpamFilterService();
export { spamFilterService, SpamFilterService };
export default spamFilterService;
