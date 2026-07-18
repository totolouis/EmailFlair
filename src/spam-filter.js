const { db } = require('./db');

// Very small, deterministic MVP heuristic scoring engine.
// V2 (per PRD roadmap) replaces/augments this with Rspamd + ClamAV + URL reputation.

const SUSPICIOUS_SUBJECT_WORDS = [
  'urgent', 'wire transfer', 'gift card', 'password expired', 'verify your account',
  'invoice overdue', 'crypto', 'act now', 'bitcoin', 'unusual sign-in',
];

function isListed(tenantId, table, type, value) {
  if (!value) return false;
  const row = db
    .prepare(`SELECT 1 FROM ${table} WHERE tenant_id = ? AND type = ? AND lower(value) = lower(?) LIMIT 1`)
    .get(tenantId, type, value);
  return !!row;
}

/**
 * Score an inbound message. Returns { score, reasons: string[] }.
 * Higher score = more likely spam/phishing. Whitelisted senders short-circuit to 0.
 */
function scoreEmail({ tenantId, remoteIp, senderDomain, senderAddress, subject = '', hasAttachments = false }) {
  const reasons = [];

  // Whitelist short-circuits everything
  if (isListed(tenantId, 'whitelist', 'ip', remoteIp) || isListed(tenantId, 'whitelist', 'domain', senderDomain)) {
    return { score: 0, reasons: ['sender is whitelisted'] };
  }

  let score = 0;

  if (isListed(tenantId, 'blacklist', 'ip', remoteIp)) {
    score += 10;
    reasons.push(`sending IP ${remoteIp} is blacklisted`);
  }

  if (isListed(tenantId, 'blacklist', 'domain', senderDomain)) {
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
    score += 0.5; // small nudge; real scanning happens in attachment scanner (V2)
    reasons.push('message has attachments (flagged for informational scoring)');
  }

  return { score, reasons };
}

module.exports = { scoreEmail };
