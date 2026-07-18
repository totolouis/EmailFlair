const crypto = require('crypto');
const config = require('./config');

const MAX_HOPS = 25; // generous ceiling before we assume something is wrong

function signRelayId(relayId, secret) {
  return crypto.createHmac('sha256', secret).update(relayId).digest('hex');
}

function verifySignature(relayId, signature, secret) {
  const expected = signRelayId(relayId, secret);
  // constant-time comparison
  const a = Buffer.from(expected);
  const b = Buffer.from(signature || '');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Inspect parsed message headers for signs this message already passed through
 * this relay (or a suspicious number of hops), per PRD 6.4.
 *
 * @param {Map|Object} headers - mailparser `headers` Map
 * @returns {{ isLoop: boolean, reason: string|null }}
 */
function detectLoop(headers) {
  // 1. Signed header check — did WE already stamp this message?
  const existingRelayId = headers.get ? headers.get('x-relay-id') : headers['x-relay-id'];
  const existingSignature = headers.get ? headers.get('x-relay-signature') : headers['x-relay-signature'];

  if (existingRelayId) {
    const relayIds = Array.isArray(existingRelayId) ? existingRelayId : [existingRelayId];
    for (const rid of relayIds) {
      if (rid === config.relayId && verifySignature(rid, existingSignature, config.relaySecret)) {
        return { isLoop: true, reason: `Message already carries a valid X-Relay-ID for ${config.relayId}` };
      }
    }
  }

  // 2. Hop count check via Received headers
  const received = headers.get ? headers.get('received') : headers['received'];
  if (received) {
    const hops = Array.isArray(received) ? received.length : 1;
    if (hops > MAX_HOPS) {
      return { isLoop: true, reason: `Excessive hop count (${hops} Received headers)` };
    }
  }

  return { isLoop: false, reason: null };
}

module.exports = { signRelayId, verifySignature, detectLoop, MAX_HOPS };
