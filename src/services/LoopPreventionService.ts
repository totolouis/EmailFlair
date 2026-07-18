import crypto from 'crypto';
import config from '../config';
import { ILoopCheckResult } from '../interfaces';

class LoopPreventionService {
  readonly MAX_HOPS = 25;

  signRelayId(relayId: string, secret: string): string {
    return crypto.createHmac('sha256', secret).update(relayId).digest('hex');
  }

  verifySignature(relayId: string, signature: string, secret: string): boolean {
    const expected = this.signRelayId(relayId, secret);
    const a = Buffer.from(expected);
    const b = Buffer.from(signature || '');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  detectLoop(headers: Map<string, unknown> | Record<string, unknown>): ILoopCheckResult {
    const getHeader = (name: string): unknown => {
      if (typeof (headers as Map<string, unknown>).get === 'function') {
        return (headers as Map<string, unknown>).get(name);
      }
      return (headers as Record<string, unknown>)[name];
    };

    const existingRelayId = getHeader('x-relay-id') as string | string[] | undefined;
    const existingSignature = getHeader('x-relay-signature') as string | undefined;

    if (existingRelayId) {
      const relayIds = Array.isArray(existingRelayId) ? existingRelayId : [existingRelayId];
      for (const rid of relayIds) {
        if (
          rid === config.relayId &&
          existingSignature &&
          this.verifySignature(rid, existingSignature, config.relaySecret)
        ) {
          return {
            isLoop: true,
            reason: `Message already carries a valid X-Relay-ID for ${config.relayId}`,
          };
        }
      }
    }

    const received = getHeader('received') as string | string[] | undefined;
    if (received) {
      const hops = Array.isArray(received) ? received.length : 1;
      if (hops > this.MAX_HOPS) {
        return { isLoop: true, reason: `Excessive hop count (${hops} Received headers)` };
      }
    }

    return { isLoop: false, reason: null };
  }
}

const loopPreventionService = new LoopPreventionService();
export { loopPreventionService, LoopPreventionService };
export default loopPreventionService;
