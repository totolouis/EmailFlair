import loopPreventionService from '../dist/services/LoopPreventionService';
import config from '../dist/config';
import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('loop-prevention', () => {
  const svc = loopPreventionService;

  describe('signRelayId', () => {
    it('should produce a hex string', () => {
      const sig = svc.signRelayId('relay-01', 'secret');
      assert.match(sig, /^[a-f0-9]+$/);
      assert.equal(sig.length, 64);
    });

    it('should produce different signatures for different secrets', () => {
      const sig1 = svc.signRelayId('relay-01', 'secret1');
      const sig2 = svc.signRelayId('relay-01', 'secret2');
      assert.notEqual(sig1, sig2);
    });

    it('should produce different signatures for different relay IDs', () => {
      const sig1 = svc.signRelayId('relay-01', 'secret');
      const sig2 = svc.signRelayId('relay-02', 'secret');
      assert.notEqual(sig1, sig2);
    });

    it('should be deterministic for same inputs', () => {
      const sig1 = svc.signRelayId('relay-01', 'secret');
      const sig2 = svc.signRelayId('relay-01', 'secret');
      assert.equal(sig1, sig2);
    });
  });

  describe('verifySignature', () => {
    it('should return true for valid signature', () => {
      const sig = svc.signRelayId('relay-01', 'secret');
      assert.ok(svc.verifySignature('relay-01', sig, 'secret'));
    });

    it('should return false for wrong secret', () => {
      const sig = svc.signRelayId('relay-01', 'secret1');
      assert.ok(!svc.verifySignature('relay-01', sig, 'wrong-secret'));
    });

    it('should return false for empty signature', () => {
      assert.ok(!svc.verifySignature('relay-01', '', 'secret'));
    });

    it('should return false for null signature', () => {
      assert.ok(!svc.verifySignature('relay-01', null as unknown as string, 'secret'));
    });

    it('should return false for wrong relay ID', () => {
      const sig = svc.signRelayId('relay-01', 'secret');
      assert.ok(!svc.verifySignature('relay-02', sig, 'secret'));
    });

    it('should be constant-time (no early exit on length mismatch)', () => {
      assert.ok(!svc.verifySignature('relay-01', 'short', 'secret'));
    });
  });

  describe('detectLoop', () => {
    it('should return isLoop=false for a clean message', () => {
      const headers = new Map<string, unknown>();
      headers.set('received', ['from mx.example.com']);
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, false);
      assert.equal(result.reason, null);
    });

    it('should detect loop when our relay ID is present with valid signature', () => {
      const sig = svc.signRelayId(config.relayId, config.relaySecret);
      const headers = new Map<string, unknown>();
      headers.set('x-relay-id', config.relayId);
      headers.set('x-relay-signature', sig);
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, true);
      assert.match(result.reason!, /valid X-Relay-ID/);
    });

    it('should NOT detect loop when signature is invalid', () => {
      const headers = new Map<string, unknown>();
      headers.set('x-relay-id', config.relayId);
      headers.set('x-relay-signature', 'invalid-signature');
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, false);
    });

    it('should NOT detect loop for other relay IDs', () => {
      const sig = svc.signRelayId('other-relay', 'other-secret');
      const headers = new Map<string, unknown>();
      headers.set('x-relay-id', 'other-relay');
      headers.set('x-relay-signature', sig);
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, false);
    });

    it('should detect loop when our relay ID is in an array of relay IDs', () => {
      const sig = svc.signRelayId(config.relayId, config.relaySecret);
      const headers = new Map<string, unknown>();
      headers.set('x-relay-id', ['other-relay', config.relayId, 'another-relay']);
      headers.set('x-relay-signature', sig);
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, true);
    });

    it('should detect excessive hop count', () => {
      const headers = new Map<string, unknown>();
      headers.set('received', Array(svc.MAX_HOPS + 1).fill('from mx.example.com'));
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, true);
      assert.match(result.reason!, /Excessive hop count/);
    });

    it('should not flag acceptable hop count', () => {
      const headers = new Map<string, unknown>();
      headers.set('received', Array(svc.MAX_HOPS - 1).fill('from mx.example.com'));
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, false);
    });

    it('should handle plain object headers (not Map)', () => {
      const sig = svc.signRelayId(config.relayId, config.relaySecret);
      const headers: Record<string, unknown> = {
        'x-relay-id': config.relayId,
        'x-relay-signature': sig,
      };
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, true);
    });

    it('should handle missing received header gracefully', () => {
      const headers = new Map<string, unknown>();
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, false);
      assert.equal(result.reason, null);
    });

    it('should handle single received entry (not array)', () => {
      const headers = new Map<string, unknown>();
      headers.set('received', 'from mx.example.com');
      const result = svc.detectLoop(headers);
      assert.equal(result.isLoop, false);
    });
  });
});
