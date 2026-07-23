import crypto from 'crypto';

const ALGORITHM = 'sha256';

export function hashApiKey(key: string): string {
  return crypto.createHash(ALGORITHM).update(key).digest('hex');
}

export function verifyApiKey(plaintext: string, storedHash: string): boolean {
  const computed = hashApiKey(plaintext);
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(storedHash));
}
