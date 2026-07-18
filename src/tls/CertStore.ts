import fs from 'fs';
import path from 'path';

export interface CertFiles {
  key: Buffer;
  cert: Buffer;
  ca?: Buffer;
}

function certDir(domain: string, storage: string): string {
  return path.join(storage, domain.replace(/[^a-z0-9.-]/gi, '_'));
}

function accountKeyPath(storage: string): string {
  return path.join(storage, 'account-key.pem');
}

function privkeyPath(domain: string, storage: string): string {
  return path.join(certDir(domain, storage), 'privkey.pem');
}

function fullchainPath(domain: string, storage: string): string {
  return path.join(certDir(domain, storage), 'fullchain.pem');
}

function parseNotAfterFromPem(pem: string): Date | null {
  try {
    const pki = require('node-forge').pki;
    const cert = pki.certificateFromPem(pem);
    return cert.validity.notAfter;
  } catch {
    return null;
  }
}

export class CertStore {
  static hasCert(domain: string, storage: string): boolean {
    return fs.existsSync(privkeyPath(domain, storage))
      && fs.existsSync(fullchainPath(domain, storage));
  }

  static load(domain: string, storage: string): CertFiles | null {
    const keyPath = privkeyPath(domain, storage);
    const certPath = fullchainPath(domain, storage);
    if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) return null;
    const caPath = path.join(certDir(domain, storage), 'chain.pem');
    return {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
      ...(fs.existsSync(caPath) ? { ca: fs.readFileSync(caPath) } : {}),
    };
  }

  static save(domain: string, storage: string, files: CertFiles): void {
    const dir = certDir(domain, storage);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(privkeyPath(domain, storage), files.key, { mode: 0o600 });
    fs.writeFileSync(fullchainPath(domain, storage), files.cert);
    if (files.ca) {
      fs.writeFileSync(path.join(dir, 'chain.pem'), files.ca);
    }
  }

  static hasAccountKey(storage: string): boolean {
    return fs.existsSync(accountKeyPath(storage));
  }

  static loadAccountKey(storage: string): Buffer {
    return fs.readFileSync(accountKeyPath(storage));
  }

  static saveAccountKey(storage: string, key: Buffer): void {
    fs.mkdirSync(storage, { recursive: true });
    fs.writeFileSync(accountKeyPath(storage), key, { mode: 0o600 });
  }

  static daysUntilExpiry(domain: string, storage: string): number | null {
    if (!CertStore.hasCert(domain, storage)) return null;
    const certPem = fs.readFileSync(fullchainPath(domain, storage), 'utf8');
    const notAfter = parseNotAfterFromPem(certPem);
    if (!notAfter) return null;
    const diff = notAfter.getTime() - Date.now();
    return Math.max(0, Math.floor(diff / 86_400_000));
  }
}
