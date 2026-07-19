import fs from 'fs';
import path from 'path';
import forge from 'node-forge';

const pki = forge.pki;

function generateSelfSignedCert(domain: string): { key: Buffer; cert: Buffer } {
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  cert.setSubject([{ name: 'commonName', value: domain }]);
  cert.setIssuer([{ name: 'commonName', value: domain }]);
  cert.sign(keys.privateKey);
  return {
    key: Buffer.from(pki.privateKeyToPem(keys.privateKey)),
    cert: Buffer.from(pki.certificateToPem(cert)),
  };
}

export interface CertFiles {
  key: Buffer;
  cert: Buffer;
}

export type CertChangeCallback = (cert: CertFiles) => void;

export class CertManager {
  private selfSignedKeyPath: string;
  private selfSignedCertPath: string;
  private certbotKeyPath: string;
  private certbotCertPath: string;
  private cert: CertFiles | null = null;
  private domain: string;
  private onChange: CertChangeCallback | null = null;
  private watcher: fs.FSWatcher | null = null;
  private watching = false;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private usingCertbot = false;

  constructor(selfSignedDir: string, domain: string) {
    this.selfSignedKeyPath = path.join(selfSignedDir, 'relay-key.pem');
    this.selfSignedCertPath = path.join(selfSignedDir, 'relay.pem');
    this.certbotKeyPath = `/etc/letsencrypt/live/${domain}/privkey.pem`;
    this.certbotCertPath = `/etc/letsencrypt/live/${domain}/fullchain.pem`;
    this.domain = domain;
  }

  init(): CertFiles | undefined {
    if (fs.existsSync(this.certbotKeyPath) && fs.existsSync(this.certbotCertPath)) {
      this.loadCertbotCerts();
      console.log(`[tls] Using certbot LE cert for ${this.domain}`);
    } else if (fs.existsSync(this.selfSignedKeyPath) && fs.existsSync(this.selfSignedCertPath)) {
      this.loadSelfSignedCerts();
      console.log(`[tls] Using existing self-signed cert for ${this.domain}`);
    } else {
      this.generateSelfSigned();
      console.log(`[tls] Generated self-signed cert for ${this.domain}`);
    }

    if (!this.usingCertbot) {
      this.startPollingForCertbot();
    }

    return this.cert ?? undefined;
  }

  private loadCertbotCerts(): void {
    this.cert = {
      key: fs.readFileSync(this.certbotKeyPath),
      cert: fs.readFileSync(this.certbotCertPath),
    };
    this.usingCertbot = true;
  }

  private loadSelfSignedCerts(): void {
    this.cert = {
      key: fs.readFileSync(this.selfSignedKeyPath),
      cert: fs.readFileSync(this.selfSignedCertPath),
    };
  }

  private generateSelfSigned(): void {
    const dir = path.dirname(this.selfSignedKeyPath);
    fs.mkdirSync(dir, { recursive: true });
    const generated = generateSelfSignedCert(this.domain);
    fs.writeFileSync(this.selfSignedKeyPath, generated.key, { mode: 0o600 });
    fs.writeFileSync(this.selfSignedCertPath, generated.cert);
    this.cert = generated;
  }

  private startPollingForCertbot(): void {
    this.pollTimer = setInterval(() => {
      if (fs.existsSync(this.certbotKeyPath) && fs.existsSync(this.certbotCertPath)) {
        this.loadCertbotCerts();
        console.log(`[tls] Certbot cert now available for ${this.domain} – switching from self-signed`);
        if (this.pollTimer) {
          clearInterval(this.pollTimer);
          this.pollTimer = null;
        }
        if (this.onChange) {
          this.onChange(this.cert!);
        }
      }
    }, 30_000);
  }

  getServerOptions(): CertFiles | undefined {
    return this.cert ?? undefined;
  }

  watchForRenewal(callback: CertChangeCallback): void {
    this.onChange = callback;
    if (this.watching) return;
    const certbotDir = path.dirname(this.certbotKeyPath);
    if (!fs.existsSync(certbotDir)) {
      console.log(`[tls] Certbot dir not found (${certbotDir}), not watching for renewal`);
      return;
    }
    this.watching = true;
    try {
      this.watcher = fs.watch(certbotDir, (event, filename) => {
        if (filename === 'fullchain.pem' || filename === 'privkey.pem') {
          this.reloadFromCertbot();
        }
      });
      console.log(`[tls] Watching ${certbotDir} for cert renewal`);
    } catch (err) {
      console.error(`[tls] Failed to watch certbot dir: ${(err as Error).message}`);
    }
  }

  stopWatching(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    this.watching = false;
  }

  dispose(): void {
    this.stopWatching();
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private reloadFromCertbot(): void {
    try {
      if (!fs.existsSync(this.certbotKeyPath) || !fs.existsSync(this.certbotCertPath)) return;
      this.cert = {
        key: fs.readFileSync(this.certbotKeyPath),
        cert: fs.readFileSync(this.certbotCertPath),
      };
      console.log(`[tls] Reloaded LE cert from certbot for ${this.domain}`);
      if (this.onChange) {
        this.onChange(this.cert);
      }
    } catch (err) {
      console.error(`[tls] Failed to reload certbot cert: ${(err as Error).message}`);
    }
  }
}
