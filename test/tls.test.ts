import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs';
import { CertManager } from '../dist/tls/CertManager';

const TEST_DIR = path.join(__dirname, '..', 'data', 'test-tls-' + process.pid);
const TEST_DOMAIN = 'test.example.com';

describe('CertManager', () => {
  after(() => {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('should generate a self-signed cert when none exists', () => {
    const mgr = new CertManager(TEST_DIR, TEST_DOMAIN);
    mgr.init();
    const opts = mgr.getServerOptions();
    assert.ok(opts);
    assert.ok(opts!.key.length > 0, 'key should not be empty');
    assert.ok(opts!.cert.length > 0, 'cert should not be empty');
    assert.ok(opts!.key.toString().includes('-----BEGIN RSA PRIVATE KEY-----'));
    assert.ok(opts!.cert.toString().includes('-----BEGIN CERTIFICATE-----'));
    mgr.dispose();
  });

  it('should persist and reload cert', () => {
    const mgr1 = new CertManager(TEST_DIR, TEST_DOMAIN);
    mgr1.init();
    const opts1 = mgr1.getServerOptions()!;
    mgr1.dispose();

    const mgr2 = new CertManager(TEST_DIR, TEST_DOMAIN);
    mgr2.init();
    const opts2 = mgr2.getServerOptions()!;
    mgr2.dispose();

    assert.equal(opts1.key.toString(), opts2.key.toString());
    assert.equal(opts1.cert.toString(), opts2.cert.toString());
  });

  it('should return undefined for getServerOptions before init', () => {
    const mgr = new CertManager(TEST_DIR, TEST_DOMAIN);
    assert.strictEqual(mgr.getServerOptions(), undefined);
    mgr.dispose();
  });
});

describe('CertManager — different domains', () => {
  const dirA = path.join(TEST_DIR, 'domain-a');
  const dirB = path.join(TEST_DIR, 'domain-b');

  after(() => {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('should generate different certs for different domains', () => {
    const mgrA = new CertManager(dirA, 'domain-a.example.com');
    mgrA.init();
    const optsA = mgrA.getServerOptions()!;
    mgrA.dispose();

    const mgrB = new CertManager(dirB, 'domain-b.example.com');
    mgrB.init();
    const optsB = mgrB.getServerOptions()!;
    mgrB.dispose();

    assert.notEqual(optsA.cert.toString(), optsB.cert.toString());
  });
});

function generateSelfSignedCert(domain: string) {
  const forge = require('node-forge');
  const pki = forge.pki;
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 365 * 86_400_000);
  cert.setSubject([{ name: 'commonName', value: domain }]);
  cert.setIssuer([{ name: 'commonName', value: domain }]);
  cert.sign(keys.privateKey);
  return {
    key: pki.privateKeyToPem(keys.privateKey),
    cert: pki.certificateToPem(cert),
  };
}

describe('smtp-gateway — buildServer with TLS options', () => {
  const tlsOpts = generateSelfSignedCert('test.smtp.local');
  const key = Buffer.from(tlsOpts.key);
  const cert = Buffer.from(tlsOpts.cert);

  it('should build server without TLS options', () => {
    const { buildServer } = require('../dist/smtp-gateway');
    const server = buildServer();
    assert.ok(server);
    assert.equal(typeof server.listen, 'function');
    server.close();
  });

  it('should build server with TLS options', () => {
    const { buildServer } = require('../dist/smtp-gateway');
    const server = buildServer({ key, cert });
    assert.ok(server);
    assert.equal(typeof server.listen, 'function');
    server.close();
  });

  it('should build server with full TLS options including ca', () => {
    const { buildServer } = require('../dist/smtp-gateway');
    const server = buildServer({ key, cert, ca: cert });
    assert.ok(server);
    server.close();
  });
});
