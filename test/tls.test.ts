import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs';
import { CertStore } from '../dist/tls/CertStore';

const TEST_STORAGE = path.join(__dirname, '..', 'data', 'test-tls-' + process.pid);
const TEST_DOMAIN = 'test.example.com';

describe('CertStore', () => {
  before(() => {
    fs.mkdirSync(TEST_STORAGE, { recursive: true });
  });

  after(() => {
    fs.rmSync(TEST_STORAGE, { recursive: true, force: true });
  });

  it('should return false for hasCert when no cert exists', () => {
    assert.equal(CertStore.hasCert(TEST_DOMAIN, TEST_STORAGE), false);
  });

  it('should save and load cert files', () => {
    CertStore.save(TEST_DOMAIN, TEST_STORAGE, {
      key: Buffer.from('test-key-data'),
      cert: Buffer.from('test-cert-data'),
    });
    assert.ok(CertStore.hasCert(TEST_DOMAIN, TEST_STORAGE));

    const loaded = CertStore.load(TEST_DOMAIN, TEST_STORAGE);
    assert.ok(loaded);
    assert.equal(loaded!.key.toString(), 'test-key-data');
    assert.equal(loaded!.cert.toString(), 'test-cert-data');
  });

  it('should return null when loading non-existent cert', () => {
    const loaded = CertStore.load('nonexistent.com', TEST_STORAGE);
    assert.strictEqual(loaded, null);
  });

  it('should save cert with ca', () => {
    CertStore.save(TEST_DOMAIN, TEST_STORAGE, {
      key: Buffer.from('key'),
      cert: Buffer.from('cert'),
      ca: Buffer.from('ca-data'),
    });
    const loaded = CertStore.load(TEST_DOMAIN, TEST_STORAGE);
    assert.ok(loaded);
    assert.equal(loaded!.ca?.toString(), 'ca-data');
  });

  it('should manage account key lifecycle', () => {
    assert.equal(CertStore.hasAccountKey(TEST_STORAGE), false);
    CertStore.saveAccountKey(TEST_STORAGE, Buffer.from('account-key-data'));
    assert.equal(CertStore.hasAccountKey(TEST_STORAGE), true);
    const loaded = CertStore.loadAccountKey(TEST_STORAGE);
    assert.equal(loaded.toString(), 'account-key-data');
  });

  it('should return null for daysUntilExpiry when no cert', () => {
    const days = CertStore.daysUntilExpiry('nonexistent.com', TEST_STORAGE);
    assert.strictEqual(days, null);
  });

  it('should calculate correct days until expiry', () => {
    const pki = require('node-forge').pki;
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '02';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 30 * 86_400_000);
    cert.setSubject([{ name: 'commonName', value: TEST_DOMAIN }]);
    cert.setIssuer([{ name: 'commonName', value: TEST_DOMAIN }]);
    cert.sign(keys.privateKey);
    const pem = pki.certificateToPem(cert);

    CertStore.save(TEST_DOMAIN, TEST_STORAGE, {
      key: Buffer.from('dummy-key'),
      cert: Buffer.from(pem),
    });

    const days = CertStore.daysUntilExpiry(TEST_DOMAIN, TEST_STORAGE);
    assert.ok(days !== null);
    assert.ok(days >= 28 && days <= 31, `Expected ~30 days, got ${days}`);
  });
});

function generateSelfSignedCert(domain: string) {
  const pki = require('node-forge').pki;
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
