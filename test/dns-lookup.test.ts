import { describe, it } from 'node:test';
import assert from 'node:assert';
import dnsLookupService from '../dist/services/DnsLookupService';

describe('DnsLookupService', () => {
  describe('detectProvider', () => {
    it('should detect Microsoft365', () => {
      const result = dnsLookupService.detectProvider('contoso.mail.protection.outlook.com');
      assert.equal(result, 'Microsoft365');
    });

    it('should detect GoogleWorkspace', () => {
      assert.equal(dnsLookupService.detectProvider('aspmx.l.google.com'), 'GoogleWorkspace');
      assert.equal(dnsLookupService.detectProvider('alt1.aspmx.l.google.com'), 'GoogleWorkspace');
    });

    it('should detect ProtonMail', () => {
      const result = dnsLookupService.detectProvider('mail.protonmail.ch');
      assert.equal(result, 'ProtonMail');
    });

    it('should detect OVH', () => {
      assert.equal(dnsLookupService.detectProvider('smtp.mx.ovh.net'), 'OVH');
      assert.equal(dnsLookupService.detectProvider('smtp.mail.ovh.com'), 'OVH');
    });

    it('should return Unknown/Custom SMTP for unknown providers', () => {
      const result = dnsLookupService.detectProvider('mx.custom-company.com');
      assert.equal(result, 'Unknown/Custom SMTP');
    });
  });

  describe('lookupDomainMx', () => {
    it('should resolve MX for google.com', async () => {
      const result = await dnsLookupService.lookupDomainMx('google.com');
      assert.ok(result);
      assert.ok(result.mxHost);
      assert.ok(result.allRecords.length > 0);
      assert.equal(typeof result.priority, 'number');
    });

    it('should return null for non-existent domain', async () => {
      const result = await dnsLookupService.lookupDomainMx('thisshouldnotexist12345.com');
      assert.strictEqual(result, null);
    });

    it('should sort records by priority', async () => {
      const result = await dnsLookupService.lookupDomainMx('google.com');
      if (result && result.allRecords.length > 1) {
        for (let i = 1; i < result.allRecords.length; i++) {
          assert.ok(result.allRecords[i].priority >= result.allRecords[i - 1].priority);
        }
      }
    });
  });
});
