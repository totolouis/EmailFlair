import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import fs from 'fs';

const TEST_DIR = path.join(__dirname, '..', 'data', 'test-quarantine-' + process.pid);

import quarantineService from '../dist/services/QuarantineService';
import config from '../dist/config';

describe('quarantine', () => {
  before(() => {
    fs.mkdirSync(TEST_DIR, { recursive: true });
    config.quarantineDir = TEST_DIR;
  });

  after(() => {
    fs.rmSync(TEST_DIR, { recursive: true, force: true });
  });

  describe('storeRaw', () => {
    it('should store a raw email and return the file path', () => {
      const emailId = 'test-email-001';
      const content = Buffer.from('Subject: Test\r\n\r\nBody');
      const filePath = quarantineService.storeRaw(emailId, content);
      assert.ok(filePath.endsWith(`${emailId}.eml`));
      assert.ok(fs.existsSync(filePath));
      assert.equal(fs.readFileSync(filePath).toString(), 'Subject: Test\r\n\r\nBody');
    });

    it('should handle binary content', () => {
      const emailId = 'test-binary';
      const content = Buffer.from([0x00, 0x01, 0x02, 0xFF]);
      const filePath = quarantineService.storeRaw(emailId, content);
      const read = fs.readFileSync(filePath);
      assert.deepEqual(read, content);
    });

    it('should generate unique paths for different IDs', () => {
      const p1 = quarantineService.storeRaw('unique-1', Buffer.from('a'));
      const p2 = quarantineService.storeRaw('unique-2', Buffer.from('b'));
      assert.notEqual(p1, p2);
    });
  });

  describe('readRaw', () => {
    it('should read a stored email', () => {
      const emailId = 'test-read';
      const content = Buffer.from('Subject: Read Test\r\n\r\nContent');
      quarantineService.storeRaw(emailId, content);
      const filePath = path.join(config.quarantineDir, `${emailId}.eml`);
      const read = quarantineService.readRaw(filePath);
      assert.deepEqual(read, content);
    });

    it('should return null for missing file', () => {
      const result = quarantineService.readRaw(path.join(config.quarantineDir, 'nonexistent.eml'));
      assert.strictEqual(result, null);
    });
  });

  describe('deleteRaw', () => {
    it('should delete a stored file', () => {
      const emailId = 'test-delete';
      const content = Buffer.from('To be deleted');
      const filePath = quarantineService.storeRaw(emailId, content);
      assert.ok(fs.existsSync(filePath));
      quarantineService.deleteRaw(filePath);
      assert.ok(!fs.existsSync(filePath));
    });

    it('should not throw when deleting nonexistent path', () => {
      quarantineService.deleteRaw(path.join(config.quarantineDir, 'nonexistent.eml'));
    });

    it('should handle null path gracefully', () => {
      quarantineService.deleteRaw(null);
    });

    it('should handle undefined path gracefully', () => {
      quarantineService.deleteRaw(undefined);
    });
  });
});
