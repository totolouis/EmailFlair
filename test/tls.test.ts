import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('smtp-gateway — buildServer', () => {
  it('should build server without TLS options', () => {
    const { buildServer } = require('../dist/smtp-gateway');
    const server = buildServer();
    assert.ok(server);
    assert.equal(typeof server.listen, 'function');
    server.close();
  });
});
