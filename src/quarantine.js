const fs = require('fs');
const path = require('path');
const config = require('./config');

/**
 * Persist the raw .eml to the quarantine directory and return its path.
 * Used both for QUARANTINED messages (kept for release/delete) and, optionally,
 * as an audit copy for REJECTED ones.
 */
function storeRaw(emailId, rawBuffer) {
  const filePath = path.join(config.quarantineDir, `${emailId}.eml`);
  fs.writeFileSync(filePath, rawBuffer);
  return filePath;
}

function readRaw(emlPath) {
  try {
    return fs.readFileSync(emlPath);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

function deleteRaw(emlPath) {
  if (emlPath && fs.existsSync(emlPath)) {
    try {
      fs.unlinkSync(emlPath);
    } catch (err) {
      console.error('[quarantine] error deleting file:', err.message);
    }
  }
}

module.exports = { storeRaw, readRaw, deleteRaw };
