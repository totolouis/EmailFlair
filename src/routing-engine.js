const { getDb } = require('./db');

/**
 * Look up the destination mail server for a given recipient domain.
 * The destination is the ORIGINAL provider MX captured at domain-add time
 * (section 5) — we can't re-discover it via live DNS once the MX has been
 * switched to point at us, so it must be stored.
 *
 * Returns the domain row, or null if the domain isn't configured on this relay.
 */
function resolveDestination(recipientDomain) {
  const row = getDb().prepare('SELECT * FROM domains WHERE lower(name) = lower(?)').get(recipientDomain);
  if (!row) return null;
  return row;
}

module.exports = { resolveDestination };
