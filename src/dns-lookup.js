const dns = require('dns').promises;

// Known MX patterns -> provider name, per PRD section 5 example ("Provider: Microsoft 365")
const PROVIDER_PATTERNS = [
  { pattern: /\.mail\.protection\.outlook\.com$/i, provider: 'Microsoft365' },
  { pattern: /aspmx.*\.google(mail)?\.com$/i, provider: 'GoogleWorkspace' },
  { pattern: /googlemail\.com$/i, provider: 'GoogleWorkspace' },
  { pattern: /\.l\.google\.com$/i, provider: 'GoogleWorkspace' }, // covers gmail-smtp-in.l.google.com et al.
  { pattern: /\.protonmail\.ch$/i, provider: 'ProtonMail' },
  { pattern: /\.purelymail\.com$/i, provider: 'Purelymail' },
  { pattern: /\.mx\.ovh\.(net|com)$/i, provider: 'OVH' },
  { pattern: /\.mail\.ovh\.(net|com)$/i, provider: 'OVH' },
];

function detectProvider(mxHost) {
  const match = PROVIDER_PATTERNS.find((p) => p.pattern.test(mxHost));
  return match ? match.provider : 'Unknown/Custom SMTP';
}

/**
 * Resolve current MX records for a domain and classify the provider.
 * Returns { mxHost, priority, provider } for the lowest-priority (primary) record,
 * or null if no MX records are found.
 */
async function lookupDomainMx(domain) {
  let records;
  try {
    records = await dns.resolveMx(domain);
  } catch (err) {
    if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return null;
    throw err;
  }
  if (!records || records.length === 0) return null;

  records.sort((a, b) => a.priority - b.priority);
  const primary = records[0];
  return {
    mxHost: primary.exchange,
    priority: primary.priority,
    provider: detectProvider(primary.exchange),
    allRecords: records,
  };
}

/**
 * Check whether a domain's current MX already points at our relay hostname.
 * Used by the /domains/:name/activate endpoint.
 */
async function mxPointsToRelay(domain, relayHostname) {
  const result = await lookupDomainMx(domain);
  if (!result) return false;
  return result.mxHost.replace(/\.$/, '').toLowerCase() === relayHostname.replace(/\.$/, '').toLowerCase();
}

module.exports = { lookupDomainMx, detectProvider, mxPointsToRelay };
