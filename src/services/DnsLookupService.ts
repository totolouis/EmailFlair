import { promises as dns } from 'dns';
import type { MxRecord } from 'dns';
import { IMxRecord } from '../interfaces';

const PROVIDER_PATTERNS: { pattern: RegExp; provider: string }[] = [
  { pattern: /\.mail\.protection\.outlook\.com$/i, provider: 'Microsoft365' },
  { pattern: /aspmx.*\.google(mail)?\.com$/i, provider: 'GoogleWorkspace' },
  { pattern: /googlemail\.com$/i, provider: 'GoogleWorkspace' },
  { pattern: /\.l\.google\.com$/i, provider: 'GoogleWorkspace' },
  { pattern: /\.protonmail\.ch$/i, provider: 'ProtonMail' },
  { pattern: /\.purelymail\.com$/i, provider: 'Purelymail' },
  { pattern: /\.mx\.ovh\.(net|com)$/i, provider: 'OVH' },
  { pattern: /\.mail\.ovh\.(net|com)$/i, provider: 'OVH' },
];

class DnsLookupService {
  detectProvider(mxHost: string): string {
    const match = PROVIDER_PATTERNS.find((p) => p.pattern.test(mxHost));
    return match ? match.provider : 'Unknown/Custom SMTP';
  }

  async lookupDomainMx(domain: string): Promise<IMxRecord | null> {
    let records: MxRecord[];
    try {
      records = await dns.resolveMx(domain);
    } catch (err: unknown) {
      const dnsErr = err as NodeJS.ErrnoException;
      if (dnsErr.code === 'ENOTFOUND' || dnsErr.code === 'ENODATA') return null;
      throw err;
    }
    if (!records || records.length === 0) return null;

    records.sort((a, b) => a.priority - b.priority);
    const primary = records[0];
    return {
      mxHost: primary.exchange,
      priority: primary.priority,
      provider: this.detectProvider(primary.exchange),
      allRecords: records,
    };
  }

  async mxPointsToRelay(domain: string, relayHostname: string): Promise<boolean> {
    const result = await this.lookupDomainMx(domain);
    if (!result) return false;
    return (
      result.mxHost.replace(/\.$/, '').toLowerCase() ===
      relayHostname.replace(/\.$/, '').toLowerCase()
    );
  }
}

const dnsLookupService = new DnsLookupService();
export { dnsLookupService, DnsLookupService };
export default dnsLookupService;
