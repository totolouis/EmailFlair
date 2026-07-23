import dns from 'dns';
import { promisify } from 'util';
import spamFilterService from './SpamFilterService';
import { IEnhancedSpamParams, ISpamScoreResult, IDnsblResult } from '../interfaces';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);
const resolve4 = promisify(dns.resolve4);
const reverse = promisify(dns.reverse);

const DNS_TIMEOUT_MS = 2000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error('DNS timeout')), ms),
    ),
  ]);
}

const DNSBL_ZONES = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'b.barracudacentral.org',
  'dnsbl.sorbs.net',
  'spam.dnsbl.sorbs.net',
  'dul.dnsbl.sorbs.net',
  'dnsbl-1.uceprotect.net',
  'dnsbl-2.uceprotect.net',
  'dnsbl-3.uceprotect.net',
  'cbl.abuseat.org',
  'dyna.spamrats.com',
  'noptr.spamrats.com',
  'spam.spamrats.com',
  'all.s5h.net',
  'rbl.intl.net',
];

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'club', 'work', 'buzz', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq',
  'info', 'biz', 'download', 'racing', 'win', 'bid', 'stream', 'date', 'racing',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in', 't.ly', 'v.gd',
]);

const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.wsf',
  '.ps1', '.msi', '.msp', '.mst', '.cpl', '.hta', '.inf', '.reg', '.rgs',
  '.sct', '.shb', '.shs', '.lnk', '.url', '.application', '.gadget',
]);

class EnhancedSpamFilterService {

  async scoreEmail(params: IEnhancedSpamParams): Promise<ISpamScoreResult> {
    const base = spamFilterService.scoreEmail(params);

    if (base.score === 0 && base.reasons.includes('sender is whitelisted')) {
      return base;
    }

    let extraScore = 0;
    const extraReasons: string[] = [];

    const dnsResults = await this.runDnsChecks(params.remoteIp, params.senderDomain);

    if (dnsResults.dnsbl) {
      for (const hit of dnsResults.dnsbl) {
        extraScore += 5;
        extraReasons.push(`IP listed on DNSBL: ${hit.blacklist}`);
      }
    }

    if (params.remoteIp && dnsResults.ptr) {
      if (!dnsResults.ptr.hostname) {
        extraScore += 2;
        extraReasons.push('sender IP has no reverse DNS (PTR) record');
      }
    }

    if (dnsResults.spf) {
      if (!dnsResults.spf.pass) {
        extraScore += 3;
        extraReasons.push(`SPF check failed: ${dnsResults.spf.mechanism}`);
      }
    }

    if (dnsResults.dmarc) {
      if (!dnsResults.dmarc.exists) {
        extraScore += 1;
        extraReasons.push('no DMARC record found');
      }
    }

    const headerIssues = this.analyzeHeaders(params.headers);
    extraScore += headerIssues.score;
    extraReasons.push(...headerIssues.reasons);

    const urlIssues = this.analyzeUrls(params.bodyText || '', params.bodyHtml || '');
    extraScore += urlIssues.score;
    extraReasons.push(...urlIssues.reasons);

    const attachmentIssues = this.analyzeAttachments(params.attachmentNames || []);
    extraScore += attachmentIssues.score;
    extraReasons.push(...attachmentIssues.reasons);

    const contentIssues = this.analyzeContent(params.bodyText || '', params.bodyHtml || '');
    extraScore += contentIssues.score;
    extraReasons.push(...contentIssues.reasons);

    return {
      score: base.score + extraScore,
      reasons: [...base.reasons, ...extraReasons],
    };
  }

  private async runDnsChecks(
    remoteIp: string | null,
    senderDomain: string,
  ): Promise<{
    dnsbl: IDnsblResult[];
    ptr: { hostname: string | null; matchesIp: boolean } | null;
    spf: { pass: boolean; mechanism: string } | null;
    dmarc: { exists: boolean; policy: string } | null;
  }> {
    const [dnsbl, ptr, spf, dmarc] = await Promise.allSettled([
      this.checkDnsbl(remoteIp),
      this.checkPtr(remoteIp),
      this.checkSpf(remoteIp, senderDomain),
      this.checkDmarc(senderDomain),
    ]);

    return {
      dnsbl: dnsbl.status === 'fulfilled' ? dnsbl.value : [],
      ptr: ptr.status === 'fulfilled' ? ptr.value : null,
      spf: spf.status === 'fulfilled' ? spf.value : null,
      dmarc: dmarc.status === 'fulfilled' ? dmarc.value : null,
    };
  }

  private async checkDnsbl(remoteIp: string | null): Promise<IDnsblResult[]> {
    if (!remoteIp || !this.isValidIp(remoteIp)) return [];

    const octets = remoteIp.split('.');
    if (octets.length !== 4) return [];
    const reversed = octets.reverse().join('.');

    const checks = DNSBL_ZONES.map(async (zone) => {
      const query = `${reversed}.${zone}`;
      try {
        await withTimeout(resolve4(query), DNS_TIMEOUT_MS);
        return { listed: true, blacklist: zone };
      } catch {
        return null;
      }
    });

    const results = await Promise.allSettled(checks);
    return results
      .filter((r): r is PromiseFulfilledResult<IDnsblResult> =>
        r.status === 'fulfilled' && r.value !== null)
      .map((r) => r.value!);
  }

  private async checkPtr(
    remoteIp: string | null,
  ): Promise<{ hostname: string | null; matchesIp: boolean }> {
    if (!remoteIp || !this.isValidIp(remoteIp)) {
      return { hostname: null, matchesIp: false };
    }

    try {
      const hostnames = await withTimeout(reverse(remoteIp), DNS_TIMEOUT_MS);
      const hostname = hostnames[0] || null;
      if (!hostname) return { hostname: null, matchesIp: false };

      let matchesIp = false;
      try {
        const addrs = await withTimeout(resolve4(hostname), DNS_TIMEOUT_MS);
        matchesIp = addrs.includes(remoteIp);
      } catch { /* hostname didn't resolve */ }

      return { hostname, matchesIp };
    } catch {
      return { hostname: null, matchesIp: false };
    }
  }

  private async checkSpf(
    remoteIp: string | null,
    senderDomain: string,
  ): Promise<{ pass: boolean; mechanism: string } | null> {
    if (!senderDomain || !remoteIp) return null;

    let txtRecords: string[][] | undefined;
    try {
      txtRecords = await withTimeout(resolveTxt(senderDomain), DNS_TIMEOUT_MS);
    } catch {
      return { pass: false, mechanism: 'no SPF record (domain has no TXT records)' };
    }

    const spfRecord = txtRecords
      .flat()
      .find((r) => r.startsWith('v=spf1'));

    if (!spfRecord) {
      return { pass: false, mechanism: 'no SPF record found' };
    }

    return this.evaluateSpf(spfRecord, remoteIp, senderDomain);
  }

  private evaluateSpf(
    spfRecord: string,
    remoteIp: string,
    senderDomain: string,
  ): { pass: boolean; mechanism: string } {
    const mechanisms = spfRecord.split(/\s+/).slice(1);

    let lastIpMechanism: string | null = null;

    for (const mech of mechanisms) {
      const trimmed = mech.trim();
      if (!trimmed || trimmed.startsWith('v=spf1')) continue;

      if (trimmed.startsWith('+ip4:') || trimmed.startsWith('ip4:')) {
        const cidr = trimmed.replace(/^(\+)?ip4:/, '');
        lastIpMechanism = cidr;
        if (this.ipMatchesCidr(remoteIp, cidr)) {
          return { pass: true, mechanism: `matched ip4:${cidr}` };
        }
      } else if (trimmed.startsWith('+ip6:') || trimmed.startsWith('ip6:')) {
        lastIpMechanism = trimmed;
      } else if (trimmed.startsWith('+include:') || trimmed.startsWith('include:')) {
        // Simplified: just note it exists, don't recursively resolve
        lastIpMechanism = trimmed;
      } else if (trimmed === '+all' || trimmed === 'all') {
        if (!lastIpMechanism) {
          return { pass: true, mechanism: 'spf +all (allow all)' };
        }
      } else if (trimmed.startsWith('-all') || trimmed.startsWith('~all') || trimmed.startsWith('?all')) {
        if (!lastIpMechanism) {
          return { pass: false, mechanism: `spf ${trimmed} and IP not matched` };
        }
      }
    }

    return { pass: false, mechanism: 'IP not matched by any SPF ip4 mechanism' };
  }

  private ipMatchesCidr(ip: string, cidr: string): boolean {
    const parts = cidr.split('/');
    const network = parts[0];
    const prefixLen = parts[1] ? parseInt(parts[1], 10) : 32;

    const ipNum = this.ipToNum(ip);
    const netNum = this.ipToNum(network);
    if (ipNum === null || netNum === null) return false;

    const mask = ~(2 ** (32 - prefixLen) - 1);
    return (ipNum & mask) === (netNum & mask);
  }

  private ipToNum(ip: string): number | null {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255)) return null;
    return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  }

  private async checkDmarc(
    senderDomain: string,
  ): Promise<{ exists: boolean; policy: string }> {
    if (!senderDomain) return { exists: false, policy: 'none' };

    try {
      const txtRecords = await withTimeout(resolveTxt(`_dmarc.${senderDomain}`), DNS_TIMEOUT_MS);
      const dmarcRecord = txtRecords
        .flat()
        .find((r) => r.toLowerCase().startsWith('v=dmarc1'));

      if (!dmarcRecord) return { exists: false, policy: 'none' };

      const policyMatch = dmarcRecord.match(/;\s*p=(\w+)/);
      const policy = policyMatch ? policyMatch[1] : 'none';

      return { exists: true, policy };
    } catch {
      return { exists: false, policy: 'none' };
    }
  }

  private analyzeHeaders(
    headers: Record<string, unknown> | null | undefined,
  ): { score: number; reasons: string[] } {
    if (!headers) return { score: 1, reasons: ['no email headers present'] };

    let score = 0;
    const reasons: string[] = [];

    const hasMessageId = this.getHeader(headers, 'message-id');
    if (!hasMessageId) {
      score += 1.5;
      reasons.push('missing Message-ID header');
    } else if (!hasMessageId.includes('@')) {
      score += 1;
      reasons.push('Message-ID header missing @ symbol (forged)');
    }

    const hasDate = this.getHeader(headers, 'date');
    if (!hasDate) {
      score += 1;
      reasons.push('missing Date header');
    }

    const received = this.getHeaderArray(headers, 'received');
    if (received.length === 0) {
      score += 1;
      reasons.push('no Received headers (possibly forged)');
    }

    const xMailer = this.getHeader(headers, 'x-mailer') || this.getHeader(headers, 'x-mimeole');
    if (xMailer) {
      const suspicious = ['phpmailer', 'axe smtp', 'universal email mailer', 'email engine'];
      if (suspicious.some((s) => xMailer.toLowerCase().includes(s))) {
        score += 2;
        reasons.push(`suspicious X-Mailer: ${xMailer}`);
      }
    }

    const fromHeader = this.getHeader(headers, 'from') || '';
    const replyTo = this.getHeader(headers, 'reply-to');
    if (replyTo && fromHeader && !replyTo.toLowerCase().includes(fromHeader.split('@')[1]?.toLowerCase() || '')) {
      score += 1.5;
      reasons.push('Reply-To domain differs from From domain (possible phishing)');
    }

    const returnPath = this.getHeader(headers, 'return-path');
    if (returnPath && fromHeader) {
      const returnDomain = returnPath.match(/@([^>]+)>/)?.[1]?.toLowerCase();
      const fromDomain = fromHeader.match(/@([^>]+)>/)?.[1]?.toLowerCase();
      if (returnDomain && fromDomain && returnDomain !== fromDomain) {
        score += 1;
        reasons.push(`Return-Path domain (${returnDomain}) differs from From domain (${fromDomain})`);
      }
    }

    const contentType = this.getHeader(headers, 'content-type') || '';
    if (contentType.includes('text/html') && !contentType.includes('charset=')) {
      score += 0.5;
      reasons.push('HTML content without charset declaration');
    }

    return { score, reasons };
  }

  private analyzeUrls(
    bodyText: string,
    bodyHtml: string,
  ): { score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];

    const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
    const allContent = bodyText + ' ' + bodyHtml;
    const urls = allContent.match(urlRegex) || [];

    if (urls.length > 20) {
      score += 2;
      reasons.push(`excessive URLs in message (${urls.length})`);
    }

    for (const url of urls) {
      try {
        const parsed = new URL(url);

        const host = parsed.hostname.toLowerCase();

        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
          score += 3;
          reasons.push(`URL uses IP address instead of hostname: ${host}`);
          break;
        }

        const tld = host.split('.').pop() || '';
        if (SUSPICIOUS_TLDS.has(tld)) {
          score += 1;
          reasons.push(`URL uses suspicious TLD (.${tld}): ${host}`);
        }

        if (URL_SHORTENERS.has(host)) {
          score += 1;
          reasons.push(`URL uses shortener: ${host}`);
        }

        if (host.includes('login') || host.includes('verify') || host.includes('secure') || host.includes('account')) {
          const domainParts = host.split('.');
          if (domainParts.length > 2) {
            score += 2;
            reasons.push(`URL mimics login/verify page on subdomain: ${host}`);
            break;
          }
        }

        if (host.includes('xn--')) {
          score += 1;
          reasons.push(`URL uses internationalized domain (punycode): ${host}`);
        }
      } catch { /* malformed URL */ }
    }

    const hasTel = /tel:\+?\d{7,}/i.test(allContent);
    if (hasTel) {
      score += 1;
      reasons.push('message contains tel: links (common in phishing)');
    }

    const hasMailto = /mailto:/i.test(allContent);
    const hasJavascript = /javascript:/i.test(allContent);
    if (hasJavascript) {
      score += 3;
      reasons.push('message contains javascript: URLs');
    }

    return { score, reasons };
  }

  private analyzeAttachments(
    attachmentNames: string[],
  ): { score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];

    for (const name of attachmentNames) {
      const lower = name.toLowerCase();
      const ext = lower.match(/\.[a-z0-9]+$/)?.[0] || '';
      if (DANGEROUS_EXTENSIONS.has(ext)) {
        score += 4;
        reasons.push(`dangerous attachment type: ${name}`);
      }

      if (lower.endsWith('.zip')) {
        const inner = lower.replace('.zip', '');
        if (DANGEROUS_EXTENSIONS.has(inner)) {
          score += 4;
          reasons.push(`zipped executable: ${name}`);
        }
      }

      const doubleExt = lower.split('.');
      if (doubleExt.length >= 3) {
        const finalExt = '.' + doubleExt[doubleExt.length - 1];
        if (DANGEROUS_EXTENSIONS.has(finalExt)) {
          score += 3;
          reasons.push(`double-extension attachment: ${name}`);
        }
      }
    }

    const archiveCount = attachmentNames.filter((n) =>
      /\.(zip|rar|7z|tar|gz)$/i.test(n),
    ).length;
    if (archiveCount >= 3) {
      score += 2;
      reasons.push(`${archiveCount} archive attachments (bulk file transfer pattern)`);
    }

    return { score, reasons };
  }

  private analyzeContent(
    bodyText: string,
    bodyHtml: string,
  ): { score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];

    const text = bodyText || '';
    const html = bodyHtml || '';

    const invisibleText = html.match(/color:\s*(?:#fff(?:fff)?|white|transparent)/gi) || [];
    if (invisibleText.length >= 3) {
      score += 3;
      reasons.push('hidden text detected (color set to white/transparent)');
    }

    const displayNone = (html.match(/display\s*:\s*none/gi) || []).length;
    if (displayNone > 2) {
      score += 2;
      reasons.push('hidden elements via display:none');
    }

    const iframes = (html.match(/<iframe/gi) || []).length;
    if (iframes > 0) {
      score += 2;
      reasons.push(`message contains ${iframes} iframe(s)`);
    }

    const forms = (html.match(/<form/gi) || []).length;
    if (forms > 0) {
      score += 2;
      reasons.push(`message contains ${forms} form(s) (possible credential harvesting)`);
    }

    const baseTags = (html.match(/<base\s/gi) || []).length;
    if (baseTags > 0) {
      score += 2;
      reasons.push('message contains <base> tag (can hijack relative URLs)');
    }

    const dataUris = (html.match(/data:/gi) || []).length;
    if (dataUris > 5) {
      score += 1;
      reasons.push('excessive data: URIs in HTML');
    }

    if (text.length > 0) {
      const upperRatio = (text.match(/[A-Z]/g) || []).length / text.length;
      if (upperRatio > 0.6 && text.length > 50) {
        score += 1.5;
        reasons.push(`excessive uppercase text (${(upperRatio * 100).toFixed(0)}%)`);
      }

      const exclaimCount = (text.match(/!/g) || []).length;
      if (exclaimCount > 5) {
        score += 1;
        reasons.push(`excessive exclamation marks (${exclaimCount})`);
      }
    }

    const nigerianPatterns = [
      /dear\s+(sir|madam|friend|beloved|beneficiary)/i,
      /congratulations.*you\s+have\s+been\s+selected/i,
      /next\s+of\s+kin/i,
      /bank\s+account.*transfer/i,
      /unclaimed\s+funds/i,
      /inheritance/i,
      /lottery.*winner/i,
      /million\s+(dollars|usd|eur)/i,
    ];

    const combined = text + ' ' + html;
    for (const pattern of nigerianPatterns) {
      if (pattern.test(combined)) {
        score += 3;
        reasons.push('419/advance-fee scam pattern detected');
        break;
      }
    }

    return { score, reasons };
  }

  private getHeader(headers: Record<string, unknown>, name: string): string | null {
    const val = headers[name];
    if (typeof val === 'string') return val;
    if (Array.isArray(val) && val.length > 0) return String(val[0]);
    if (val && typeof val === 'object' && 'text' in val) {
      return String((val as { text: string }).text);
    }
    return null;
  }

  private getHeaderArray(headers: Record<string, unknown>, name: string): string[] {
    const val = headers[name];
    if (typeof val === 'string') return [val];
    if (Array.isArray(val)) return val.map(String);
    return [];
  }

  private isValidIp(ip: string): boolean {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
  }
}

const enhancedSpamFilterService = new EnhancedSpamFilterService();
export { enhancedSpamFilterService, EnhancedSpamFilterService };
export default enhancedSpamFilterService;
