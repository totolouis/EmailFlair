export interface ISpamScoreParams {
  tenantId: string;
  remoteIp: string | null;
  senderDomain: string;
  senderAddress: string | null;
  subject: string;
  hasAttachments: boolean;
}

export interface ISpamScoreResult {
  score: number;
  reasons: string[];
}

export interface IEnhancedSpamParams extends ISpamScoreParams {
  heloHostname?: string | null;
  headers?: Record<string, unknown> | null;
  bodyText?: string | null;
  bodyHtml?: string | null;
  attachmentCount?: number;
  attachmentNames?: string[];
}

export interface IDnsblResult {
  listed: boolean;
  blacklist: string;
}

export interface IDnsCheckResult {
  spf?: { pass: boolean; mechanism: string };
  dmarc?: { exists: boolean; policy: string };
  ptr?: { hostname: string | null; matchesIp: boolean };
  dnsbl?: IDnsblResult[];
}
