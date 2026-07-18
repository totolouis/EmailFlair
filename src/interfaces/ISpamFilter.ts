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
