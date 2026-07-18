export type EmailDecision = 'FORWARDED' | 'QUARANTINED' | 'REJECTED';
export type EmailStatus = 'RECEIVED' | 'ANALYZING' | 'FORWARDED' | 'QUARANTINED' | 'REJECTED';

export interface IEmail {
  id: string;
  tenant_id: string;
  domain: string;
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  remote_ip: string | null;
  spam_score: number;
  decision: EmailDecision | null;
  status: EmailStatus;
  relay_id: string | null;
  reason: string | null;
  headers_json: string | null;
  size_bytes: number | null;
  eml_path: string | null;
  received_at: string;
  processed_at: string | null;
}

export interface IEmailCreate {
  id: string;
  tenant_id: string;
  domain: string;
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  remote_ip: string | null;
  spam_score: number;
  decision: EmailDecision | null;
  status: EmailStatus;
  relay_id: string | null;
  reason: string | null;
  headers_json: string | null;
  size_bytes: number;
  eml_path: string | null;
  received_at: string;
  processed_at: string;
}

export interface IEmailResponse {
  id: string;
  domain: string;
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  remoteIp: string | null;
  spamScore: number;
  decision: EmailDecision | null;
  status: EmailStatus;
  reason: string | null;
  sizeBytes: number | null;
  receivedAt: string;
  processedAt: string | null;
  headers?: Record<string, unknown> | null;
}
