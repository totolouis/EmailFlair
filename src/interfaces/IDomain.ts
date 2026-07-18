export type DomainStatus = 'PENDING_DNS' | 'ACTIVE' | 'SUSPENDED';

export interface IDomain {
  id: string;
  tenant_id: string;
  name: string;
  provider: string | null;
  origin_mx: string | null;
  destination_mx: string | null;
  relay_target: string;
  status: DomainStatus;
  created_at: string;
  activated_at: string | null;
}

export interface IDomainCreate {
  id: string;
  tenant_id: string;
  name: string;
  provider: string | null;
  origin_mx: string | null;
  destination_mx: string;
  relay_target: string;
  status: DomainStatus;
  created_at: string;
  activated_at: string | null;
}

export interface IMxInstructions {
  before: string | null;
  after: string;
  note: string;
}

export interface IDomainResponse {
  id: string;
  name: string;
  provider: string | null;
  status: DomainStatus;
  originMx: string | null;
  destinationMx: string | null;
  relayTarget: string;
  createdAt: string;
  activatedAt: string | null;
}
