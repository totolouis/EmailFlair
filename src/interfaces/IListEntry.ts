export type ListType = 'ip' | 'domain';

export interface IListEntry {
  id: string;
  tenant_id: string;
  type: ListType;
  value: string;
  created_at: string;
}

export interface IListEntryResponse {
  id: string;
  type: ListType;
  value: string;
  createdAt: string;
}
