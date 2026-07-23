export interface ITenant {
  id: string;
  name: string;
  api_key_hash: string;
  created_at: string;
}

export interface ITenantCreate {
  name: string;
  api_key_hash: string;
}
