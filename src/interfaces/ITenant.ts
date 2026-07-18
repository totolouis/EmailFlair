export interface ITenant {
  id: string;
  name: string;
  api_key: string;
  created_at: string;
}

export interface ITenantCreate {
  name: string;
  api_key: string;
}
