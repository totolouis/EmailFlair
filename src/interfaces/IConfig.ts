export interface IConfig {
  relayId: string;
  relaySecret: string;
  relayHostname: string;
  smtpPort: number;
  apiPort: number;
  quarantineThreshold: number;
  rejectThreshold: number;
  dbPath: string;
  quarantineDir: string;
  defaultTenantName: string;
  defaultTenantApiKey: string;
}
