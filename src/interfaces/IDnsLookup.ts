export interface IMxRecord {
  mxHost: string;
  priority: number;
  provider: string;
  allRecords: { exchange: string; priority: number }[];
}
