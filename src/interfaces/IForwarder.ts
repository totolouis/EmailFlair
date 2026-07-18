export interface IForwardOptions {
  destinationHost: string;
  destinationPort?: number;
  from: string;
  to: string[];
  rawMessage: Buffer;
}
