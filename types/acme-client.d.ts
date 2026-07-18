declare module 'acme-client' {
  import { EventEmitter } from 'events';

  export interface ClientOptions {
    directoryUrl: string;
    accountKey: string | Buffer;
    accountUrl?: string;
    backoffAttempts?: number;
    backoffMin?: number;
    backoffMax?: number;
  }

  export interface AccountPayload {
    termsOfServiceAgreed: boolean;
    contact?: string[];
  }

  export interface AutoOptions {
    csr: Buffer;
    email?: string;
    preferredChain?: string;
    termsOfServiceAgreed?: boolean;
    skipChallengeVerification?: boolean;
    challengePriority?: string[];
    challengeCreateFn: (authz: unknown, challenge: { token: string; type: string; url: string }, keyAuthorization: string) => Promise<void>;
    challengeRemoveFn: (authz: unknown, challenge: { token: string; type: string; url: string }, keyAuthorization: string) => Promise<void>;
  }

  export interface CertificateInfo {
    issuer: Record<string, string>;
    domains: { commonName: string; altNames: string[] };
    notAfter: string;
    notBefore: string;
  }

  export class Client {
    constructor(opts: ClientOptions);
    auto(opts: AutoOptions): Promise<Buffer>;
    createAccount(payload: AccountPayload): Promise<unknown>;
    getAccountUrl(): string;
    createOrder(identifiers: unknown): Promise<unknown>;
    getAuthorizations(order: unknown): Promise<unknown[]>;
    finalizeOrder(order: unknown, csr: Buffer): Promise<unknown>;
    getCertificate(order: unknown, preferredChain?: string): Promise<Buffer>;
    deactivateAuthorization(authz: unknown): Promise<void>;
    getChallengeKeyAuthorization(challenge: { type: string; token: string; url: string }): Promise<string>;
    completeChallenge(challenge: { type: string; token: string; url: string }): Promise<unknown>;
    waitForValidStatus(authz: { challenges: Array<{ type: string; token: string; url: string }>; identifier?: { value: string }; status?: string }): Promise<unknown>;
  }

  export const directory: {
    letsencrypt: {
      staging: string;
      production: string;
    };
  };

  export const forge: {
    createPrivateKey(): Promise<Buffer>;
    createPublicKey(key: string | Buffer): Promise<Buffer>;
    createCsr(opts: { commonName: string; altNames?: string[]; key?: Buffer }): Promise<[Buffer, Buffer]>;
    readCertificateInfo(pem: string | Buffer): Promise<CertificateInfo>;
    getPemBody(pem: string | Buffer): string;
    splitPemChain(pem: string | Buffer): string[];
  };
}