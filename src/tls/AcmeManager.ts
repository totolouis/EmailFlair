import { EventEmitter } from 'events';
import type { IConfig } from '../interfaces';
import { CertStore, type CertFiles } from './CertStore';

let acmeModule: typeof import('acme-client') | null = null;

async function getAcme(): Promise<typeof import('acme-client')> {
  if (!acmeModule) {
    acmeModule = await import('acme-client');
  }
  return acmeModule;
}

async function generateAccountKey(): Promise<Buffer> {
  const acme = await getAcme();
  return acme.forge.createPrivateKey();
}

async function generateCsr(domain: string, key?: Buffer): Promise<{ key: Buffer; csr: Buffer }> {
  const acme = await getAcme();
  const csrKey = key || (await acme.forge.createPrivateKey());
  const [, csr] = await acme.forge.createCsr({ commonName: domain, key: csrKey });
  return { key: csrKey, csr };
}

export class AcmeManager extends EventEmitter {
  private domain: string;
  private email: string;
  private storage: string;
  private staging: boolean;
  private challenges = new Map<string, string>();
  private cert: CertFiles | null = null;
  private renewalTimer: ReturnType<typeof setInterval> | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: IConfig) {
    super();
    this.domain = config.relayHostname;
    this.email = config.tlsAcmeEmail;
    this.storage = config.tlsAcmeStorage;
    this.staging = false;
  }

  hasCert(): boolean {
    return CertStore.hasCert(this.domain, this.storage);
  }

  getServerOptions(): CertFiles | undefined {
    return this.cert ?? undefined;
  }

  getChallengeResponse(token: string): string | undefined {
    return this.challenges.get(token);
  }

  async init(): Promise<void> {
    if (this.hasCert()) {
      const loaded = CertStore.load(this.domain, this.storage);
      if (loaded) {
        this.cert = loaded;
        const days = CertStore.daysUntilExpiry(this.domain, this.storage);
        console.log(`[tls] Loaded existing cert for ${this.domain} (${days} days remaining)`);
        return;
      }
    }
    console.log(`[tls] No valid cert found for ${this.domain}, provisioning via Let's Encrypt...`);
    await this.provision();
  }

  async provision(): Promise<void> {
    const acme = await getAcme();

    const directoryUrl = this.staging
      ? acme.directory.letsencrypt.staging
      : acme.directory.letsencrypt.production;

    let accountKey: Buffer;
    if (CertStore.hasAccountKey(this.storage)) {
      accountKey = CertStore.loadAccountKey(this.storage);
    } else {
      accountKey = await generateAccountKey();
      CertStore.saveAccountKey(this.storage, accountKey);
    }

    const client = new acme.Client({
      directoryUrl,
      accountKey,
      backoffAttempts: 5,
      backoffMin: 3000,
      backoffMax: 15000,
    });

    try {
      client.getAccountUrl();
    } catch {
      await client.createAccount({
        termsOfServiceAgreed: true,
        contact: [`mailto:${this.email}`],
      });
    }

    const { key: csrKey, csr } = await generateCsr(this.domain);

    /* Manual ACME flow (instead of client.auto()) because auto() calls
       verifyHttpChallenge internally, which does an HTTP GET from within
       the container to the public domain. Docker cannot hairpin NAT back
       to itself, so the internal verification always fails with 404.
       By doing it manually, we        skip the internal verify and let Let's
       Encrypt's servers verify the challenge from the internet (which
       properly reaches Traefik → relay). */
    const order = await client.createOrder({ identifiers: [{ type: 'dns', value: this.domain }] }) as { authorizations: string[]; finalize: string; url: string; status: string; certificate: string };
    const authorizations = await client.getAuthorizations(order);

    for (const raw of authorizations) {
      const authz = raw as { challenges: Array<{ type: string; token: string; url: string }>; identifier?: { value: string }; status?: string };
      const challenge = (authz.challenges || []).find((c) => c.type === 'http-01');
      if (!challenge) {
        throw new Error(`No HTTP-01 challenge available for ${authz.identifier?.value || 'unknown'}`);
      }
      const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);
      this.challenges.set(challenge.token, keyAuthorization);
      await client.completeChallenge(challenge);
      await client.waitForValidStatus(authz);
      this.challenges.delete(challenge.token);
    }

    await client.finalizeOrder(order, csr);
    const certPem = await client.getCertificate(order);

    const chain = acme.forge.splitPemChain(certPem.toString());
    const ca = chain.length > 1 ? chain.slice(1).join('\n') : undefined;

    this.cert = { key: csrKey, cert: certPem };

    CertStore.save(this.domain, this.storage, {
      key: csrKey,
      cert: certPem,
      ca: ca ? Buffer.from(ca) : undefined,
    });

    console.log(`[tls] Certificate provisioned for ${this.domain}`);
  }

  scheduleRenewal(intervalMs = 86_400_000): void {
    if (this.renewalTimer) clearInterval(this.renewalTimer);
    this.renewalTimer = setInterval(async () => {
      try {
        const days = CertStore.daysUntilExpiry(this.domain, this.storage);
        if (days === null || days < 30) {
          console.log(`[tls] Cert for ${this.domain} expires in ${days ?? 0} days, renewing...`);
          await this.provision();
          this.emit('renew', this.cert);
        }
      } catch (err) {
        console.error('[tls] Renewal check failed:', (err as Error).message);
      }
    }, intervalMs).unref();
  }

  stopRenewal(): void {
    if (this.renewalTimer) {
      clearInterval(this.renewalTimer);
      this.renewalTimer = null;
    }
  }

  startRetry(initialDelayMs = 30_000): void {
    const delays = [initialDelayMs, 60_000, 120_000, 300_000, 600_000];
    let attempt = 0;

    const tryRetry = async (): Promise<void> => {
      if (this.cert) return;
      try {
        console.log(`[tls] ACME retry attempt ${attempt + 1}/${delays.length}...`);
        await this.init();
        if (this.cert) {
          console.log('[tls] ACME provisioning succeeded on retry');
          this.scheduleRenewal();
          this.emit('renew', this.cert);
          return;
        }
      } catch (err) {
        console.error(`[tls] ACME retry ${attempt + 1} failed:`, (err as Error).message);
      }
      attempt++;
      if (attempt < delays.length && !this.cert) {
        this.retryTimer = setTimeout(tryRetry, delays[attempt]).unref();
      } else if (!this.cert) {
        console.log('[tls] All ACME retries exhausted. TLS will not be available.');
      }
    };

    this.retryTimer = setTimeout(tryRetry, delays[0]).unref();
  }

  stopRetry(): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }
}
