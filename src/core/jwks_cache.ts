import { importJWK, type JWK } from 'jose';
import { JumpError, type IssuerConfig } from './types';

type CachedSet = {
  keys: JWK[];
  expiresAt: number;
};

export type FetchJwks = (issuer: IssuerConfig) => Promise<{ keys: JWK[] }>;

export class JwksCache {
  private readonly cache = new Map<string, CachedSet>();
  private readonly negative = new Map<string, number>();

  constructor(
    private readonly fetchJwks: FetchJwks,
    private readonly ttlMs = 300_000,
    private readonly negativeTtlMs = 30_000,
  ) {}

  async getKey(
    issuer: IssuerConfig,
    kid: string,
    alg: string,
    forceRefresh = false,
  ): ReturnType<typeof importJWK> {
    if (issuer.revoked_kids?.includes(kid)) throw new JumpError('invalid_signature', 'revoked kid');
    const negKey = `${issuer.iss}:${kid}`;
    const now = Date.now();
    if (!forceRefresh && (this.negative.get(negKey) ?? 0) > now) {
      throw new JumpError('invalid_signature', 'kid negative cached');
    }

    const jwks = await this.getJwks(issuer, forceRefresh);
    const jwk = jwks.keys.find((key) => key.kid === kid && key.alg === alg);
    if (!jwk) {
      if (!forceRefresh) return this.getKey(issuer, kid, alg, true);
      this.negative.set(negKey, now + this.negativeTtlMs);
      throw new JumpError('invalid_signature', 'kid not found');
    }
    return importJWK(jwk, alg);
  }

  private async getJwks(issuer: IssuerConfig, forceRefresh: boolean) {
    const now = Date.now();
    const cached = this.cache.get(issuer.iss);
    if (!forceRefresh && cached && cached.expiresAt > now) return cached;
    const next = await this.fetchJwks(issuer);
    const cachedSet = { keys: next.keys, expiresAt: now + this.ttlMs };
    this.cache.set(issuer.iss, cachedSet);
    return cachedSet;
  }
}
