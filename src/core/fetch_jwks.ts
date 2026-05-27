import type { JWK } from 'jose';
import type { FetchJwks } from './jwks_cache';

export const fetchRegistryJwks: FetchJwks = async (issuer) => {
  const response = await fetch(issuer.jwks_uri, {
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`JWKS fetch failed: ${response.status}`);
  return (await response.json()) as { keys: JWK[] };
};
