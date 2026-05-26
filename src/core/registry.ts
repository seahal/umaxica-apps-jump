import type { IssuerConfig, IssuerRegistry } from './types';

export function getIssuer(registry: IssuerRegistry, iss: string): IssuerConfig | undefined {
  return registry[iss];
}

export function normalizeAllowedOrigins(origins: string[]) {
  return origins.map((origin) => new URL(origin).origin);
}
