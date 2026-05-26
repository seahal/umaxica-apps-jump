import type { IssuerRegistry } from '../core/types';

export const registry: IssuerRegistry = {
  'https://app.example.com': {
    iss: 'https://app.example.com',
    jwks_uri: 'https://app.example.com/.well-known/jwks.json',
    allowed_dst_internal: ['https://app.example.com', 'https://docs.example.com'],
    allowed_dst_external: true,
    revoked_kids: [],
  },
};
