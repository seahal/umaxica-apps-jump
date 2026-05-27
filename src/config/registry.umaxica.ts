import type { IssuerRegistry } from '../core/types';

export const registry: IssuerRegistry = {
  'https://id.umaxica.app': {
    iss: 'https://id.umaxica.app',
    jwks_uri: 'https://id.umaxica.app/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.umaxica.app'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://id.umaxica.com': {
    iss: 'https://id.umaxica.com',
    jwks_uri: 'https://id.umaxica.com/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.umaxica.com'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://id.umaxica.org': {
    iss: 'https://id.umaxica.org',
    jwks_uri: 'https://id.umaxica.org/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.umaxica.org'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://www.umaxica.app': {
    iss: 'https://www.umaxica.app',
    jwks_uri: 'https://www.umaxica.app/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.umaxica.app'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://www.umaxica.com': {
    iss: 'https://www.umaxica.com',
    jwks_uri: 'https://www.umaxica.com/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.umaxica.com'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://www.umaxica.org': {
    iss: 'https://www.umaxica.org',
    jwks_uri: 'https://www.umaxica.org/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.umaxica.org'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://www.jp.umaxica.app': {
    iss: 'https://www.jp.umaxica.app',
    jwks_uri: 'https://www.jp.umaxica.app/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.jp.umaxica.app'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://www.jp.umaxica.com': {
    iss: 'https://www.jp.umaxica.com',
    jwks_uri: 'https://www.jp.umaxica.com/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.jp.umaxica.com'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
  'https://www.jp.umaxica.org': {
    iss: 'https://www.jp.umaxica.org',
    jwks_uri: 'https://www.jp.umaxica.org/.well-known/jwks.json',
    allowed_dst_internal: ['https://www.jp.umaxica.org'],
    allowed_dst_external: false,
    revoked_kids: [],
  },
};
