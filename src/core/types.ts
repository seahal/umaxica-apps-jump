export const SERVICE = {
  name: 'jump',
  version: '0.1.0',
} as const;

export const PRODUCTION_SERVICE_ORIGIN = 'https://jump.umaxica.net';

type EdgeName = 'fastly' | 'cloudflare' | 'local' | 'unknown';

export type RuntimeInfo = {
  edge: EdgeName;
  version?: string | null;
  production: boolean;
};

export type JumpConfig = {
  serviceOrigin: string;
};

export type IssuerConfig = {
  iss: string;
  jwks_uri: string;
  allowed_dst_internal: string[];
  allowed_dst_external: boolean | string[];
  revoked_kids?: string[];
};

export type IssuerRegistry = Record<string, IssuerConfig>;

type JumpDst = 'internal' | 'external';

export type InboundJumpClaim = {
  schema: 1;
  iss: string;
  aud: string;
  sub: 'jump-redirect';
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  dst: JumpDst;
  url: string;
};

export type OutboundJumpClaim = {
  schema: 1;
  iss: string;
  aud: string;
  sub: 'jump-redirect';
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  src: string;
  dst: 'internal';
  url: string;
};

export type JumpErrorCode =
  | 'malformed'
  | 'invalid_header'
  | 'invalid_signature'
  | 'invalid_claim'
  | 'expired'
  | 'replay'
  | 'invalid_dst'
  | 'invalid_url'
  | 'signer_unavailable';

export class JumpError extends Error {
  readonly code: JumpErrorCode;

  constructor(code: JumpErrorCode, message?: string) {
    const text = message ?? code;
    super(text);
    this.code = code;
  }
}
