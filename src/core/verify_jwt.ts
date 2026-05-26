import { errors, jwtVerify, type JWTPayload } from 'jose';
import { getIssuer } from './registry';
import type { JwksCache } from './jwks_cache';
import { JumpError, SERVICE, type InboundJumpClaim, type IssuerRegistry } from './types';
import type { ReplayCache } from './replay_cache';

const ALLOWED_ALGS = new Set(['EdDSA']);
const SKEW = 60;

type Header = {
  typ?: unknown;
  alg?: unknown;
  kid?: unknown;
  crit?: unknown;
  jku?: unknown;
  jwk?: unknown;
  x5u?: unknown;
};

export async function verifyJumpJwt(
  token: string,
  registry: IssuerRegistry,
  jwksCache: JwksCache,
  replayCache: ReplayCache,
  now = Math.floor(Date.now() / 1000),
) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new JumpError('malformed', 'not compact jwt');
  for (const part of parts) assertBase64Url(part);

  const header = decodeJson<Header>(parts[0] ?? '', 'invalid_header');
  if (header.typ !== 'JWT') throw new JumpError('invalid_header', 'typ rejected');
  if (typeof header.alg !== 'string' || !ALLOWED_ALGS.has(header.alg)) {
    throw new JumpError('invalid_header', 'alg rejected');
  }
  if (typeof header.kid !== 'string' || !header.kid)
    throw new JumpError('invalid_header', 'kid required');
  if ('crit' in header || 'jku' in header || 'jwk' in header || 'x5u' in header) {
    throw new JumpError('invalid_header', 'embedded key hints rejected');
  }

  const unsafePayload = decodeJson<JWTPayload>(parts[1] ?? '', 'malformed');
  if (typeof unsafePayload.iss !== 'string') throw new JumpError('invalid_claim', 'iss required');
  const issuer = getIssuer(registry, unsafePayload.iss);
  if (!issuer) throw new JumpError('invalid_claim', 'issuer rejected');

  let payload: JWTPayload;
  try {
    const key = await jwksCache.getKey(issuer, header.kid, header.alg);
    const verified = await jwtVerify(token, key, {
      issuer: issuer.iss,
      audience: SERVICE.origin,
      algorithms: [header.alg],
      typ: 'JWT',
      clockTolerance: SKEW,
      currentDate: new Date(now * 1000),
    });
    payload = verified.payload;
  } catch (error) {
    if (error instanceof JumpError) throw error;
    try {
      const key = await jwksCache.getKey(issuer, header.kid, header.alg, true);
      const verified = await jwtVerify(token, key, {
        issuer: issuer.iss,
        audience: SERVICE.origin,
        algorithms: [header.alg],
        typ: 'JWT',
        clockTolerance: SKEW,
        currentDate: new Date(now * 1000),
      });
      payload = verified.payload;
    } catch (retryError) {
      if (retryError instanceof JumpError) throw retryError;
      throw mapJoseVerifyError(retryError);
    }
  }

  const claim = validateClaim(payload, issuer.iss, now);
  await replayCache.checkAndStore(claim.iss, claim.jti, claim.exp, now, SKEW);
  return { claim, issuer };
}

function mapJoseVerifyError(error: unknown) {
  if (error instanceof errors.JWTExpired) return new JumpError('expired', 'expired');
  if (error instanceof errors.JWTClaimValidationFailed) {
    return new JumpError('invalid_claim', 'claim validation failed');
  }
  return new JumpError('invalid_signature', 'verify failed');
}

export function assertBase64Url(value: string) {
  if (
    !value ||
    value.includes('=') ||
    value.includes('+') ||
    value.includes('/') ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new JumpError('malformed', 'invalid base64url');
  }
}

function decodeJson<T>(value: string, code: 'malformed' | 'invalid_header'): T {
  try {
    const bytes = Uint8Array.from(atob(toBase64(value)), (char) => char.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    throw new JumpError(code, 'json decode failed');
  }
}

function toBase64(value: string) {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/');
  return padded + '='.repeat((4 - (padded.length % 4)) % 4);
}

function validateClaim(payload: JWTPayload, iss: string, now: number): InboundJumpClaim {
  if (payload.schema !== 1) throw new JumpError('invalid_claim', 'schema rejected');
  if (payload.iss !== iss) throw new JumpError('invalid_claim', 'iss mismatch');
  if (payload.aud !== SERVICE.origin) throw new JumpError('invalid_claim', 'aud rejected');
  if (payload.sub !== 'jump-redirect') throw new JumpError('invalid_claim', 'sub rejected');
  if (typeof payload.exp !== 'number') throw new JumpError('invalid_claim', 'exp required');
  if (typeof payload.nbf !== 'number') throw new JumpError('invalid_claim', 'nbf required');
  if (typeof payload.iat !== 'number') throw new JumpError('invalid_claim', 'iat required');
  if (payload.exp < now - SKEW) throw new JumpError('expired', 'expired');
  if (payload.nbf > now + SKEW) throw new JumpError('invalid_claim', 'nbf future');
  if (typeof payload.jti !== 'string' || !payload.jti)
    throw new JumpError('invalid_claim', 'jti required');
  if (payload.dst !== 'internal' && payload.dst !== 'external')
    throw new JumpError('invalid_dst', 'dst rejected');
  if (typeof payload.url !== 'string' || !payload.url)
    throw new JumpError('invalid_url', 'url required');
  return payload as InboundJumpClaim;
}
