import { importJWK, importPKCS8, jwtVerify, SignJWT, type JWK } from 'jose';
import { registry as umaxicaRegistry } from './config/registry.umaxica';
import { fetchRegistryJwks } from './core/fetch_jwks';
import { createApp } from './index';
import { JoseOutboundSigner, NoopOutboundSigner, type OutboundSigner } from './core/sign_outbound';
import { JumpError, PRODUCTION_SERVICE_ORIGIN, type OutboundJumpClaim } from './core/types';
import { parseJumpJwks, type JumpJwks } from './core/jump_jwks';

type SecretBinding = string | { get(): Promise<string> };
type RateLimiter = {
  limit(options: { key: string }): Promise<{ success: boolean }>;
};
type VersionMetadata = {
  id?: string;
  tag?: string;
  timestamp?: string;
};

export type CloudflareEnv = {
  CF_VERSION_METADATA?: VersionMetadata;
  JUMP_PRIVATE_KEY_PEM?: SecretBinding;
  JUMP_PRIVATE_KEY_KID?: SecretBinding;
  RATE_LIMITER?: RateLimiter;
  UMAXICA_JUMP_PRIVATE_KEY_PEM?: SecretBinding;
  UMAXICA_JUMP_PRIVATE_KEY_KID?: SecretBinding;
  UMAXICA_JUMP_ORIGIN?: string;
  UMAXICA_JUMP_PUBLIC_JWKS?: SecretBinding;
  UMAXICA_JUMP_PUBLIC_KEYSET?: SecretBinding;
  ratelimit?: RateLimiter;
  'UMAXICA-APPS-EDGE-JUMP-VERSION'?: VersionMetadata;
};

export default {
  async fetch(request: Request, env: CloudflareEnv, executionContext: ExecutionContext) {
    const rateLimit = await checkRateLimit(request, env);
    if (rateLimit) return rateLimit;
    const url = new URL(request.url);
    const serviceOrigin = env.UMAXICA_JUMP_ORIGIN || PRODUCTION_SERVICE_ORIGIN;
    const jumpJwks = await readJumpJwks(env);

    const app = createApp({
      registry: umaxicaRegistry,
      fetchJwks: fetchRegistryJwks,
      config: { serviceOrigin },
      ...(jumpJwks ? { jumpJwks } : {}),
      runtime: {
        edge: 'cloudflare',
        version: cloudflareRevision(env),
        production: true,
      },
      signer: shouldSignJump(url) ? createSigner(env, jumpJwks) : new NoopOutboundSigner(),
    });
    return app.fetch(request, env, executionContext);
  },
};

function cloudflareRevision(env: CloudflareEnv) {
  const metadata = env['UMAXICA-APPS-EDGE-JUMP-VERSION'] ?? env.CF_VERSION_METADATA;
  return metadata?.id ?? metadata?.tag ?? null;
}

function shouldSignJump(url: URL) {
  return url.pathname === '/' && url.searchParams.has('rt');
}

async function checkRateLimit(request: Request, env: CloudflareEnv) {
  const rateLimiter = env.RATE_LIMITER || env.ratelimit;
  if (!rateLimiter) return null;
  const { pathname } = new URL(request.url);
  const { success } = await rateLimiter.limit({ key: pathname });
  if (success) return null;
  return new Response(`429 Failure - rate limit exceeded for ${pathname}`, { status: 429 });
}

function createSigner(env: CloudflareEnv, jumpJwks: JumpJwks | undefined) {
  return new LazyCloudflareSigner(env, jumpJwks);
}

class LazyCloudflareSigner implements OutboundSigner {
  readonly kid: string;
  private loading: Promise<OutboundSigner> | null = null;

  constructor(
    private readonly env: CloudflareEnv,
    private readonly jumpJwks: JumpJwks | undefined,
  ) {
    this.kid = readStringBindingSync(env.UMAXICA_JUMP_PRIVATE_KEY_KID ?? env.JUMP_PRIVATE_KEY_KID);
  }

  async sign(claim: OutboundJumpClaim) {
    return (await this.loadSigner()).sign(claim);
  }

  private loadSigner() {
    if (!this.loading) this.loading = createJoseSigner(this.env, this.jumpJwks);
    return this.loading;
  }
}

async function createJoseSigner(env: CloudflareEnv, jumpJwks: JumpJwks | undefined) {
  const pem = await readPrivateKeyPem(env);
  const kid = await readPrivateKeyKid(env);
  const context = {
    pem_present: Boolean(pem),
    kid_present: Boolean(kid),
    kid: kid || undefined,
    jwks_present: Boolean(jumpJwks),
  };
  if (!pem || !kid) {
    logSignerUnavailable({ ...context, reason: !pem ? 'missing_private_key' : 'missing_kid' });
    throw new JumpError('signer_unavailable', 'outbound signer not configured');
  }

  const publicJwk = jumpJwks?.keys.find((key) => key.kid === kid);
  if (!publicJwk) {
    logSignerUnavailable({ ...context, reason: 'kid_not_in_public_jwks' });
    throw new JumpError('signer_unavailable', 'outbound signer public key mismatch');
  }

  try {
    const privateKey = await importPKCS8(pem, 'ES384');
    await assertPrivateKeyMatchesPublicJwk(privateKey, publicJwk, kid);
    return new JoseOutboundSigner(privateKey, kid);
  } catch {
    logSignerUnavailable({ ...context, reason: 'private_key_import_or_pair_check_failed' });
    throw new JumpError('signer_unavailable', 'outbound signer not configured');
  }
}

async function readPrivateKeyPem(env: CloudflareEnv) {
  return readBinding(env.UMAXICA_JUMP_PRIVATE_KEY_PEM ?? env.JUMP_PRIVATE_KEY_PEM);
}

async function readPrivateKeyKid(env: CloudflareEnv) {
  return readBinding(env.UMAXICA_JUMP_PRIVATE_KEY_KID ?? env.JUMP_PRIVATE_KEY_KID);
}

async function readJumpJwks(env: CloudflareEnv) {
  const value = await readBinding(env.UMAXICA_JUMP_PUBLIC_JWKS ?? env.UMAXICA_JUMP_PUBLIC_KEYSET);
  return value ? parseJumpJwks(value) : undefined;
}

async function readBinding(binding: SecretBinding | undefined) {
  if (!binding) return null;
  if (typeof binding === 'string') return binding;
  return binding.get();
}

function readStringBindingSync(binding: SecretBinding | undefined) {
  return typeof binding === 'string' ? binding : 'unloaded';
}

async function assertPrivateKeyMatchesPublicJwk(
  privateKey: Parameters<SignJWT['sign']>[0],
  publicJwk: JWK,
  kid: string,
) {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ probe: true, iat: now })
    .setProtectedHeader({ typ: 'JWT', alg: 'ES384', kid })
    .sign(privateKey);
  await jwtVerify(token, await importJWK(publicJwk, 'ES384'), {
    algorithms: ['ES384'],
    typ: 'JWT',
    currentDate: new Date(now * 1000),
  });
}

function logSignerUnavailable(entry: {
  reason: string;
  pem_present: boolean;
  kid_present: boolean;
  kid?: string | undefined;
  jwks_present: boolean;
}) {
  // eslint-disable-next-line no-console -- safe signer diagnostics omit tokens and secret material.
  console.warn(JSON.stringify({ event: 'jump_signer_unavailable', ...entry }));
}
