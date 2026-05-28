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
    private_key_present: Boolean(pem),
    kid_present: Boolean(kid),
    kid: kid || undefined,
    jwks_present: Boolean(jumpJwks),
  };
  logSignerConfig(context);
  if (!pem || !kid) {
    logSignerUnavailable({ ...context, reason: !pem ? 'missing_private_key' : 'missing_kid' });
    throw new JumpError('signer_unavailable', 'outbound signer not configured');
  }

  const publicJwk = jumpJwks?.keys.find((key) => key.kid === kid);
  if (!publicJwk) {
    logSignerUnavailable({ ...context, reason: 'kid_not_in_public_jwks' });
    throw new JumpError('signer_unavailable', 'outbound signer public key mismatch');
  }

  let privateKey: Parameters<SignJWT['sign']>[0];
  try {
    privateKey = await importPKCS8(pem, 'ES384');
  } catch (error) {
    logSignerImportFailed(context, error);
    logSignerUnavailable({ ...context, import_pkcs8_ok: false, reason: 'pkcs8_import_failed' });
    throw new JumpError('signer_unavailable', 'outbound signer not configured');
  }

  try {
    await assertPrivateKeyMatchesPublicJwk(privateKey, publicJwk, kid);
  } catch (error) {
    logSignerPairCheckFailed(context, error);
    logSignerUnavailable({ ...context, import_pkcs8_ok: true, reason: 'key_pair_mismatch' });
    throw new JumpError('signer_unavailable', 'outbound signer public key mismatch');
  }

  logSignerConfigured({
    kid,
    public_jwks_kids: jumpJwks?.keys.flatMap((key) => (key.kid ? [key.kid] : [])) ?? [],
  });
  return new JoseOutboundSigner(privateKey, kid);
}

async function readPrivateKeyPem(env: CloudflareEnv) {
  const value = await readBinding(env.UMAXICA_JUMP_PRIVATE_KEY_PEM ?? env.JUMP_PRIVATE_KEY_PEM);
  return normalizePem(value);
}

async function readPrivateKeyKid(env: CloudflareEnv) {
  const value = await readBinding(env.UMAXICA_JUMP_PRIVATE_KEY_KID ?? env.JUMP_PRIVATE_KEY_KID);
  return value?.trim() || null;
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
  return typeof binding === 'string' ? binding.trim() || 'unloaded' : 'unloaded';
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

function logSignerConfig(entry: {
  private_key_present: boolean;
  kid_present: boolean;
  kid?: string | undefined;
  jwks_present: boolean;
}) {
  // eslint-disable-next-line no-console -- safe signer diagnostics omit tokens and secret material.
  console.warn(JSON.stringify({ event: 'jump_signer_config', ...entry }));
}

function logSignerUnavailable(entry: {
  reason: string;
  private_key_present: boolean;
  kid_present: boolean;
  kid?: string | undefined;
  jwks_present: boolean;
  import_pkcs8_ok?: boolean | undefined;
}) {
  // eslint-disable-next-line no-console -- safe signer diagnostics omit tokens and secret material.
  console.warn(JSON.stringify({ event: 'jump_signer_unavailable', ...entry }));
}

function logSignerImportFailed(
  entry: {
    private_key_present: boolean;
    kid_present: boolean;
    kid?: string | undefined;
    jwks_present: boolean;
  },
  error: unknown,
) {
  // eslint-disable-next-line no-console -- safe signer diagnostics omit tokens and secret material.
  console.error(
    JSON.stringify({
      event: 'jump_signer_import_failed',
      ...entry,
      import_pkcs8_ok: false,
      reason: error instanceof Error ? error.name : 'unknown',
    }),
  );
}

function logSignerPairCheckFailed(
  entry: {
    private_key_present: boolean;
    kid_present: boolean;
    kid?: string | undefined;
    jwks_present: boolean;
  },
  error: unknown,
) {
  // eslint-disable-next-line no-console -- safe signer diagnostics omit tokens and secret material.
  console.error(
    JSON.stringify({
      event: 'jump_signer_pair_check_failed',
      ...entry,
      import_pkcs8_ok: true,
      reason: error instanceof Error ? error.name : 'unknown',
    }),
  );
}

function logSignerConfigured(entry: { kid: string; public_jwks_kids: string[] }) {
  // eslint-disable-next-line no-console -- safe signer diagnostics omit tokens and secret material.
  console.info(
    JSON.stringify({
      event: 'jump_signer_configured',
      signer_configured: true,
      signer_kid: entry.kid,
      private_key_imported: true,
      public_jwks_kids: entry.public_jwks_kids,
    }),
  );
}

function normalizePem(value: string | null) {
  let normalized = value?.trim();
  if (!normalized) return null;

  if (
    (normalized.startsWith('"') && normalized.endsWith('"')) ||
    (normalized.startsWith("'") && normalized.endsWith("'"))
  ) {
    const quote = normalized[0];
    if (quote === '"') {
      try {
        const parsed = JSON.parse(normalized) as unknown;
        if (typeof parsed === 'string') normalized = parsed.trim();
      } catch {
        normalized = normalized.slice(1, -1).trim();
      }
    } else {
      normalized = normalized.slice(1, -1).trim();
    }
  }

  return normalized.replaceAll('\\r\\n', '\n').replaceAll('\\n', '\n').replaceAll('\r\n', '\n');
}
