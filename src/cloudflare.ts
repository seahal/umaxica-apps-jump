import { importPKCS8 } from 'jose';
import { createApp } from './index';
import { JoseOutboundSigner, NoopOutboundSigner, type OutboundSigner } from './core/sign_outbound';
import type { OutboundJumpClaim } from './core/types';

const CLOUDFLARE_VERSION_TAG = 'UMAXICA-APPS-EDGE-JUMP-VERSION';

type SecretBinding = string | { get(): Promise<string> };
type RateLimiter = {
  limit(options: { key: string }): Promise<{ success: boolean }>;
};
type VersionMetadata = {
  id: string;
  tag?: string;
  timestamp: string;
};

export type CloudflareEnv = {
  CF_VERSION_METADATA?: VersionMetadata;
  JUMP_PRIVATE_KEY_PEM?: SecretBinding;
  JUMP_PRIVATE_KEY_KID?: SecretBinding;
  RATE_LIMITER?: RateLimiter;
  UMAXICA_JUMP_PRIVATE_KEY_PEM?: SecretBinding;
  UMAXICA_JUMP_PRIVATE_KEY_KID?: SecretBinding;
  ratelimit?: RateLimiter;
  'UMAXICA-APPS-EDGE-JUMP-VERSION'?: VersionMetadata;
};

export default {
  async fetch(request: Request, env: CloudflareEnv, executionContext: ExecutionContext) {
    const rateLimit = await checkRateLimit(request, env);
    if (rateLimit) return rateLimit;
    const url = new URL(request.url);

    const app = createApp({
      runtime: {
        edge: 'cloudflare',
        version:
          env.CF_VERSION_METADATA?.tag ||
          env['UMAXICA-APPS-EDGE-JUMP-VERSION']?.tag ||
          CLOUDFLARE_VERSION_TAG,
        production: true,
      },
      signer: shouldSignJump(url) ? createSigner(env) : new NoopOutboundSigner(),
    });
    return app.fetch(request, env, executionContext);
  },
};

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

function createSigner(env: CloudflareEnv) {
  return new LazyCloudflareSigner(env);
}

class LazyCloudflareSigner implements OutboundSigner {
  readonly kid = 'jump-current';
  private signer: OutboundSigner | null = null;

  constructor(private readonly env: CloudflareEnv) {}

  async sign(claim: OutboundJumpClaim) {
    return (await this.loadSigner()).sign(claim);
  }

  private async loadSigner() {
    if (this.signer) return this.signer;
    this.signer = await createJoseSigner(this.env);
    return this.signer;
  }
}

async function createJoseSigner(env: CloudflareEnv) {
  const pem = await readPrivateKeyPem(env);
  if (!pem) return new NoopOutboundSigner();
  const kid = (await readPrivateKeyKid(env)) || 'jump-current';
  return new JoseOutboundSigner(await importPKCS8(pem, 'EdDSA'), kid);
}

async function readPrivateKeyPem(env: CloudflareEnv) {
  return readBinding(env.UMAXICA_JUMP_PRIVATE_KEY_PEM ?? env.JUMP_PRIVATE_KEY_PEM);
}

async function readPrivateKeyKid(env: CloudflareEnv) {
  return readBinding(env.UMAXICA_JUMP_PRIVATE_KEY_KID ?? env.JUMP_PRIVATE_KEY_KID);
}

async function readBinding(binding: SecretBinding | undefined) {
  if (!binding) return null;
  if (typeof binding === 'string') return binding;
  return binding.get();
}
