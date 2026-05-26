import { normalizeUrl } from './normalize_url';
import { assertDestinationPolicy } from './policy';
import { renderCushion } from './render_cushion';
import { renderError } from './render_error';
import { verifyJumpJwt } from './verify_jwt';
import { JumpError, type IssuerRegistry, type RuntimeInfo } from './types';
import type { JwksCache } from './jwks_cache';
import type { ReplayCache } from './replay_cache';

export type JumpDeps = {
  registry: IssuerRegistry;
  jwksCache: JwksCache;
  replayCache: ReplayCache;
  runtime: RuntimeInfo;
  now?: () => number;
};

export async function handleJump(request: Request, deps: JumpDeps): Promise<Response> {
  try {
    const url = new URL(request.url);
    const tokens = url.searchParams.getAll('rt');
    if (tokens.length !== 1) throw new JumpError('malformed', 'rt count rejected');
    const { claim, issuer } = await verifyJumpJwt(
      tokens[0] ?? '',
      deps.registry,
      deps.jwksCache,
      deps.replayCache,
      deps.now?.() ?? Math.floor(Date.now() / 1000),
    );
    const target = normalizeUrl(claim.url, deps.runtime);
    assertDestinationPolicy(claim, issuer, target);

    if (claim.dst === 'external') {
      return new Response(renderCushion(target), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    return new Response(null, {
      status: 302,
      headers: { Location: target.href },
    });
  } catch (error) {
    const code = error instanceof JumpError ? error.code : 'malformed';
    return new Response(renderError(), {
      status: code === 'expired' ? 410 : 400,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Jump-Error': code,
      },
    });
  }
}
