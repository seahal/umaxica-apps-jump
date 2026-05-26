import { Hono, type Context } from 'hono';
import { jwk } from 'hono/jwk';
import { languageDetector } from 'hono/language';
import { logger } from 'hono/logger';
import { requestId } from 'hono/request-id';
import { secureHeaders } from 'hono/secure-headers';
import { timeout } from 'hono/timeout';
import { trimTrailingSlash } from 'hono/trailing-slash';
import { decode, sign, verify } from 'hono/jwt';
import exampleJwks from './config/jwks.example.json';
import { registry as exampleRegistry } from './config/registry.example';
import { handleJump, type JumpDeps } from './core/handle_jump';
import { healthJson, renderHealthHtml, wantsJson } from './core/health';
import { JwksCache, type FetchJwks } from './core/jwks_cache';
import { MemoryReplayCache } from './core/replay_cache';
import { renderAbout } from './core/render_about';
import { renderRobots } from './core/render_robots';
import { securityHeaders } from './core/security_headers';
import type { RuntimeInfo } from './core/types';

void [jwk, decode, sign, verify];

export type AppOptions = Partial<JumpDeps> & {
  fetchJwks?: FetchJwks;
};

export function createApp(options: AppOptions = {}) {
  const runtime = options.runtime ?? detectRuntime();
  const registry = options.registry ?? exampleRegistry;
  const jwksCache =
    options.jwksCache ?? new JwksCache(options.fetchJwks ?? (async () => exampleJwks));
  const replayCache = options.replayCache ?? new MemoryReplayCache();

  const app = new Hono({ strict: true });
  app.use('*', logger());
  app.use('*', requestId());
  app.use('*', timeout(5000));
  app.use('*', trimTrailingSlash());
  app.use('*', languageDetector({}));
  app.use('*', securityHeaders);
  app.use('*', secureHeaders());

  app.get('/', async (c) => {
    if (c.req.query('rt') !== undefined) {
      const deps: JumpDeps = { registry, jwksCache, replayCache, runtime };
      if (options.now) deps.now = options.now;
      return handleJump(c.req.raw, deps);
    }
    return c.redirect('/about', 302);
  });

  app.get('/about', (c) => html(c, renderAbout()));
  app.get('/health', (c) => {
    if (wantsJson(c.req.header('Accept') ?? null)) return json(c, healthJson(runtime));
    return html(c, renderHealthHtml(runtime));
  });
  app.get('/health.json', (c) => json(c, healthJson(runtime)));
  app.get('/health.html', (c) => html(c, renderHealthHtml(runtime)));
  app.get('/robots.txt', (c) => c.text(renderRobots()));
  app.get('/.well-known/jwks.json', (c) => json(c, exampleJwks));

  return app;
}

function html(c: Context, body: string) {
  return c.body(body, 200, { 'Content-Type': 'text/html; charset=utf-8' });
}

function json(c: Context, body: unknown) {
  return c.body(JSON.stringify(body), 200, { 'Content-Type': 'application/json; charset=utf-8' });
}

function detectRuntime(): RuntimeInfo {
  const globalEdge = globalThis as { FASTLY_SERVICE_VERSION?: string; WebSocketPair?: unknown };
  if (globalEdge.FASTLY_SERVICE_VERSION) {
    return { edge: 'fastly', region: 'unknown', production: true };
  }
  if (globalEdge.WebSocketPair) {
    return { edge: 'cloudflare', region: 'unknown', production: true };
  }
  return { edge: 'local', region: 'unknown', production: false };
}

export default createApp();
