import { Hono, type Context } from 'hono';
import { languageDetector, type LanguageVariables } from 'hono/language';
import { logger } from 'hono/logger';
import { requestId } from 'hono/request-id';
import { timeout } from 'hono/timeout';
import { trimTrailingSlash } from 'hono/trailing-slash';
import exampleJwks from './config/jwks.example.json';
import { registry as exampleRegistry } from './config/registry.example';
import {
  handleJump,
  type AuditLog,
  type JumpDeps,
  type JumpAuditLogEntry,
} from './core/handle_jump';
import { healthJson, renderHealthHtml, wantsJson } from './core/health';
import { asLocale, type Locale } from './core/i18n';
import { JwksCache, type FetchJwks } from './core/jwks_cache';
import { MemoryReplayCache } from './core/replay_cache';
import { renderAbout } from './core/render_about';
import { renderRobots, renderSitemap } from './core/render_discovery';
import { jumpSecureHeaders, responseHygiene } from './core/security_headers';
import { NoopOutboundSigner } from './core/sign_outbound';
import type { RuntimeInfo } from './core/types';

export type AppOptions = Partial<JumpDeps> & {
  fetchJwks?: FetchJwks;
  auditLog?: AuditLog;
};

export function createApp(options: AppOptions = {}) {
  const runtime = options.runtime ?? detectRuntime();
  const registry = options.registry ?? exampleRegistry;
  const jwksCache = options.jwksCache ?? new JwksCache(options.fetchJwks ?? fetchExampleJwks);
  const replayCache = options.replayCache ?? new MemoryReplayCache();
  const signer = options.signer ?? new NoopOutboundSigner();

  const app = new Hono<{ Variables: LanguageVariables }>({ strict: true });
  app.use('*', logger(redactLogLine));
  app.use(
    '*',
    languageDetector({
      supportedLanguages: ['ja', 'en'],
      fallbackLanguage: 'ja',
      order: ['header'],
      caches: false,
    }),
  );
  app.use('*', requestId());
  app.use('*', timeout(1000));
  app.use('*', trimTrailingSlash());
  app.use('*', responseHygiene);
  app.use('*', jumpSecureHeaders());

  app.get('/', async (c) => {
    const locale = requestLocale(c);
    if (c.req.query('rt') !== undefined) {
      const deps: JumpDeps = { registry, jwksCache, replayCache, runtime, signer };
      deps.auditLog = options.auditLog ?? auditLog;
      deps.locale = locale;
      if (options.now) deps.now = options.now;
      if (options.randomJti) deps.randomJti = options.randomJti;
      if (options.outboundTtl !== undefined) deps.outboundTtl = options.outboundTtl;
      return handleJump(c.req.raw, deps);
    }
    return c.redirect('/about', 302);
  });

  app.get('/about', (c) => html(c, renderAbout(requestLocale(c)), requestLocale(c)));
  app.get('/health', (c) => {
    if (wantsJson(c.req.header('Accept') ?? null)) return json(c, healthJson(runtime));
    const locale = requestLocale(c);
    return html(c, renderHealthHtml(runtime, locale), locale);
  });
  app.get('/health.json', (c) => json(c, healthJson(runtime)));
  app.get('/health.html', (c) => {
    const locale = requestLocale(c);
    return html(c, renderHealthHtml(runtime, locale), locale);
  });
  app.get('/favicon.ico', (c) => c.body(null, 204));
  app.get('/robots.txt', (c) => c.text(renderRobots(new URL(c.req.url).origin)));
  app.get('/sitemap.xml', (c) =>
    c.body(renderSitemap(new URL(c.req.url).origin), 200, {
      'Content-Type': 'application/xml; charset=utf-8',
    }),
  );
  app.get('/.well-known/jwks.json', (c) => json(c, exampleJwks));

  return app;
}

function requestLocale(c: Context<{ Variables: LanguageVariables }>): Locale {
  return asLocale(c.get('language'));
}

function html(c: Context, body: string, locale: Locale) {
  return c.body(body, 200, {
    'Content-Language': locale,
    'Content-Type': 'text/html; charset=utf-8',
  });
}

function json(c: Context, body: unknown) {
  return c.body(JSON.stringify(body), 200, { 'Content-Type': 'application/json; charset=utf-8' });
}

export function detectRuntime(): RuntimeInfo {
  const globalEdge = globalThis as { FASTLY_SERVICE_VERSION?: string; WebSocketPair?: unknown };
  if (globalEdge.FASTLY_SERVICE_VERSION) {
    return { edge: 'fastly', production: true };
  }
  if (globalEdge.WebSocketPair) {
    return { edge: 'cloudflare', production: true };
  }
  return { edge: 'local', production: false };
}

export async function fetchExampleJwks() {
  return exampleJwks;
}

function redactLogLine(message: string) {
  // eslint-disable-next-line no-console -- request logging is intentional, but rt values are redacted.
  console.log(message.replaceAll(/([?&]rt=)[^&\s]*/g, '$1[redacted]'));
}

function auditLog(entry: JumpAuditLogEntry) {
  // eslint-disable-next-line no-console -- structured redirect decision logging is intentional.
  console.log(JSON.stringify(entry));
}
