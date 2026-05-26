import { createApp } from './index';

export type CloudflareEnv = Record<string, never>;

const app = createApp({
  runtime: {
    edge: 'cloudflare',
    region: 'unknown',
    production: true,
  },
});

export default {
  fetch(request: Request, env: CloudflareEnv, executionContext: ExecutionContext) {
    return app.fetch(request, env, executionContext);
  },
};
