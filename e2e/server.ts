import { serve } from '@hono/node-server';
import { createApp } from '../src';

const port = Number(process.env.E2E_PORT ?? 4173);

const server = serve({
  fetch: createApp().fetch,
  hostname: '127.0.0.1',
  port,
});

function close() {
  server.close();
}

process.once('SIGINT', close);
process.once('SIGTERM', close);
