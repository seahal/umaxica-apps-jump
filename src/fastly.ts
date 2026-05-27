/// <reference types="@fastly/js-compute" />

import { fire } from '@fastly/hono-fastly-compute';
import { registry as umaxicaRegistry } from './config/registry.umaxica';
import { fetchRegistryJwks } from './core/fetch_jwks';
import { createApp } from './index';

const app = createApp({
  registry: umaxicaRegistry,
  fetchJwks: fetchRegistryJwks,
  runtime: {
    edge: 'fastly',
    production: true,
  },
});

fire(app);
