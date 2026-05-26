/// <reference types="@fastly/js-compute" />

import { fire } from '@fastly/hono-fastly-compute';
import { createApp } from './index';

const app = createApp({
  runtime: {
    edge: 'fastly',
    region: 'unknown',
    production: true,
  },
});

fire(app);
