import { defineConfig } from 'vite-plus';

export default defineConfig({
  resolve: {
    tsconfigPaths: true,
  },
  test: {
    coverage: {
      exclude: [
        '**/+types/**',
        '**/*.d.ts',
        '**/*.test.{ts,tsx}',
        '**/node_modules/**',
        '**/build/**',
        '**/bin/**',
        '**/dist/**',
        '**/pkg/**',
        '**/__mocks__/**',
        '**/public/**',
        '**/*.css',
        '**/*.svg',
        '**/workers/**',
        '**/test-setup.ts',
        '**/locales/**',
        '**/zod.ts',
        '**/coverage/**',
        '**/.next/**',
        '**/.open-next/**',
        '**/next.config.ts',
        '**/open-next.config.ts',
        '**/src/config/**',
        '**/src/cloudflare.ts',
        '**/src/fastly.ts',
      ],
      include: ['src/**/*.ts'],
      provider: 'v8',
      reporter: ['text', 'text-summary', 'html'],
      thresholds: {
        branches: 70,
        functions: 80,
        lines: 85,
        statements: 80,
      },
    },
    deps: {
      interopDefault: true,
    },
    environment: 'happy-dom',
    globals: true,
    include: ['test/**/*.test.{ts,tsx}'],
    setupFiles: ['./vitest.setup.ts'],
  },
});
