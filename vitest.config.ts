import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['**/__tests__/**/*.test.ts', '**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: [
        'classifier/**/*.ts',
        'honeypot/**/*.ts',
        'supply-chain/**/*.ts',
        'router/**/*.ts',
        'intel-export/**/*.ts',
        'attribution/**/*.ts',
      ],
      exclude: ['**/__tests__/**', '**/*.test.ts'],
    },
    // Print test file name + each test name for clear progress logs
    reporters: ['verbose'],
  },
});
