/**
 * Assembled-application tests: each one spawns the built `lib/cli.js` as a real
 * subprocess, so `pnpm run test:e2e` builds first. No network, no API key.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/e2e/**/*.e2e.ts'],
    testTimeout: 30_000,
    fileParallelism: false,
  },
})
