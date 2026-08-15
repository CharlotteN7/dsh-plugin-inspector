/** Unit tests: no subprocess, no network, no harness checkout required. */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      // CONVENTIONS.md §4 sets the target at 100 % per file. These are the
      // measured Phase 1 numbers, held as a ratchet so the gate fails on a
      // regression instead of failing on every run; Phase 3 raises them to 100.
      thresholds: { lines: 89, functions: 95, branches: 69, statements: 85 },
    },
  },
})
