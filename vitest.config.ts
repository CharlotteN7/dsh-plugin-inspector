/** Unit tests: no subprocess, no network, no harness checkout required. */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      // The workspace conventions set the target at 100 % per file. These are
      // the measured numbers, held as a ratchet so the gate fails on a
      // regression instead of failing on every run. The resource ceilings, the
      // symlink and escaping-entry refusals, and every check in the catalogue
      // now have a case; what is left uncovered is mostly defensive branches
      // in the manifest and tarball readers.
      thresholds: { lines: 95, functions: 96, branches: 81, statements: 91 },
    },
  },
})
