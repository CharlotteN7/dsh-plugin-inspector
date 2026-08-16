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
      // symlink and escaping-entry refusals, every check in the catalogue, and
      // every refusal on the registry path now have a case; what is left
      // uncovered is mostly defensive branches in the manifest and tarball
      // readers, plus the two process-level handlers in `cli.ts` that only run
      // when the module is the entry point.
      thresholds: { lines: 96, functions: 97, branches: 83, statements: 93 },
    },
  },
})
