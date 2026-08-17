/**
 * Unit tests: no subprocess, no network, no harness checkout required.
 *
 * The thresholds are 100 % **per file**. An aggregate gate lets one file hide
 * behind the rest: `cordis-yaml.ts` sat at 79.69 % branch coverage while the
 * project-wide branch number cleared its bar, and the alias-attribution defect
 * that erased a critical finding lived in the branches nothing reached. This is
 * a security control, so an arm nothing exercises is an arm nobody has checked;
 * the handful of genuinely unreachable lines carry a `v8 ignore` with a stated
 * reason instead.
 */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      thresholds: { perFile: true, lines: 100, functions: 100, branches: 100, statements: 100 },
    },
  },
})
