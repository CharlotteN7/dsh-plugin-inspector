/**
 * The assembled application: the built `lib/cli.js`, run as a real subprocess
 * against a real fixture, exactly as a user or a CI job would run it.
 *
 * The unit suite imports `inspect()` and can therefore be fooled by an export
 * shape that only works in-process. This file resolves nothing by hand — it
 * runs the file `package.json` points `bin` at, under plain Node, and asserts
 * on the bytes and the exit code that reach the terminal.
 *
 * Run it with `pnpm run test:e2e`, which builds first.
 * @module tests/e2e/cli
 */

import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/** The built entry `package.json` declares as the `dsh-inspect` binary. */
const BIN = fileURLToPath(new URL('../../lib/cli.js', import.meta.url))

/** Absolute path of the fixture directory. */
const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url))

/**
 * Run the built binary.
 * @param args - command line arguments.
 * @returns exit code and both streams.
 */
function cli(...args: readonly string[]): { code: number, stdout: string, stderr: string } {
  const result = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' })
  return { code: result.status ?? -1, stdout: result.stdout, stderr: result.stderr }
}

describe('the built binary', () => {
  it('prints usage and exits clean for --help', () => {
    const result = cli('--help')
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('know what a DeepSeek Harness plugin does before you install it')
    expect(result.stdout).toContain('npm pack')
  })

  it('exits 0 on a well-behaved plugin and prints no findings', () => {
    const result = cli(`${FIXTURES}benign-control`, '--no-color')
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('No findings.')
    expect(result.stderr).toBe('')
  })

  it('exits 1 and names the disabled row on a plugin that switches approval off', () => {
    const result = cli(`${FIXTURES}disables-approval`, '--no-color')
    expect(result.code).toBe(1)
    expect(result.stdout).toContain('CRITICAL')
    expect(result.stdout).toContain('disables the core row "approval"')
  })

  it('exits 2 when the target cannot be analysed, so CI cannot mistake it for clean', () => {
    const result = cli(`${FIXTURES}nothing-here`)
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('cannot read target')
    expect(result.stdout).toBe('')
  })

  it('emits a JSON document a CI job can gate on', () => {
    const result = cli(`${FIXTURES}credential-exfil`, '--json')
    const report = JSON.parse(result.stdout) as {
      schemaVersion: number
      analysis: { negativesReliable: boolean }
      findings: { checkId: string, severity: string }[]
    }
    expect(result.code).toBe(1)
    expect(report.schemaVersion).toBe(1)
    expect(report.analysis.negativesReliable).toBe(true)
    expect(report.findings.some(finding => finding.checkId === 'B8')).toBe(true)
  })

  it('runs the canary fixture without leaving a sentinel behind', () => {
    const sentinel = fileURLToPath(new URL('../fixtures/execution-canary/CANARY-FIRED', import.meta.url))
    const result = spawnSync(
      process.execPath,
      [BIN, `${FIXTURES}execution-canary`, '--json'],
      { encoding: 'utf8', env: { ...process.env, DSH_INSPECTOR_CANARY: sentinel } },
    )
    expect(result.status).toBe(1)
    expect(spawnSync('test', ['-e', sentinel]).status).not.toBe(0)
  })
})
