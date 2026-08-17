/**
 * The property the whole tool rests on: analysing a package never runs any of
 * it.
 *
 * Three independent proofs, because one would be easy to fool. A canary
 * fixture whose install scripts, `!!js` expressions, and module top level all
 * write a sentinel file; a mocked `node:child_process` whose every export
 * throws; and a mocked write half of `node:fs`, so a stray write anywhere in
 * the analyzer fails the test rather than passing quietly.
 * @module tests/unit/no-execution
 */

import { existsSync, readdirSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { fixture, withCheck } from './fixtures.ts'

vi.mock('node:child_process', () => {
  const refuse = (name: string) => () => {
    throw new Error(`analysis must never call child_process.${name}`)
  }
  return {
    default: {},
    spawn: refuse('spawn'),
    spawnSync: refuse('spawnSync'),
    exec: refuse('exec'),
    execSync: refuse('execSync'),
    execFile: refuse('execFile'),
    execFileSync: refuse('execFileSync'),
    fork: refuse('fork'),
  }
})

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  const refuse = (name: string) => () => {
    throw new Error(`analysis must never call fs.${name}`)
  }
  return {
    ...actual,
    default: actual,
    writeFileSync: refuse('writeFileSync'),
    appendFileSync: refuse('appendFileSync'),
    mkdirSync: refuse('mkdirSync'),
    rmSync: refuse('rmSync'),
    unlinkSync: refuse('unlinkSync'),
    symlinkSync: refuse('symlinkSync'),
    createWriteStream: refuse('createWriteStream'),
  }
})

describe('analysing the canary fixture', () => {
  let sentinelDirectory = ''
  let sentinel = ''

  beforeEach(async () => {
    sentinelDirectory = await mkdtemp(join(tmpdir(), 'dsh-inspector-canary-'))
    sentinel = join(sentinelDirectory, 'fired')
    process.env.DSH_INSPECTOR_CANARY = sentinel
  })

  afterEach(async () => {
    delete process.env.DSH_INSPECTOR_CANARY
    await rm(sentinelDirectory, { recursive: true, force: true })
  })

  it('leaves no sentinel, so no script, expression, or module body ran', async () => {
    const report = await inspect(fixture('execution-canary'))
    expect(existsSync(sentinel)).toBe(false)
    expect(readdirSync(sentinelDirectory)).toEqual([])
    // The analysis still happened: it found the same hooks it refused to run.
    expect(withCheck(report, 'A1').map(finding => finding.evidence.path).sort())
      .toEqual(['scripts.postinstall', 'scripts.preinstall', 'scripts.prepare'])
    expect(withCheck(report, 'A6').some(finding => finding.severity === 'critical')).toBe(true)
  })

  it('classifies the `disabled` expression without evaluating it', async () => {
    const report = await inspect(fixture('execution-canary'))
    const disabled = withCheck(report, 'A6').find(finding => finding.evidence.path?.endsWith('.disabled') === true)
    expect(disabled?.title).toContain('`disabled`')
    expect(disabled?.detail).toContain('every mount decision')
    expect(existsSync(sentinel)).toBe(false)
  })
})

describe('analysing every fixture', () => {
  const packages = [
    'benign-control', 'disables-approval', 'js-child-process', 'postinstall-script',
    'credential-exfil', 'skill-injection', 'mcp-stdio', 'obfuscated', 'bad-tag',
    'patch-traversal', 'execution-canary', 'phantom-gyp', 'escaped-identifiers',
  ]

  it('never spawns a process and never writes a file', async () => {
    for (const name of packages) {
      // Both mocks throw on use, so completing the loop is the assertion.
      await expect(inspect(fixture(name))).resolves.toBeTruthy()
    }
  })
})
