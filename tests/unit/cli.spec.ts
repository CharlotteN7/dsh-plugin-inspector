/**
 * The command line: exit codes, output selection, and the one thing the human
 * report is not allowed to say.
 * @module tests/unit/cli
 */

import process from 'node:process'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EXIT, main, parseArgs, reportFatal, UsageError } from '../../src/cli.ts'
import { inspect } from '../../src/inspect.ts'
import { renderHuman, renderJson } from '../../src/report.ts'
import { fixture } from './fixtures.ts'

/**
 * Run the CLI with stdout and stderr captured.
 * @param argv - the arguments.
 * @returns the exit code and both streams.
 */
async function run(argv: readonly string[]): Promise<{ code: number, out: string, err: string }> {
  let out = ''
  let err = ''
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    out += String(chunk)
    return true
  })
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    err += String(chunk)
    return true
  })
  try {
    return { code: await main(argv), out, err }
  } finally {
    stdout.mockRestore()
    stderr.mockRestore()
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

/**
 * Collapse whitespace so an assertion on a sentence is not defeated by the
 * report's word wrapping.
 * @param text - the rendered report.
 * @returns the text on one line.
 */
function flat(text: string): string {
  return text.replace(/\s+/g, ' ')
}

describe('exit codes', () => {
  it('separates a clean run, a gated run, and a broken analysis', async () => {
    expect((await run([fixture('benign-control'), '--json'])).code).toBe(EXIT.clean)
    expect((await run([fixture('disables-approval'), '--json'])).code).toBe(EXIT.findings)
    expect((await run(['/definitely/not/here'])).code).toBe(EXIT.unanalysable)
  })

  it('honours --fail-on, including turning the gate off', async () => {
    // skill-injection's worst finding is high, so the gate moves between the
    // three settings rather than sitting on one side of all of them.
    const target = fixture('skill-injection')
    expect((await run([target, '--json', '--fail-on', 'critical'])).code).toBe(EXIT.clean)
    expect((await run([target, '--json', '--fail-on', 'high'])).code).toBe(EXIT.findings)
    expect((await run([target, '--json', '--fail-on', 'none'])).code).toBe(EXIT.clean)
  })

  it('leaves with 2 for a failure no `catch` could reach, never with 1', () => {
    // A RangeError raised inside a stream's 'end' handler is thrown at an
    // EventEmitter and walks past every try/catch in the program. Node's
    // default handler then exits 1, which in this tool's contract means
    // "analysis completed, findings at or above --fail-on" — a crash read as a
    // verdict, which is the exact confusion code 2 exists to prevent.
    let err = ''
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      err += String(chunk)
      return true
    })
    try {
      expect(reportFatal(new RangeError('Array buffer allocation failed'))).toBe(EXIT.unanalysable)
    } finally {
      stderr.mockRestore()
    }
    expect(err).toContain('could not be completed')
    expect(err).toContain('Array buffer allocation failed')
  })

  it('treats a malformed command line as unanalysable, never as clean', async () => {
    const result = await run(['--fail-on', 'catastrophic', fixture('benign-control')])
    expect(result.code).toBe(EXIT.unanalysable)
    expect(result.err).toContain('--fail-on must be one of')
  })
})

describe('argument parsing', () => {
  it('rejects an unknown option and a second target', () => {
    expect(() => parseArgs(['--nope', 'x'])).toThrow(UsageError)
    expect(() => parseArgs(['a', 'b'])).toThrow(/only one target/)
    expect(() => parseArgs([])).toThrow(/target directory or tarball is required/)
  })

  it('keeps fetching opt-in: --from-npm is never combined with, or inferred from, a path', () => {
    expect(parseArgs(['--from-npm', 'dsh-thing@1.0.0'])).toMatchObject({
      target: null, fromNpm: 'dsh-thing@1.0.0', registry: 'https://registry.npmjs.org',
    })
    expect(parseArgs(['./plugin'])).toMatchObject({ target: './plugin', fromNpm: null })
    expect(() => parseArgs(['--from-npm', 'a', './plugin'])).toThrow(/cannot be combined with a local target/)
    expect(() => parseArgs(['--from-npm'])).toThrow(/--from-npm needs a value/)
    expect(() => parseArgs(['--from-npm', 'a', '--from-npm', 'b'])).toThrow(/only one package/)
    expect(() => parseArgs(['--registry'])).toThrow(/--registry needs a value/)
  })

  it('returns null for --help and --version, which are not analyses', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true)
    expect(parseArgs(['--help'])).toBeNull()
    expect(parseArgs(['--version'])).toBeNull()
    stdout.mockRestore()
  })
})

describe('output', () => {
  it('emits parseable JSON under --json', async () => {
    const result = await run([fixture('mcp-stdio'), '--json'])
    const parsed = JSON.parse(result.out) as { schemaVersion: number, findings: unknown[] }
    expect(parsed.schemaVersion).toBe(2)
    expect(parsed.findings.length).toBeGreaterThan(0)
  })

  it('produces byte-identical JSON on repeated runs', async () => {
    const first = await run([fixture('skill-injection'), '--json'])
    const second = await run([fixture('skill-injection'), '--json'])
    expect(first.out).toBe(second.out)
  })

  it('leads the human report with what the plugin declares', async () => {
    const result = await run([fixture('mcp-stdio'), '--no-color'])
    expect(result.out).toContain('What this plugin declares')
    expect(result.out).toContain('mounted layer')
  })
})

describe('the human report on a package it could not read', () => {
  it('refuses to say nothing was found', async () => {
    const report = await inspect(fixture('obfuscated'))
    const text = flat(renderHuman(report, false))
    expect(text).toContain('Analysis is degraded')
    expect(text).toContain('This report does not say the package is clean')
    expect(text).not.toContain('No findings')
  })

  it('qualifies even a clean result', async () => {
    const report = await inspect(fixture('benign-control'))
    const text = flat(renderHuman(report, false))
    expect(text).toContain('No findings.')
    expect(text).toContain('not a statement that the package is safe')
    expect(text).toContain('does not read transitive dependencies')
  })

  it('renders JSON ending in exactly one newline', async () => {
    const report = await inspect(fixture('benign-control'))
    const text = renderJson(report)
    expect(text.endsWith('}\n')).toBe(true)
    expect(text.endsWith('}\n\n')).toBe(false)
  })
})
