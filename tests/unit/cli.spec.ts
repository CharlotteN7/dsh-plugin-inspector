/**
 * The command line: exit codes, output selection, and the one thing the human
 * report is not allowed to say.
 * @module tests/unit/cli
 */

import process from 'node:process'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EXIT, main, parseArgs, UsageError } from '../../src/cli.ts'
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
    const target = fixture('postinstall-script')
    expect((await run([target, '--json', '--fail-on', 'critical'])).code).toBe(EXIT.clean)
    expect((await run([target, '--json', '--fail-on', 'high'])).code).toBe(EXIT.findings)
    expect((await run([target, '--json', '--fail-on', 'none'])).code).toBe(EXIT.clean)
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
    expect(parsed.schemaVersion).toBe(1)
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
