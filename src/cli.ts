#!/usr/bin/env node
/**
 * `dsh-inspect` — the command line face of the inspector.
 *
 * Exit codes are the CI contract and are deliberately three-valued:
 * `0` clean, `1` findings at or above the threshold, `2` the analysis could not
 * be performed. A job that cannot tell "the analyzer broke" from "the plugin is
 * clean" is the failure mode that split exists to prevent.
 * @module dsh-plugin-inspector/cli
 */

import process from 'node:process'
import { exceedsThreshold, inspect, TOOL_VERSION } from './inspect.ts'
import { SEVERITY_RANK, type Report, type Severity } from './model.ts'
import { inspectFromNpm } from './npm.ts'
import { DEFAULT_REGISTRY } from './registry.ts'
import { renderHuman, renderJson } from './report.ts'

/** Exit codes this tool uses. */
export const EXIT = {
  clean: 0,
  findings: 1,
  unanalysable: 2,
} as const

const USAGE = `dsh-inspect — know what a DeepSeek Harness plugin does before you install it

Usage
  dsh-inspect <target> [options]
  dsh-inspect --from-npm <name>[@<version>] [options]

  <target>                A plugin directory, or an npm tarball (.tgz / .tar.gz).
                          Nothing in the target is installed, built, or executed.

Options
  --from-npm <spec>       Fetch a published package from the registry, verify its
                          dist.integrity hash, and analyse it in memory. This is
                          the only mode that opens a socket, and it never runs
                          npm, writes to disk, or executes an install script.
  --registry <url>        Registry base URL for --from-npm.
                          (default: ${DEFAULT_REGISTRY})
  --json                  Emit the machine-readable JSON document on stdout.
  --fail-on <severity>    Exit 1 at or above this severity.
                          critical | high | medium | low | none    (default: high)
  --no-color              Plain text, no ANSI.
  --version               Print version.
  --help                  Print this message.

Exit codes
  0  analysis completed, nothing at or above --fail-on
  1  analysis completed, at least one finding at or above --fail-on
  2  analysis could not be performed

To inspect a published package without installing it:
  dsh-inspect --from-npm <name>@<version>
`

/** Options that do not depend on which target form was given. */
interface CommonOptions {
  /** Registry base URL, used only in `--from-npm` mode. */
  readonly registry: string
  readonly json: boolean
  readonly failOn: Severity | 'none'
  readonly color: boolean
}

/**
 * One parsed command line. Exactly one of the two target forms is present:
 * a local path, or a registry spec that opts this invocation into fetching.
 */
type Options = CommonOptions & (
  { readonly target: string, readonly fromNpm: null }
  | { readonly target: null, readonly fromNpm: string }
)

/** Raised for a malformed command line; the message is printed and the tool exits 2. */
export class UsageError extends Error {}

/**
 * Parse argv.
 * @param argv - arguments after the node binary and script path.
 * @returns the parsed options, or `null` when usage or version was requested.
 * @throws UsageError on an unrecognised or incomplete argument.
 */
export function parseArgs(argv: readonly string[]): Options | null {
  let target: string | null = null
  let fromNpm: string | null = null
  let registry = DEFAULT_REGISTRY
  let json = false
  let failOn: Severity | 'none' = 'high'
  let color = process.stdout.isTTY === true
  /**
   * Read the value of an option that takes one.
   * @param index - the option's own position in argv.
   * @param option - the option name, for the error message.
   * @returns the value.
   */
  const value = (index: number, option: string): string => {
    const next = argv[index + 1]
    if (next === undefined) throw new UsageError(`${option} needs a value`)
    return next
  }
  for (let index = 0; index < argv.length; index += 1) {
    /* v8 ignore next -- `index` is bounded by the loop condition. */
    const argument = argv[index] ?? ''
    if (argument === '--help' || argument === '-h') {
      process.stdout.write(USAGE)
      return null
    }
    if (argument === '--version' || argument === '-V') {
      process.stdout.write(`${TOOL_VERSION}\n`)
      return null
    }
    if (argument === '--json') {
      json = true
      continue
    }
    if (argument === '--no-color') {
      color = false
      continue
    }
    if (argument === '--color') {
      color = true
      continue
    }
    if (argument === '--from-npm') {
      if (fromNpm !== null) throw new UsageError('only one package may be fetched at a time')
      fromNpm = value(index, '--from-npm')
      index += 1
      continue
    }
    if (argument === '--registry') {
      registry = value(index, '--registry')
      index += 1
      continue
    }
    if (argument === '--fail-on') {
      const severity = value(index, '--fail-on')
      index += 1
      if (severity !== 'none' && !(severity in SEVERITY_RANK)) {
        throw new UsageError(`--fail-on must be one of critical, high, medium, low, none — got ${severity}`)
      }
      failOn = severity as Severity | 'none'
      continue
    }
    if (argument.startsWith('-')) throw new UsageError(`unknown option ${argument}`)
    if (target !== null) throw new UsageError('only one target may be inspected at a time')
    target = argument
  }
  // Fetching is opt-in per invocation and never a fallback: a mistyped path
  // must not become a registry lookup, and a registry spec must not silently
  // shadow a local directory of the same name.
  if (target !== null && fromNpm !== null) {
    throw new UsageError('--from-npm fetches a published package; it cannot be combined with a local target')
  }
  const common: CommonOptions = { registry, json, failOn, color }
  if (fromNpm !== null) return { ...common, target: null, fromNpm }
  if (target === null) throw new UsageError('a target directory or tarball is required, or --from-npm <name>')
  return { ...common, target, fromNpm: null }
}

/**
 * Run one invocation.
 * @param argv - arguments after the node binary and script path.
 * @returns the process exit code.
 */
export async function main(argv: readonly string[]): Promise<number> {
  let options: Options | null
  try {
    options = parseArgs(argv)
  } catch (error) {
    /* v8 ignore next -- `parseArgs` refuses a command line only with a UsageError. */
    process.stderr.write(`dsh-inspect: ${error instanceof Error ? error.message : String(error)}\n\n${USAGE}`)
    return EXIT.unanalysable
  }
  if (options === null) return EXIT.clean
  try {
    const report: Report = options.fromNpm === null
      ? await inspect(options.target)
      : await inspectFromNpm(options.fromNpm, { registry: options.registry })
    process.stdout.write(options.json ? renderJson(report) : renderHuman(report, options.color))
    return exceedsThreshold(report, options.failOn) ? EXIT.findings : EXIT.clean
  } catch (error) {
    /* v8 ignore next -- every refusal on the read path is a SourceError, ManifestError or RegistryError. */
    process.stderr.write(`dsh-inspect: ${error instanceof Error ? error.message : String(error)}\n`)
    return EXIT.unanalysable
  }
}

/**
 * Report a failure that reached no `try`, and say which exit code it is.
 *
 * Not every failure can be caught where it happens. A `RangeError` raised
 * inside a stream's `'end'` handler is thrown at an EventEmitter, not at the
 * `await`, so it walks past every `catch` in this program and kills the process
 * with Node's default handler — which exits **1**, the code that means "the
 * analysis completed and found something at or above --fail-on". A CI job then
 * reads a crash as a verdict. The whole point of a separate code 2 is that this
 * cannot happen, so the last resort has to be covered too.
 * @param error - whatever was thrown.
 * @returns the exit code to leave with.
 */
export function reportFatal(error: unknown): number {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error)
  process.stderr.write(`dsh-inspect: the analysis could not be completed: ${message}\n`)
  return EXIT.unanalysable
}

/* v8 ignore start -- the process entry, exercised by tests/e2e/cli.e2e.ts against the built CLI rather than by the instrumented unit run. */
if (import.meta.main) {
  process.on('uncaughtException', (error) => {
    process.exit(reportFatal(error))
  })
  process.on('unhandledRejection', (error) => {
    process.exit(reportFatal(error))
  })
  process.exitCode = await main(process.argv.slice(2))
}
/* v8 ignore stop */
