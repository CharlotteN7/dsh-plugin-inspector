/**
 * Measure this tool against the real ecosystem, repeatably.
 *
 * The 0.1 README quoted a number taken over the harness's own bundles and our
 * sibling plugins — twelve targets we wrote or already trusted. That sample
 * cannot tell whether a check is calibrated, because a check that fires on half
 * of npm still looks quiet on it. This script scans published packages instead,
 * and prints the distribution that decides whether the tool can be a gate.
 *
 * Two modes:
 *
 * ```sh
 * node --experimental-strip-types scripts/ecosystem-sweep.ts --discover --size 40
 * node --experimental-strip-types scripts/ecosystem-sweep.ts [--out <file>]
 * ```
 *
 * `--discover` rewrites the corpus from the most-starred repositories carrying
 * the ecosystem's topic and pins every package to the version it resolved to;
 * the default mode scans the pinned corpus. Pinning is what makes a
 * before/after comparison mean anything: an npm version is immutable, so two
 * runs over the same corpus read the same bytes.
 *
 * Every package is fetched through the same integrity-verified path as
 * `--from-npm` and decoded in memory. This script writes no tarball to disk.
 * @module scripts/ecosystem-sweep
 */

import { readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { TOOL_VERSION } from '../src/inspect.ts'
import { SEVERITIES, type Report, type Severity } from '../src/model.ts'
import { inspectFromNpm, precheck } from '../src/npm.ts'
import { DEFAULT_REGISTRY } from '../src/registry.ts'

/** The checked-in corpus, pinned so two runs read the same bytes. */
const CORPUS = fileURLToPath(new URL('./ecosystem-corpus.json', import.meta.url))

/** GitHub's search endpoint, which ranks the topic by stars. */
const GITHUB_SEARCH = 'https://api.github.com/search/repositories'

/** The topic every plugin in the ecosystem is tagged with. */
const TOPIC = 'dsh-plugin'

/** One pinned package. */
interface CorpusEntry {
  readonly name: string
  readonly version: string
  /** Stars on the repository the package was published from, at selection time. */
  readonly stars: number
  /** `owner/name`, when discovery recorded it. */
  readonly repository?: string
}

/** The checked-in corpus file. */
interface Corpus {
  /** How the sample was chosen, in one sentence, for whoever reads the baseline. */
  readonly sample: string
  readonly topic: string
  readonly registry: string
  readonly selectedOn: string
  readonly packages: readonly CorpusEntry[]
}

/** What one package contributed to the distribution. */
interface PackageResult {
  readonly name: string
  readonly version: string
  /** Present when the package could not be fetched or read at all. */
  readonly error?: string
  readonly findings: number
  readonly severities: Readonly<Record<Severity, number>>
  /** How many findings each check produced in this package. */
  readonly checks: Readonly<Record<string, number>>
  readonly degraded: boolean
}

/** The whole measurement. */
interface Baseline {
  readonly tool: string
  readonly measuredOn: string
  readonly sample: string
  readonly corpusSize: number
  readonly scanned: number
  readonly failed: number
  readonly findings: number
  readonly severities: Readonly<Record<Severity, number>>
  readonly cleanPackages: number
  readonly withHighOrCritical: number
  readonly medianFindingsPerPackage: number
  /** Per check: how many findings it produced, and in how many packages it fired. */
  readonly checks: Readonly<Record<string, { readonly findings: number, readonly packages: number }>>
  readonly packages: readonly PackageResult[]
}

/**
 * Read the pinned corpus.
 * @returns the corpus.
 */
function readCorpus(): Corpus {
  return JSON.parse(readFileSync(CORPUS, 'utf8')) as Corpus
}

/**
 * GET a JSON document, waiting out GitHub's search rate limit rather than
 * giving up on it. Unauthenticated search allows ten requests a minute, which
 * one page of results is enough to exhaust; a `GITHUB_TOKEN` in the environment
 * raises that and is used when present.
 * @param url - the absolute URL.
 * @returns the parsed body.
 */
async function getJson(url: string): Promise<unknown> {
  const token = process.env.GITHUB_TOKEN
  const headers: Record<string, string> = {
    accept: 'application/json',
    'user-agent': 'dsh-plugin-inspector',
    ...token === undefined ? {} : { authorization: `Bearer ${token}` },
  }
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await fetch(url, { headers })
    if (response.ok) return response.json()
    if (response.status !== 403 && response.status !== 429) {
      throw new Error(`${url} returned HTTP ${response.status}`)
    }
    const reset = Number(response.headers.get('x-ratelimit-reset') ?? '0') * 1000
    const wait = Math.min(Math.max(reset - Date.now() + 2000, 5000), 90_000)
    process.stderr.write(`  rate limited; waiting ${Math.round(wait / 1000)}s\n`)
    await new Promise(resolve => setTimeout(resolve, wait))
  }
  throw new Error(`${url} stayed rate limited`)
}

/**
 * Rebuild the corpus: the most-starred repositories carrying the ecosystem's
 * topic, narrowed to the ones that publish to npm.
 *
 * Ranked by GitHub rather than hand-picked, because a sample chosen by the
 * tool's author is a sample chosen to make the tool look calibrated. Ranked by
 * stars rather than by downloads because stars are what a user browsing the
 * ecosystem sees, so this is the set most likely to be installed.
 *
 * A repository qualifies when its root `package.json` names a package the
 * registry resolves. Monorepos that publish from a subdirectory therefore drop
 * out, which is a known and recorded gap in the sample rather than a silent
 * one.
 * @param size - how many packages to pin.
 * @returns the new corpus.
 */
async function discover(size: number): Promise<Corpus> {
  const packages: CorpusEntry[] = []
  const skipped: string[] = []
  for (let page = 1; packages.length < size && page <= 6; page += 1) {
    const url = `${GITHUB_SEARCH}?q=${encodeURIComponent(`topic:${TOPIC}`)}&sort=stars&order=desc&per_page=50&page=${page}`
    const body = await getJson(url) as {
      items?: { full_name?: string, stargazers_count?: number, default_branch?: string }[]
    }
    const items = body.items ?? []
    if (items.length === 0) break
    for (const item of items) {
      if (packages.length >= size) break
      const repository = item.full_name
      if (repository === undefined) continue
      const name = await publishedName(repository, item.default_branch ?? 'main')
      if (name === null) {
        skipped.push(repository)
        continue
      }
      let version: string
      try {
        version = (await precheck(name)).version
      } catch {
        skipped.push(repository)
        continue
      }
      packages.push({ name, version, stars: item.stargazers_count ?? 0, repository })
      process.stderr.write(`  pinned ${name}@${version} (${item.stargazers_count ?? 0} stars)\n`)
    }
  }
  process.stderr.write(`  skipped ${skipped.length} repositories that publish no resolvable root package\n`)
  return {
    sample: `the ${packages.length} most-starred GitHub repositories tagged \`${TOPIC}\` that publish a `
      + 'resolvable npm package from their repository root, each pinned to the version that was current then',
    topic: TOPIC,
    registry: DEFAULT_REGISTRY,
    selectedOn: new Date().toISOString().slice(0, 10),
    packages,
  }
}

/**
 * The npm package name a repository's root `package.json` declares, when it
 * declares one and does not mark itself private.
 * @param repository - `owner/name`.
 * @param branch - the default branch.
 * @returns the package name, or `null`.
 */
async function publishedName(repository: string, branch: string): Promise<string | null> {
  const url = `https://raw.githubusercontent.com/${repository}/${branch}/package.json`
  const response = await fetch(url, { headers: { 'user-agent': 'dsh-plugin-inspector' } })
  if (!response.ok) return null
  let manifest: { name?: unknown, private?: unknown }
  try {
    manifest = await response.json() as { name?: unknown, private?: unknown }
  } catch {
    return null
  }
  if (manifest.private === true || typeof manifest.name !== 'string') return null
  return manifest.name
}

/**
 * Inspect one pinned package.
 * @param entry - the package and version.
 * @returns what it contributed, or the reason it contributed nothing.
 */
async function scan(entry: CorpusEntry): Promise<PackageResult> {
  const empty: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  let report: Report
  try {
    report = await inspectFromNpm(`${entry.name}@${entry.version}`)
  } catch (error) {
    return {
      ...entry,
      error: error instanceof Error ? error.message : String(error),
      findings: 0,
      severities: empty,
      checks: {},
      degraded: false,
    }
  }
  const checks: Record<string, number> = {}
  for (const finding of report.findings) checks[finding.checkId] = (checks[finding.checkId] ?? 0) + 1
  return {
    ...entry,
    findings: report.findings.length,
    severities: report.summary,
    checks: Object.fromEntries(Object.entries(checks).sort(([a], [b]) => a.localeCompare(b, 'en', { numeric: true }))),
    degraded: !report.analysis.negativesReliable,
  }
}

/**
 * The middle value of a list of numbers.
 * @param values - the numbers.
 * @returns the median, or 0 for an empty list.
 */
function median(values: readonly number[]): number {
  if (values.length === 0) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  if (sorted.length % 2 === 1) return sorted[middle] ?? 0
  return ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
}

/**
 * Reduce every package result to the distribution.
 * @param corpus - the corpus that was scanned.
 * @param results - one result per package.
 * @returns the baseline.
 */
function summarise(corpus: Corpus, results: readonly PackageResult[]): Baseline {
  const scanned = results.filter(result => result.error === undefined)
  const severities: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  const checks: Record<string, { findings: number, packages: number }> = {}
  for (const result of scanned) {
    for (const severity of SEVERITIES) severities[severity] += result.severities[severity]
    for (const [check, count] of Object.entries(result.checks)) {
      const entry = checks[check] ?? { findings: 0, packages: 0 }
      checks[check] = { findings: entry.findings + count, packages: entry.packages + 1 }
    }
  }
  return {
    tool: TOOL_VERSION,
    measuredOn: new Date().toISOString().slice(0, 10),
    sample: corpus.sample,
    corpusSize: corpus.packages.length,
    scanned: scanned.length,
    failed: results.length - scanned.length,
    findings: scanned.reduce((sum, result) => sum + result.findings, 0),
    severities,
    cleanPackages: scanned.filter(result => result.findings === 0).length,
    withHighOrCritical: scanned.filter(result => result.severities.critical + result.severities.high > 0).length,
    medianFindingsPerPackage: median(scanned.map(result => result.findings)),
    checks: Object.fromEntries(Object.entries(checks).sort(([a], [b]) => a.localeCompare(b, 'en', { numeric: true }))),
    packages: results,
  }
}

/**
 * Print the distribution a person reads.
 * @param baseline - the measurement.
 */
function render(baseline: Baseline): void {
  const lines = [
    '',
    `dsh-plugin-inspector ${baseline.tool} — ecosystem sweep, ${baseline.measuredOn}`,
    `sample: ${baseline.sample}`,
    '',
    `  packages scanned      ${baseline.scanned} of ${baseline.corpusSize}`
      + (baseline.failed > 0 ? ` (${baseline.failed} could not be read)` : ''),
    `  findings              ${baseline.findings}`,
    `  critical              ${baseline.severities.critical}`,
    `  high                  ${baseline.severities.high}`,
    `  medium                ${baseline.severities.medium}`,
    `  low                   ${baseline.severities.low}`,
    `  clean packages        ${baseline.cleanPackages} of ${baseline.scanned}`,
    `  with high or critical ${baseline.withHighOrCritical} of ${baseline.scanned}`
      + ` (${Math.round(baseline.withHighOrCritical * 100 / Math.max(baseline.scanned, 1))}%)`,
    `  median per package    ${baseline.medianFindingsPerPackage}`,
    '',
    '  check   packages  share   findings',
  ]
  for (const [check, counts] of Object.entries(baseline.checks)) {
    const share = Math.round(counts.packages * 100 / Math.max(baseline.scanned, 1))
    lines.push(`  ${check.padEnd(6)}  ${String(counts.packages).padStart(8)}  ${String(share).padStart(4)}%`
      + `  ${String(counts.findings).padStart(8)}`)
  }
  lines.push('')
  for (const result of baseline.packages) {
    if (result.error === undefined) continue
    lines.push(`  could not read ${result.name}@${result.version}: ${result.error}`)
  }
  process.stdout.write(`${lines.join('\n')}\n`)
}

/**
 * Run the sweep.
 * @param argv - arguments after the script path.
 */
async function main(argv: readonly string[]): Promise<void> {
  if (argv.includes('--discover')) {
    const sizeIndex = argv.indexOf('--size')
    const size = sizeIndex < 0 ? 40 : Number(argv[sizeIndex + 1] ?? '40')
    const corpus = await discover(size)
    writeFileSync(CORPUS, `${JSON.stringify(corpus, null, 2)}\n`)
    process.stdout.write(`pinned ${corpus.packages.length} packages into ${CORPUS}\n`)
    return
  }
  if (argv.includes('--pin')) {
    // Move every pin to the version that is current now, keeping the names and
    // the selection they came from. Re-pinning is a deliberate act: the numbers
    // in the README are about the versions in the file, and moving them moves
    // what those numbers describe.
    const current = readCorpus()
    const packages: CorpusEntry[] = []
    for (const entry of current.packages) {
      try {
        packages.push({ ...entry, version: (await precheck(entry.name)).version })
      } catch (error) {
        process.stderr.write(`  keeping ${entry.name}@${entry.version}: `
          + `${error instanceof Error ? error.message : String(error)}\n`)
        packages.push(entry)
      }
    }
    writeFileSync(CORPUS, `${JSON.stringify({ ...current, packages }, null, 2)}\n`)
    process.stdout.write(`re-pinned ${packages.length} packages in ${CORPUS}\n`)
    return
  }
  const corpus = readCorpus()
  const results: PackageResult[] = []
  for (const entry of corpus.packages) {
    const result = await scan(entry)
    results.push(result)
    process.stderr.write(`  ${result.name}@${result.version}: `
      + `${result.error === undefined ? `${result.findings} finding(s)` : result.error}\n`)
  }
  const baseline = summarise(corpus, results)
  render(baseline)
  const outIndex = argv.indexOf('--out')
  if (outIndex >= 0) {
    const out = argv[outIndex + 1]
    if (out === undefined) throw new Error('--out needs a path')
    writeFileSync(out, `${JSON.stringify(baseline, null, 2)}\n`)
    process.stderr.write(`wrote ${out}\n`)
  }
}

await main(process.argv.slice(2))
