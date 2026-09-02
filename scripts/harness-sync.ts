/**
 * Hold `src/knowledge.ts` against a published harness release.
 *
 * Every Tier A verdict is a claim about what one harness version does with a
 * declaration, so a stale table is not a cosmetic problem: a core row that no
 * longer exists produces a verdict about nothing, and a security seam the
 * catalogue has gained but this tool has not is a miss that looks like a clean
 * report. `HARNESS_REFERENCE` says which version the tables describe; this
 * script is what makes that claim checkable rather than remembered.
 *
 * ```sh
 * node --experimental-strip-types scripts/harness-sync.ts            # against `latest`
 * node --experimental-strip-types scripts/harness-sync.ts --release 0.1.1-rc.2
 * ```
 *
 * Exits non-zero when a table and the release disagree, printing the diff in
 * both directions. It reads the published tarballs over the same
 * integrity-verified path `--from-npm` uses, decodes them in memory, and parses
 * the api-catalog with `ts.createSourceFile` — nothing here imports, requires,
 * or evaluates a byte of what it downloads.
 * @module scripts/harness-sync
 */

import process from 'node:process'
import ts from 'typescript'
import { parsePatchDocument } from '../src/cordis-yaml.ts'
import { CORE_ROWS, HARNESS_REFERENCE, SEAM_KEYS, WATERFALL_EVENTS, type BundleName } from '../src/knowledge.ts'
import { fetchVerifiedTarball, parseSpec, resolvePackage } from '../src/registry.ts'
import { loadTarballBuffer } from '../src/source.ts'

/** The bundle packages, each of which ships one patch layer. */
const BUNDLE_PACKAGES: ReadonlyMap<BundleName, string> = new Map([
  ['base', '@deepseek-ai/dsh-base'],
  ['headless', '@deepseek-ai/dsh-headless'],
  ['web-app', '@deepseek-ai/dsh-web-app'],
])

/** The package whose built output carries `SERVICE_API` and `EVENT_API`. */
const CATALOG_PACKAGE = '@deepseek-ai/dsh-tool-cordis'

/**
 * The CLI, whose version names the release every other package is read at.
 *
 * Asking each bundle for its own `latest` reads a different harness: the
 * bundle packages carry dist-tags of their own, and `@deepseek-ai/dsh-base`'s
 * `latest` currently points at `0.0.1-rc.1` — five releases behind the CLI, a
 * different row inventory, and not what anybody has installed. One version,
 * resolved once, is what makes the diff a statement about a release.
 */
const CLI_PACKAGE = '@deepseek-ai/dsh'

/** Where the catalogue lives inside that package's published tarball. */
const CATALOG_ENTRY = 'lib/index.js'

/** Read one published package's files into memory.
 * @param spec - `<name>@<version-or-tag>`.
 * @returns the decoded file map and the version that resolved.
 */
async function fetchPackage(spec: string): Promise<{ version: string, files: ReadonlyMap<string, string> }> {
  const resolved = await resolvePackage(parseSpec(spec))
  const verified = await fetchVerifiedTarball(resolved)
  const source = await loadTarballBuffer(verified.bytes, spec)
  return { version: resolved.version, files: source.files }
}

/** One row as the harness declares it. */
interface HarnessRow {
  readonly module: string
  readonly bundles: BundleName[]
}

/**
 * Read the row inventory out of the three shipped bundle patches.
 * @param release - the version or dist-tag to read.
 * @returns row id to module and inserting bundles, and the bundles' version.
 */
async function readRows(release: string): Promise<{ version: string, rows: Map<string, HarnessRow> }> {
  const rows = new Map<string, HarnessRow>()
  let version = ''
  for (const [bundle, name] of BUNDLE_PACKAGES) {
    const { version: resolved, files } = await fetchPackage(`${name}@${release}`)
    version = resolved
    const text = files.get('cordis.patch.yml')
    if (text === undefined) throw new Error(`${name} ships no cordis.patch.yml`)
    for (const row of parsePatchDocument('cordis.patch.yml', text).inserts) {
      if (row.id === null || row.name === null) continue
      const prior = rows.get(row.id)
      if (prior === undefined) rows.set(row.id, { module: row.name, bundles: [bundle] })
      else prior.bundles.push(bundle)
    }
  }
  return { version, rows }
}

/**
 * Every string-literal value of one property, across every object literal in a
 * named array.
 * @param source - the parsed catalogue module.
 * @param binding - the exported array's name.
 * @param property - the property to read.
 * @param where - an optional filter on the whole object literal.
 * @returns the values, in declaration order.
 */
function literalsIn(
  source: ts.SourceFile,
  binding: string,
  property: string,
  where: (node: ts.ObjectLiteralExpression) => boolean = () => true,
): string[] {
  const found: string[] = []
  const read = (node: ts.ObjectLiteralExpression, key: string): string | null => {
    for (const member of node.properties) {
      if (!ts.isPropertyAssignment(member) || !ts.isIdentifier(member.name) || member.name.text !== key) continue
      if (ts.isStringLiteral(member.initializer)) return member.initializer.text
    }
    return null
  }
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === binding
      && node.initializer !== undefined && ts.isArrayLiteralExpression(node.initializer)) {
      for (const element of node.initializer.elements) {
        if (!ts.isObjectLiteralExpression(element) || !where(element)) continue
        const value = read(element, property)
        if (value !== null) found.push(value)
      }
    }
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(source, visit)
  return found
}

/**
 * Read the seam keys and waterfall event names out of the api-catalog.
 * @param release - the version or dist-tag to read.
 * @returns the two name sets.
 */
async function readCatalog(release: string): Promise<{ seams: string[], waterfalls: string[] }> {
  const { files } = await fetchPackage(`${CATALOG_PACKAGE}@${release}`)
  const text = files.get(CATALOG_ENTRY)
  if (text === undefined) throw new Error(`${CATALOG_PACKAGE} ships no ${CATALOG_ENTRY}`)
  const source = ts.createSourceFile(CATALOG_ENTRY, text, ts.ScriptTarget.ESNext, true, ts.ScriptKind.JS)
  const mode = (node: ts.ObjectLiteralExpression): boolean => node.properties.some(member =>
    ts.isPropertyAssignment(member) && ts.isIdentifier(member.name) && member.name.text === 'mode'
    && ts.isStringLiteral(member.initializer) && member.initializer.text === 'waterfall')
  return {
    seams: literalsIn(source, 'SERVICE_API', 'key'),
    waterfalls: literalsIn(source, 'EVENT_API', 'name', mode),
  }
}

/**
 * Compare one table against the release and describe the difference.
 * @param table - what this tool believes.
 * @param harness - what the release declares.
 * @param what - the table's name, for the report.
 * @returns one line per difference.
 */
function compare(table: readonly string[], harness: readonly string[], what: string): string[] {
  const missing = harness.filter(entry => !table.includes(entry))
  const extra = table.filter(entry => !harness.includes(entry))
  return [
    ...missing.map(entry => `${what}: the release declares \`${entry}\` and the table does not`),
    ...extra.map(entry => `${what}: the table holds \`${entry}\` and the release does not`),
  ]
}

/**
 * One row rendered as a comparable line, so a renamed module or a moved bundle
 * shows up as a difference rather than as a match on the id alone.
 * @param id - the row id.
 * @param row - the row.
 * @returns the line.
 */
function rowLine(id: string, row: { module: string, bundles: readonly BundleName[] }): string {
  const order = [...BUNDLE_PACKAGES.keys()]
  return `${id} → ${row.module} [${[...row.bundles].sort((a, b) => order.indexOf(a) - order.indexOf(b)).join(', ')}]`
}

/** Read the release, diff every table, and report. */
async function main(): Promise<void> {
  const argv = process.argv.slice(2)
  const index = argv.indexOf('--release')
  const requested = index === -1 ? null : argv[index + 1]
  if (index !== -1 && requested === undefined) throw new Error('--release needs a version or dist-tag')
  const release = requested ?? (await resolvePackage(parseSpec(`${CLI_PACKAGE}@latest`))).version

  const { version, rows } = await readRows(release)
  const { seams, waterfalls } = await readCatalog(release)
  const differences = [
    ...compare(
      [...CORE_ROWS].map(([id, row]) => rowLine(id, row)),
      [...rows].map(([id, row]) => rowLine(id, row)),
      'CORE_ROWS',
    ),
    ...compare([...SEAM_KEYS], seams, 'SEAM_KEYS'),
    ...compare([...WATERFALL_EVENTS], waterfalls, 'WATERFALL_EVENTS'),
    ...HARNESS_REFERENCE === version
      ? []
      : [`HARNESS_REFERENCE says \`${HARNESS_REFERENCE}\` and the release is \`${version}\``],
  ]
  process.stdout.write(`knowledge tables vs @deepseek-ai/dsh-base@${version}\n`)
  process.stdout.write(`  rows ${CORE_ROWS.size} / ${rows.size}  seams ${SEAM_KEYS.size} / ${seams.length}`
    + `  waterfalls ${WATERFALL_EVENTS.size} / ${waterfalls.length}\n`)
  if (differences.length === 0) {
    process.stdout.write('  every table is exact against this release\n')
    return
  }
  for (const line of differences) process.stdout.write(`  ${line}\n`)
  process.exitCode = 1
}

await main()
