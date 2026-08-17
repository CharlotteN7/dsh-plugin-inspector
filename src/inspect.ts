/**
 * Orchestration: decode the package once, run the three tiers over the decoded
 * form, apply the Tier C downgrade, and assemble the report.
 *
 * This module is the only place that reads the package and the only place that
 * decides confidence. Nothing here — and nothing it calls — imports, requires,
 * spawns, or evaluates anything from the analysed package. The only `Function`
 * constructed anywhere in this tool is the parse-only compile in
 * `cordis-yaml.ts`, and its result is discarded without being called.
 * @module dsh-plugin-inspector/inspect
 */

import { readFileSync } from 'node:fs'
import {
  EXPRESSION_CLASSES,
  PatchParseError,
  parsePatchDocument,
  type ExpressionClass,
  type PatchDocument,
} from './cordis-yaml.ts'
import { isCordisConfigFile, isModelVisibleText, isSourceFile, normalizePackagePath } from './files.ts'
import { HARNESS_REFERENCE } from './knowledge.ts'
import { parseManifest } from './manifest.ts'
import {
  SEVERITY_RANK,
  aggregateFindings,
  compareFindings,
  summarize,
  type Confidence,
  type Facts,
  type Finding,
  type RegistryProvenance,
  type Report,
  type Severity,
} from './model.ts'
import { loadSource, type PluginSource } from './source.ts'
import type { CheckInput, PatchFailure } from './checks/input.ts'
import { runTierA } from './checks/tier-a.ts'
import { runTierB } from './checks/tier-b.ts'
import { NON_DEGRADING_CHECKS, runTierC } from './checks/tier-c.ts'

/**
 * This tool's own version, reported in the JSON document, by `--version`, and
 * in the recorded ecosystem measurement.
 *
 * Read from this package's own `package.json` rather than written down a second
 * time. A constant is a copy that only a release checklist keeps honest, and it
 * stopped being honest for two releases: every report claimed `0.1.0` while the
 * published package was `0.2.1`. The manifest sits one directory above this
 * module in the source tree, in `lib/` after a build, and in the published
 * tarball, so the same relative path resolves in all three.
 */
export const TOOL_VERSION: string = (
  JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }
).version

/** This tool's package name, reported in the JSON document. */
export const TOOL_NAME = 'dsh-plugin-inspector'

/**
 * Locate the one Cordis patch layer that actually mounts.
 *
 * `dsh.bundle.patch` is the whole of it. The launcher reads that key and no
 * other (`packages/boot/app-boot/src/profile.ts`), so a file named
 * `cordis.patch.yml` sitting anywhere else in the package is a document, an
 * example, or a test fixture — not a layer. Treating those as mounted is how a
 * tool comes to report `[critical] disables the core row "approval"` about a
 * package that mounts nothing at all.
 * @param source - the decoded package.
 * @param declaredPatch - the `dsh.bundle.patch` value, already normalised.
 * @returns the mounted layer's path, and every other cordis YAML file.
 */
function patchFiles(
  source: PluginSource, declaredPatch: string | null,
): { mounted: string | null, others: readonly string[] } {
  const candidates = [...source.files.keys()].filter(isCordisConfigFile).sort()
  const mounted = declaredPatch !== null && source.files.has(declaredPatch) ? declaredPatch : null
  return { mounted, others: candidates.filter(path => path !== mounted) }
}

/**
 * Tally the `!!js` inventory by what each expression reaches. The inventory is
 * a fact — a constant or a service read in a config value is what the shipped
 * bundles are made of — and only the classes with reach become findings.
 * @param patches - the parsed patch layers.
 * @returns one count per classification.
 */
function tallyExpressions(patches: readonly PatchDocument[]): Record<ExpressionClass, number> {
  const tally = Object.fromEntries(EXPRESSION_CLASSES.map(name => [name, 0])) as Record<ExpressionClass, number>
  for (const patch of patches) {
    for (const site of patch.expressions) tally[site.classification] += 1
  }
  return tally
}

/**
 * Lower a Tier B confidence when Tier C fired. A Tier B positive stays true —
 * the tool saw what it saw — but it is no longer a `high`-confidence reading of
 * the package as a whole.
 * @param confidence - the check's own confidence.
 * @param degraded - whether any Tier C check fired.
 * @returns the effective confidence.
 */
function downgrade(confidence: Confidence, degraded: boolean): Confidence {
  if (!degraded || confidence !== 'high') return confidence
  return 'moderate'
}

/**
 * Inspect a plugin package on disk.
 *
 * Nothing on this path opens a socket: neither this module nor anything it
 * imports can reach the registry, which is what makes "a directory or tarball
 * scan never fetches" structural rather than a promise.
 * @param target - a plugin directory, or a `.tgz` / `.tar.gz` npm tarball.
 * @returns the complete report.
 * @throws SourceError or ManifestError when the target cannot be analysed at all.
 */
export async function inspect(target: string): Promise<Report> {
  return analyze(await loadSource(target))
}

/**
 * Run every check over an already-decoded package.
 * @param source - the decoded package.
 * @param registry - provenance, when the bytes were fetched from a registry.
 * @returns the complete report.
 * @throws ManifestError when the manifest cannot be read.
 */
export function analyze(source: PluginSource, registry?: RegistryProvenance): Report {
  const manifest = parseManifest(source.files.get('package.json') ?? '')
  const declared = manifest.dsh.bundle?.patch
  const mountsAsBundle = declared !== undefined
  const declaredPatch = declared === undefined ? null : normalizePackagePath(declared)
  const { mounted, others } = patchFiles(source, declaredPatch)

  const patches: PatchDocument[] = []
  const patchFailures: PatchFailure[] = []
  if (mounted !== null) {
    const text = source.files.get(mounted) ?? ''
    try {
      patches.push(parsePatchDocument(mounted, text))
    } catch (error) {
      if (!(error instanceof PatchParseError)) throw error
      patchFailures.push({ file: mounted, error })
    }
  }

  const sourceFiles = [...source.files.keys()].filter(isSourceFile).sort()
  const modelVisibleFiles = [...source.files.keys()].filter(isModelVisibleText).sort()
  const input: CheckInput = {
    source,
    manifest,
    mountsAsBundle,
    patches,
    patchFailures,
    unmountedPatchFiles: others,
    sourceFiles,
    modelVisibleFiles,
  }

  const tierC = runTierC(input)
  const unreadable = tierC.filter(finding => !NON_DEGRADING_CHECKS.has(finding.checkId))
  const degraded = unreadable.length > 0
  const raw = [
    ...runTierA(input),
    ...runTierB(input).map(finding => ({ ...finding, confidence: downgrade(finding.confidence, degraded) })),
    ...tierC,
  ]
  // Aggregate before sorting: the report is a list of decisions, one per check
  // per subject, and the count travels inside the finding. A package importing
  // `node:fs` from eleven files states that once.
  const findings = aggregateFindings(raw).sort(compareFindings)

  const facts: Facts = {
    packageName: manifest.name,
    packageVersion: manifest.version,
    license: manifest.license,
    mountsAsBundle,
    bundlePatchPath: declared ?? null,
    shipsClientBundle: manifest.dsh.client !== undefined && manifest.exportPaths.includes('./client'),
    profileBundles: manifest.dsh.profile?.bundles ?? [],
    binNames: manifest.binNames,
    insertedRows: patches.flatMap(patch => patch.inserts.map(row => ({
      id: row.id ?? '(unnamed)',
      ...row.name === null ? {} : { name: row.name },
    }))),
    targetedRows: [...new Set(patches.flatMap(patch => patch.overrides.map(override => override.id)))].sort(),
    jsExpressions: tallyExpressions(patches),
    unmountedPatchFiles: others,
    dependencies: Object.keys(manifest.dependencies).sort(),
    peerDependencies: Object.keys(manifest.peerDependencies).sort(),
    modelVisibleFiles,
    filesRead: source.files.size,
    bytesRead: source.bytesRead,
    sourceFilesParsed: sourceFiles.length,
    publishBasis: source.publishBasis,
    unpublishedFiles: source.unpublishedFiles,
  }

  return {
    schemaVersion: 2,
    tool: { name: TOOL_NAME, version: TOOL_VERSION, harnessReference: HARNESS_REFERENCE },
    target: { kind: source.kind, path: source.path, ...registry === undefined ? {} : { registry } },
    facts,
    analysis: {
      integrity: degraded ? 'degraded' : 'complete',
      negativesReliable: !degraded,
      degradedBy: [...new Set(unreadable.map(finding => finding.checkId))].sort(),
      filesSkipped: source.skipped,
    },
    summary: summarize(findings),
    findings,
  }
}

/**
 * Whether a report should fail a CI gate.
 * @param report - the report.
 * @param threshold - the lowest severity that fails, or `none` to never fail.
 * @returns true when at least one finding is at or above the threshold.
 */
export function exceedsThreshold(report: Report, threshold: Severity | 'none'): boolean {
  if (threshold === 'none') return false
  return report.findings.some(finding => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold])
}
