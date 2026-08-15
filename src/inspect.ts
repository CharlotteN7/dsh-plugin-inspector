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

import { PatchParseError, parsePatchDocument, type PatchDocument } from './cordis-yaml.ts'
import { isCordisConfigFile, isModelVisibleText, isSourceFile } from './files.ts'
import { parseManifest } from './manifest.ts'
import {
  SEVERITY_RANK,
  compareFindings,
  summarize,
  type Confidence,
  type Facts,
  type Finding,
  type Report,
  type Severity,
} from './model.ts'
import { loadSource, type PluginSource } from './source.ts'
import type { CheckInput, PatchFailure } from './checks/input.ts'
import { runTierA } from './checks/tier-a.ts'
import { runTierB } from './checks/tier-b.ts'
import { runTierC } from './checks/tier-c.ts'

/** This tool's own version, reported in the JSON document. */
export const TOOL_VERSION = '0.1.0'

/** This tool's package name, reported in the JSON document. */
export const TOOL_NAME = 'dsh-plugin-inspector'

/**
 * Locate every Cordis patch layer the package ships. The declared
 * `dsh.bundle.patch` is what actually mounts; other cordis YAML files in the
 * package are analysed too, because a plugin frequently ships an example layer
 * that a user is invited to copy into their profile.
 * @param source - the decoded package.
 * @param declaredPatch - the `dsh.bundle.patch` value, already normalised.
 * @returns package-relative paths, the mounted layer first.
 */
function patchFiles(source: PluginSource, declaredPatch: string | null): string[] {
  const candidates = [...source.files.keys()].filter(isCordisConfigFile).sort()
  if (declaredPatch === null || !source.files.has(declaredPatch)) return candidates
  return [declaredPatch, ...candidates.filter(path => path !== declaredPatch)]
}

/**
 * Normalise a manifest-declared relative path, or return `null` when it leaves
 * the package. Tier A reports the escape; this only needs to not follow it.
 * @param declared - the manifest value.
 * @returns the package-relative path, or `null`.
 */
function normalizeDeclaredPath(declared: string | undefined): string | null {
  if (declared === undefined) return null
  if (declared.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(declared)) return null
  const segments: string[] = []
  for (const segment of declared.split(/[\\/]/)) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      if (segments.length === 0) return null
      segments.pop()
      continue
    }
    segments.push(segment)
  }
  return segments.join('/')
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
 * Inspect a plugin package.
 * @param target - a plugin directory, or a `.tgz` / `.tar.gz` npm tarball.
 * @returns the complete report.
 * @throws SourceError or ManifestError when the target cannot be analysed at all.
 */
export async function inspect(target: string): Promise<Report> {
  const source = await loadSource(target)
  const manifest = parseManifest(source.files.get('package.json') ?? '')
  const declaredPatch = normalizeDeclaredPath(manifest.dsh.bundle?.patch)

  const patches: PatchDocument[] = []
  const patchFailures: PatchFailure[] = []
  for (const file of patchFiles(source, declaredPatch)) {
    const text = source.files.get(file)
    if (text === undefined) continue
    try {
      patches.push(parsePatchDocument(file, text))
    } catch (error) {
      if (!(error instanceof PatchParseError)) throw error
      patchFailures.push({ file, error })
    }
  }

  const sourceFiles = [...source.files.keys()].filter(isSourceFile).sort()
  const modelVisibleFiles = [...source.files.keys()].filter(isModelVisibleText).sort()
  const input: CheckInput = { source, manifest, patches, patchFailures, sourceFiles, modelVisibleFiles }

  const tierC = runTierC(input)
  const degraded = tierC.length > 0
  const raw = [
    ...runTierA(input),
    ...runTierB(input).map(finding => ({ ...finding, confidence: downgrade(finding.confidence, degraded) })),
    ...tierC,
  ]
  const findings = [...raw].sort(compareFindings)

  const facts: Facts = {
    packageName: manifest.name,
    packageVersion: manifest.version,
    license: manifest.license,
    mountsAsBundle: manifest.dsh.bundle?.patch !== undefined,
    bundlePatchPath: manifest.dsh.bundle?.patch ?? null,
    shipsClientBundle: manifest.dsh.client !== undefined && manifest.exportPaths.includes('./client'),
    insertedRows: patches.flatMap(patch => patch.inserts.map(row => ({
      id: row.id ?? '(unnamed)',
      ...row.name === null ? {} : { name: row.name },
    }))),
    targetedRows: [...new Set(patches.flatMap(patch => patch.overrides.map(override => override.id)))].sort(),
    dependencies: Object.keys(manifest.dependencies).sort(),
    peerDependencies: Object.keys(manifest.peerDependencies).sort(),
    modelVisibleFiles,
    filesRead: source.files.size,
    bytesRead: source.bytesRead,
    sourceFilesParsed: sourceFiles.length,
  }

  return {
    schemaVersion: 1,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    target: { kind: source.kind, path: source.path },
    facts,
    analysis: {
      integrity: degraded ? 'degraded' : 'complete',
      negativesReliable: !degraded,
      degradedBy: [...new Set(tierC.map(finding => finding.checkId))].sort(),
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
