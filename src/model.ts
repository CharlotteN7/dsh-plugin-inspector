/**
 * The report vocabulary: what a finding is, how findings rank, and what the
 * complete inspection document looks like.
 *
 * The document separates `facts` from `findings` deliberately. Facts carry no
 * severity and answer "what does this plugin do"; findings carry severity and
 * answer "what warrants a decision". A well-behaved plugin has a full facts
 * section and an empty findings section — emitting `dsh.bundle` as a finding
 * would fire on every legitimate plugin and train users to ignore the tool.
 * @module dsh-plugin-inspector/model
 */

/** How much a finding should weigh on an install decision. */
export type Severity = 'critical' | 'high' | 'medium' | 'low'

/**
 * How much the detection itself can be trusted, which is separate from how bad
 * the thing detected is. Tier A reads structured declarations and is always
 * `certain`; Tier B recognises syntax and is downgraded when Tier C fires.
 */
export type Confidence = 'certain' | 'high' | 'moderate' | 'low'

/** Which analysis produced a finding. See PLAN.md §6. */
export type Tier = 'A' | 'B' | 'C'

/** Severity ordering, ascending. Used for `--fail-on` comparison and ranking. */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** Every severity, most severe first — the order the human report prints in. */
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low']

/** Where in the analysed package a finding was observed. */
export interface Evidence {
  /** Package-relative path of the file the finding came from. */
  readonly file: string
  /** A locator inside that file: a YAML path, a JSON pointer, or `line:column`. */
  readonly path?: string
  /** A short verbatim excerpt, truncated and single-lined for display. */
  readonly snippet?: string
}

/** One thing the inspector believes warrants a decision. */
export interface Finding {
  /** Catalogue id from PLAN.md §6, e.g. `A2`. Stable across releases. */
  readonly checkId: string
  /** Machine-readable check name, e.g. `core-row-disabled`. Stable across releases. */
  readonly name: string
  readonly tier: Tier
  readonly severity: Severity
  readonly confidence: Confidence
  /** One line naming what was found. */
  readonly title: string
  /** Why it matters, in terms of what the harness does with the declaration. */
  readonly detail: string
  readonly evidence: Evidence
  /**
   * The one-line evasion for this specific check, or `null` when there is none.
   * Non-null for every Tier B and Tier C check. Carried inside the finding
   * rather than in a footnote so a consumer cannot render the finding without
   * also holding its caveat.
   */
  readonly bypass: string | null
}

/** A Cordis row this patch layer inserts or modifies. */
export interface RowFact {
  readonly id: string
  /** Module specifier for an inserted row; absent when the row only overrides. */
  readonly name?: string
}

/** The "what does this plugin do" half of the report. No severities here. */
export interface Facts {
  readonly packageName: string
  readonly packageVersion: string
  readonly license: string | null
  /** True when `package.json` declares `dsh.bundle.patch` — a mounted patch layer. */
  readonly mountsAsBundle: boolean
  /** The declared patch path, verbatim and unresolved, or `null`. */
  readonly bundlePatchPath: string | null
  /** True when the package declares `dsh.client`, shipping browser-executed code. */
  readonly shipsClientBundle: boolean
  /** Bundles this package's `dsh.profile.bundles` mounts, when it is a profile. */
  readonly profileBundles: readonly string[]
  /** Command names the package installs on the user's PATH. */
  readonly binNames: readonly string[]
  /** Rows this layer adds to the composed profile. */
  readonly insertedRows: readonly RowFact[]
  /** Ids of pre-existing rows this layer modifies by id. */
  readonly targetedRows: readonly string[]
  /** The mounted layer's `!!js` inventory, counted by what each expression reaches. */
  readonly jsExpressions: Readonly<Record<string, number>>
  /**
   * Cordis YAML the package ships that no manifest key mounts. Examples,
   * documentation, and test fixtures live here; none of it is a profile layer.
   */
  readonly unmountedPatchFiles: readonly string[]
  readonly dependencies: readonly string[]
  readonly peerDependencies: readonly string[]
  /** Shipped markdown that can reach the model. See PLAN.md §6.1 reach note. */
  readonly modelVisibleFiles: readonly string[]
  readonly filesRead: number
  readonly bytesRead: number
  readonly sourceFilesParsed: number
  /**
   * How the analysed file set was chosen: a tarball is already the published
   * set, a directory is narrowed to what npm would publish out of it.
   */
  readonly publishBasis: 'files-allowlist' | 'ignore-rules' | 'tarball'
  /** Working-tree files npm would not publish, and which were therefore not read. */
  readonly unpublishedFiles: number
}

/** A file the analyzer chose not to or could not read. */
export interface SkippedFile {
  readonly path: string
  readonly reason: 'size-cap' | 'total-cap' | 'entry-cap' | 'binary' | 'unreadable'
}

/** How much of the package the analyzer could actually see. */
export interface AnalysisIntegrity {
  readonly integrity: 'complete' | 'degraded'
  /**
   * False when any Tier C check fired. A Tier B *negative* carries no
   * information under those conditions, so the report is forbidden from
   * claiming nothing was found.
   */
  readonly negativesReliable: boolean
  /** Check ids that caused the degradation, e.g. `['C2']`. */
  readonly degradedBy: readonly string[]
  readonly filesSkipped: readonly SkippedFile[]
}

/**
 * Where a `--from-npm` target came from and how the bytes were checked.
 *
 * Present only in registry mode. Its presence in a report is the record that
 * this invocation opened a socket, which a directory or tarball scan never
 * does.
 */
export interface RegistryProvenance {
  /** The spec as the user typed it. */
  readonly spec: string
  /** The registry base URL the packument was read from. */
  readonly registry: string
  readonly resolvedVersion: string
  readonly tarball: string
  /** The digest that matched, in the registry's own encoding. */
  readonly digest: string
  /** The algorithm that digest was taken with. `sha1` means no `dist.integrity` was published. */
  readonly algorithm: string
  /** The registry's own flag, read before the tarball was fetched. */
  readonly hasInstallScript: boolean
  readonly metadataBytes: number
  readonly tarballBytes: number
}

/** The complete inspection result, and the shape of `--json` output. */
export interface Report {
  readonly schemaVersion: 1
  readonly tool: {
    readonly name: string
    readonly version: string
    /**
     * The harness version the row inventory, seam keys, and event tables were
     * transcribed from. Every Tier A verdict is a claim about what *that*
     * version does with a declaration, so a report is only as current as this.
     */
    readonly harnessReference: string
  }
  readonly target: {
    readonly kind: 'directory' | 'tarball' | 'registry'
    readonly path: string
    /** Present only when the bytes were fetched from a registry. */
    readonly registry?: RegistryProvenance
  }
  readonly facts: Facts
  readonly analysis: AnalysisIntegrity
  readonly summary: Readonly<Record<Severity, number>>
  readonly findings: readonly Finding[]
}

/**
 * Order findings for display: most severe first, then by tier (A before B
 * before C, since A carries verdicts), then by check id, then by evidence
 * location. Total and deterministic, so two runs diff cleanly.
 * @param a - left finding.
 * @param b - right finding.
 * @returns negative when `a` sorts first.
 */
export function compareFindings(a: Finding, b: Finding): number {
  const bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  if (bySeverity !== 0) return bySeverity
  const byTier = a.tier.localeCompare(b.tier)
  if (byTier !== 0) return byTier
  const byCheck = a.checkId.localeCompare(b.checkId, 'en', { numeric: true })
  if (byCheck !== 0) return byCheck
  const byFile = a.evidence.file.localeCompare(b.evidence.file)
  if (byFile !== 0) return byFile
  return (a.evidence.path ?? '').localeCompare(b.evidence.path ?? '')
}

/**
 * Count findings per severity, including zeroes, so the JSON summary has a
 * fixed key set that consumers can rely on.
 * @param findings - the findings to tally.
 * @returns one count per severity.
 */
export function summarize(findings: readonly Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const finding of findings) summary[finding.severity] += 1
  return summary
}
