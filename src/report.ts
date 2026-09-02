/**
 * Rendering a report for a person and for a machine.
 *
 * The human renderer has one rule it is not allowed to break: when
 * `analysis.negativesReliable` is false it must not print a clean bill. Saying
 * "no findings" about a package the tool could not read would be worse than
 * printing nothing at all, so the degraded banner replaces that line rather
 * than accompanying it.
 * @module dsh-plugin-inspector/report
 */

import type { ProvenanceFact, ProvenanceGap } from './attestation.ts'
import { SEVERITIES, type Finding, type Report, type Severity } from './model.ts'

/** ANSI colour per severity, and the reset. */
const COLOR: Readonly<Record<Severity | 'reset' | 'dim' | 'bold', string>> = {
  critical: '\u001b[1;31m',
  high: '\u001b[31m',
  medium: '\u001b[33m',
  low: '\u001b[36m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  reset: '\u001b[0m',
}

/** Indent that lines a wrapped fact value up under the first one. */
const CONTINUATION = `\n${' '.repeat(18)}`

/** What each unchecked claim means, spelled out rather than left as a key. */
const GAP_MEANING: Readonly<Record<ProvenanceGap, string>> = {
  'certificate-chain': 'that the signing certificate is Sigstore\'s — this tool carries no trust root, so a '
    + 'registry serving a doctored bundle passes every check above',
  'transparency-log': 'the Rekor transparency-log inclusion proof in the bundle, which needs the same trust root',
  'builder-identity': 'the signer identity, because the statement names no GitHub Actions workflow to compare the '
    + 'certificate against',
}

/** How the human report labels each severity. */
const LABEL: Readonly<Record<Severity, string>> = {
  critical: 'CRITICAL',
  high: 'HIGH    ',
  medium: 'MEDIUM  ',
  low: 'LOW     ',
}

/**
 * Serialise the report as stable JSON. Key order is fixed by the object
 * literals in `inspect.ts` and findings are pre-sorted, so two runs over the
 * same input produce byte-identical output.
 * @param report - the report.
 * @returns pretty-printed JSON with a trailing newline.
 */
export function renderJson(report: Report): string {
  return `${JSON.stringify(report, null, 2)}\n`
}

/**
 * Render one finding as an indented block.
 * @param finding - the finding.
 * @param paint - the colouring function.
 * @returns the rendered lines.
 */
function renderFinding(finding: Finding, paint: (code: string, text: string) => string): string[] {
  const count = finding.occurrences > 1 ? ` ${paint('dim', `(×${finding.occurrences})`)}` : ''
  const lines = [
    `${paint(finding.severity, LABEL[finding.severity])}  ${paint('bold', finding.title)}${count}`,
    `          ${paint('dim', `${finding.checkId} ${finding.name} · tier ${finding.tier} · confidence ${finding.confidence}`)}`,
  ]
  for (const example of finding.examples) lines.push(`          ${paint('dim', locate(example))}`)
  if (finding.occurrences > finding.examples.length) {
    lines.push(`          ${paint('dim', `… and ${finding.occurrences - finding.examples.length} more site(s)`)}`)
  }
  if (finding.evidence.snippet !== undefined) lines.push(`          ${paint('dim', `> ${finding.evidence.snippet}`)}`)
  for (const line of wrap(finding.detail, 88)) lines.push(`          ${line}`)
  if (finding.bypass !== null) lines.push(`          ${paint('dim', `bypass: ${finding.bypass}`)}`)
  lines.push('')
  return lines
}

/**
 * Render one example site as `file:locator`.
 * @param evidence - the site.
 * @returns the location.
 */
function locate(evidence: Finding['evidence']): string {
  return evidence.path === undefined ? evidence.file : `${evidence.file}:${evidence.path}`
}

/**
 * Wrap prose to a column without breaking words.
 * @param text - the prose.
 * @param width - the maximum line length.
 * @returns the wrapped lines.
 */
function wrap(text: string, width: number): string[] {
  const lines: string[] = []
  let current = ''
  for (const word of text.split(/\s+/)) {
    if (current === '') {
      current = word
    } else if (current.length + 1 + word.length <= width) {
      current = `${current} ${word}`
    } else {
      lines.push(current)
      current = word
    }
  }
  /* v8 ignore next -- every wrapped string is a finding's detail, and none is empty. */
  if (current !== '') lines.push(current)
  return lines
}

/**
 * Summarise the mounted layer's `!!js` inventory, dropping the classes that
 * scored nothing so the line stays readable.
 * @param tally - one count per classification.
 * @returns the summary line.
 */
function describeExpressions(tally: Readonly<Record<string, number>>): string {
  const present = Object.entries(tally).filter(([, count]) => count > 0)
  if (present.length === 0) return 'none'
  return present.map(([name, count]) => `${count} ${name}`).join(', ')
}

/**
 * Say which files were analysed and, in directory mode, how many were left out
 * because npm would not publish them.
 * @param facts - the report's facts.
 * @returns the description.
 */
function describeFileSet(facts: Report['facts']): string {
  if (facts.publishBasis === 'tarball') return 'the tarball as published'
  const basis = facts.publishBasis === 'files-allowlist'
    ? 'the package.json `files` allowlist'
    : 'npm defaults over .npmignore/.gitignore'
  return `working tree narrowed to what npm would publish, by ${basis}`
    + ` (${facts.unpublishedFiles} unpublished file(s) not read)`
}

/**
 * Say what the registry attested about this tarball's build origin, and — with
 * equal prominence — what of that was checked here and what was not.
 *
 * The report is not allowed to let a reader mistake one for the other. "The
 * registry told me a claim exists" and "I checked the claim" are different
 * statements, and the second is only partly true: the digest, the package
 * name, the DSSE signature and the certificate's own identity are checked, and
 * whether the certificate belongs to Sigstore is not. So the `not checked` row
 * is printed whenever the `checked` row is, never as a footnote and never
 * conditionally.
 * @param provenance - the fact.
 * @returns the rows to print.
 */
function renderProvenance(provenance: ProvenanceFact): [string, string][] {
  if (provenance.state === 'unavailable') {
    return [['provenance', `not readable here — ${provenance.reason}`]]
  }
  if (provenance.state === 'absent') {
    return [['provenance',
      'none — the registry published no build provenance for this version, which most published packages do not']]
  }
  if (provenance.state === 'unreadable') {
    return [['provenance', `the registry says this version has one and it could not be read — ${provenance.reason}`]]
  }
  const origin = `${provenance.sourceRepository ?? 'an unnamed repository'}`
    + `${provenance.sourceCommit === null ? '' : ` @ ${provenance.sourceCommit}`}`
    + `${provenance.sourceRef === null ? '' : ` (${provenance.sourceRef})`}`
  return [
    ['provenance', provenance.state === 'attested'
      ? `attested to ${origin}`
      : `ATTESTED TO ${origin}, AND THE ATTESTATION DOES NOT CHECK OUT`],
    ['built by', `${provenance.workflow ?? 'an unnamed workflow'}`
      + `${provenance.builder === null ? '' : ` on ${provenance.builder}`}`],
    ['checked', provenance.checks
      .map(check => `${check.passed ? 'ok  ' : 'FAIL'} ${check.name} — ${check.detail}`)
      .join(CONTINUATION)],
    ['not checked', provenance.notChecked.map(gap => GAP_MEANING[gap]).join(CONTINUATION)],
  ]
}

/**
 * Render the "what does this plugin do" section, which is printed whether or
 * not there are findings.
 * @param report - the report.
 * @param paint - the colouring function.
 * @returns the rendered lines.
 */
function renderFacts(report: Report, paint: (code: string, text: string) => string): string[] {
  const { facts } = report
  const registry = report.target.registry
  const rows: [string, string][] = [
    ['package', `${facts.packageName}@${facts.packageVersion}${facts.license === null ? '' : ` (${facts.license})`}`],
    ['read from', `${report.target.kind} ${report.target.path}`],
    ...registry === undefined
      ? []
      : [
          ['fetched from', `${registry.tarball} (${registry.tarballBytes} bytes, never written to disk)`] as [string, string],
          // Which field matched is not cosmetic: `dist.shasum` is SHA-1 and is
          // only reached on packages published before npm 5, so naming
          // `dist.integrity` there would report a stronger check than ran.
          ['verified', `${registry.digest} matched `
            + `${registry.algorithm === 'sha1' ? 'dist.shasum' : 'dist.integrity'} before anything parsed it`] as [string, string],
          ['install script', registry.hasInstallScript
            ? 'yes — the registry marks this package as running one at install time'
            : 'no — the registry does not mark this package as running one'] as [string, string],
        ],
    ...renderProvenance(facts.provenance),
    /* v8 ignore start -- `mountsAsBundle` is true exactly when the manifest declared a path. */
    ['mounted layer', facts.mountsAsBundle
      ? `yes — dsh.bundle.patch = ${facts.bundlePatchPath ?? '?'} (imported into the harness process at the agent's uid)`
      : 'no — installs as a plain library, and dsh plugin add prints a warning saying so'],
    /* v8 ignore stop */
    ['browser bundle', facts.shipsClientBundle ? 'yes — dsh.client with an ./client export, executed in the user\'s browser' : 'no'],
    ['rows inserted', facts.insertedRows.length === 0
      ? 'none'
      : facts.insertedRows.map(row => `${row.id}${row.name === undefined ? '' : ` → ${row.name}`}`).join(CONTINUATION)],
    ['rows modified', facts.targetedRows.length === 0 ? 'none' : facts.targetedRows.join(', ')],
    ['!!js in layer', describeExpressions(facts.jsExpressions)],
    ['other layers', facts.unmountedPatchFiles.length === 0
      ? 'none'
      : `${facts.unmountedPatchFiles.join(', ')} (shipped, mounted by no manifest key)`],
    ['installs', facts.binNames.length === 0 ? 'no commands' : facts.binNames.join(', ')],
    ['dependencies', facts.dependencies.length === 0 ? 'none' : facts.dependencies.join(', ')],
    ['model-visible', facts.modelVisibleFiles.length === 0 ? 'none' : facts.modelVisibleFiles.join(', ')],
    ['analysed', `${facts.filesRead} files, ${facts.sourceFilesParsed} parsed as source, ${facts.bytesRead} bytes`],
    ['file set', describeFileSet(facts)],
    ['checked against', `DeepSeek Harness ${report.tool.harnessReference}`],
  ]
  const lines = [paint('bold', 'What this plugin declares'), '']
  for (const [key, value] of rows) lines.push(`  ${paint('dim', key.padEnd(16))}${value}`)
  lines.push('')
  return lines
}

/**
 * Render the human report.
 * @param report - the report.
 * @param color - whether to emit ANSI colour.
 * @returns the rendered text, ending in a newline.
 */
export function renderHuman(report: Report, color: boolean): string {
  /* v8 ignore start -- every call site passes a literal key of COLOR. */
  const paint = (code: string, text: string): string =>
    color ? `${COLOR[code as keyof typeof COLOR] ?? ''}${text}${COLOR.reset}` : text
  /* v8 ignore stop */
  const lines = ['', ...renderFacts(report, paint)]

  if (report.findings.length > 0) {
    const counts = SEVERITIES
      .filter(severity => report.summary[severity] > 0)
      .map(severity => paint(severity, `${report.summary[severity]} ${severity}`))
      .join(', ')
    lines.push(paint('bold', `Findings (${counts})`), '')
    for (const finding of report.findings) lines.push(...renderFinding(finding, paint))
  }

  if (!report.analysis.negativesReliable) {
    lines.push(
      paint('medium', 'Analysis is degraded.'),
      ...wrap(
        `Tier C fired (${report.analysis.degradedBy.join(', ')}), so parts of this package could not be read the `
        + 'way capability detection needs to read them. The findings above are real — the tool saw what it saw — '
        + 'but the ABSENCE of a capability finding means nothing here. This report does not say the package is clean.',
        88,
      ).map(line => `  ${line}`),
      '',
    )
  } else if (report.findings.length === 0) {
    lines.push(
      paint('bold', 'No findings.'),
      ...wrap(
        'Nothing was found at any severity in the parts that could be read. That is not a statement that the '
        + 'package is safe: this tool reads one version of one package. It does not read transitive dependencies, '
        + 'it cannot see code fetched at runtime, and a later version that gains a dsh.bundle declaration is '
        + 'mounted automatically by the next `dsh plugin update` with no notice.',
        88,
      ).map(line => `  ${line}`),
      '',
    )
  }
  return `${lines.join('\n')}\n`
}
