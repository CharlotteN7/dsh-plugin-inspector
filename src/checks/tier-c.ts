/**
 * Tier C — how much of the package the analyzer could actually read.
 *
 * These checks do not describe the plugin's behavior. They describe the limits
 * of the analysis, and that is why a Tier C hit is a finding rather than a
 * silent internal flag: "we cannot read this" is a legitimate result and the
 * user is entitled to see it.
 *
 * A Tier C hit also has a mechanical consequence. Tier B recognises a whitelist
 * of syntactic shapes, so when code is minified, when identifiers are computed,
 * or when the shipped artifact has no readable source, a Tier B *positive* is
 * still true but a Tier B *negative* means nothing. `inspect.ts` reads the
 * output of this module to lower Tier B confidence and to forbid the report
 * from claiming nothing was found.
 * @module dsh-plugin-inspector/checks/tier-c
 */

import ts from 'typescript'
import { lineColumn, snippet } from '../files.ts'
import type { Finding } from '../model.ts'
import type { CheckInput } from './input.ts'

/** A line longer than this is not written by hand. */
const MINIFIED_LINE_LENGTH = 500

/** Below this many bytes, a low line count says nothing. */
const MINIFICATION_SIZE_FLOOR = 4096

/** Object names whose computed member access is a dispatch, not an array index. */
const DISPATCH_RECEIVERS: ReadonlySet<string> = new Set(['ctx', 'context', 'globalThis', 'global'])

/** Members whose first argument names a seam, an event, or a tool. */
const NAMED_TARGET_CALLEES: ReadonlySet<string> = new Set([
  'on', 'once', 'provide', 'set', 'get', 'emit', 'waterfall', 'bail', 'parallel', 'serial',
])

/**
 * Build one Tier C finding. Confidence is `moderate`: these are heuristics
 * about form, and a hand-written file can legitimately have one long line.
 * @param finding - everything but the fixed fields.
 * @returns the complete finding.
 */
function tierC(finding: Omit<Finding, 'tier' | 'confidence' | 'examples' | 'occurrences'>): Finding {
  return { ...finding, tier: 'C', confidence: 'moderate', examples: [finding.evidence], occurrences: 1 }
}

/** C1 — source that is not written to be read. */
function checkMinification(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const path of input.sourceFiles) {
    const text = input.source.files.get(path)
    /* v8 ignore next -- `sourceFiles` is filtered from `source.files`'s own keys, so the lookup always hits. */
    if (text === undefined) continue
    const lines = text.split('\n')
    const longest = lines.reduce((max, line) => Math.max(max, line.length), 0)
    const dense = text.length >= MINIFICATION_SIZE_FLOOR && lines.length < 5
    // One long line does not make a file unreadable — an embedded prompt or a
    // base64 asset in otherwise ordinary code is one long line, and the
    // harness's own web bundle has one. What makes a file unreadable is when
    // the long lines are most of it.
    const longBytes = lines.filter(line => line.length >= MINIFIED_LINE_LENGTH)
      .reduce((sum, line) => sum + line.length, 0)
    const dominated = longBytes * 2 >= text.length
    if (!dense && !dominated) continue
    findings.push(tierC({
      checkId: 'C1',
      name: 'minified-source',
      subject: 'minified-source',
      severity: 'medium',
      title: 'Ships source that is minified or generated',
      detail: `In \`${path}\` the longest line is ${longest} characters across ${lines.length} line(s), and lines `
        + `that long are ${Math.round(longBytes * 100 / Math.max(text.length, 1))}% of the file. Capability `
        + 'detection reads syntax, and it reads minified syntax no better than a person does. Every Tier B '
        + 'negative for this package is unreliable while a file like this is in it.',
      /* v8 ignore next -- `split` returns at least one element for any string, so the fallback is unreachable. */
      evidence: { file: path, path: '1:1', snippet: snippet(lines[0] ?? '') },
      bypass: 'none — this finding is about the analysis, not about the plugin',
    }))
  }
  return findings
}

/** C2 — names the analyzer cannot resolve without running the code. */
function checkDynamicDispatch(input: CheckInput): Finding[] {
  const findings: Finding[] = []
  for (const path of input.sourceFiles) {
    const text = input.source.files.get(path)
    /* v8 ignore next -- `sourceFiles` is filtered from `source.files`'s own keys, so the lookup always hits. */
    if (text === undefined) continue
    const source = ts.createSourceFile(path, text, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS)
    const report = (node: ts.Node, what: string): void => {
      findings.push(tierC({
        checkId: 'C2',
        name: 'dynamic-dispatch',
        subject: what,
        severity: 'high',
        title: `Shipped source ${what}`,
        detail: 'Every Tier B check matches a literal name. A name assembled at runtime defeats all of them, so no '
          + 'Tier B negative for this package carries any information. A Tier B positive still does — the tool saw '
          + 'what it saw.',
        evidence: {
          file: path,
          path: lineColumn(text, node.getStart(source)),
          snippet: snippet(text.slice(node.getStart(source), node.end)),
        },
        bypass: 'none — this finding is about the analysis, not about the plugin',
      }))
    }
    const isComputed = (node: ts.Node | undefined): boolean =>
      node !== undefined && !ts.isStringLiteral(node) && !ts.isNoSubstitutionTemplateLiteral(node)
    const visit = (node: ts.Node): void => {
      if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression)
        && DISPATCH_RECEIVERS.has(node.expression.text) && isComputed(node.argumentExpression)) {
        report(node, `resolves a member of \`${node.expression.text}\` from a computed name`)
      }
      if (ts.isCallExpression(node)) {
        const callee = node.expression
        const isRequire = ts.isIdentifier(callee) && callee.text === 'require'
        const isImport = callee.kind === ts.SyntaxKind.ImportKeyword
        if ((isRequire || isImport) && isComputed(node.arguments[0])) {
          report(node, 'loads a module from a computed specifier')
        }
        if (ts.isIdentifier(callee) && callee.text === 'atob') {
          report(node, 'decodes a base64 string at runtime')
        }
        if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'from'
          && ts.isIdentifier(callee.expression) && callee.expression.text === 'Buffer'
          && (literalOf(node.arguments[1]) === 'base64' || literalOf(node.arguments[1]) === 'base64url')) {
          report(node, 'decodes a base64 string at runtime')
        }
        if (ts.isPropertyAccessExpression(callee) && NAMED_TARGET_CALLEES.has(callee.name.text)
          && isDispatchReceiver(callee.expression) && isAssembledName(node.arguments[0])) {
          report(node, `passes an assembled name to \`${receiverName(callee.expression)}.${callee.name.text}()\``)
        }
      }
      ts.forEachChild(node, visit)
    }
    ts.forEachChild(source, visit)
  }
  return findings
}

/**
 * Whether an expression names the plugin context.
 *
 * `.set`, `.get`, `.on` and `.emit` are the plugin API's names and also
 * `Map`'s, `Set`'s, and every EventEmitter's. Without this guard the check
 * reads `this.steps.set(\`${turn}:${step}\`, time)` — an ordinary composite Map
 * key — as evasion, which alone degrades the whole report and makes every
 * Tier B negative unreliable. Element access is already guarded this way; this
 * makes the call form agree with it.
 * @param node - the receiver expression.
 * @returns true when the receiver is a known context binding.
 */
function isDispatchReceiver(node: ts.Expression): boolean {
  if (ts.isIdentifier(node)) return DISPATCH_RECEIVERS.has(node.text)
  // `this.ctx.on(…)` and `self.ctx.on(…)` are the same receiver held on a field.
  if (ts.isPropertyAccessExpression(node)) return DISPATCH_RECEIVERS.has(node.name.text)
  return false
}

/**
 * The receiver's own name, for the finding's title.
 * @param node - the receiver expression.
 * @returns the identifier or member name.
 */
function receiverName(node: ts.Expression): string {
  if (ts.isIdentifier(node)) return node.text
  /* v8 ignore start -- only called after `isDispatchReceiver`, which accepts these two forms and no other. */
  if (ts.isPropertyAccessExpression(node)) return node.name.text
  return '?'
  /* v8 ignore stop */
}

/**
 * Whether a node builds a string at runtime rather than naming one. A plain
 * identifier is deliberately excluded: `ctx.on(EVENT_NAME, …)` against a module
 * constant is ordinary code, and treating it as evasion would degrade the
 * analysis of nearly every well-written plugin.
 * @param node - the argument node.
 * @returns true for concatenation, an interpolated template, or a call.
 */
function isAssembledName(node: ts.Node | undefined): boolean {
  if (node === undefined) return false
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return true
  if (ts.isTemplateExpression(node)) return true
  return ts.isCallExpression(node)
}

/**
 * The literal text of a node, or `null`.
 * @param node - the node.
 * @returns the literal text.
 */
function literalOf(node: ts.Node | undefined): string | null {
  if (node === undefined) return null
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text
  return null
}

/**
 * Tier C checks that do **not** make a Tier B negative unreliable.
 *
 * Every other check here says the analyzer could not read something. C3 says
 * the opposite: the bytes were read exactly as written and exactly as they will
 * run — what cannot be checked is whether they match the repository that
 * claims to have produced them. That is worth reporting and it is not a reason
 * to distrust the parse, and treating it as one marks every ordinary published
 * tarball `degraded`, because shipping built output and no source is what
 * publishing a package *is*.
 */
export const NON_DEGRADING_CHECKS: ReadonlySet<string> = new Set(['C3'])

/** C3, C6 — shipped build output with nothing to compare it against. */
function checkSourcelessBuild(input: CheckInput): Finding[] {
  const built = input.sourceFiles.filter(path => /^(?:lib|dist|build|out)\//.test(path))
  const authored = input.sourceFiles.filter(path => /^(?:src|source)\//.test(path))
  const minified = input.sourceFiles.filter(path => path.endsWith('.min.js'))
  const findings: Finding[] = []
  if (built.length > 0 && authored.length === 0) {
    findings.push(tierC({
      checkId: 'C3',
      name: 'sourceless-build-output',
      subject: 'no-authored-source',
      severity: 'low',
      title: `Ships ${built.length} built file(s) and no source`,
      detail: 'What runs is the built output, so that is what this tool analysed — but there is nothing in the '
        + 'package to check the build against. Whether the source that produced it matches the repository is not '
        + 'decidable from here.',
      /* v8 ignore next -- guarded by `built.length > 0` two lines above. */
      evidence: { file: built[0] ?? '', snippet: snippet(built.slice(0, 5).join(', ')) },
      bypass: 'none — this finding is about the analysis, not about the plugin',
    }))
  }
  for (const path of minified) {
    findings.push(tierC({
      checkId: 'C6',
      name: 'minified-artifact',
      subject: 'min-js',
      severity: 'low',
      title: 'Ships a minified artifact',
      detail: 'A `.min.js` file is output, not source. It was still parsed, but nothing about its readability '
        + 'supports a confident negative.',
      evidence: { file: path },
      bypass: 'none — this finding is about the analysis, not about the plugin',
    }))
  }
  return findings
}

/** C4 — files the reader refused or could not decode. */
function checkUnreadableFiles(input: CheckInput): Finding[] {
  const skipped = input.source.skipped
  if (skipped.length === 0) return []
  const byReason = new Map<string, string[]>()
  for (const entry of skipped) {
    byReason.set(entry.reason, [...byReason.get(entry.reason) ?? [], entry.path])
  }
  return [...byReason].map(([reason, paths]) => tierC({
    checkId: 'C4',
    name: 'unreadable-payload',
    subject: reason,
    severity: reason === 'binary' ? 'medium' : 'low',
    title: `${paths.length} file(s) were not analysed (${reason})`,
    detail: reason === 'binary'
      ? 'Binary payloads — native addons, WebAssembly, archives — are shipped code this tool cannot read at all. '
        + 'A mounted layer can load a `.node` addon with no restriction whatsoever.'
      : 'These files exceeded a size or count cap and were not read. Nothing is claimed about their contents.',
    /* v8 ignore next -- a reason only appears in the map once a path was pushed under it. */
    evidence: { file: paths[0] ?? '', snippet: snippet(paths.slice(0, 8).join(', ')) },
    bypass: 'none — this finding is about the analysis, not about the plugin',
  }))
}

/** C5 — a patch layer whose structure hit a walk ceiling before it was read out. */
function checkPatchWalkLimit(input: CheckInput): Finding[] {
  return input.patches.filter(patch => patch.limit !== null).map(patch => tierC({
    checkId: 'C5',
    name: 'patch-walk-truncated',
    subject: patch.file,
    severity: 'high',
    title: `\`${patch.file}\` was only read in part (${patch.limit === 'depth' ? 'nesting' : 'node count'} ceiling)`,
    detail: patch.limit === 'depth'
      ? 'The layer nests deeper than any composition needs. Everything below that point is unread, so no Tier A '
        + 'reading of this layer is complete.'
      : 'The layer expands to more nodes than the analyzer will walk. YAML anchors make that cheap to write — a '
        + 'few hundred bytes of `*alias` references describe a graph with billions of paths through it — and the '
        + 'usual reason to write one is that a reader gives up before reaching what it hides. Rows past the '
        + 'ceiling were not read.',
    evidence: { file: patch.file },
    bypass: 'none — this finding is about the analysis, not about the plugin',
  }))
}

/** C7 — a patch layer whose rows are assembled out of YAML anchors and aliases. */
function checkPatchAliases(input: CheckInput): Finding[] {
  return input.patches.filter(patch => patch.aliased).map(patch => tierC({
    checkId: 'C7',
    name: 'patch-uses-aliases',
    subject: patch.file,
    severity: 'medium',
    title: `\`${patch.file}\` builds rows out of YAML anchors and aliases`,
    detail: 'An alias is not a copy: `*a` hands the loader the same node again, so one row in the file can be two '
      + 'rows in the composed profile, and the row a reader sees under an inert key can be the row that lands in a '
      + 'live one. This tool expands every alias to its own node before reading the layer, which is what makes the '
      + 'reading match the loader — but the layer a person reviews and the layer that mounts are no longer the same '
      + 'document, and no Tier B negative about this package is claimed while that is true.',
    evidence: { file: patch.file },
    bypass: 'none — this finding is about the analysis, not about the plugin',
  }))
}

/**
 * Run every Tier C check.
 * @param input - the decoded package.
 * @returns findings, unordered.
 */
export function runTierC(input: CheckInput): Finding[] {
  return [
    ...checkMinification(input),
    ...checkDynamicDispatch(input),
    ...checkSourcelessBuild(input),
    ...checkUnreadableFiles(input),
    ...checkPatchWalkLimit(input),
    ...checkPatchAliases(input),
  ]
}
