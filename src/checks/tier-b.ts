/**
 * Tier B — capability detection over shipped source.
 *
 * Everything here answers "this plugin CAN do X", never "this plugin DOES X".
 * The distinction is load-bearing for B8: finding a credential read and a
 * network call in the same package is not evidence that the credential reaches
 * the socket, and the finding says so.
 *
 * Parsing is `ts.createSourceFile` — syntax only. No program is created, no
 * type checker is instantiated, no module is resolved, nothing is transpiled,
 * and nothing is executed. Every check is a shape match on one AST node, which
 * is also why every check has a one-line bypass, carried in the finding.
 * @module dsh-plugin-inspector/checks/tier-b
 */

import ts from 'typescript'
import { lineColumn, snippet } from '../files.ts'
import { scanInjection } from '../injection.ts'
import {
  NETWORK_MODULES,
  SEAM_KEYS,
  SECURITY_SEAM_KEYS,
  UNMEDIATED_FS_MODULES,
  UNMEDIATED_PROCESS_MODULES,
} from '../knowledge.ts'
import type { Finding, Severity } from '../model.ts'
import type { CheckInput } from './input.ts'

/** Global functions that fetch over the network without any `ctx` service. */
const NETWORK_GLOBALS: ReadonlySet<string> = new Set(['fetch', 'WebSocket', 'EventSource', 'XMLHttpRequest'])

/** `process.env` keys whose names say they hold a secret. */
const SECRET_ENV_KEY = /(?:^|_)(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|APIKEY|SESSION)(?:_|$)|API_?KEY|ACCESS_?TOKEN/i

/** Filesystem locations that hold credentials. */
const CREDENTIAL_PATH = /(?:\.npmrc|\.netrc|\.ssh\/|id_rsa|id_ed25519|\.aws\/|\.docker\/config\.json|\.git-credentials|credentials\.json|\.dsh\/credentials|\.env(?:\.[a-z]+)?$)/i

/** Members of `ctx` that construct or evaluate code, or mount further plugins. */
const DYNAMIC_CODE_CALLEES: ReadonlySet<string> = new Set([
  'eval', 'runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction',
])

/** `ctx.systemPrompt` members that change what the model is told. */
const SYSTEM_PROMPT_MEMBERS: ReadonlySet<string> = new Set([
  'section', 'context', 'variable', 'tools', 'suppressRuntimeContext',
])

/** One parsed source file, kept alongside its text for evidence locators. */
interface ParsedFile {
  readonly path: string
  readonly text: string
  readonly node: ts.SourceFile
}

/** Facts accumulated across all files, needed for the cross-file pair check. */
interface Accumulator {
  readonly findings: Finding[]
  credentialRead: Finding | null
  networkCall: Finding | null
}

/**
 * Build one Tier B finding. Confidence starts at `high`; `inspect.ts` lowers it
 * when Tier C fires.
 * @param finding - everything but the fixed fields.
 * @returns the complete finding.
 */
function tierB(finding: Omit<Finding, 'tier' | 'confidence' | 'examples' | 'occurrences'>): Finding {
  return { ...finding, tier: 'B', confidence: 'high', examples: [finding.evidence], occurrences: 1 }
}

/**
 * The literal text of a string argument, or `null` when it is computed.
 * A computed argument is not a Tier B miss to paper over — it is a Tier C
 * signal, and `tier-c.ts` records it.
 * @param node - the argument expression.
 * @returns the literal text, or `null`.
 */
function literalText(node: ts.Node | undefined): string | null {
  if (node === undefined) return null
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text
  return null
}

/**
 * Strip the `node:` prefix so `node:fs` and `fs` compare equal.
 * @param specifier - the module specifier.
 * @returns the bare module name.
 */
function bareModule(specifier: string): string {
  return specifier.startsWith('node:') ? specifier.slice(5) : specifier
}

/**
 * Every module specifier the file imports or requires, as literal text.
 * @param file - the parsed file.
 * @returns specifier text paired with the node it came from.
 */
function moduleSpecifiers(file: ParsedFile): { specifier: string, node: ts.Node }[] {
  const found: { specifier: string, node: ts.Node }[] = []
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const text = literalText(node.moduleSpecifier)
      if (text !== null) found.push({ specifier: text, node })
    }
    if (ts.isCallExpression(node)) {
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require'
      const isImport = node.expression.kind === ts.SyntaxKind.ImportKeyword
      if (isRequire || isImport) {
        const text = literalText(node.arguments[0])
        if (text !== null) found.push({ specifier: text, node })
      }
    }
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(file.node, visit)
  return found
}

/**
 * Evidence for one AST node.
 * @param file - the parsed file.
 * @param node - the node to locate.
 * @returns the evidence record.
 */
function at(file: ParsedFile, node: ts.Node): Finding['evidence'] {
  return {
    file: file.path,
    path: lineColumn(file.text, node.getStart(file.node)),
    snippet: snippet(file.text.slice(node.getStart(file.node), node.end)),
  }
}

/** B9, B7, B13 — what the file imports. */
function checkImports(file: ParsedFile, accumulator: Accumulator): void {
  for (const { specifier, node } of moduleSpecifiers(file)) {
    const bare = bareModule(specifier)
    const unmediated = UNMEDIATED_PROCESS_MODULES.get(bare)
    if (unmediated !== undefined) {
      accumulator.findings.push(tierB({
        checkId: 'B9',
        name: 'unmediated-process-api',
        subject: specifier,
        severity: 'critical',
        title: `Imports \`${specifier}\`, which ${unmediated}`,
        detail: 'A mounted bundle layer is imported into the harness process at the agent\'s uid. The harness\'s own '
          + 'dynamic-package sandbox denies untrusted code `require` outright and redirects it to ctx services; a '
          + 'bundle layer gets no such restriction, so this import does exactly what the harness forbids elsewhere.',
        evidence: at(file, node),
        bypass: 'a computed specifier — `await import(["node","child_process"].join(":"))` — is not matched, which is why C2 downgrades every Tier B negative',
      }))
    }
    if (NETWORK_MODULES.has(bare)) {
      const finding = tierB({
        checkId: 'B7',
        name: 'network-egress',
        subject: specifier,
        severity: 'medium',
        title: `Imports \`${specifier}\`, which can move bytes off the machine`,
        detail: 'Network access is a capability, not a verdict: most plugins that reach the network do so for a '
          + 'declared reason. It is recorded because paired with a credential read it becomes B8.',
        evidence: at(file, node),
        bypass: 'a computed specifier, or a transitive dependency doing the request on this package\'s behalf',
      })
      accumulator.findings.push(finding)
      accumulator.networkCall ??= finding
    }
    if (UNMEDIATED_FS_MODULES.has(bare)) {
      accumulator.findings.push(tierB({
        checkId: 'B13',
        name: 'unmediated-filesystem',
        subject: specifier,
        severity: 'medium',
        title: `Imports \`${specifier}\` rather than using the \`ctx.fs\` service`,
        detail: 'Reads and writes through the Node filesystem API are invisible to `fs/write-intent`, '
          + '`fs/edit-intent`, `fs/observed`, and the `fs-sandbox` row, so no policy in the profile sees them and '
          + 'nothing appears in the session log.',
        evidence: at(file, node),
        bypass: 'a computed specifier, or `process.getBuiltinModule("node:fs")`',
      }))
    }
  }
}

/** B1 — replacing a core capability seam. */
function checkSeamReplacement(file: ParsedFile, node: ts.CallExpression, accumulator: Accumulator): void {
  if (!ts.isPropertyAccessExpression(node.expression)) return
  const method = node.expression.name.text
  if (method !== 'provide' && method !== 'set' && method !== 'mixin') return
  const seam = literalText(node.arguments[0])
  if (seam === null || !SEAM_KEYS.has(seam)) return
  const critical = SECURITY_SEAM_KEYS.has(seam)
  accumulator.findings.push(tierB({
    checkId: 'B1',
    name: 'seam-replacement',
    subject: `${seam}.${method}`,
    severity: critical ? 'critical' : 'high',
    title: `Replaces the \`${seam}\` capability seam via \`.${method}()\``,
    detail: `\`${seam}\` is a catalogued core service. Providing it from a third-party layer substitutes this `
      + 'package\'s implementation for every consumer in the scope, and consumers cannot tell the difference.'
      + (critical ? ' This seam is one whose whole purpose is to constrain what the agent may do.' : ''),
    evidence: at(file, node),
    bypass: "`ctx['pro' + 'vide']('approval', …)` — a computed member name is not matched",
  }))
}

/** B5 — changing what the model is told. */
function checkSystemPrompt(file: ParsedFile, node: ts.CallExpression, accumulator: Accumulator): void {
  const callee = node.expression
  if (!ts.isPropertyAccessExpression(callee)) return
  const isPromptMember = SYSTEM_PROMPT_MEMBERS.has(callee.name.text)
    && ts.isPropertyAccessExpression(callee.expression)
    && callee.expression.name.text === 'systemPrompt'
  const isAssembleListener = callee.name.text === 'on' && literalText(node.arguments[0]) === 'system-prompt/assemble'
  if (!isPromptMember && !isAssembleListener) return
  accumulator.findings.push(tierB({
    checkId: 'B5',
    name: 'system-prompt-mutation',
    subject: isAssembleListener ? 'system-prompt/assemble' : callee.name.text,
    severity: 'high',
    title: isAssembleListener
      ? 'Listens on `system-prompt/assemble`'
      : `Contributes to the system prompt via \`ctx.systemPrompt.${callee.name.text}()\``,
    detail: 'The system prompt is the model\'s standing instructions. Text added here reaches every request in the '
      + 'scope and is not attributable to this package from the model\'s side.',
    evidence: at(file, node),
    bypass: 'a computed member or event name, or contributing the same text through a registered tool description instead',
  }))
}

/** B11 — mounting further plugins from inside this one. */
function checkNestedMount(file: ParsedFile, node: ts.CallExpression, accumulator: Accumulator): void {
  const callee = node.expression
  if (!ts.isPropertyAccessExpression(callee)) return
  const isPluginCall = callee.name.text === 'plugin' && ts.isIdentifier(callee.expression)
  const isLoaderCall = ts.isPropertyAccessExpression(callee.expression) && callee.expression.name.text === 'loader'
  if (!isPluginCall && !isLoaderCall) return
  accumulator.findings.push(tierB({
    checkId: 'B11',
    name: 'nested-plugin-mount',
    subject: 'runtime-mount',
    severity: 'high',
    title: 'Mounts further plugins at runtime',
    detail: 'A layer that mounts other layers moves the analysis target: what actually runs is decided by code '
      + 'rather than by the composed entry list, and none of it appears in `dsh --dump-config`.',
    evidence: at(file, node),
    bypass: 'a computed member name, or mounting through a helper imported from a dependency',
  }))
}

/**
 * Whether a `new Function(…)` is ever called.
 *
 * Constructing a function does not run anything: this tool compiles `!!js`
 * expressions with `new Function` purely to learn whether they parse, and
 * discards the result. A check that cannot tell that apart from an invocation
 * fires on its own documented parse step, and an analyzer that fails its own
 * default gate has no standing to gate anything else. So the finding is about
 * the call, in either of the two forms it takes: invoked where it is built, or
 * bound to a name that is called later in the same file.
 * @param node - the `new Function(…)` expression.
 * @param file - the parsed file it came from.
 * @returns true when the constructed function is invoked.
 */
function isInvokedFunctionCtor(node: ts.NewExpression, file: ParsedFile): boolean {
  const parent = node.parent as ts.Node | undefined
  if (parent !== undefined && ts.isCallExpression(parent) && parent.expression === node) return true
  if (parent === undefined || !ts.isVariableDeclaration(parent) || !ts.isIdentifier(parent.name)) return false
  const bound = parent.name.text
  let called = false
  const visit = (child: ts.Node): void => {
    if (ts.isCallExpression(child) && ts.isIdentifier(child.expression) && child.expression.text === bound) called = true
    ts.forEachChild(child, visit)
  }
  ts.forEachChild(file.node, visit)
  return called
}

/** B12 — building code at runtime and running it. */
function checkDynamicCode(file: ParsedFile, node: ts.Node, accumulator: Accumulator): void {
  const isEvalCall = ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'eval'
  const isVmCall = ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
    && DYNAMIC_CODE_CALLEES.has(node.expression.name.text)
  const isFunctionCtor = ts.isNewExpression(node) && ts.isIdentifier(node.expression)
    && node.expression.text === 'Function' && isInvokedFunctionCtor(node, file)
  if (!isEvalCall && !isVmCall && !isFunctionCtor) return
  accumulator.findings.push(tierB({
    checkId: 'B12',
    name: 'dynamic-code-construction',
    subject: 'runtime-code',
    severity: 'high',
    title: 'Builds and runs code at runtime',
    detail: 'Whatever this evaluates is not in the package and cannot be analysed from it. Construction alone is '
      + 'not the finding: a `new Function` whose result is never called compiles a string and discards it, which is '
      + 'how this tool checks that a `!!js` expression parses.',
    evidence: at(file, node),
    bypass: 'building the function in one statement and calling it through a value this tool does not track',
  }))
}

/** B6 — reading a credential. */
function checkCredentialRead(file: ParsedFile, node: ts.Node, accumulator: Accumulator): void {
  let title: string | null = null
  let subject = ''
  if (ts.isPropertyAccessExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const outer = node.expression
    if (ts.isIdentifier(outer.expression) && outer.expression.text === 'process' && outer.name.text === 'env') {
      if (SECRET_ENV_KEY.test(node.name.text)) {
        title = `Reads the environment variable \`${node.name.text}\``
        subject = `env:${node.name.text}`
      }
    }
  }
  if (ts.isElementAccessExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const outer = node.expression
    const key = literalText(node.argumentExpression)
    if (ts.isIdentifier(outer.expression) && outer.expression.text === 'process' && outer.name.text === 'env'
      && key !== null && SECRET_ENV_KEY.test(key)) {
      title = `Reads the environment variable \`${key}\``
      subject = `env:${key}`
    }
  }
  if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && CREDENTIAL_PATH.test(node.text)) {
    title = `References the credential location \`${node.text}\``
    subject = `path:${node.text}`
  }
  if (ts.isPropertyAccessExpression(node) && node.name.text === 'credentials' && ts.isIdentifier(node.expression)) {
    title = 'Reads the `credentials` service'
    subject = 'service:credentials'
  }
  if (title === null) return
  const finding = tierB({
    checkId: 'B6',
    name: 'credential-read',
    subject,
    severity: 'medium',
    title,
    detail: 'Reading a credential is a capability, not a verdict — a plugin that authenticates to its own service '
      + 'must do it. It is recorded because paired with network access it becomes B8.',
    evidence: at(file, node),
    bypass: 'a computed key — `process.env["API"+"_KEY"]` — or reading the whole `process.env` object and indexing it later',
  })
  accumulator.findings.push(finding)
  accumulator.credentialRead ??= finding
}

/** B10 — injection phrasing in a registered tool description. */
function checkToolDescription(file: ParsedFile, node: ts.Node, accumulator: Accumulator): void {
  if (!ts.isPropertyAssignment(node)) return
  if (!ts.isIdentifier(node.name) || node.name.text !== 'description') return
  const text = literalText(node.initializer)
  if (text === null) return
  for (const match of scanInjection(text)) {
    accumulator.findings.push(tierB({
      checkId: 'B10',
      name: 'model-visible-injection',
      subject: match.ruleId,
      severity: 'high',
      title: `Tool description ${match.meaning}`,
      detail: `Heuristic \`${match.ruleId}\` matched a tool \`description\`, which is prompt text the model receives `
        + 'verbatim on every request that lists the tool. This is a natural-language heuristic: it will miss a '
        + 'rephrasing, and it can fire on a description that legitimately discusses the subject.',
      evidence: { ...at(file, node), snippet: snippet(match.excerpt) },
      bypass: 'any rephrasing the pattern does not cover, or building the description by concatenation',
    }))
  }
}

/** B7 — network calls that need no import. */
function checkNetworkGlobals(file: ParsedFile, node: ts.Node, accumulator: Accumulator): void {
  const callee = ts.isCallExpression(node) || ts.isNewExpression(node) ? node.expression : undefined
  if (callee === undefined || !ts.isIdentifier(callee) || !NETWORK_GLOBALS.has(callee.text)) return
  const finding = tierB({
    checkId: 'B7',
    name: 'network-egress',
    subject: callee.text,
    severity: 'medium',
    title: `Calls \`${callee.text}()\``,
    detail: 'The harness\'s own dynamic-package sandbox traps `fetch` and redirects it to the `ctx.web` service, so '
      + 'that untrusted code\'s network use is mediated. A mounted bundle layer is not in that sandbox and this call '
      + 'goes straight out.',
    evidence: at(file, node),
    bypass: '`globalThis["fet"+"ch"]`, or a transitive dependency making the request',
  })
  accumulator.findings.push(finding)
  accumulator.networkCall ??= finding
}

/**
 * Run every Tier B check.
 * @param input - the decoded package.
 * @returns findings, unordered.
 */
export function runTierB(input: CheckInput): Finding[] {
  const accumulator: Accumulator = { findings: [], credentialRead: null, networkCall: null }
  for (const path of input.sourceFiles) {
    const text = input.source.files.get(path)
    if (text === undefined) continue
    const file: ParsedFile = {
      path,
      text,
      node: ts.createSourceFile(path, text, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS),
    }
    checkImports(file, accumulator)
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        checkSeamReplacement(file, node, accumulator)
        checkSystemPrompt(file, node, accumulator)
        checkNestedMount(file, node, accumulator)
      }
      checkDynamicCode(file, node, accumulator)
      checkCredentialRead(file, node, accumulator)
      checkToolDescription(file, node, accumulator)
      checkNetworkGlobals(file, node, accumulator)
      ts.forEachChild(node, visit)
    }
    ts.forEachChild(file.node, visit)
  }
  const pair = pairFinding(accumulator)
  if (pair !== null) accumulator.findings.push(pair)
  return accumulator.findings
}

/**
 * B8 — a credential read and a network call in the same package.
 * @param accumulator - the accumulated Tier B state.
 * @returns the pair finding, or `null` when only one half is present.
 */
function pairFinding(accumulator: Accumulator): Finding | null {
  const credential = accumulator.credentialRead
  const network = accumulator.networkCall
  if (credential === null || network === null) return null
  const severity: Severity = 'critical'
  return tierB({
    checkId: 'B8',
    name: 'exfiltration-capability',
    subject: 'credential-and-egress',
    severity,
    title: 'This package can read a credential and can make a network call',
    detail: 'This is a capability, not a dataflow. The tool found a credential read at '
      + `${credential.evidence.file}:${credential.evidence.path ?? '?'} and a network call at `
      + `${network.evidence.file}:${network.evidence.path ?? '?'}. It has NOT shown that the credential value `
      + 'reaches the request, and it cannot: proving that needs value tracking this tool does not do. Many '
      + 'legitimate packages — any telemetry or authenticated API client — trip this pair for good reasons. Treat '
      + 'it as a prompt to read those two sites, not as a verdict.',
    evidence: credential.evidence,
    bypass: 'splitting the read and the send across two packages, or letting a dependency do either half',
  })
}
