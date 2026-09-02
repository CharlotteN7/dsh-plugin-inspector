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
import { foldConstantString, isBuiltinModuleGetter } from '../syntax.ts'
import type { CheckInput } from './input.ts'

/** Global functions that fetch over the network without any `ctx` service. */
const NETWORK_GLOBALS: ReadonlySet<string> = new Set(['fetch', 'WebSocket', 'EventSource', 'XMLHttpRequest'])

/** `process.env` keys whose names say they hold a secret. */
const SECRET_ENV_KEY = /(?:^|_)(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|APIKEY|SESSION)(?:_|$)|API_?KEY|ACCESS_?TOKEN/i

/** One filesystem location that holds credentials, and how it is spelled. */
export interface CredentialPath {
  readonly id: string
  /** Pattern source, matched case-insensitively anywhere in a string literal. */
  readonly pattern: string
}

/**
 * Filesystem locations that hold credentials.
 *
 * A table rather than one regular expression so each location can be pinned by
 * name: `tests/unit/rule-tables.spec.ts` iterates this export, and a location
 * added without a fixture fails there.
 */
export const CREDENTIAL_PATHS: readonly CredentialPath[] = [
  { id: 'npmrc', pattern: String.raw`\.npmrc` },
  { id: 'netrc', pattern: String.raw`\.netrc` },
  { id: 'ssh-directory', pattern: String.raw`\.ssh\/` },
  { id: 'ssh-key-rsa', pattern: 'id_rsa' },
  { id: 'ssh-key-ed25519', pattern: 'id_ed25519' },
  { id: 'aws-directory', pattern: String.raw`\.aws\/` },
  { id: 'docker-config', pattern: String.raw`\.docker\/config\.json` },
  { id: 'git-credentials', pattern: String.raw`\.git-credentials` },
  { id: 'service-account-json', pattern: String.raw`credentials\.json` },
  { id: 'dsh-credentials', pattern: String.raw`\.dsh\/credentials` },
  { id: 'dotenv', pattern: String.raw`\.env(?:\.[a-z]+)?$` },
]

const CREDENTIAL_PATH = new RegExp(`(?:${CREDENTIAL_PATHS.map(path => path.pattern).join('|')})`, 'i')

/**
 * Whether a string names a location that holds credentials.
 * @param text - the literal text of a string in shipped source.
 * @returns true when it names one of {@link CREDENTIAL_PATHS}.
 */
export function matchesCredentialPath(text: string): boolean {
  return CREDENTIAL_PATH.test(text)
}

/** Members of `ctx` that construct or evaluate code, or mount further plugins. */
const DYNAMIC_CODE_CALLEES: ReadonlySet<string> = new Set([
  'eval', 'runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction',
])

/**
 * The harness's own tool-definition helper, exported from
 * `@deepseek-ai/dsh-tools`. Every registered tool in the harness is built by
 * either calling it or handing `tools.register` a literal, so recognising the
 * two shapes is what tells a tool `description` from every other kind.
 */
const TOOL_DEFINITION_HELPER = 'defineTool'

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
 * The text a string argument holds, folding the constant forms — a `+` chain of
 * literals, a template whose spans are literals, `[…].join(…)` over literals.
 *
 * Folding is bounded on purpose. An argument this cannot resolve is not a
 * Tier B miss to paper over: it is a Tier C signal, and `tier-c.ts` records it
 * by asking the same folder, so a site is either matched here or degraded
 * there and never both.
 * @param node - the argument expression.
 * @returns the text, or `null`.
 */
function literalText(node: ts.Node | undefined): string | null {
  return foldConstantString(node)
}

/**
 * Strip the `node:` prefix so `node:fs` and `fs` compare equal.
 * @param specifier - the module specifier.
 * @returns the bare module name.
 */
function bareModule(specifier: string): string {
  return specifier.startsWith('node:') ? specifier.slice(5) : specifier
}

/** One module a file reaches, and the expression that reached it. */
interface ModuleReference {
  readonly specifier: string
  readonly node: ts.Node
  /** How the module was obtained, which decides how the finding names it. */
  readonly via: 'import' | 'builtin-getter'
}

/**
 * Every module the file reaches by a name this tool can resolve.
 *
 * Three ways in, not two. `import` and `require` are the declarations a reader
 * looks for; `process.getBuiltinModule('node:fs')` is a third that needs
 * neither, returns the same module object, and appears in no import list.
 * @param file - the parsed file.
 * @returns one entry per resolved reference.
 */
function moduleSpecifiers(file: ParsedFile): ModuleReference[] {
  const found: ModuleReference[] = []
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier !== undefined) {
      const text = literalText(node.moduleSpecifier)
      /* v8 ignore next -- an import declaration only parses with a string-literal specifier. */
      if (text !== null) found.push({ specifier: text, node, via: 'import' })
    }
    if (ts.isCallExpression(node)) {
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require'
      const isImport = node.expression.kind === ts.SyntaxKind.ImportKeyword
      const isBuiltin = isBuiltinModuleGetter(node)
      if (isRequire || isImport || isBuiltin) {
        const text = literalText(node.arguments[0])
        if (text !== null) found.push({ specifier: text, node, via: isBuiltin ? 'builtin-getter' : 'import' })
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

/**
 * How a finding names the way a module was reached.
 *
 * `Imports` would be false of `process.getBuiltinModule('node:fs')`, and the
 * difference is the point of covering it: the module arrives with no import
 * declaration and no `require` for a reader to find.
 * @param reference - the resolved module reference.
 * @returns the opening clause of the finding's title.
 */
function reachedBy(reference: ModuleReference): string {
  return reference.via === 'import'
    ? `Imports \`${reference.specifier}\``
    : `Loads \`${reference.specifier}\` through \`process.getBuiltinModule\``
}

/** B9, B7, B13 — what modules the file reaches. */
function checkImports(file: ParsedFile, accumulator: Accumulator): void {
  for (const reference of moduleSpecifiers(file)) {
    const { specifier, node } = reference
    const reached = reachedBy(reference)
    const bare = bareModule(specifier)
    const unmediated = UNMEDIATED_PROCESS_MODULES.get(bare)
    if (unmediated !== undefined) {
      accumulator.findings.push(tierB({
        checkId: 'B9',
        name: 'unmediated-process-api',
        subject: specifier,
        // Raised to `high` by `escalateProcessImports` when this package also
        // reads a credential or reaches the network. On its own it is a
        // capability half the ecosystem has.
        severity: 'medium',
        title: `${reached}, which ${unmediated}`,
        detail: 'A mounted bundle layer is imported into the harness process at the agent\'s uid. The harness\'s own '
          + 'dynamic-package sandbox denies untrusted code `require` outright and redirects it to ctx services; a '
          + 'bundle layer gets no such restriction, so this import does exactly what the harness forbids elsewhere.',
        evidence: at(file, node),
        bypass: 'a specifier this tool cannot fold to a constant — `import(name)` against a binding — which C2 '
          + 'reports, so the negative degrades rather than passing quietly',
      }))
    }
    if (NETWORK_MODULES.has(bare)) {
      const finding = tierB({
        checkId: 'B7',
        name: 'network-egress',
        subject: specifier,
        severity: 'medium',
        title: `${reached}, which can move bytes off the machine`,
        detail: 'Network access is a capability, not a verdict: most plugins that reach the network do so for a '
          + 'declared reason. It is recorded because paired with a credential read it becomes B8.',
        evidence: at(file, node),
        bypass: 'a transitive dependency doing the request on this package\'s behalf',
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
        title: `${reached} rather than using the \`ctx.fs\` service`,
        detail: 'Reads and writes through the Node filesystem API are invisible to `fs/write-intent`, '
          + '`fs/edit-intent`, `fs/observed`, and the `fs-sandbox` row, so no policy in the profile sees them and '
          + 'nothing appears in the session log.',
        evidence: at(file, node),
        bypass: 'a transitive dependency reading the file on this package\'s behalf',
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
    bypass: "`ctx['pro' + 'vide']('approval', …)` — a computed member name is not matched — and neither is a "
      + '`provide` destructured off `ctx` and called through the bare name. C2 reports both',
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
  if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && matchesCredentialPath(node.text)) {
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
    bypass: 'a key this tool cannot fold to a constant, or reading the whole `process.env` object and indexing it later',
  })
  accumulator.findings.push(finding)
  accumulator.credentialRead ??= finding
}

/**
 * Whether a call hands its arguments to the tool registry: the registry call
 * itself, `<ctx>.tools.register(…)`, or the harness's `defineTool(…)` helper,
 * whose argument is a tool definition and nothing else.
 * @param node - the call expression.
 * @returns true when its arguments are tool definitions.
 */
function isToolRegistration(node: ts.CallExpression): boolean {
  const callee = node.expression
  if (ts.isIdentifier(callee)) return callee.text === TOOL_DEFINITION_HELPER
  return ts.isPropertyAccessExpression(callee) && callee.name.text === 'register'
    && ts.isPropertyAccessExpression(callee.expression) && callee.expression.name.text === 'tools'
}

/**
 * Whether a name bound in this file is passed to a tool registration call, so
 * a definition built as `const tool = {…}` and registered on a later line is
 * still recognised as one.
 * @param name - the bound identifier.
 * @param file - the parsed file it was bound in.
 * @returns true when a registration call in the same file receives it.
 */
function isRegisteredName(name: string, file: ParsedFile): boolean {
  let registered = false
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && isToolRegistration(node)
      && node.arguments.some(argument => ts.isIdentifier(argument) && argument.text === name)) {
      registered = true
    }
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(file.node, visit)
  return registered
}

/**
 * Whether a `description` property belongs to a tool definition this package
 * registers.
 *
 * The receiver guard is the whole check. `description` is one of the commonest
 * property names in JavaScript — a JSON schema, an OpenAPI document, a
 * changelog entry and a CLI option table all carry one — and none of that text
 * reaches a model. Without the guard the injection heuristics run on release
 * notes, and the finding's title then asserts something about a tool that the
 * package does not have.
 *
 * Nested properties count, because the whole definition is model-visible: a
 * parameter's `description` is rendered into the tool schema the model
 * receives alongside the tool's own.
 * @param node - the `description` property assignment.
 * @param file - the parsed file it came from.
 * @returns true when an enclosing object literal is a registered tool definition.
 */
function isRegisteredToolDescription(node: ts.PropertyAssignment, file: ParsedFile): boolean {
  let parent: ts.Node = node.parent
  for (;;) {
    if (ts.isCallExpression(parent)) return isToolRegistration(parent)
    if (ts.isVariableDeclaration(parent)) return ts.isIdentifier(parent.name) && isRegisteredName(parent.name.text, file)
    if (!ts.isObjectLiteralExpression(parent) && !ts.isPropertyAssignment(parent)) return false
    parent = parent.parent
  }
}

/** B10 — injection phrasing in a registered tool description. */
function checkToolDescription(file: ParsedFile, node: ts.Node, accumulator: Accumulator): void {
  if (!ts.isPropertyAssignment(node)) return
  if (!ts.isIdentifier(node.name) || node.name.text !== 'description') return
  const text = literalText(node.initializer)
  if (text === null) return
  if (!isRegisteredToolDescription(node, file)) return
  for (const match of scanInjection(text)) {
    accumulator.findings.push(tierB({
      checkId: 'B10',
      name: 'model-visible-injection',
      subject: match.ruleId,
      severity: 'high',
      title: `Tool description ${match.meaning}`,
      detail: `Heuristic \`${match.ruleId}\` matched a \`description\` inside a registered tool definition, which is `
        + 'prompt text the model receives verbatim on every request that lists the tool. This is a natural-language '
        + 'heuristic: it will miss a rephrasing, and it can fire on a description that legitimately discusses the '
        + 'subject.',
      evidence: { ...at(file, node), snippet: snippet(match.excerpt) },
      bypass: 'any rephrasing the pattern does not cover, assembling the description out of anything this tool '
        + 'cannot fold to a constant, or registering the definition through a value this tool does not track — a '
        + 'definition exported from one file and passed to `tools.register` in another is not matched',
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
    /* v8 ignore next -- `sourceFiles` is filtered from `source.files`'s own keys, so the lookup always hits. */
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
  return escalateProcessImports(accumulator)
}

/**
 * B9 — raise a process-API import from `medium` to `high` when the same package
 * also reads a credential or reaches the network.
 *
 * A bare `import 'node:child_process'` was hardcoded `critical` and fired on
 * half the published ecosystem. A severity that common is not a severity: it
 * pushed a package disabling `fs-sandbox` down a list of a thousand identical
 * criticals. Spawning a process is what a plugin that wraps `git`, `ffmpeg` or
 * a language server does, and the tool cannot tell that from the other thing.
 *
 * The pairing is exactly the one B8 already uses — a credential read *and* a
 * network call in the same package — and for the same reason: the combination
 * is what changes the question from "can it run a program" to "can it run a
 * program with something worth sending, and somewhere to send it". Either half
 * alone is not enough, and it would not narrow anything if it were: 68 % of
 * published plugins reach the network at all.
 *
 * That pairing is still a capability, not a dataflow, so it stops at `high`.
 * @param accumulator - the accumulated Tier B state.
 * @returns the findings, with B9 severities settled.
 */
function escalateProcessImports(accumulator: Accumulator): Finding[] {
  const paired = accumulator.credentialRead !== null && accumulator.networkCall !== null
  if (!paired) return accumulator.findings
  return accumulator.findings.map(finding => finding.checkId !== 'B9' ? finding : {
    ...finding,
    severity: 'high' as Severity,
    detail: `${finding.detail} This package also reads a credential or reaches the network, which is why this is `
      + 'graded above a bare process import: the two capabilities together are what an exfiltration needs. It '
      + 'remains a capability report — nothing here shows the two are connected.',
  })
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
  // Not critical. This pair fires on 18 % of the published ecosystem — every
  // telemetry client and every authenticated API client trips it — and the
  // finding's own text says it is not a verdict. A severity that says "do not
  // treat this as a verdict" cannot be the top one.
  const severity: Severity = 'high'
  /* v8 ignore start -- `at()` records a line and column for every finding these two come from. */
  const credentialSite = `${credential.evidence.file}:${credential.evidence.path ?? '?'}`
  const networkSite = `${network.evidence.file}:${network.evidence.path ?? '?'}`
  /* v8 ignore stop */
  return tierB({
    checkId: 'B8',
    name: 'exfiltration-capability',
    subject: 'credential-and-egress',
    severity,
    title: 'This package can read a credential and can make a network call',
    detail: `This is a capability, not a dataflow. The tool found a credential read at ${credentialSite} `
      + `and a network call at ${networkSite}. It has NOT shown that the credential value `
      + 'reaches the request, and it cannot: proving that needs value tracking this tool does not do. Many '
      + 'legitimate packages — any telemetry or authenticated API client — trip this pair for good reasons. Treat '
      + 'it as a prompt to read those two sites, not as a verdict.',
    evidence: credential.evidence,
    bypass: 'splitting the read and the send across two packages, or letting a dependency do either half',
  })
}
