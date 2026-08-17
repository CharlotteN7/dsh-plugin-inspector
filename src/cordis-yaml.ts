/**
 * Parsing a Cordis patch layer with the harness's own `!!js` dialect, and
 * modelling it the way `applyEntryPatches` does.
 *
 * The dialect is transcribed from `dsh/scripts/verify-cordis-config.ts` and
 * `dsh/vendor/include/src/index.ts`: `yaml.JSON_SCHEMA` extended with one
 * scalar type for `tag:yaml.org,2002:js`, whose constructor produces an inert
 * `{ __jsExpr }` node. **The expression text is never evaluated here.** Where
 * the harness would call `new Function('ctx', 'expr', 'with (ctx) { return
 * eval(expr) }')`, this module only ever compiles `return (expr)` to learn
 * whether it parses, and parses it a second time with the TypeScript parser to
 * classify what it reaches. Neither compiles-and-calls.
 *
 * js-yaml is pinned to the harness's `^4.2.0`. Parsing the same bytes
 * differently from the runtime would make every downstream result unsound.
 * @module dsh-plugin-inspector/cordis-yaml
 */

import yaml from 'js-yaml'
import ts from 'typescript'
import { HARNESS_INERT_CALLS, STATIC_ENTRY_FIELDS } from './knowledge.ts'

/** The inert node a `!!js` scalar becomes. Mirrors the loader's own representation. */
export interface JsExprNode {
  readonly __jsExpr: string
}

/** Module specifiers whose `config` holds other rows rather than plugin data. */
const TREE_CARRIERS: ReadonlySet<string> = new Set([
  '@deepseek-ai/cordis-plugin-group',
  '@deepseek-ai/cordis-plugin-include',
  'cordis:include',
])

const jsExprType = new yaml.Type('tag:yaml.org,2002:js', {
  kind: 'scalar',
  resolve: data => typeof data === 'string',
  construct: (data: unknown): JsExprNode => {
    /* v8 ignore next -- js-yaml calls `construct` only for data its `resolve` accepted, which is a string. */
    if (typeof data !== 'string') throw new TypeError('!!js requires a scalar string')
    return { __jsExpr: data }
  },
})

/**
 * The entry-list dialect: JSON schema plus `!!js`. Deliberately *not*
 * `DEFAULT_SCHEMA`, which would also accept `!!python`, `!!binary` and friends
 * — matching the harness exactly means a tag the harness rejects is rejected
 * here too, and shows up as a finding rather than as parsed data.
 */
export const patchSchema = yaml.JSON_SCHEMA.extend(jsExprType)

/** What a `!!js` expression can reach, in ascending order of reach. */
export type ExpressionClass =
  | 'literal'
  | 'inert-read'
  | 'harness-call'
  | 'call'
  | 'mutation'
  | 'module-access'
  | 'unparseable'

/** Every classification, in the order the report tallies them. */
export const EXPRESSION_CLASSES: readonly ExpressionClass[] = [
  'literal', 'inert-read', 'harness-call', 'call', 'mutation', 'module-access', 'unparseable',
]

/** Whether the loader ever evaluates the node at this location. */
export type ExpressionSlot = 'config' | 'disabled' | 'inert'

/** One `!!js` node found in a patch document. */
export interface ExpressionSite {
  /** Diagnostic path, e.g. `[0].insert[1].config.cwd`. */
  readonly path: string
  readonly expression: string
  readonly slot: ExpressionSlot
  readonly classification: ExpressionClass
  /** Parse diagnostic when `classification` is `unparseable`. */
  readonly parseError?: string
}

/** A patch that modifies a row that some earlier layer already defined. */
export interface OverridePatch {
  readonly path: string
  readonly id: string
  /** `name` on a non-insert patch is an assertion guard, not an override. */
  readonly nameGuard: string | null
  /** Keys copied verbatim onto the target row, in declaration order. */
  readonly overriddenKeys: readonly string[]
  /** The raw `disabled` value, present only when the patch sets it. */
  readonly disabled: unknown
  readonly config: unknown
}

/** A row this layer adds to the composed profile. */
export interface InsertedRow {
  readonly path: string
  readonly id: string | null
  readonly name: string | null
  readonly config: unknown
  /** Id of the group row this insert targets, or `null` for a top-level insert. */
  readonly intoGroupId: string | null
  /** Service names the row re-maps to a fresh realm for its whole subtree. */
  readonly isolate: readonly string[]
  /** Service names the row interposes on for its whole subtree. */
  readonly intercept: readonly string[]
}

/** Why a walk stopped early, or `null` when it ran to completion. */
export type WalkLimit = 'nodes' | 'depth' | null

/** One parsed patch layer. */
export interface PatchDocument {
  /** Package-relative path of the YAML file. */
  readonly file: string
  readonly overrides: readonly OverridePatch[]
  readonly inserts: readonly InsertedRow[]
  readonly expressions: readonly ExpressionSite[]
  /**
   * Which walk ceiling stopped the analysis of this layer, or `null`. Non-null
   * means the layer was read in part, which Tier C reports.
   */
  readonly limit: WalkLimit
  /**
   * True when the layer reached at least one node twice, which is what a YAML
   * alias does and what nothing else does. Tier C reports it, because a reader
   * of the file sees one row where the loader sees two.
   */
  readonly aliased: boolean
}

/**
 * The two ceilings that make reading a patch layer terminate.
 *
 * They apply to {@link expandAliases}, and through it to everything downstream:
 * the walk runs over the tree the expansion produced, which holds at most
 * `MAX_WALK_NODES` nodes nested at most `MAX_WALK_DEPTH` deep, so the walk needs
 * no ceiling of its own.
 */
export const MAX_WALK_NODES = 200_000

/** Nesting one patch layer may reach before the reader gives up. */
export const MAX_WALK_DEPTH = 200

/** What {@link expandAliases} produced, and which ceiling stopped it. */
interface Expansion {
  /** The entry list with every alias occurrence materialised as its own node. */
  readonly entries: readonly unknown[]
  /** True when some node was reached twice, which only an anchor and alias do. */
  readonly aliased: boolean
  readonly limit: WalkLimit
}

/**
 * Materialise a parsed patch layer's alias graph as a tree, so that every
 * occurrence of an anchored node is a distinct node at its own path.
 *
 * js-yaml resolves `*a` to the *same JavaScript object* as `&a`, not to a copy.
 * A reader that walks the result as a graph and skips an object it has already
 * seen therefore attributes an anchored node to whichever position it reached
 * first and drops every other one — which is how a row anchored in an inert
 * `inject:` slot and aliased into a real patch slot came to be read as inert
 * and analysed no further. The loader has no such notion: `interpolate` in
 * `vendor/loader/src/config/utils.ts` maps over arrays and objects as a tree
 * and evaluates each occurrence it reaches, and `applyEntryPatches` reads each
 * element of the patch list on its own. Expanding first makes this module agree
 * with both.
 *
 * The expansion is bounded, which is what keeps an alias bomb from becoming a
 * hang: a 475-byte file can describe 100 nodes with 31 billion paths through
 * them, and materialising those paths is exactly the non-terminating walk the
 * ceilings exist to stop. Past either ceiling the subtree becomes `null` and
 * the limit is recorded, so a truncated read is reported rather than presented
 * as a complete one.
 * @param entries - the entry list js-yaml returned.
 * @returns the expanded entries, whether an alias was used, and the ceiling hit.
 */
function expandAliases(entries: readonly unknown[]): Expansion {
  const state = { aliased: false, nodes: 1, limit: null as WalkLimit }
  const seen = new WeakSet<object>([entries])
  const expand = (value: unknown, depth: number): unknown => {
    if (typeof value !== 'object' || value === null) return value
    if (state.limit !== null) return null
    if (depth > MAX_WALK_DEPTH) {
      state.limit = 'depth'
      return null
    }
    state.nodes += 1
    if (state.nodes > MAX_WALK_NODES) {
      state.limit = 'nodes'
      return null
    }
    if (seen.has(value)) state.aliased = true
    else seen.add(value)
    if (Array.isArray(value)) return value.map(item => expand(item, depth + 1))
    const clone: Record<string, unknown> = {}
    for (const [key, child] of Object.entries(value)) {
      // Assignment would invoke the `__proto__` setter, and js-yaml keeps a
      // `__proto__` key from the document as an own property precisely so that
      // it stays data. Defining the property keeps it data here too.
      Object.defineProperty(clone, key, {
        value: expand(child, depth + 1), enumerable: true, writable: true, configurable: true,
      })
    }
    return clone
  }
  const expanded = entries.map(entry => expand(entry, 1))
  return { entries: expanded, aliased: state.aliased, limit: state.limit }
}

/** Thrown when the patch file cannot be parsed as an entry list. */
export class PatchParseError extends Error {
  /** True when the failure is a `!js` single-bang tag, which never loads anywhere. */
  readonly singleBangTag: boolean

  /**
   * @param message - the underlying parse diagnostic.
   * @param singleBangTag - whether the raw text contains a `!js` tag.
   */
  constructor(message: string, singleBangTag: boolean) {
    super(message)
    this.singleBangTag = singleBangTag
  }
}

/**
 * Whether a value is a plain object. Patch rows are objects; anything else at a
 * row position is malformed input from an untrusted file.
 * @param value - the parsed value.
 * @returns true for a non-null, non-array object.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Whether a value is a `!!js` node. Matches the loader's own predicate.
 * @param value - the parsed value.
 * @returns true for an expression node.
 */
export function isJsExpr(value: unknown): value is JsExprNode {
  return isRecord(value) && typeof value.__jsExpr === 'string'
}

/**
 * Classify what a `!!js` expression can reach, by parsing it — never running
 * it. Precedence is by reach: module access beats mutation beats an unknown
 * call beats a known-inert call beats a read, so an expression is reported at
 * its most capable form.
 *
 * The grading is by reach, not by syntactic form. `dshHomePath('sessions')` is
 * a `CallExpression` and so is `steal()`, but the first is a helper the harness
 * itself provides to these expressions and uses in its own shipped bundle,
 * while the second names something this tool cannot resolve. Grading both as
 * the same thing puts the harness's own configuration at the same severity as
 * an attack and teaches the reader to skip the class.
 * @param expression - the raw expression text.
 * @returns the classification and, when it does not parse, the diagnostic.
 */
export function classifyExpression(expression: string): { class: ExpressionClass, parseError?: string } {
  try {
    // Compilation only. The Function constructor never executes the body, and
    // the resulting function is discarded without being called.
    new Function(`return (${expression})`)
  } catch (error) {
    /* v8 ignore next -- the Function constructor rejects a body only with a SyntaxError. */
    return { class: 'unparseable', parseError: error instanceof Error ? error.message : String(error) }
  }
  const source = ts.createSourceFile('expr.ts', `(${expression})`, ts.ScriptTarget.ESNext, false, ts.ScriptKind.TS)
  let sawCall = false
  let sawHarnessCall = false
  let sawMutation = false
  let sawModuleAccess = false
  let sawIdentifier = false
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && MODULE_REACHING_NAMES.has(node.text)) sawModuleAccess = true
    if (ts.isPropertyAccessExpression(node) && MODULE_REACHING_NAMES.has(node.name.text)) sawModuleAccess = true
    if (node.kind === ts.SyntaxKind.ImportKeyword) sawModuleAccess = true
    if (ts.isBinaryExpression(node) && ASSIGNMENT_OPERATORS.has(node.operatorToken.kind)) sawMutation = true
    if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
      if (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) sawMutation = true
    }
    if (ts.isDeleteExpression(node)) sawMutation = true
    if (ts.isCallExpression(node)) {
      if (isInertCall(node)) sawHarnessCall = true
      else sawCall = true
    }
    if (ts.isNewExpression(node)) sawCall = true
    if (ts.isIdentifier(node)) sawIdentifier = true
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(source, visit)
  if (sawModuleAccess) return { class: 'module-access' }
  if (sawMutation) return { class: 'mutation' }
  if (sawCall) return { class: 'call' }
  if (sawHarnessCall) return { class: 'harness-call' }
  if (sawIdentifier) return { class: 'inert-read' }
  return { class: 'literal' }
}

/** Names that reach the module system, the global object, or the evaluator. */
const MODULE_REACHING_NAMES: ReadonlySet<string> = new Set([
  'require', 'eval', 'Function', 'globalThis', 'global', 'getBuiltinModule',
  'constructor', 'binding', 'dlopen', '__proto__',
])

/** Binary operator kinds that write. */
const ASSIGNMENT_OPERATORS: ReadonlySet<ts.SyntaxKind> = new Set([
  ts.SyntaxKind.EqualsToken,
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken,
  ts.SyntaxKind.SlashEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
])

/**
 * Calls the harness itself puts in scope for these expressions, or that only
 * read the current process's own identity — `cwd: !!js process.cwd()` and
 * `root: !!js dshHomePath('sessions')` are both from the shipped bundles.
 * Grading these as an unknown call would fire on the reference configuration.
 * @param node - the call expression.
 * @returns true when the callee is a catalogued harness or process helper.
 */
function isInertCall(node: ts.CallExpression): boolean {
  const callee = node.expression
  if (ts.isIdentifier(callee)) return HARNESS_INERT_CALLS.has(callee.text)
  if (!ts.isPropertyAccessExpression(callee)) return false
  if (!ts.isIdentifier(callee.expression)) return false
  return HARNESS_INERT_CALLS.has(`${callee.expression.text}.${callee.name.text}`)
}

/**
 * Collect every `!!js` node below a value, with its diagnostic path. Mirrors
 * `collectExpressionPaths` in the harness's verify script.
 * @param value - the value to walk.
 * @param path - the diagnostic path prefix.
 * @param slot - the slot these expressions occupy.
 * @param sink - accumulators, including the walk budget.
 * @param depth - the current nesting depth.
 */
function collect(value: unknown, path: string, slot: ExpressionSlot, sink: WalkSink, depth: number): void {
  if (isJsExpr(value)) {
    const classified = classifyExpression(value.__jsExpr)
    sink.expressions.push({
      path,
      expression: value.__jsExpr,
      slot,
      classification: classified.class,
      ...classified.parseError !== undefined ? { parseError: classified.parseError } : {},
    })
    return
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) collect(item, `${path}[${index}]`, slot, sink, depth + 1)
    return
  }
  if (!isRecord(value)) return
  for (const [key, child] of Object.entries(value)) collect(child, `${path}.${key}`, slot, sink, depth + 1)
}

/**
 * Collect the expressions of one row or patch, applying the loader's rule:
 * `config` is interpolated recursively, `disabled` only at its own top level,
 * and every other field stays literal so an expression there is inert data.
 * @param entry - the row or patch object.
 * @param path - its diagnostic path.
 * @param sink - accumulators, including the walk budget.
 * @param configIsData - false when `config` holds child rows rather than plugin data.
 * @param depth - the current nesting depth.
 */
function collectEntryExpressions(
  entry: Record<string, unknown>, path: string, sink: WalkSink, configIsData: boolean, depth: number,
): void {
  if (configIsData && 'config' in entry) collect(entry.config, `${path}.config`, 'config', sink, depth + 1)
  if ('disabled' in entry) {
    const disabled = entry.disabled
    const slot: ExpressionSlot = isJsExpr(disabled) ? 'disabled' : 'inert'
    collect(disabled, `${path}.disabled`, slot, sink, depth + 1)
  }
  for (const field of STATIC_ENTRY_FIELDS) {
    if (field in entry) collect(entry[field], `${path}.${field}`, 'inert', sink, depth + 1)
  }
}

/**
 * The service names an `isolate` or `intercept` entry field names. The loader
 * reads both as a dictionary keyed by service name (`entry.options.isolate?.[name]`).
 * @param value - the raw field value.
 * @returns the service names, or an empty list when the field is absent or malformed.
 */
function serviceNames(value: unknown): string[] {
  return isRecord(value) ? Object.keys(value) : []
}

/**
 * Whether a row carries other rows in its `config` rather than plugin data.
 * The loader keeps such a config literal and evaluates each child expression in
 * the child's own fiber instead.
 * @param entry - the row.
 * @returns true for a group or include carrier.
 */
function isTreeCarrier(entry: Record<string, unknown>): boolean {
  return entry.group === true || (typeof entry.name === 'string' && TREE_CARRIERS.has(entry.name))
}

/** Accumulators threaded through the recursive walk. */
interface WalkSink {
  readonly overrides: OverridePatch[]
  readonly inserts: InsertedRow[]
  readonly expressions: ExpressionSite[]
}

/**
 * Walk one inserted row and, when it carries children, its children too.
 * @param value - the row.
 * @param path - its diagnostic path.
 * @param intoGroupId - the group this row is inserted into, or `null`.
 * @param sink - accumulators.
 * @param depth - the current nesting depth.
 */
function walkRow(value: unknown, path: string, intoGroupId: string | null, sink: WalkSink, depth: number): void {
  if (!isRecord(value)) return
  const carrier = isTreeCarrier(value)
  sink.inserts.push({
    path,
    id: typeof value.id === 'string' ? value.id : null,
    name: typeof value.name === 'string' ? value.name : null,
    config: value.config,
    intoGroupId,
    isolate: serviceNames(value.isolate),
    intercept: serviceNames(value.intercept),
  })
  collectEntryExpressions(value, path, sink, !carrier, depth)
  if (!carrier) return
  const config = value.config
  if (Array.isArray(config)) {
    for (const [index, child] of config.entries()) {
      walkRow(child, `${path}.config[${index}]`, typeof value.id === 'string' ? value.id : null, sink, depth + 1)
    }
    return
  }
  if (isRecord(config) && Array.isArray(config.patches)) {
    walkPatchList(config.patches, `${path}.config.patches`, sink, depth + 1)
  }
}

/**
 * Walk a patch list, separating inserts from overrides exactly as
 * `applyEntryPatches` does: `insert` is checked first and wins outright, so a
 * patch carrying both `insert` and override keys applies only the insert.
 * @param list - the patch array.
 * @param prefix - diagnostic path prefix.
 * @param sink - accumulators.
 * @param depth - the current nesting depth.
 */
function walkPatchList(list: readonly unknown[], prefix: string, sink: WalkSink, depth: number): void {
  for (const [index, patch] of list.entries()) {
    const path = `${prefix}[${index}]`
    if (!isRecord(patch)) continue
    const id = typeof patch.id === 'string' ? patch.id : null
    if (Array.isArray(patch.insert)) {
      for (const [rowIndex, row] of patch.insert.entries()) {
        walkRow(row, `${path}.insert[${rowIndex}]`, id, sink, depth + 1)
      }
      continue
    }
    if (id === null) continue
    const overriddenKeys = Object.keys(patch).filter(key => key !== 'id' && key !== 'insert' && key !== 'name')
    sink.overrides.push({
      path,
      id,
      nameGuard: typeof patch.name === 'string' ? patch.name : null,
      overriddenKeys,
      disabled: 'disabled' in patch ? patch.disabled : undefined,
      config: patch.config,
    })
    collectEntryExpressions(patch, path, sink, true, depth)
  }
}

/**
 * Parse a patch layer.
 * @param file - package-relative path, used in findings.
 * @param text - the YAML text.
 * @returns the modelled patch document.
 * @throws PatchParseError when the text is not a loadable entry list.
 */
export function parsePatchDocument(file: string, text: string): PatchDocument {
  let loaded: unknown
  try {
    loaded = yaml.load(text, { schema: patchSchema })
  } catch (error) {
    /* v8 ignore next -- js-yaml rejects a document only with a YAMLException. */
    const message = error instanceof Error ? error.message : String(error)
    throw new PatchParseError(message, /(?<!!)!js(?![a-zA-Z0-9_-])/.test(text))
  }
  if (!Array.isArray(loaded)) {
    throw new PatchParseError('a patch layer must be a top-level array of entries', false)
  }
  const expansion = expandAliases(loaded)
  const sink: WalkSink = { overrides: [], inserts: [], expressions: [] }
  walkPatchList(expansion.entries, '', sink, 0)
  return {
    file,
    overrides: sink.overrides,
    inserts: sink.inserts,
    expressions: sink.expressions,
    limit: expansion.limit,
    aliased: expansion.aliased,
  }
}
