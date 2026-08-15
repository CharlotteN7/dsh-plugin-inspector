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
import { STATIC_ENTRY_FIELDS } from './knowledge.ts'

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
  | 'call'
  | 'mutation'
  | 'module-access'
  | 'unparseable'

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
}

/** One parsed patch layer. */
export interface PatchDocument {
  /** Package-relative path of the YAML file. */
  readonly file: string
  readonly overrides: readonly OverridePatch[]
  readonly inserts: readonly InsertedRow[]
  readonly expressions: readonly ExpressionSite[]
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
 * it. Precedence is by reach: module access beats mutation beats call beats
 * read, so an expression is reported at its most capable form.
 * @param expression - the raw expression text.
 * @returns the classification and, when it does not parse, the diagnostic.
 */
export function classifyExpression(expression: string): { class: ExpressionClass, parseError?: string } {
  try {
    // Compilation only. The Function constructor never executes the body, and
    // the resulting function is discarded without being called.
    new Function(`return (${expression})`)
  } catch (error) {
    return { class: 'unparseable', parseError: error instanceof Error ? error.message : String(error) }
  }
  const source = ts.createSourceFile('expr.ts', `(${expression})`, ts.ScriptTarget.ESNext, false, ts.ScriptKind.TS)
  let sawCall = false
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
    if (ts.isCallExpression(node) && !isInertCall(node)) sawCall = true
    if (ts.isNewExpression(node)) sawCall = true
    if (ts.isIdentifier(node)) sawIdentifier = true
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(source, visit)
  if (sawModuleAccess) return { class: 'module-access' }
  if (sawMutation) return { class: 'mutation' }
  if (sawCall) return { class: 'call' }
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
 * Calls with no reach beyond reading the current process's own identity, which
 * the harness's own shipped examples use (`cwd: !!js process.cwd()`). Treating
 * these as `call` would fire on the reference configuration and teach users to
 * ignore the class.
 * @param node - the call expression.
 * @returns true when the callee is a known side-effect-free process read.
 */
function isInertCall(node: ts.CallExpression): boolean {
  const callee = node.expression
  if (!ts.isPropertyAccessExpression(callee)) return false
  if (!ts.isIdentifier(callee.expression) || callee.expression.text !== 'process') return false
  return callee.name.text === 'cwd' || callee.name.text === 'uptime'
}

/**
 * Collect every `!!js` node below a value, with its diagnostic path. Mirrors
 * `collectExpressionPaths` in the harness's verify script.
 * @param value - the value to walk.
 * @param path - the diagnostic path prefix.
 * @param slot - the slot these expressions occupy.
 * @param output - accumulator.
 */
function collect(value: unknown, path: string, slot: ExpressionSlot, output: ExpressionSite[]): void {
  if (isJsExpr(value)) {
    const classified = classifyExpression(value.__jsExpr)
    output.push({
      path,
      expression: value.__jsExpr,
      slot,
      classification: classified.class,
      ...classified.parseError !== undefined ? { parseError: classified.parseError } : {},
    })
    return
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) collect(item, `${path}[${index}]`, slot, output)
    return
  }
  if (!isRecord(value)) return
  for (const [key, child] of Object.entries(value)) collect(child, `${path}.${key}`, slot, output)
}

/**
 * Collect the expressions of one row or patch, applying the loader's rule:
 * `config` is interpolated recursively, `disabled` only at its own top level,
 * and every other field stays literal so an expression there is inert data.
 * @param entry - the row or patch object.
 * @param path - its diagnostic path.
 * @param output - accumulator.
 * @param configIsData - false when `config` holds child rows rather than plugin data.
 */
function collectEntryExpressions(
  entry: Record<string, unknown>, path: string, output: ExpressionSite[], configIsData: boolean,
): void {
  if (configIsData && 'config' in entry) collect(entry.config, `${path}.config`, 'config', output)
  if ('disabled' in entry) {
    const disabled = entry.disabled
    if (isJsExpr(disabled)) {
      collect(disabled, `${path}.disabled`, 'disabled', output)
    } else {
      collect(disabled, `${path}.disabled`, 'inert', output)
    }
  }
  for (const field of STATIC_ENTRY_FIELDS) {
    if (field in entry) collect(entry[field], `${path}.${field}`, 'inert', output)
  }
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
 */
function walkRow(value: unknown, path: string, intoGroupId: string | null, sink: WalkSink): void {
  if (!isRecord(value)) return
  const carrier = isTreeCarrier(value)
  sink.inserts.push({
    path,
    id: typeof value.id === 'string' ? value.id : null,
    name: typeof value.name === 'string' ? value.name : null,
    config: value.config,
    intoGroupId,
  })
  collectEntryExpressions(value, path, sink.expressions, !carrier)
  if (!carrier) return
  const config = value.config
  if (Array.isArray(config)) {
    for (const [index, child] of config.entries()) {
      walkRow(child, `${path}.config[${index}]`, typeof value.id === 'string' ? value.id : null, sink)
    }
    return
  }
  if (isRecord(config) && Array.isArray(config.patches)) {
    walkPatchList(config.patches, `${path}.config.patches`, sink)
  }
}

/**
 * Walk a patch list, separating inserts from overrides exactly as
 * `applyEntryPatches` does: `insert` is checked first and wins outright, so a
 * patch carrying both `insert` and override keys applies only the insert.
 * @param list - the patch array.
 * @param prefix - diagnostic path prefix.
 * @param sink - accumulators.
 */
function walkPatchList(list: readonly unknown[], prefix: string, sink: WalkSink): void {
  for (const [index, patch] of list.entries()) {
    const path = `${prefix}[${index}]`
    if (!isRecord(patch)) continue
    const id = typeof patch.id === 'string' ? patch.id : null
    if (Array.isArray(patch.insert)) {
      for (const [rowIndex, row] of patch.insert.entries()) {
        walkRow(row, `${path}.insert[${rowIndex}]`, id, sink)
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
    collectEntryExpressions(patch, path, sink.expressions, true)
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
  let document: unknown
  try {
    document = yaml.load(text, { schema: patchSchema })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new PatchParseError(message, /(?<!!)!js(?![a-zA-Z0-9_-])/.test(text))
  }
  if (!Array.isArray(document)) {
    throw new PatchParseError('a patch layer must be a top-level array of entries', false)
  }
  const sink: WalkSink = { overrides: [], inserts: [], expressions: [] }
  walkPatchList(document, '', sink)
  return { file, overrides: sink.overrides, inserts: sink.inserts, expressions: sink.expressions }
}
