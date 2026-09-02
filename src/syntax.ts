/**
 * Readings of a syntax tree that both capability detection and readability
 * detection need, and that must agree between them.
 *
 * Tier B matches a name; Tier C reports the names it could not match. If the
 * two disagree about which expressions are constant, a package gets both a
 * finding and a degrade for the same site, or neither. They agree because they
 * ask the same function.
 *
 * Nothing here evaluates anything. {@link foldConstantString} reads literals
 * out of an already-parsed tree and concatenates them; it never constructs a
 * function, and it never touches an identifier's value.
 * @module dsh-plugin-inspector/syntax
 */

import ts from 'typescript'

/**
 * How far {@link foldConstantString} descends before answering `null`.
 *
 * A bound rather than a promise: the folder recurses over attacker-supplied
 * syntax, and a name worth hiding is not hidden eight levels of concatenation
 * deep. Past the bound the answer is "this tool cannot resolve it", which
 * degrades the report rather than dropping the site.
 */
const MAX_FOLD_DEPTH = 8

/**
 * The separator `Array.prototype.join` uses when called with no argument.
 */
const DEFAULT_JOIN_SEPARATOR = ','

/**
 * The `Array.prototype.join` case: `['node:child', '_process'].join('')`.
 * @param node - the call expression.
 * @param depth - the current recursion depth.
 * @returns the joined text, or `null` when any part is not a constant.
 */
function foldJoin(node: ts.CallExpression, depth: number): string | null {
  const callee = node.expression
  if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'join') return null
  if (!ts.isArrayLiteralExpression(callee.expression)) return null
  const separator = node.arguments.length === 0
    ? DEFAULT_JOIN_SEPARATOR
    : fold(node.arguments[0], depth + 1)
  if (separator === null) return null
  const parts: string[] = []
  for (const element of callee.expression.elements) {
    const part = fold(element, depth + 1)
    if (part === null) return null
    parts.push(part)
  }
  return parts.join(separator)
}

/**
 * The template case: `` `node:${'fs'}` ``.
 * @param node - the template expression.
 * @param depth - the current recursion depth.
 * @returns the assembled text, or `null` when any span is not a constant.
 */
function foldTemplate(node: ts.TemplateExpression, depth: number): string | null {
  let text = node.head.text
  for (const span of node.templateSpans) {
    const value = fold(span.expression, depth + 1)
    if (value === null) return null
    text += value + span.literal.text
  }
  return text
}

/**
 * The recursive half of {@link foldConstantString}.
 * @param node - the expression to fold.
 * @param depth - the current recursion depth.
 * @returns the text, or `null`.
 */
function fold(node: ts.Node | undefined, depth: number): string | null {
  if (node === undefined || depth > MAX_FOLD_DEPTH) return null
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text
  if (ts.isParenthesizedExpression(node)) return fold(node.expression, depth + 1)
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = fold(node.left, depth + 1)
    const right = fold(node.right, depth + 1)
    return left === null || right === null ? null : left + right
  }
  if (ts.isTemplateExpression(node)) return foldTemplate(node, depth)
  if (ts.isCallExpression(node)) return foldJoin(node, depth)
  return null
}

/**
 * The text a constant string expression holds, or `null` when the expression is
 * not constant.
 *
 * Four forms, chosen because each one is a spelling of a name that a reader
 * sees and a name-matching check does not: a literal, a `+` chain of them, a
 * template whose every span is one, and `[…].join(…)` over an array of them.
 * Anything reaching an identifier, a property, or any other call answers
 * `null` — resolving those is value tracking, which this tool does not do and
 * which Tier C exists to admit.
 * @param node - the expression, or `undefined` for a missing argument.
 * @returns the text, or `null`.
 */
export function foldConstantString(node: ts.Node | undefined): string | null {
  return fold(node, 0)
}

/**
 * The Node API that hands back a builtin module without `require` and without
 * an `import` declaration, added in Node 22.3.
 *
 * It reaches the same modules the harness sandbox's `require` trap covers,
 * from a call that sandbox never sees: the sandbox leaves
 * `process` `undefined`, so inside it this expression throws, and a mounted
 * bundle layer is not inside it.
 * @see https://nodejs.org/api/process.html#processgetbuiltinmoduleid
 */
export const BUILTIN_MODULE_GETTER = 'getBuiltinModule'

/**
 * Whether a call is `process.getBuiltinModule(…)`.
 *
 * The receiver is required. `getBuiltinModule` pulled off `process` and bound
 * to a bare name is not this — it is a detached member, which Tier C reports as
 * dispatch it cannot follow.
 * @param node - the call expression.
 * @returns true when the call loads a builtin through `process`.
 */
export function isBuiltinModuleGetter(node: ts.CallExpression): boolean {
  const callee = node.expression
  return ts.isPropertyAccessExpression(callee) && callee.name.text === BUILTIN_MODULE_GETTER
    && ts.isIdentifier(callee.expression) && callee.expression.text === 'process'
}
