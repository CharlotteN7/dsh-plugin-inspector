/**
 * The constant folder, one case per form it accepts and one per form it
 * refuses.
 *
 * Both tiers read it: Tier B matches the text it returns, Tier C degrades the
 * report on the `null`. So a form this accepts too readily invents a finding,
 * and a form it refuses too readily degrades a package that could be read —
 * which is why the refusals are pinned as hard as the acceptances.
 * @module tests/unit/folding
 */

import ts from 'typescript'
import { describe, expect, it } from 'vitest'
import { foldConstantString, isBuiltinModuleGetter } from '../../src/syntax.ts'

/**
 * Parse one expression and hand back its node.
 * @param expression - the expression text.
 * @returns the parsed expression.
 */
function parse(expression: string): ts.Expression {
  const source = ts.createSourceFile('e.ts', `const x = ${expression}\n`, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS)
  const statement = source.statements[0] as ts.VariableStatement
  return statement.declarationList.declarations[0]?.initializer as ts.Expression
}

/**
 * Fold one expression written as source.
 * @param expression - the expression text.
 * @returns the folded text, or `null`.
 */
function fold(expression: string): string | null {
  return foldConstantString(parse(expression))
}

describe('an expression whose value is written in the file', () => {
  it.each([
    ['a string literal', '"node:fs"', 'node:fs'],
    ['a template with no substitution', '`node:fs`', 'node:fs'],
    ['a parenthesised literal', '("node:" + "fs")', 'node:fs'],
    ['a concatenation of literals', '"node:" + "child" + "_process"', 'node:child_process'],
    ['a template whose spans are literals', '`node:${"child"}${"_process"}`', 'node:child_process'],
    ['an array of literals joined on a literal', "['node:child','_process'].join('')", 'node:child_process'],
    ['an array joined on the default separator', "['a','b'].join()", 'a,b'],
    ['an empty array joined', "[].join('')", ''],
  ])('is folded to the name it holds: %s', (_what, expression, expected) => {
    expect(fold(expression)).toBe(expected)
  })
})

describe('an expression whose value is not written in the file', () => {
  it.each([
    ['an identifier', 'name'],
    ['a property read', 'config.name'],
    ['a concatenation reaching an identifier on the left', 'prefix + "_process"'],
    ['a concatenation reaching an identifier on the right', '"node:" + suffix'],
    ['an operator that is not concatenation', '"node:" in target'],
    ['a template with a computed span', '`node:${suffix}`'],
    ['a call that is not `join`', 'assemble("node:fs")'],
    ['a `join` on something that is not an array literal', "parts.join('')"],
    ['a `join` over an element that is computed', "['node:', suffix].join('')"],
    ['a `join` on a computed separator', "['a','b'].join(separator)"],
    ['a numeric literal', '42'],
  ])('is refused, so the site degrades the report instead: %s', (_what, expression) => {
    expect(fold(expression)).toBeNull()
  })

  it('is refused past the nesting bound, however constant each part is', () => {
    // The bound is what keeps the folder from recursing over attacker-supplied
    // syntax. Refusing is the conservative answer: the site degrades.
    const deep = Array.from({ length: 24 }, (_unused, index) => `"${index}"`).join(' + ')
    expect(fold(deep)).toBeNull()
    expect(fold('"0" + "1" + "2"')).toBe('012')
  })

  it('is refused when there is no expression at all', () => {
    expect(foldConstantString(undefined)).toBeNull()
  })
})

describe('the builtin-module getter', () => {
  it.each([
    ['is recognised on `process`', 'process.getBuiltinModule("node:fs")', true],
    ['is not recognised on another receiver', 'sandbox.getBuiltinModule("node:fs")', false],
    ['is not recognised under another member name', 'process.binding("fs")', false],
    ['is not recognised as a bare call', 'getBuiltinModule("node:fs")', false],
  ])('%s', (_what, expression, expected) => {
    expect(isBuiltinModuleGetter(parse(expression) as ts.CallExpression)).toBe(expected)
  })
})
