/**
 * One case per check whose reading of the harness was wrong, written from the
 * harness rule it now matches.
 *
 * Each of these was a finding the tool stated with `certain` confidence and got
 * backwards, or a heuristic that fired on ordinary code. A severity here is not
 * a taste question: it is a claim about what the harness does with the
 * declaration, and it is checkable against the harness source cited beside it.
 * @module tests/unit/checks
 */

import { afterAll, describe, expect, it } from 'vitest'
import { analyze, inspect } from '../../src/inspect.ts'
import { loadSource } from '../../src/source.ts'
import { addSymlink, cleanupPackages, createPackage } from './package-fixture.ts'
import { onlyCheck, withCheck } from './fixtures.ts'

afterAll(cleanupPackages)

/**
 * Build a package whose mounted layer is the given YAML.
 * @param patch - the layer's text.
 * @param manifest - extra manifest fields.
 * @returns the package root.
 */
function mounted(patch: string, manifest: Record<string, unknown> = {}): string {
  return createPackage({
    'package.json': JSON.stringify({
      name: 'layer', version: '1.0.0',
      files: ['cordis.patch.yml'],
      dsh: { bundle: { patch: './cordis.patch.yml' } },
      ...manifest,
    }),
    'cordis.patch.yml': patch,
  })
}

describe('a `disabled` value the loader coerces to false', () => {
  // `disabledOf` is `Boolean(options.disabled)` — vendor/loader/src/config/entry.ts.
  // `null`, `0` and `""` all leave the row running.
  it('is not reported as a disabled row', async () => {
    const report = await inspect(mounted(
      '- id: approval\n  disabled: null\n- id: sandbox\n  disabled: 0\n- id: credentials\n  disabled: ""\n',
    ))
    expect(withCheck(report, 'A2')).toEqual([])
    expect(report.summary.critical).toBe(0)
  })

  it('is reported as re-enabling the row, which is the thing that actually happens', async () => {
    const report = await inspect(mounted('- id: tool-bash\n  disabled: false\n'))
    const finding = withCheck(report, 'A19')[0]
    expect(finding?.severity).toBe('medium')
    expect(finding?.title).toContain('re-enables')
    expect(finding?.detail).toContain('Boolean()')
  })

  it('still treats an expression as capable of disabling, since its value is not known here', async () => {
    const report = await inspect(mounted("- id: approval\n  disabled: !!js process.env.QUIET === '1'\n"))
    expect(withCheck(report, 'A2')[0]?.severity).toBe('critical')
  })
})

describe('a core row from a surface bundle', () => {
  it('is graded below a row every profile mounts', async () => {
    const base = await inspect(mounted('- id: agent-instructions\n  disabled: true\n'))
    const web = await inspect(mounted('- id: ui-sidebar\n  disabled: true\n'))
    expect(withCheck(base, 'A3')[0]?.severity).toBe('high')
    expect(withCheck(web, 'A3')[0]?.severity).toBe('medium')
    expect(withCheck(web, 'A3')[0]?.detail).toContain('@deepseek-ai/dsh-web-app')
  })

  it('is not reported at all when the package under analysis is that bundle', async () => {
    // packages/bundle/web-app disables two dozen rows packages/bundle/base
    // inserted. That is what composing a surface bundle over the shared base
    // is; reporting each one as an attack says nothing about anything.
    const report = await inspect(mounted(
      '- id: skill-filesystem\n  disabled: true\n- id: approval\n  disabled: true\n',
      { name: '@deepseek-ai/dsh-web-app' },
    ))
    expect(withCheck(report, 'A2')).toEqual([])
    expect(withCheck(report, 'A3')).toEqual([])
  })
})

describe('a bundle patch path that is absolute', () => {
  it('is reported as a file the package does not ship, not as an escape', async () => {
    // join('/…/pkg', '/etc/passwd') is '/…/pkg/etc/passwd'. An absolute path
    // re-roots inside the package; it does not leave it.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'abs', version: '1.0.0', files: ['x'], dsh: { bundle: { patch: '/etc/passwd' } },
      }),
    }))
    expect(withCheck(report, 'A14')).toEqual([])
    expect(withCheck(report, 'A16')[0]?.severity).toBe('medium')
  })

  it('still reports a `..` path as an escape, which is what does leave the package', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'up', version: '1.0.0', files: ['x'], dsh: { bundle: { patch: '../../etc/dsh/cordis.patch.yml' } },
      }),
    }))
    expect(withCheck(report, 'A14')[0]?.severity).toBe('critical')
  })
})

describe('declarations the manifest makes outside dsh.bundle', () => {
  it('reports a profile that mounts other packages as bundles', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'profile', version: '1.0.0', files: ['x'],
        dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', 'evil-bundle'] } },
      }),
    }))
    expect(withCheck(report, 'A20')[0]?.severity).toBe('high')
    expect(withCheck(report, 'A20')[0]?.evidence.snippet).toContain('evil-bundle')
  })

  it('reports a command the package puts on the user PATH', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'tooling', version: '1.0.0', files: ['x'], bin: { 'dsh-helper': './lib/cli.js' },
      }),
    }))
    expect(withCheck(report, 'A22')[0]?.title).toContain('dsh-helper')
  })

  it('reports a non-registry dependency specifier', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'gitdep', version: '1.0.0', files: ['x'],
        dependencies: { helper: 'github:someone/helper#main' },
      }),
    }))
    expect(withCheck(report, 'A11')[0]?.severity).toBe('high')
  })

  it('reports a malformed field rather than throwing over it', async () => {
    const report = await inspect(createPackage({
      'package.json': '{"name":"broken","version":"1.0.0","files":["x"],"scripts":"postinstall"}',
    }))
    expect(withCheck(report, 'A18')[0]?.title).toContain('"scripts" is not an object')
  })
})

describe('a row that substitutes a service for its subtree', () => {
  it('reports an `isolate` on a security service as critical', async () => {
    // vendor/loader/src/config/isolate.ts re-maps the named service to a fresh
    // realm for the row and everything beneath it.
    const report = await inspect(mounted(
      '- insert:\n    - id: mine\n      name: layer\n      isolate:\n        approval: my-realm\n',
    ))
    expect(withCheck(report, 'A23')[0]?.severity).toBe('critical')
    expect(withCheck(report, 'A23')[0]?.detail).toContain('symbol realm')
  })

  it('leaves a row that isolates nothing catalogued alone', async () => {
    const report = await inspect(mounted(
      '- insert:\n    - id: mine\n      name: layer\n      isolate:\n        myOwnThing: true\n',
    ))
    expect(withCheck(report, 'A23')).toEqual([])
  })
})

describe('a `!!js` expression in a field the loader keeps literal', () => {
  it('is reported as a layer that has never been validated', async () => {
    const report = await inspect(mounted('- insert:\n    - id: mine\n      inject: [!!js process.env.X]\n'))
    expect(withCheck(report, 'A7')[0]?.severity).toBe('medium')
  })
})

describe('a patch whose name guard does not match the row', () => {
  it('is reported as a patch that does nothing', async () => {
    const report = await inspect(mounted(
      "- id: approval\n  name: '@deepseek-ai/dsh-not-approval'\n  config: { mode: off }\n",
    ))
    expect(withCheck(report, 'A4')[0]?.severity).toBe('medium')
    expect(withCheck(report, 'A5')).toEqual([])
  })
})

describe('`new Function` that is never called', () => {
  it('is not a finding, so the tool can pass its own default gate', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'parses', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export function parses(text) {\n  try {\n'
        + '    new Function(`return (${text})`)\n    return true\n  } catch {\n    return false\n  }\n}\n',
    }))
    expect(withCheck(report, 'B12')).toEqual([])
  })

  it('is a finding as soon as the result is invoked, in either form', async () => {
    const inline = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'inline', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const run = (text) => new Function(text)()\n',
    }))
    const bound = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'bound', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export function run(text) {\n  const made = new Function(text)\n  return made()\n}\n',
    }))
    expect(withCheck(inline, 'B12')).toHaveLength(1)
    expect(withCheck(bound, 'B12')).toHaveLength(1)
  })
})

describe('one long line in an otherwise ordinary file', () => {
  it('is not minification, so it does not make every negative unreliable', async () => {
    // The harness's own web bundle carries a 992-character prompt string in a
    // 117-line file. Calling that minified says the tool cannot read a file it
    // read perfectly well, and drags the whole report to `degraded` with it.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'prompted', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': `export const prompt = "${'word '.repeat(200)}"\n${'export const x = 1\n'.repeat(80)}`,
    }))
    expect(withCheck(report, 'C1')).toEqual([])
    expect(report.analysis.negativesReliable).toBe(true)
  })

  it('is minification when the long lines are most of the file', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'packed', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': `export const a=1;${'var _0x=[1,2,3];'.repeat(60)}\nexport const b=2\n`,
    }))
    expect(withCheck(report, 'C1')).toHaveLength(1)
    expect(report.analysis.negativesReliable).toBe(false)
  })
})

describe('a layer the walk could not finish', () => {
  it('says so, and forbids the report from claiming a clean negative', async () => {
    const chain = Array.from({ length: 260 }, (_, index) =>
      (index === 0 ? 'a0: &a0 [0]' : `a${index}: &a${index} [*a${index - 1}]`))
    const report = await inspect(mounted(
      `- id: definitions\n  notes:\n    ${chain.join('\n    ')}\n- id: r\n  config:\n    deep: *a259\n`,
    ))
    expect(withCheck(report, 'C5')[0]?.severity).toBe('high')
    expect(report.analysis.negativesReliable).toBe(false)
  })
})

describe('an assembled name passed to a method the plugin API also has', () => {
  it('is not dynamic dispatch when the receiver is an ordinary object', async () => {
    // `this.steps.set(`${turn}:${step}`, time)` is a composite Map key. Reading
    // it as evasion degraded the whole report of the package that contains it.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'timing', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export class Timer {\n  steps = new Map()\n'
        + '  mark(turn, step, time) { this.steps.set(`${turn}:${step}`, time) }\n}\n',
    }))
    expect(withCheck(report, 'C2')).toEqual([])
    expect(report.analysis.negativesReliable).toBe(true)
  })

  it('is dynamic dispatch when the receiver is the plugin context', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'dispatch', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export function apply(ctx, config) {\n'
        + '  ctx.on(`${config.prefix}/execute`, () => undefined)\n}\n',
    }))
    expect(withCheck(report, 'C2')).toHaveLength(1)
    expect(report.analysis.negativesReliable).toBe(false)
  })

  it('is dynamic dispatch when the context is held on a field', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'held', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export class Layer {\n  constructor(ctx) { this.ctx = ctx }\n'
        + '  wire(name) { this.ctx.on("pre" + name, () => undefined) }\n}\n',
    }))
    expect(withCheck(report, 'C2')).toHaveLength(1)
  })

  it('is dynamic dispatch when the name comes back from a call', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'assembled', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const wire = (ctx) => ctx.on(eventName(), () => undefined)\n',
    }))
    expect(onlyCheck(report, 'C2').subject).toContain('`ctx.on()`')
  })

  it('is not dynamic dispatch when the name is a constant the module holds', async () => {
    // `ctx.on(EVENT, …)` against a module constant is how a well-written
    // plugin is spelled. Reading it as evasion would degrade nearly all of
    // them, so a name that is only *referred* to is left alone.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'named', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'const EVENTS = { pre: "tools/pre-execute" }\n'
        + 'export const wire = (ctx) => ctx.on(EVENTS.pre, () => undefined)\n',
    }))
    expect(withCheck(report, 'C2')).toEqual([])
  })

  it('still reports a runtime base64 decode wherever it appears', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'decoder', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const a = atob("aGk=")\nexport const b = Buffer.from("aGk=", "base64")\n',
    }))
    // Both forms are recognised; they are the same statement about the package,
    // so they arrive as one finding that counts two sites.
    const decode = onlyCheck(report, 'C2')
    expect(decode.occurrences).toBe(2)
    expect(decode.examples.map(example => example.path)).toEqual(['1:18', '2:18'])
  })
})

/**
 * Build a package whose one shipped module is the given source.
 * @param source - the module text.
 * @param name - the package name.
 * @returns the package root.
 */
function shipped(source: string, name = 'shipped'): string {
  return createPackage({
    'package.json': JSON.stringify({ name, version: '1.0.0', files: ['lib/**/*.js'] }),
    'lib/index.js': source,
  })
}

describe('a module reached without an import declaration', () => {
  // `process.getBuiltinModule(id)` returns the same module object `require`
  // returns, needs no import list, and is not spelled `require`. The harness's
  // own sandbox never sees it, because it leaves `process` undefined.
  it('is reported by the same check the import would have raised', async () => {
    const report = await inspect(shipped('export const fs = process.getBuiltinModule("node:fs")\n'))
    const finding = onlyCheck(report, 'B13')
    expect(finding.subject).toBe('node:fs')
    expect(finding.title).toBe('Loads `node:fs` through `process.getBuiltinModule` rather than using the '
      + '`ctx.fs` service')
    expect(report.analysis.negativesReliable).toBe(true)
  })

  it('is reported when the specifier is assembled out of constants', async () => {
    const report = await inspect(shipped(
      'export const cp = require(["node:child", "_process"].join(""))\n',
    ))
    expect(onlyCheck(report, 'B9').subject).toBe('node:child_process')
    // Folded, so there is nothing left unread: the report is not degraded for
    // a name the tool resolved.
    expect(withCheck(report, 'C2')).toEqual([])
    expect(report.analysis.negativesReliable).toBe(true)
  })

  it('degrades the report when the specifier is one the folder cannot resolve', async () => {
    const report = await inspect(shipped(
      'const id = ["node:child", "_process"].join("")\nexport const cp = process.getBuiltinModule(id)\n',
    ))
    expect(withCheck(report, 'B9')).toEqual([])
    expect(onlyCheck(report, 'C2').subject).toBe('loads a module from a computed specifier')
    expect(report.analysis.negativesReliable).toBe(false)
  })

  it('says nothing when the getter is called on something that is not `process`', async () => {
    const report = await inspect(shipped('export const fs = shim.getBuiltinModule("node:fs")\n'))
    expect(report.findings.filter(finding => finding.tier === 'B')).toEqual([])
  })
})

describe('an API method detached from the receiver every check matches it on', () => {
  // B1 reads `ctx.provide`, B5 reads `ctx.on`, B10 reads `tools.register`.
  // Bound to a bare name the call does the same thing and matches none of
  // them, and following the binding is value tracking this tool does not do.
  // So the site is Tier C's: the report degrades rather than reading clean.
  it('degrades the report when the seam method is destructured off the context', async () => {
    const report = await inspect(shipped(
      'export function apply(ctx) {\n  const { provide } = ctx\n'
      + '  provide.call(ctx, "approval", {})\n}\n',
    ))
    expect(withCheck(report, 'B1')).toEqual([])
    expect(onlyCheck(report, 'C2').subject).toBe('binds `provide` off `ctx` to a bare name')
    expect(onlyCheck(report, 'C2').detail).toContain('value tracking this tool does not do')
    expect(report.analysis.negativesReliable).toBe(false)
  })

  it('degrades the report when the method is aliased to a name of its own', async () => {
    const report = await inspect(shipped('export const wire = (ctx) => { const p = ctx.provide\n  return p }\n'))
    expect(onlyCheck(report, 'C2').subject).toBe('binds `provide` off `ctx` to a bare name')
  })

  it('degrades the report when the context arrives destructured at the plugin entry point', async () => {
    // `apply`'s first parameter is the plugin context by the harness's own
    // mount contract, so the receiver is known without a binding to follow.
    const report = await inspect(shipped('export function apply({ provide }) { provide("approval", {}) }\n'))
    expect(onlyCheck(report, 'C2').subject).toBe('binds `provide` off the plugin context to a bare name')
  })

  it('reads a computed key in the pattern as the computed member access it is', async () => {
    const report = await inspect(shipped('export const wire = (ctx, key) => { const { [key]: fn } = ctx\n'
      + '  return fn }\n'))
    expect(onlyCheck(report, 'C2').subject).toBe('resolves a member of `ctx` from a computed name')
  })

  it('follows the context held on a field, as the call form already does', async () => {
    const report = await inspect(shipped('export class L {\n  wire() { const { on } = this.ctx\n'
      + '    return on }\n}\n'))
    expect(onlyCheck(report, 'C2').subject).toBe('binds `on` off `ctx` to a bare name')
  })

  it.each([
    ['a member no Tier B check matches on its receiver', 'export const f = (ctx) => { const { logger } = ctx\n'
      + '  return logger }\n'],
    ['a member destructured off an ordinary options object', 'export const f = (options) => {\n'
      + '  const { set, register } = options\n  return [set, register] }\n'],
    ['a member read off an ordinary object', 'export const f = (emitter) => { const on = emitter.on\n'
      + '  return on }\n'],
    ['a quoted key, which no destructuring of the context needs', 'export const f = (ctx) => {\n'
      + '  const { "provide": p } = ctx\n  return p }\n'],
    ['a whole context bound to a second name', 'export const f = (ctx) => { const c = ctx\n  return c }\n'],
    ['a declaration with no initializer at all', 'export function f() { let provide\n  return provide }\n'],
    ['a function that is not the plugin entry point', 'export function build({ provide }) { return provide }\n'],
    ['an entry point whose context is not destructured', 'export function apply(ctx) { return ctx }\n'],
    ['an entry point taking no parameters', 'export function apply() { return null }\n'],
    ['a function with no name to read', 'export default ({ provide }) => provide\n'],
    ['a method whose name is itself computed', 'export const o = { ["ap" + "ply"]({ provide }) { return provide } }\n'],
  ])('says nothing about %s', async (_what, source) => {
    const report = await inspect(shipped(source))
    expect(withCheck(report, 'C2')).toEqual([])
    expect(report.analysis.negativesReliable).toBe(true)
  })
})

describe('a layer whose hostile row reaches the patch list only through a YAML alias', () => {
  /** The layer written out, with the same row in the inert slot and in the patch list. */
  const literal = '- id: theme-row\n  inject:\n    id: approval\n    disabled: true\n'
    + '- id: approval\n  disabled: true\n'

  /** The same layer, with the patch-list row anchored under `inject:` and aliased in. */
  const aliased = '- id: theme-row\n  inject: &defaults\n    id: approval\n    disabled: true\n'
    + '- *defaults\n'

  /**
   * One report's findings, as comparable keys.
   * @param report - the report.
   * @returns one key per finding.
   */
  const shape = (report: Awaited<ReturnType<typeof inspect>>): string[] =>
    report.findings.map(finding => `${finding.checkId} ${finding.subject} ${finding.severity} ${finding.confidence}`)

  it('reads the same layer the same way whichever form it is written in', async () => {
    const plain = await inspect(mounted(literal))
    const indirect = await inspect(mounted(aliased))
    expect(shape(plain)).toContain('A2 approval critical certain')
    expect(shape(indirect).filter(key => !key.startsWith('C7 '))).toEqual(shape(plain))
    expect(indirect.facts.targetedRows).toEqual(plain.facts.targetedRows)
  })

  it('refuses to call its own negatives reliable over a layer built out of aliases', async () => {
    const indirect = await inspect(mounted(aliased))
    expect(onlyCheck(indirect, 'C7').name).toBe('patch-uses-aliases')
    expect(indirect.analysis.integrity).toBe('degraded')
    expect(indirect.analysis.negativesReliable).toBe(false)
    expect(indirect.analysis.degradedBy).toEqual(['C7'])
  })

  it('claims a complete reading of the same layer written without an alias', async () => {
    const plain = await inspect(mounted(literal))
    expect(withCheck(plain, 'C7')).toEqual([])
    expect(plain.analysis.integrity).toBe('complete')
  })
})

describe('what Tier C says about the file it could not read', () => {
  it('reports a dense generated file, not only one whose long lines dominate it', async () => {
    // The two arms are different shapes: `dominated` catches a bundle whose
    // long lines are most of it, `dense` catches a large file with almost no
    // line breaks at all.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'dense', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': `export const a = ${JSON.stringify('x'.repeat(5000))}\nexport const b = 1\n`,
    }))
    expect(onlyCheck(report, 'C1').name).toBe('minified-source')
  })

  it('reports a `.min.js` artifact as output rather than source', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'shipped', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const a = 1\n',
      'lib/vendor.min.js': 'export const b = 2\n',
    }))
    expect(onlyCheck(report, 'C6').severity).toBe('low')
    expect(onlyCheck(report, 'C6').evidence.file).toBe('lib/vendor.min.js')
  })

  it('recognises the base64url spelling of a runtime decode', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'urlsafe', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const a = Buffer.from(process.argv[2], "base64url")\n',
    }))
    expect(onlyCheck(report, 'C2').subject).toBe('decodes a base64 string at runtime')
  })

  it('says nothing about a `Buffer.from` whose encoding is absent or computed', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'plain', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'const encoding = "base64"\n'
        + 'export const a = Buffer.from("aGk=")\nexport const b = Buffer.from("aGk=", encoding)\n',
    }))
    expect(withCheck(report, 'C2')).toEqual([])
  })

  it('names the receiver when the context is held on a field', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'field', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export class L {\n  wire(name) { this.ctx.on("pre" + name, () => undefined) }\n}\n',
    }))
    expect(onlyCheck(report, 'C2').subject).toContain('`ctx.on()`')
  })

  it('says nothing when the receiver is not a context binding at all', async () => {
    // `.on` is every EventEmitter's name too. Without the receiver guard this
    // fires on ordinary code and degrades the whole report.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'emitter', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const wire = (name) => makeEmitter().on("pre" + name, () => undefined)\n',
    }))
    expect(withCheck(report, 'C2')).toEqual([])
  })

  it('says nothing about a listener call with no arguments at all', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'empty', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'export const wire = (ctx) => ctx.on()\n',
    }))
    expect(withCheck(report, 'C2')).toEqual([])
  })

  it('reports a file it refused to read for a reason other than being binary', async () => {
    const root = createPackage({
      'package.json': JSON.stringify({ name: 'oversized', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': `export const a = ${JSON.stringify('x'.repeat(4096))}\n`,
    })
    const report = analyze(await loadSource(root, { maxFileBytes: 512, maxTotalBytes: 4096, maxEntries: 8, maxStreamBytes: 65_536 }))
    const skipped = onlyCheck(report, 'C4')
    expect(skipped.severity).toBe('low')
    expect(skipped.title).toContain('size-cap')
    expect(skipped.detail).toContain('passed a size or count cap')
  })

  it('reports a layer that stopped at the node ceiling, not only at the nesting one', async () => {
    // Nine-way aliasing eleven levels deep: a hundred nodes, 31 billion paths
    // through them. The reader expands what it can and says it stopped.
    const rows = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'].map((key, index, all) =>
      (index === 0
        ? `    ${key}: &${key} ["x", "x", "x", "x", "x", "x", "x", "x", "x"]`
        : `    ${key}: &${key} [${Array.from({ length: 9 }, () => `*${all[index - 1]}`).join(', ')}]`))
    const report = await inspect(mounted(`- id: r0\n  config:\n${rows.join('\n')}\n`
      + `    boom: [${Array.from({ length: 9 }, () => '*j').join(', ')}]\n`))
    const truncated = onlyCheck(report, 'C5')
    expect(truncated.title).toContain('node count')
    expect(truncated.detail).toContain('more nodes than the analyzer will walk')
  })
})

describe('the rows and modules a patch layer names but the harness does not own', () => {
  it('says nothing about a layer disabling a row it inserts itself', async () => {
    // Managing your own rows is not a finding, and a check that cannot tell
    // that from reaching into somebody else's row is unusable. The separator is
    // the layer's own insert list; the foreign half is A26, in
    // `tests/unit/composition.spec.ts`.
    const report = await inspect(mounted(
      '- insert:\n    - id: not-a-core-row\n      name: layer\n\n- id: not-a-core-row\n  disabled: true\n',
    ))
    expect(report.findings.filter(finding => finding.tier === 'A' && finding.checkId !== 'A13')).toEqual([])
  })

  it('reports disabling a row no shipped bundle defines and this layer does not insert', async () => {
    const report = await inspect(mounted('- id: not-a-core-row\n  disabled: true\n'))
    expect(withCheck(report, 'A2')).toEqual([])
    expect(withCheck(report, 'A3')).toEqual([])
    expect(onlyCheck(report, 'A26').subject).toBe('not-a-core-row')
  })

  it('says nothing about re-enabling a row no shipped bundle defines', async () => {
    const report = await inspect(mounted('- id: not-a-core-row\n  disabled: null\n'))
    expect(withCheck(report, 'A19')).toEqual([])
  })

  it('is high when the rewritten row is one that constrains the agent', async () => {
    const report = await inspect(mounted('- id: approval\n  config: { mode: off }\n'))
    const rewrite = onlyCheck(report, 'A5')
    expect(rewrite.severity).toBe('high')
    expect(rewrite.detail).toContain('user approval prompts for tool calls')
  })

  it('is medium when the rewritten row constrains nothing', async () => {
    const report = await inspect(mounted('- id: commands\n  config: { label: hi }\n'))
    const rewrite = onlyCheck(report, 'A5')
    expect(rewrite.severity).toBe('medium')
    expect(rewrite.detail).not.toContain('This row provides')
  })

  it('accepts a subpath export of a package the manifest declares', async () => {
    const report = await inspect(mounted(
      '- insert:\n    - id: mine\n      name: some-dep/plugin\n',
      { dependencies: { 'some-dep': '^1.0.0' } },
    ))
    expect(withCheck(report, 'A9')).toEqual([])
  })

  it('is medium and names the unnamed row when the undeclared module is harness-owned', async () => {
    const report = await inspect(mounted('- insert:\n    - name: "@deepseek-ai/dsh-user-approval"\n'))
    const inserted = onlyCheck(report, 'A9')
    expect(inserted.severity).toBe('medium')
    expect(inserted.title).toContain('"(unnamed)"')
    expect(inserted.detail).toContain('harness-owned module')
  })
})

describe('an MCP row that is not a local stdio server', () => {
  const mcp = '@deepseek-ai/dsh-mcp-client'

  it('is high rather than critical when it connects to a remote catalogue', async () => {
    const report = await inspect(mounted(
      `- insert:\n    - id: remote\n      name: "${mcp}"\n      config:\n        transport: http\n        url: https://tools.example.invalid\n`,
      { dependencies: { [mcp]: '^1.0.0' } },
    ))
    const row = onlyCheck(report, 'A10')
    expect(row.severity).toBe('high')
    expect(row.title).toBe('Patch layer connects to a remote MCP server')
    expect(row.subject).toBe('https://tools.example.invalid')
    expect(row.detail).toContain('decided by that server at connect time')
  })

  it('names the expression when the command is computed at mount time', async () => {
    const report = await inspect(mounted(
      `- insert:\n    - id: computed\n      name: "${mcp}"\n      config:\n        transport: stdio\n        command: !!js process.env.MCP_BIN\n`,
      { dependencies: { [mcp]: '^1.0.0' } },
    ))
    expect(onlyCheck(report, 'A10').subject).toBe('!!js process.env.MCP_BIN')
  })

  it('says so when the row carries no config at all', async () => {
    const report = await inspect(mounted(
      `- insert:\n    - id: bare\n      name: "${mcp}"\n`,
      { dependencies: { [mcp]: '^1.0.0' } },
    ))
    expect(onlyCheck(report, 'A10').subject).toBe('(no command or url)')
  })
})

describe('a skill-filesystem row that redirects nothing', () => {
  it('says nothing when the config touches no skill root', async () => {
    const report = await inspect(mounted('- id: skill-filesystem\n  config: { maxBytes: 1000 }\n'))
    expect(withCheck(report, 'A15')).toEqual([])
  })

  it('adds the trustedHost consequence only for `bundledSkillDir`', async () => {
    const custom = await inspect(mounted('- id: skill-filesystem\n  config: { customSkillDirs: ["./skills"] }\n'))
    const bundled = await inspect(mounted('- id: skill-filesystem\n  config: { bundledSkillDir: "./skills" }\n'))
    expect(onlyCheck(custom, 'A15').detail).not.toContain('trustedHost')
    expect(onlyCheck(bundled, 'A15').detail).toContain('trustedHost')
  })
})

describe('the layers and manifests that cannot be read as written', () => {
  it('reports a tag outside the dialect as a layer that does not parse', async () => {
    const report = await inspect(mounted('- id: x\n  config: !!binary aGk=\n'))
    const failure = onlyCheck(report, 'A17')
    expect(failure.name).toBe('patch-parse-error')
    expect(failure.detail).toContain('fails the profile boot')
  })

  it('reports an expression that does not compile, with the diagnostic', async () => {
    const report = await inspect(mounted('- id: x\n  config:\n    a: !!js "if (y) {"\n'))
    const expression = onlyCheck(report, 'A6')
    expect(expression.detail).toContain('It does not parse:')
  })

  it('reads a mutable specifier in `optionalDependencies` as well as in `dependencies`', async () => {
    const report = await inspect(mounted('- id: x\n  config: {}\n', {
      optionalDependencies: { 'some-dep': 'github:someone/some-dep' },
    }))
    expect(withCheck(report, 'A11').map(finding => finding.subject)).toContain('optionalDependencies.some-dep')
  })
})

/**
 * Build a package around a `binding.gyp`.
 * @param gyp - the gyp file's text.
 * @param files - extra package files, e.g. the sources the gyp names.
 * @returns the package root.
 */
function native(gyp: string, files: Readonly<Record<string, string>> = {}): string {
  return createPackage({
    'package.json': JSON.stringify({ name: 'addon', version: '1.0.0', files: ['binding.gyp', 'src/**'] }),
    'binding.gyp': gyp,
    ...files,
  })
}

describe('a native build declaration', () => {
  it('is medium when the gyp describes a compile, and says so', async () => {
    const report = await inspect(native(
      "{ 'targets': [ { 'target_name': 'addon', 'sources': [ 'src/addon.cc' ] } ] }\n",
      { 'src/addon.cc': '// the thing the target compiles\n' },
    ))
    const finding = onlyCheck(report, 'A24')
    expect(finding.severity).toBe('medium')
    expect(finding.confidence).toBe('certain')
    expect(finding.detail).toContain('what it describes is a build')
    expect(finding.detail).not.toContain('ships no C or C++ source')
  })

  it('stays medium when a build step runs a file the package shipped', async () => {
    // The same reading A1 gives a lifecycle command: running something the
    // package published is what a build step is, and grading it would fire on
    // every native module that generates a header.
    const report = await inspect(native(
      "{ 'targets': [ { 'target_name': 'addon', 'sources': [ 'src/addon.cc' ],\n"
      + "    'actions': [ { 'action_name': 'gen', 'action': [ 'python3', 'tools/gen.py' ] } ] } ] }\n",
      { 'src/addon.cc': '// generated from tools/gen.py\n' },
    ))
    expect(onlyCheck(report, 'A24').severity).toBe('medium')
  })

  it('is high when a build step decodes its own payload, and locates the command', async () => {
    const report = await inspect(native(
      "{ 'targets': [ { 'target_name': 'addon', 'type': 'none',\n"
      + "    'actions': [ { 'action_name': 'unpack',\n"
      + "      'action': [ 'sh', '-c', 'base64 --decode blob.b64 > run && ./run' ] } ] } ] }\n",
    ))
    const finding = onlyCheck(report, 'A24')
    expect(finding.severity).toBe('high')
    expect(finding.detail).toContain('decodes an encoded payload')
    expect(finding.evidence.snippet).toContain('base64 --decode')
    expect(finding.evidence.path).toBe('3:32')
  })

  it('counts a source it declined to read as something the target could build', async () => {
    // Otherwise the "nothing here to compile" sentence is decided by what the
    // reader felt like reading, and it says the more alarming thing whenever a
    // source was skipped.
    const root = native("{ 'targets': [ { 'target_name': 'addon', 'sources': [ 'src/addon.cc' ] } ] }\n")
    addSymlink(root, 'src/addon.cc', '/nowhere/addon.cc')
    const report = await inspect(root)
    expect(onlyCheck(report, 'A24').detail).not.toContain('ships no C or C++ source')
  })

  it('says nothing about a package that ships no gyp at all', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'plain', version: '1.0.0', files: ['lib/**'] }),
      'lib/index.js': 'export function apply() {}\n',
    }))
    expect(withCheck(report, 'A24')).toEqual([])
  })
})

describe('an inserted row that substitutes a service for its subtree', () => {
  it('is critical when the re-mapped service is one that constrains the agent', async () => {
    const report = await inspect(mounted(
      '- insert:\n    - name: some-dep\n      isolate:\n        approval: true\n',
      { dependencies: { 'some-dep': '^1.0.0' } },
    ))
    const remap = onlyCheck(report, 'A23')
    expect(remap.severity).toBe('critical')
    expect(remap.title).toContain('"(unnamed)"')
    expect(remap.detail).toContain('fresh symbol realm')
  })

  it('is high, and says what layering means, when `intercept` names an ordinary seam', async () => {
    const report = await inspect(mounted(
      '- insert:\n    - id: mine\n      name: some-dep\n      intercept:\n        llm: true\n',
      { dependencies: { 'some-dep': '^1.0.0' } },
    ))
    const remap = onlyCheck(report, 'A23')
    expect(remap.severity).toBe('high')
    expect(remap.detail).toContain('layers this row\'s own values over the named service')
    expect(remap.detail).not.toContain('constrain what the agent may do')
  })

  it('says the service constrains the agent when `intercept` names a security seam', async () => {
    const report = await inspect(mounted(
      '- insert:\n    - id: mine\n      name: some-dep\n      intercept:\n        sandbox: true\n',
      { dependencies: { 'some-dep': '^1.0.0' } },
    ))
    const remap = onlyCheck(report, 'A23')
    expect(remap.severity).toBe('critical')
    expect(remap.detail).toContain('constrain what the agent may do')
  })
})

describe('a row id whose membership of the shipped bundles moved in 0.1.2-rc.1', () => {
  // `CORE_ROWS` decides which of A3, A5, A19 and A26 a patch override lands in,
  // and at what severity. These cases pin the three kinds of movement the
  // release produced, because each one silently re-grades an override that the
  // previous table already had a verdict for.

  it('reports a row the release dropped as somebody else\'s row rather than a core one', async () => {
    // `api-gateway`, `client-runtime` and `tool-subagent-report` are gone from
    // all three bundle patches and their packages are not published at
    // 0.1.2-rc.1, so an override naming one reaches the user's own layer or
    // another plugin's row.
    const report = await inspect(mounted('- id: api-gateway\n  disabled: true\n'))
    expect(withCheck(report, 'A3')).toEqual([])
    const foreign = onlyCheck(report, 'A26')
    expect(foreign.severity).toBe('high')
    expect(foreign.subject).toBe('api-gateway')
  })

  it('reports a row the release added as a core row rather than a foreign one', async () => {
    const report = await inspect(mounted('- id: session-controller\n  disabled: true\n'))
    expect(withCheck(report, 'A26')).toEqual([])
    const disabled = onlyCheck(report, 'A3')
    expect(disabled.severity).toBe('medium')
    expect(disabled.detail).toContain('@deepseek-ai/dsh-web-app')
  })

  it('grades a row that moved from the web bundle into the base layer as a base row', async () => {
    // `storage`, `storage-domain`, `storage-json` and `session-projection-cache`
    // are inserted by `@deepseek-ai/dsh-base` at this release, so every profile
    // mounts them rather than only the ones that mount the web surface.
    const report = await inspect(mounted('- id: storage\n  disabled: true\n'))
    const disabled = onlyCheck(report, 'A3')
    expect(disabled.severity).toBe('high')
    expect(disabled.detail).toContain('@deepseek-ai/dsh-base')
    expect(disabled.detail).not.toContain('surface bundle')
  })
})
