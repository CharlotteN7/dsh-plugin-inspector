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
import { inspect } from '../../src/inspect.ts'
import { cleanupPackages, createPackage } from './package-fixture.ts'
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
