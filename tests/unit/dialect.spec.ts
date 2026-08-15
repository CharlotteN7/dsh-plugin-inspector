/**
 * The `!!js` dialect and the patch model, checked against the rules the
 * harness itself enforces.
 * @module tests/unit/dialect
 */

import { describe, expect, it } from 'vitest'
import { classifyExpression, parsePatchDocument, PatchParseError } from '../../src/cordis-yaml.ts'

describe('expression classification', () => {
  it('reports what an expression reaches, at its most capable form', () => {
    expect(classifyExpression("require('child_process').execSync('id')").class).toBe('module-access')
    expect(classifyExpression("globalThis['x']").class).toBe('module-access')
    expect(classifyExpression("process.env.HOME = '/tmp'").class).toBe('mutation')
    expect(classifyExpression('doSomething()').class).toBe('call')
    expect(classifyExpression("process.platform === 'win32'").class).toBe('inert-read')
    expect(classifyExpression('true').class).toBe('literal')
  })

  it('treats process.cwd() as inert, because the shipped harness examples use it', () => {
    expect(classifyExpression('process.cwd()').class).toBe('inert-read')
  })

  it('reports an unparseable expression instead of throwing', () => {
    const result = classifyExpression('if (x) {')
    expect(result.class).toBe('unparseable')
    expect(result.parseError).toBeTypeOf('string')
  })
})

describe('where the loader interpolates', () => {
  const document = `
- id: some-row
  config:
    a: !!js process.env.A
    nested:
      b: !!js process.env.B
  disabled: !!js process.platform === 'linux'
  inject: [!!js process.env.C]
`

  it('marks config expressions live, recursively', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', document)
    const live = parsed.expressions.filter(site => site.slot === 'config').map(site => site.path)
    expect(live).toEqual(['[0].config.a', '[0].config.nested.b'])
  })

  it('marks a top-level disabled expression live', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', document)
    expect(parsed.expressions.filter(site => site.slot === 'disabled')).toHaveLength(1)
  })

  it('marks an expression in a static metadata field inert', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', document)
    const inert = parsed.expressions.filter(site => site.slot === 'inert')
    expect(inert.map(site => site.path)).toEqual(['[0].inject[0]'])
  })
})

describe('the patch model', () => {
  it('separates rows this layer inserts from rows it modifies', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', `
- id: approval
  disabled: true
- insert:
    - id: mine
      name: my-plugin
`)
    expect(parsed.overrides.map(override => override.id)).toEqual(['approval'])
    expect(parsed.inserts.map(row => row.id)).toEqual(['mine'])
  })

  it('applies the insert-wins rule, matching applyEntryPatches', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', `
- id: some-group
  disabled: true
  insert:
    - id: mine
      name: my-plugin
`)
    expect(parsed.overrides).toEqual([])
    expect(parsed.inserts[0]?.intoGroupId).toBe('some-group')
  })

  it('records name as a guard rather than an override', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', `
- id: approval
  name: '@deepseek-ai/dsh-user-approval'
  config: { mode: off }
`)
    expect(parsed.overrides[0]?.nameGuard).toBe('@deepseek-ai/dsh-user-approval')
    expect(parsed.overrides[0]?.overriddenKeys).toEqual(['config'])
  })

  it('descends into group children, whose config carries rows rather than data', () => {
    const parsed = parsePatchDocument('cordis.patch.yml', `
- insert:
    - id: outer
      group: true
      config:
        - id: inner
          name: inner-plugin
          config:
            key: !!js process.env.SECRET
`)
    expect(parsed.inserts.map(row => row.id)).toEqual(['outer', 'inner'])
    expect(parsed.expressions.map(site => site.path)).toEqual(['[0].insert[0].config[0].config.key'])
  })
})

describe('tags the harness rejects', () => {
  it('reports `!js` as a single-bang tag rather than parsing it', () => {
    expect.assertions(2)
    try {
      parsePatchDocument('cordis.patch.yml', '- id: x\n  config:\n    a: !js 1\n')
    } catch (error) {
      expect(error).toBeInstanceOf(PatchParseError)
      expect((error as PatchParseError).singleBangTag).toBe(true)
    }
  })

  it('rejects a non-array document, matching the loader', () => {
    expect(() => parsePatchDocument('cordis.patch.yml', 'id: x\n')).toThrow(/top-level array/)
  })

  it('rejects tags outside the JSON schema, so nothing the harness refuses is parsed here', () => {
    expect(() => parsePatchDocument('cordis.patch.yml', '- id: x\n  config: !!binary aGk=\n')).toThrow(PatchParseError)
  })
})
