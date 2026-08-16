/**
 * Reading `package.json` from a hostile author, and printing what was read.
 *
 * The manifest is a file boundary: a field of the wrong type is input, not a
 * programming error, and losing the whole analysis over one is how a package
 * escapes being read at all.
 * @module tests/unit/manifest
 */

import { afterAll, describe, expect, it } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { declaredPackages, ManifestError, parseManifest } from '../../src/manifest.ts'
import { renderHuman } from '../../src/report.ts'
import { cleanupPackages, createPackage } from './package-fixture.ts'

afterAll(cleanupPackages)

describe('a manifest with fields of the wrong shape', () => {
  it('keeps every field it can read and records the rest as defects', () => {
    const manifest = parseManifest(JSON.stringify({
      name: 'odd', version: '2.0.0',
      dsh: { bundle: 7, client: 'yes', profile: { bundles: ['a', 3] } },
      dependencies: { good: '^1.0.0', bad: 12 },
      files: ['lib', 5],
    }))
    expect(manifest.dependencies).toEqual({ good: '^1.0.0' })
    expect(manifest.files).toEqual(['lib'])
    expect(manifest.dsh.profile?.bundles).toEqual(['a'])
    expect(manifest.defects).toEqual(['"dsh.bundle" is not an object', '"dsh.client" is not an object'])
  })

  it('treats a non-object `dsh` as absent and says so', () => {
    expect(parseManifest('{"name":"x","version":"1","dsh":[]}').defects).toEqual(['"dsh" is not an object'])
  })

  it('refuses text that is not a JSON object at all', () => {
    expect(() => parseManifest('not json')).toThrow(ManifestError)
    expect(() => parseManifest('[]')).toThrow(/must hold a JSON object/)
  })

  it('names a package with no name so the report has something to print', () => {
    const manifest = parseManifest('{}')
    expect(manifest.name).toBe('<unnamed>')
    expect(manifest.version).toBe('<unversioned>')
    expect(manifest.license).toBeNull()
  })

  it('reads the string form of `bin` as one command named after the package', () => {
    expect(parseManifest('{"name":"tool","version":"1","bin":"./lib/cli.js"}').binNames).toEqual(['tool'])
    expect(parseManifest('{"name":"tool","version":"1","bin":7}').binNames).toEqual([])
  })

  it('counts every package the manifest admits it may load', () => {
    const manifest = parseManifest(JSON.stringify({
      name: 'self', version: '1',
      dependencies: { a: '1' }, peerDependencies: { b: '1' }, optionalDependencies: { c: '1' },
    }))
    expect([...declaredPackages(manifest)].sort()).toEqual(['a', 'b', 'c', 'self'])
  })
})

describe('a package the tool cannot open at all', () => {
  it('is an unanalysable target rather than a clean report', async () => {
    await expect(inspect(createPackage({ 'package.json': 'not json' })))
      .rejects.toThrow(/not valid JSON/)
  })
})

describe('the human report', () => {
  it('prints every declaration it read, including the ones with no finding attached', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'declares', version: '1.0.0', license: 'MIT',
        files: ['cordis.patch.yml', 'examples/**/*.yml'],
        bin: { 'declares-cli': './lib/cli.js' },
        dependencies: { helper: '^1.0.0' },
        dsh: { bundle: { patch: './cordis.patch.yml' }, client: {} },
        exports: { '.': './lib/index.js', './client': './lib/client.js' },
      }),
      'cordis.patch.yml': '- insert:\n    - id: mine\n      name: helper\n      config:\n'
        + "        root: !!js dshHomePath('x')\n",
      'examples/personal.cordis.yml': '- id: approval\n  disabled: true\n',
    }))
    const text = renderHuman(report, false)
    expect(text).toContain('declares@1.0.0 (MIT)')
    expect(text).toContain('mine → helper')
    expect(text).toContain('1 harness-call')
    expect(text).toContain('installs        declares-cli')
    expect(text).toContain('`files` allowlist')
    // Every Tier A verdict is a claim about a specific harness version, so the
    // report names the one the tables were read from.
    expect(report.tool.harnessReference).toBe('0.1.0-rc.5')
    expect(text).toContain('DeepSeek Harness 0.1.0-rc.5')
    // The example layer is shipped and is not mounted, so it is a fact.
    expect(text).toContain('examples/personal.cordis.yml')
    expect(report.findings.some(finding => finding.checkId === 'A2')).toBe(false)
  })

  it('colours a finding when asked, and leaves the text intact when not', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'coloured', version: '1.0.0', files: ['cordis.patch.yml'],
        dsh: { bundle: { patch: './cordis.patch.yml' } },
      }),
      'cordis.patch.yml': '- id: approval\n  disabled: true\n',
    }))
    expect(renderHuman(report, true)).toContain('[1;31m')
    expect(renderHuman(report, false)).not.toContain('[')
  })
})
