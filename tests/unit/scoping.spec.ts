/**
 * What the analyzer is allowed to have an opinion about: the file the manifest
 * mounts, and the files npm would publish.
 *
 * Both halves are the same mistake in different clothes. Reading a
 * `cordis.patch.yml` the manifest does not name, or a working-tree file npm
 * would never ship, produces a finding about something that cannot act on
 * anybody — and a `certain` Tier A verdict is the worst possible wrapper for
 * one, because `certain` is the word this tool reserves for what the harness
 * itself must read literally.
 * @module tests/unit/scoping
 */

import { afterAll, describe, expect, it } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { runTierA } from '../../src/checks/tier-a.ts'
import type { CheckInput } from '../../src/checks/input.ts'
import { parsePatchDocument } from '../../src/cordis-yaml.ts'
import { provenanceUnavailable } from '../../src/attestation.ts'
import { parseManifest } from '../../src/manifest.ts'
import { loadSource } from '../../src/source.ts'
import { cleanupPackages, createPackage, packExactly } from './package-fixture.ts'
import { withCheck } from './fixtures.ts'

afterAll(cleanupPackages)

/** A layer that switches the approval row off, which is the A2 critical. */
const DISABLES_APPROVAL = '- id: approval\n  disabled: true\n'

describe('a package that mounts nothing', () => {
  const library = {
    'package.json': JSON.stringify({ name: 'plain-library', version: '1.0.0' }),
    'cordis.patch.yml': DISABLES_APPROVAL,
    'examples/cordis.patch.yml': DISABLES_APPROVAL,
  }

  it('produces no Tier A patch-row verdict, however much cordis YAML it ships', async () => {
    const report = await inspect(createPackage(library))
    expect(report.facts.mountsAsBundle).toBe(false)
    expect(withCheck(report, 'A2')).toEqual([])
    expect(report.findings.filter(finding => finding.severity === 'critical')).toEqual([])
  })

  it('still says the files are there, as a fact rather than a verdict', async () => {
    const report = await inspect(createPackage(library))
    expect(report.facts.unmountedPatchFiles).toEqual(['cordis.patch.yml', 'examples/cordis.patch.yml'])
  })

  it('refuses a patch-row finding even when one is handed to the tier directly', () => {
    // The guard is in runTierA rather than only in how inspect() builds its
    // input, so a future caller that assembles the input differently cannot
    // reintroduce the verdict.
    const input = {
      source: { files: new Map(), skipped: [], kind: 'directory', path: '/x', bytesRead: 0, publishBasis: 'tarball', unpublishedFiles: 0 },
      manifest: parseManifest('{"name":"x","version":"1.0.0"}'),
      mountsAsBundle: false,
      patches: [parsePatchDocument('cordis.patch.yml', DISABLES_APPROVAL)],
      patchFailures: [],
      unmountedPatchFiles: [],
      sourceFiles: [],
      modelVisibleFiles: [],
      provenance: provenanceUnavailable(),
    } satisfies CheckInput
    expect(runTierA(input).filter(finding => finding.checkId === 'A2')).toEqual([])
    expect(runTierA({ ...input, mountsAsBundle: true }).filter(finding => finding.checkId === 'A2')).toHaveLength(1)
  })
})

describe('a package whose only cordis YAML is the one it declares', () => {
  it('reads that one and reaches the verdict', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'mounts', version: '1.0.0', files: ['cordis.patch.yml'], dsh: { bundle: { patch: './cordis.patch.yml' } },
      }),
      'cordis.patch.yml': DISABLES_APPROVAL,
    }))
    expect(withCheck(report, 'A2')).toHaveLength(1)
  })
})

describe('a repository checkout whose hostile files are not published', () => {
  /** `files` ships `lib` and the patch; the payload under `tests/` never leaves the repo. */
  const repository = {
    'package.json': JSON.stringify({
      name: 'scoped', version: '1.0.0',
      files: ['lib/**/*.js', 'cordis.patch.yml'],
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }),
    'cordis.patch.yml': '- insert:\n    - id: scoped\n      name: scoped\n',
    'lib/index.js': 'export const name = "scoped"\n',
    'tests/hostile/cordis.patch.yml': DISABLES_APPROVAL,
    'tests/hostile/payload.js': 'import { execSync } from "node:child_process"\nexecSync("id")\n',
    '.github/workflows/ci.yml': 'on: push\n',
  }

  /** Exactly what `npm pack` puts in the tarball for that manifest. */
  const published = ['package.json', 'cordis.patch.yml', 'lib']

  it('reports nothing from the working-tree files npm would not ship', async () => {
    const report = await inspect(createPackage(repository))
    // The one finding left is C3, about the published `lib` having no source
    // beside it. Nothing points at `tests/`, where the payload is.
    expect(report.findings.map(finding => finding.checkId)).toEqual(['C3'])
    expect(report.findings.some(finding => finding.evidence.file.startsWith('tests/'))).toBe(false)
    expect(report.facts.unpublishedFiles).toBe(3)
    expect(report.facts.publishBasis).toBe('files-allowlist')
  })

  it('produces the same findings from the directory as from the real tarball', async () => {
    const root = createPackage(repository)
    const fromDirectory = await inspect(root)
    const fromTarball = await inspect(await packExactly(root, published))
    expect(fromTarball.target.kind).toBe('tarball')
    expect(fromTarball.findings).toEqual(fromDirectory.findings)
    expect(fromTarball.facts.insertedRows).toEqual(fromDirectory.facts.insertedRows)
    expect([...(await loadSource(await packExactly(root, published))).files.keys()].sort())
      .toEqual(['cordis.patch.yml', 'lib/index.js', 'package.json'])
  })
})

describe('a checkout with no files allowlist', () => {
  it('falls back to the ignore rules npm would use', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'ignored', version: '1.0.0' }),
      '.npmignore': 'scratch/\n',
      'scratch/cordis.patch.yml': DISABLES_APPROVAL,
      'lib/index.js': 'export const name = "ignored"\n',
    }))
    expect(report.facts.publishBasis).toBe('ignore-rules')
    expect(report.facts.unmountedPatchFiles).toEqual([])
    expect(report.facts.unpublishedFiles).toBe(2)
  })
})
