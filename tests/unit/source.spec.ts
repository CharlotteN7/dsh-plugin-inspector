/**
 * Reading a package from a tarball, which is the form a user actually gets
 * from the registry, and the guarantee that reading it touches no filesystem.
 * @module tests/unit/source
 */

import { readdirSync, statSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { create } from 'tar'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { loadSource } from '../../src/source.ts'
import { fixture, onlyCheck } from './fixtures.ts'

/** Where the packed fixtures live for the duration of this file. */
let workspace = ''

/**
 * Pack one fixture the way `npm pack` does: every path prefixed with
 * `package/`.
 * @param name - the fixture directory name.
 * @returns the absolute tarball path.
 */
async function pack(name: string): Promise<string> {
  const file = join(workspace, `${name}.tgz`)
  const from = fixture(name)
  await create(
    { gzip: true, file, cwd: from, prefix: 'package' },
    readdirSync(from),
  )
  return file
}

beforeAll(async () => {
  workspace = await mkdtemp(join(tmpdir(), 'dsh-inspector-tarball-'))
})

afterAll(async () => {
  await rm(workspace, { recursive: true, force: true })
})

describe('reading an npm tarball', () => {
  it('produces the same findings as reading the directory', async () => {
    const tarball = await pack('disables-approval')
    const fromTarball = await inspect(tarball)
    const fromDirectory = await inspect(fixture('disables-approval'))
    expect(fromTarball.target.kind).toBe('tarball')
    expect(fromTarball.findings).toEqual(fromDirectory.findings)
    expect(fromTarball.facts.insertedRows).toEqual(fromDirectory.facts.insertedRows)
  })

  it('writes nothing to disk while doing it', async () => {
    const tarball = await pack('skill-injection')
    const before = readdirSync(workspace).sort()
    await inspect(tarball)
    expect(readdirSync(workspace).sort()).toEqual(before)
    // The tarball itself is untouched, not merely un-extracted.
    expect(statSync(tarball).size).toBeGreaterThan(0)
  })

  it('strips the `package/` prefix so paths match the directory form', async () => {
    const tarball = await pack('benign-control')
    const source = await loadSource(tarball)
    expect([...source.files.keys()].sort()).toEqual(['cordis.patch.yml', 'package.json', 'src/index.ts'])
  })
})

describe('reading a target that is not a package', () => {
  it('refuses a directory with no package.json rather than reporting it clean', async () => {
    await expect(inspect(workspace)).rejects.toThrow(/not an npm package/)
  })

  it('refuses a path that does not exist', async () => {
    await expect(inspect(join(workspace, 'absent'))).rejects.toThrow(/cannot read target/)
  })
})

describe('the directory reader', () => {
  it('skips node_modules so a vendored dependency is not mistaken for the package', async () => {
    const source = await loadSource(fixture('benign-control'))
    expect([...source.files.keys()].some(path => path.startsWith('node_modules/'))).toBe(false)
  })

  it('reports a package that ships build output and no source', async () => {
    const report = await inspect(fixture('obfuscated'))
    expect(onlyCheck(report, 'C3').name).toBe('sourceless-build-output')
  })
})
