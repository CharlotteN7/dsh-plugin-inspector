/**
 * Reading a package from a tarball, which is the form a user actually gets
 * from the registry; the guarantee that reading it touches no filesystem; and
 * the resource ceilings, which are the difference between a hostile archive
 * being a finding and being a denial of service.
 * @module tests/unit/source
 */

import { chmodSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { create } from 'tar'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { loadSource, MAX_FILE_BYTES, type ReadLimits } from '../../src/source.ts'
import { fixture, onlyCheck } from './fixtures.ts'
import { addSymlink, cleanupPackages, createPackage, packExactly, packRawEntries } from './package-fixture.ts'

/** Where the packed fixtures live for the duration of this file. */
let workspace = ''

/** Ceilings small enough that a two-line file trips them. */
const TINY: ReadLimits = { maxFileBytes: 64, maxTotalBytes: 128, maxEntries: 3, maxStreamBytes: 1024 * 1024 }

/**
 * Pack one committed fixture with npm's own publish semantics: `package.json`
 * plus the roots of its `files` allowlist, and nothing else.
 *
 * This is the whole point of the parity assertion below. A pack helper that
 * tars the whole fixture directory makes parity hold by construction, because
 * both readers then see the same files — which is exactly how a directory
 * reader that read more than npm publishes went unnoticed.
 * @param name - the fixture directory name.
 * @returns the absolute tarball path.
 */
async function packFixture(name: string): Promise<string> {
  const root = fixture(name)
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { files?: string[] }
  const roots = (manifest.files ?? []).map(entry => entry.split('/')[0] ?? entry)
  const present = readdirSync(root)
  const paths = [...new Set(['package.json', ...roots])].filter(entry => present.includes(entry))
  const file = join(workspace, `${name}.tgz`)
  await create({ gzip: true, file, cwd: root, prefix: 'package' }, paths)
  return file
}

beforeAll(async () => {
  workspace = await mkdtemp(join(tmpdir(), 'dsh-inspector-tarball-'))
})

afterAll(async () => {
  cleanupPackages()
  await rm(workspace, { recursive: true, force: true })
})

describe('reading an npm tarball', () => {
  it('produces the same findings as reading the directory', async () => {
    const tarball = await packFixture('disables-approval')
    const fromTarball = await inspect(tarball)
    const fromDirectory = await inspect(fixture('disables-approval'))
    expect(fromTarball.target.kind).toBe('tarball')
    expect(fromTarball.findings).toEqual(fromDirectory.findings)
    expect(fromTarball.facts.insertedRows).toEqual(fromDirectory.facts.insertedRows)
  })

  it('writes nothing to disk while doing it', async () => {
    const tarball = await packFixture('skill-injection')
    const before = readdirSync(workspace).sort()
    await inspect(tarball)
    expect(readdirSync(workspace).sort()).toEqual(before)
    // The tarball itself is untouched, not merely un-extracted.
    expect(statSync(tarball).size).toBeGreaterThan(0)
  })

  it('strips the `package/` prefix so paths match the directory form', async () => {
    const tarball = await packFixture('benign-control')
    const source = await loadSource(tarball)
    expect([...source.files.keys()].sort()).toEqual(['cordis.patch.yml', 'package.json', 'src/index.ts'])
  })

  it('refuses an entry that climbs out of the package after the prefix is stripped', async () => {
    // Nothing is written from a tar entry, so this is not a traversal. It is a
    // truthfulness problem: `stripRoot` dropped only the first segment, so the
    // remaining `..` survived into a map key and a finding could report its
    // location as `../../../../etc/passwd`.
    const source = await loadSource(packRawEntries({
      'package/package.json': '{"name":"slip","version":"1.0.0"}',
      'package/../../../../etc/passwd': 'root:x:0:0:',
      'package/sub/../../../tmp/evil.js': 'export const x = 1',
    }))
    expect([...source.files.keys()].every(path => !path.includes('..'))).toBe(true)
    expect(source.files.has('etc/passwd')).toBe(false)
    expect(source.skipped.some(entry => entry.reason === 'unreadable')).toBe(true)
  })

  it('refuses every entry name that leaves nothing once the prefix is stripped', async () => {
    const source = await loadSource(packRawEntries({
      'package/package.json': '{"name":"odd","version":"1.0.0"}',
      'toplevel.txt': 'no prefix to strip',
      'package/.': 'nothing but the current directory',
      'package//nested//index.js': 'export const a = 1',
    }))
    expect([...source.files.keys()].sort()).toEqual(['nested/index.js', 'package.json'])
    expect(source.skipped.map(entry => entry.path).sort())
      .toEqual(['package/.', 'toplevel.txt'])
    expect(source.skipped.every(entry => entry.reason === 'unreadable')).toBe(true)
  })

  it('reports something that is not an archive as an unreadable tarball, not as a package with no manifest', async () => {
    const root = createPackage({ 'package.json': '{"name":"x","version":"1.0.0"}' })
    await expect(loadSource(join(root, 'package.json')))
      .rejects.toThrow(/not a readable npm tarball|cannot read tarball/)
  })
})

describe('the read ceilings', () => {
  const oversized = {
    'package.json': '{"name":"big","version":"1.0.0"}',
    'huge.txt': 'x'.repeat(4096),
  }

  it('abandons a tar entry while it is arriving rather than after it is resident', async () => {
    // The bug this pins: chunks were accumulated to the end of the entry and
    // the size cap was applied to the finished buffer, so a 27 MB tarball
    // holding one 6 GB member cost 6 GB of RSS and then a RangeError. Watching
    // what Buffer.concat is asked for is the direct statement of the fix: no
    // single call may be handed more than the per-file ceiling.
    const root = createPackage(oversized)
    const tarball = await packExactly(root, ['package.json', 'huge.txt'])
    const concat = Buffer.concat.bind(Buffer)
    let largest = 0
    const spy = vi.spyOn(Buffer, 'concat').mockImplementation((list, total) => {
      largest = Math.max(largest, list.reduce((sum, item) => sum + item.length, 0))
      return concat(list as Uint8Array[], total)
    })
    try {
      const source = await loadSource(tarball, TINY)
      expect(source.skipped).toContainEqual({ path: 'huge.txt', reason: 'size-cap' })
      expect(source.files.has('huge.txt')).toBe(false)
    } finally {
      spy.mockRestore()
    }
    expect(largest).toBeLessThanOrEqual(TINY.maxFileBytes)
  })

  it('records a file the directory reader refuses for size, without reading it', async () => {
    const source = await loadSource(createPackage(oversized), TINY)
    expect(source.skipped).toContainEqual({ path: 'huge.txt', reason: 'size-cap' })
    expect(source.bytesRead).toBeLessThanOrEqual(TINY.maxTotalBytes)
  })

  it('stops at the total ceiling', async () => {
    const source = await loadSource(createPackage({
      'package.json': '{"name":"big","version":"1.0.0"}',
      'z1.txt': 'a'.repeat(60),
      'z2.txt': 'b'.repeat(60),
      'z3.txt': 'c'.repeat(60),
    }), TINY)
    expect(source.skipped.map(entry => entry.reason)).toContain('total-cap')
  })

  it('stops at the entry ceiling', async () => {
    const source = await loadSource(createPackage({
      'package.json': '{"name":"many","version":"1.0.0"}',
      'z1.txt': 'a', 'z2.txt': 'b', 'z3.txt': 'c', 'z4.txt': 'd',
    }), TINY)
    expect(source.skipped.map(entry => entry.reason)).toContain('entry-cap')
  })

  it('abandons a tar entry that keeps arriving after it was refused', async () => {
    // The entry is abandoned on its first chunk and then drained. Every chunk
    // after that must cost nothing: `resume()` keeps the data events coming,
    // and buffering them would defeat the ceiling that just fired.
    const root = createPackage({
      'package.json': '{"name":"streamed","version":"1.0.0"}',
      'huge.txt': 'x'.repeat(400_000),
    })
    const source = await loadSource(await packExactly(root, ['package.json', 'huge.txt']), TINY)
    expect(source.skipped).toContainEqual({ path: 'huge.txt', reason: 'size-cap' })
  })

  it('abandons a tar entry that would pass the total ceiling, without reading it in', async () => {
    const root = createPackage({
      'package.json': '{"name":"streamed","version":"1.0.0"}',
      'a.txt': 'a'.repeat(60),
      'b.txt': 'b'.repeat(60),
    })
    const source = await loadSource(await packExactly(root, ['package.json', 'a.txt', 'b.txt']), TINY)
    expect(source.skipped.map(entry => entry.reason)).toContain('total-cap')
  })

  it('stops at the tar entry ceiling as the directory reader does', async () => {
    const root = createPackage({
      'package.json': '{"name":"many","version":"1.0.0"}',
      'z1.txt': 'a', 'z2.txt': 'b', 'z3.txt': 'c', 'z4.txt': 'd',
    })
    const source = await loadSource(await packExactly(root, ['package.json', 'z1.txt', 'z2.txt', 'z3.txt', 'z4.txt']), TINY)
    expect(source.skipped.map(entry => entry.reason)).toContain('entry-cap')
  })

  it('refuses a tarball that inflates past the stream ceiling instead of inflating it', async () => {
    // A compression bomb costs nothing to ship and everything to decompress.
    // The ceiling is on the decompressed stream, so it fires while inflating
    // rather than after.
    const root = createPackage({
      'package.json': '{"name":"bomb","version":"1.0.0"}',
      'zeros.txt': '0'.repeat(400_000),
    })
    const tarball = await packExactly(root, ['package.json', 'zeros.txt'])
    await expect(loadSource(tarball, { ...TINY, maxStreamBytes: 4096 }))
      .rejects.toThrow(/decompresses to more than 4096 bytes/)
  })

  it('reports a failure raised inside the tar parser as an unreadable tarball', async () => {
    // The parser's callbacks run outside the awaited path, so an error thrown
    // in one is an uncaught exception and a raw stack trace unless it is
    // captured and rethrown where the caller is waiting.
    const root = createPackage({ 'package.json': '{"name":"thrower","version":"1.0.0"}' })
    const tarball = await packExactly(root, ['package.json'])
    const spy = vi.spyOn(Buffer, 'concat').mockImplementation(() => {
      throw 'the parser threw something that is not an Error'
    })
    try {
      await expect(loadSource(tarball))
        .rejects.toThrow(/cannot read tarball .*: the parser threw something that is not an Error/)
    } finally {
      spy.mockRestore()
    }
  })

  it('reports every refusal through Tier C rather than dropping it silently', async () => {
    const report = await inspect(createPackage({
      'package.json': '{"name":"opaque","version":"1.0.0","files":["blob.bin"]}',
      'blob.bin': 'MZ\u0000 a native addon this tool cannot read',
    }))
    expect(onlyCheck(report, 'C4').title).toContain('binary')
    expect(report.analysis.negativesReliable).toBe(false)
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
  // One entry per name in `SKIPPED_DIRECTORIES`. A vendored dependency, a
  // packed git object and a coverage report are not this package's code, and a
  // reader that walks into `node_modules/` reports the findings of every
  // dependency as though the package had written them.
  it.each(['node_modules', '.git', '.pnpm-store', '.yarn', 'coverage', '.nyc_output'])(
    'never descends into %s, so nothing under it is read or counted', async directory => {
      const root = createPackage({
        'package.json': '{"name":"vendored","version":"1.0.0","files":["lib/**/*.js"]}',
        'lib/index.js': 'export const a = 1\n',
        [`${directory}/dep/package.json`]: '{"name":"dep","version":"1.0.0"}',
        [`${directory}/dep/index.js`]: 'export const b = 2\n',
      })
      const source = await loadSource(root)
      expect([...source.files.keys()].some(path => path.startsWith(`${directory}/`))).toBe(false)
      expect([...source.files.keys()]).toEqual(['lib/index.js', 'package.json'])
      // npm would not publish these either, so "not read" and "not published"
      // are two different statements. This one is that the walk never went in:
      // a descended-then-rejected file counts as unpublished.
      expect(source.unpublishedFiles).toBe(0)
      expect(source.skipped).toEqual([])
    },
  )

  it('reads past a symbolic link npm would not publish, without recording it', async () => {
    // The link is outside the allowlist, so it is not part of the package and
    // there is nothing to report about it.
    const root = createPackage({
      'package.json': '{"name":"linked","version":"1.0.0","files":["lib/**/*.js"]}',
      'lib/index.js': 'export const a = 1\n',
    })
    addSymlink(root, 'notes.md', '/etc/passwd')
    const source = await loadSource(root)
    expect(source.skipped).toEqual([])
    expect([...source.files.keys()]).toEqual(['lib/index.js', 'package.json'])
  })

  it('records a published entry that is neither a file nor a directory, rather than dropping it', async () => {
    // A socket, a FIFO and a device node are all in the published file set and
    // none of them is content the analyzer read. Dropping one silently is the
    // single shape where "how much could be read" comes out too high: the
    // symbolic link in the same position is reported, and this was not.
    const root = createPackage({ 'package.json': '{"name":"socketed","version":"1.0.0"}' })
    const server = createServer()
    await new Promise<void>(resolve => server.listen(join(root, 'live.sock'), resolve))
    try {
      const source = await loadSource(root)
      expect([...source.files.keys()]).toEqual(['package.json'])
      expect(source.skipped).toEqual([{ path: 'live.sock', reason: 'unreadable' }])
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
  })

  it('says nothing about one npm would not publish', async () => {
    const root = createPackage({
      'package.json': '{"name":"socketed","version":"1.0.0","files":["lib/**/*.js"]}',
      'lib/index.js': 'export const a = 1\n',
    })
    const server = createServer()
    await new Promise<void>(resolve => server.listen(join(root, 'live.sock'), resolve))
    try {
      const source = await loadSource(root)
      expect(source.skipped).toEqual([])
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
  })

  it('degrades the analysis over one, because it is a file the report cannot account for', async () => {
    const root = createPackage({
      'package.json': '{"name":"socketed","version":"1.0.0"}',
      'index.js': 'export const a = 1\n',
    })
    const server = createServer()
    await new Promise<void>(resolve => server.listen(join(root, 'live.sock'), resolve))
    try {
      const report = await inspect(root)
      expect(onlyCheck(report, 'C4').severity).toBe('low')
      expect(report.analysis.integrity).toBe('degraded')
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
  })

  it('records a directory it is not allowed to open, rather than reporting the package as small', async () => {
    const root = createPackage({
      'package.json': '{"name":"closed","version":"1.0.0"}',
      'lib/index.js': 'export const a = 1\n',
    })
    chmodSync(join(root, 'lib'), 0o000)
    try {
      const source = await loadSource(root)
      expect(source.skipped).toContainEqual({ path: 'lib', reason: 'unreadable' })
    } finally {
      chmodSync(join(root, 'lib'), 0o755)
    }
  })

  it('records a file it is not allowed to read, rather than dropping it silently', async () => {
    const root = createPackage({
      'package.json': '{"name":"closed","version":"1.0.0"}',
      'lib/index.js': 'export const a = 1\n',
    })
    chmodSync(join(root, 'lib/index.js'), 0o000)
    try {
      const source = await loadSource(root)
      expect(source.skipped).toContainEqual({ path: 'lib/index.js', reason: 'unreadable' })
    } finally {
      chmodSync(join(root, 'lib/index.js'), 0o644)
    }
  })

  it('reads a working tree whose package.json is valid JSON but not an object', async () => {
    const root = createPackage({ 'package.json': '["not","a","manifest"]', 'lib/index.js': 'export const a = 1\n' })
    const source = await loadSource(root)
    expect(source.publishBasis).toBe('ignore-rules')
    await expect(inspect(root)).rejects.toThrow(/must hold a JSON object/)
  })

  it('records a symbolic link and never follows it', async () => {
    const root = createPackage({ 'package.json': '{"name":"linked","version":"1.0.0"}' })
    addSymlink(root, 'passwd', '/etc/passwd')
    const source = await loadSource(root)
    expect(source.files.has('passwd')).toBe(false)
    expect(source.skipped).toContainEqual({ path: 'passwd', reason: 'unreadable' })
  })

  it('reports a package that ships build output and no source', async () => {
    const report = await inspect(fixture('obfuscated'))
    expect(onlyCheck(report, 'C3').name).toBe('sourceless-build-output')
  })
})
