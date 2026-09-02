/**
 * `--from-npm`: resolving a published package, proving the downloaded bytes are
 * the ones the registry vouched for, and analysing them without touching the
 * disk.
 *
 * No test here reaches a real network. `fetch` is injected, which also lets the
 * suite assert the two properties that matter most: that the integrity check
 * runs *before* anything parses the tarball, and that a directory or tarball
 * scan never fetches at all.
 * @module tests/unit/registry
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { inspectFromNpm, precheck } from '../../src/npm.ts'
import {
  fetchVerifiedTarball,
  parseSpec,
  RegistryError,
  resolvePackage,
  verifyIntegrity,
  type ResolvedPackage,
} from '../../src/registry.ts'
import { cleanupPackages, createPackage, packExactly } from './package-fixture.ts'

afterAll(cleanupPackages)

/** The registry every test in this file pretends to talk to. */
const REGISTRY = 'https://registry.npmjs.org'

/**
 * Build a real npm-shaped tarball in memory.
 * @param files - package-relative path to content.
 * @returns the gzipped tarball bytes.
 */
async function tarballOf(files: Readonly<Record<string, string>>): Promise<Buffer> {
  const root = createPackage(files)
  return readFileSync(await packExactly(root, Object.keys(files)))
}

/** A minimal but complete plugin package. */
const PACKAGE_FILES = {
  'package.json': JSON.stringify({
    name: 'fetched-plugin',
    version: '2.1.0',
    license: 'MIT',
    files: ['lib/**/*.js'],
    scripts: { postinstall: 'node ./setup.js' },
    dsh: { bundle: { patch: './cordis.patch.yml' } },
  }),
  'lib/index.js': 'export const name = "fetched"\n',
}

/**
 * A `fetch` that answers exactly two URLs and records every call.
 * @param metadata - the version document to serve.
 * @param tarball - the bytes to serve for the tarball URL.
 * @returns the stub and the list of URLs it was asked for.
 */
function registryStub(metadata: Record<string, unknown>, tarball: Buffer): {
  fetch: typeof globalThis.fetch
  calls: string[]
} {
  const calls: string[] = []
  const dist = metadata.dist as { tarball: string }
  const stub = ((url: string | URL): Promise<Response> => {
    const href = String(url)
    calls.push(href)
    if (href === dist.tarball) {
      return Promise.resolve(new Response(new Uint8Array(tarball), { status: 200 }))
    }
    return Promise.resolve(new Response(JSON.stringify(metadata), { status: 200 }))
  }) as unknown as typeof globalThis.fetch
  return { fetch: stub, calls }
}

/**
 * The version document a registry would publish for a set of bytes.
 * @param bytes - the tarball.
 * @param overrides - fields to replace.
 * @returns the document.
 */
function packument(bytes: Buffer, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: 'fetched-plugin',
    version: '2.1.0',
    hasInstallScript: true,
    scripts: { postinstall: 'node ./setup.js', build: 'tsc' },
    dsh: { bundle: { patch: './cordis.patch.yml' } },
    dist: {
      tarball: `${REGISTRY}/fetched-plugin/-/fetched-plugin-2.1.0.tgz`,
      integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      shasum: createHash('sha1').update(bytes).digest('hex'),
    },
    ...overrides,
  }
}

describe('reading a package spec', () => {
  it('splits a version off an unscoped and a scoped name alike', () => {
    expect(parseSpec('dsh-thing')).toEqual({ name: 'dsh-thing', version: null })
    expect(parseSpec('dsh-thing@1.2.3')).toEqual({ name: 'dsh-thing', version: '1.2.3' })
    expect(parseSpec('@scope/dsh-thing')).toEqual({ name: '@scope/dsh-thing', version: null })
    expect(parseSpec('@scope/dsh-thing@0.1.0-rc.6')).toEqual({ name: '@scope/dsh-thing', version: '0.1.0-rc.6' })
    expect(parseSpec('dsh-thing@next')).toEqual({ name: 'dsh-thing', version: 'next' })
  })

  it('refuses a name that would address a different URL', () => {
    // The name is interpolated into a registry URL, so it is a wire boundary.
    for (const hostile of ['../../etc/passwd', 'https://evil.test/pkg', 'a/b/c', 'pkg?query=1', '.hidden']) {
      expect(() => parseSpec(hostile)).toThrow(RegistryError)
    }
  })
})

describe('verifying downloaded bytes', () => {
  const bytes = Buffer.from('a published tarball')
  const base: ResolvedPackage = {
    name: 'p', version: '1.0.0', tarball: `${REGISTRY}/p/-/p-1.0.0.tgz`,
    integrity: null, shasum: null, hasInstallScript: false,
    lifecycleScripts: [], bundlePatch: null, provenancePredicateType: null, metadataBytes: 0,
  }

  it('accepts bytes whose digest is the one the registry published', () => {
    const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`
    expect(verifyIntegrity(bytes, { ...base, integrity }).algorithm).toBe('sha512')
  })

  it('refuses bytes that do not match, naming both digests', () => {
    const integrity = `sha512-${createHash('sha512').update('other bytes').digest('base64')}`
    expect(() => verifyIntegrity(bytes, { ...base, integrity }))
      .toThrow(/integrity check failed for p@1\.0\.0/)
  })

  it('falls back to the legacy shasum only when there is no integrity field', () => {
    const shasum = createHash('sha1').update(bytes).digest('hex')
    expect(verifyIntegrity(bytes, { ...base, shasum }).algorithm).toBe('sha1')
    expect(() => verifyIntegrity(bytes, { ...base, shasum: 'deadbeef' })).toThrow(/shasum check failed/)
  })

  it('refuses to call anything verified when the registry published no digest', () => {
    expect(() => verifyIntegrity(bytes, base)).toThrow(/neither dist\.integrity nor dist\.shasum/)
  })

  it('refuses an integrity string carrying only algorithms it does not implement', () => {
    expect(() => verifyIntegrity(bytes, { ...base, integrity: 'md5-abc123' })).toThrow(/no usable digest/)
    expect(() => verifyIntegrity(bytes, { ...base, integrity: 'nonsense' })).toThrow(/no usable digest/)
  })

  it('takes the first recognised algorithm when the registry published several', () => {
    const integrity = `md5-ignored sha256-${createHash('sha256').update(bytes).digest('base64')}`
    expect(verifyIntegrity(bytes, { ...base, integrity }).algorithm).toBe('sha256')
  })
})

describe('resolving a package', () => {
  it('reads the install-script flag, the lifecycle scripts and the dsh key without the tarball', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const stub = registryStub(packument(bytes), bytes)
    const resolved = await precheck('fetched-plugin@2.1.0', { fetch: stub.fetch })
    expect(resolved.hasInstallScript).toBe(true)
    expect(resolved.lifecycleScripts).toEqual(['postinstall'])
    expect(resolved.bundlePatch).toBe('./cordis.patch.yml')
    expect(resolved.metadataBytes).toBeLessThan(4096)
    // The pre-check is the point: one small request, and no tarball.
    expect(stub.calls).toEqual([`${REGISTRY}/fetched-plugin/2.1.0`])
  })

  it('refuses a tarball URL pointing off the registry that described it', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const document = packument(bytes)
    const dist = document.dist as Record<string, unknown>
    const stub = registryStub({ ...document, dist: { ...dist, tarball: 'https://evil.test/p.tgz' } }, bytes)
    await expect(precheck('fetched-plugin', { fetch: stub.fetch }))
      .rejects.toThrow(/is not on the registry's origin/)
  })

  it('rejects a version that is not a version', () => {
    expect(() => parseSpec('pkg@../../other')).toThrow(/not a version or dist-tag/)
  })

  it('refuses a document that is not JSON, and one carrying no tarball at all', async () => {
    const notJson = (() => Promise.resolve(new Response('<html>502</html>', { status: 200 }))) as typeof globalThis.fetch
    await expect(precheck('pkg', { fetch: notJson })).rejects.toThrow(/did not return JSON/)
    const noTarball = (() =>
      Promise.resolve(new Response(JSON.stringify({ name: 'pkg', version: '1.0.0', dist: 7 }), { status: 200 })
      )) as typeof globalThis.fetch
    await expect(precheck('pkg', { fetch: noTarball })).rejects.toThrow(/carries no dist\.tarball/)
  })

  it('refuses a tarball field that is not a URL, and one on a non-http scheme', async () => {
    const serving = (tarball: unknown): typeof globalThis.fetch => (() =>
      Promise.resolve(new Response(JSON.stringify({ name: 'pkg', version: '1.0.0', dist: { tarball } }), { status: 200 })
      )) as typeof globalThis.fetch
    await expect(precheck('pkg', { fetch: serving('/relative/path.tgz') })).rejects.toThrow(/is not a URL/)
    await expect(precheck('pkg', { fetch: serving('file:///etc/passwd') })).rejects.toThrow(/not an http\(s\) URL/)
  })

  it('reads an empty body as empty rather than hanging or throwing', async () => {
    const empty = (() => Promise.resolve(new Response(null, { status: 200 }))) as typeof globalThis.fetch
    await expect(precheck('pkg', { fetch: empty })).rejects.toThrow(/did not return JSON/)
  })

  it('reports a missing package as a registry failure rather than a crash', async () => {
    const missing = (() => Promise.resolve(new Response('not found', { status: 404 }))) as typeof globalThis.fetch
    await expect(precheck('no-such-plugin', { fetch: missing })).rejects.toThrow(/returned HTTP 404/)
  })
})

describe('inspecting a package fetched from the registry', () => {
  it('analyses the verified bytes in memory and records how they were checked', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const stub = registryStub(packument(bytes), bytes)
    const report = await inspectFromNpm('fetched-plugin@2.1.0', { fetch: stub.fetch })
    expect(report.target.kind).toBe('registry')
    expect(report.target.path).toBe('npm:fetched-plugin@2.1.0')
    expect(report.target.registry?.algorithm).toBe('sha512')
    expect(report.target.registry?.hasInstallScript).toBe(true)
    expect(report.target.registry?.tarballBytes).toBe(bytes.byteLength)
    expect(report.facts.packageName).toBe('fetched-plugin')
    expect(report.findings.some(finding => finding.checkId === 'A1')).toBe(true)
  })

  it('refuses tampered bytes before any of them are parsed', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const document = packument(bytes)
    // The registry describes the honest package; the mirror serves another one.
    const tampered = await tarballOf({
      ...PACKAGE_FILES,
      'lib/index.js': 'import { execSync } from "node:child_process"\nexecSync("id")\n',
    })
    const stub = registryStub(document, tampered)
    await expect(inspectFromNpm('fetched-plugin@2.1.0', { fetch: stub.fetch }))
      .rejects.toThrow(RegistryError)
    // A report was never produced, so nothing downstream saw the substituted file.
    await expect(inspectFromNpm('fetched-plugin@2.1.0', { fetch: stub.fetch }))
      .rejects.toThrow(/integrity check failed/)
  })

  it('refuses a body larger than the download ceiling instead of holding it', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const huge = (url: string | URL): Promise<Response> => {
      if (String(url).endsWith('.tgz')) {
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024))
          },
        })
        return Promise.resolve(new Response(stream, { status: 200 }))
      }
      return Promise.resolve(new Response(JSON.stringify(packument(bytes)), { status: 200 }))
    }
    await expect(inspectFromNpm('fetched-plugin', { fetch: huge as typeof globalThis.fetch }))
      .rejects.toThrow(/is larger than/)
  })

  it('surfaces a transport failure as a registry error, not an unhandled rejection', async () => {
    const broken = (() => Promise.reject(new Error('ECONNREFUSED'))) as typeof globalThis.fetch
    await expect(precheck('fetched-plugin', { fetch: broken })).rejects.toThrow(/cannot reach .*ECONNREFUSED/)
  })

  it('fetches the tarball only after the metadata, and exactly once', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const document = packument(bytes)
    const stub = registryStub(document, bytes)
    await inspectFromNpm('fetched-plugin@2.1.0', { fetch: stub.fetch })
    expect(stub.calls).toEqual([
      `${REGISTRY}/fetched-plugin/2.1.0`,
      `${REGISTRY}/fetched-plugin/-/fetched-plugin-2.1.0.tgz`,
    ])
  })

  it('reads the registry base URL it is given', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const mirror = 'https://npm.internal.test'
    const document = packument(bytes, {
      dist: {
        tarball: `${mirror}/fetched-plugin/-/fetched-plugin-2.1.0.tgz`,
        integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      },
    })
    const stub = registryStub(document, bytes)
    const resolved = await resolvePackage({ name: 'fetched-plugin', version: null }, {
      fetch: stub.fetch, registry: `${mirror}/`,
    })
    expect(stub.calls[0]).toBe(`${mirror}/fetched-plugin/latest`)
    expect(resolved.tarball).toContain(mirror)
  })

  it('falls back to the spec when the document names neither the package nor the version', async () => {
    const bytes = Buffer.from('bytes')
    const stub = registryStub({
      dist: { tarball: `${REGISTRY}/p/-/p-1.0.0.tgz`, shasum: createHash('sha1').update(bytes).digest('hex') },
    }, bytes)
    const resolved = await resolvePackage({ name: 'p', version: null }, { fetch: stub.fetch })
    expect(resolved.name).toBe('p')
    expect(resolved.version).toBe('latest')
    expect(resolved.integrity).toBeNull()
  })

  it('reports a transport failure that arrived as something other than an Error', async () => {
    // `fetch` is the process's own, replaceable global. Whatever it rejects
    // with ends up in a message a user reads, so it cannot be assumed to be an
    // Error with a `message`.
    const rejecting = ((): Promise<Response> => Promise.reject('socket closed')) as unknown as typeof globalThis.fetch
    await expect(resolvePackage({ name: 'p', version: null }, { fetch: rejecting }))
      .rejects.toThrow(/cannot reach .*: socket closed/)
  })
})

describe('the two modes that read local bytes', () => {
  it('never reaches the network, whatever the package contains', async () => {
    const forbidden = vi.fn(() => {
      throw new Error('a directory or tarball scan must never fetch')
    })
    const original = globalThis.fetch
    globalThis.fetch = forbidden as unknown as typeof globalThis.fetch
    try {
      const root = createPackage(PACKAGE_FILES)
      await expect(inspect(root)).resolves.toBeTruthy()
      await expect(inspect(await packExactly(root, ['package.json', 'lib/index.js']))).resolves.toBeTruthy()
    } finally {
      globalThis.fetch = original
    }
    expect(forbidden).not.toHaveBeenCalled()
  })

  it('is the reason fetchVerifiedTarball takes its fetch as an argument', async () => {
    const bytes = await tarballOf(PACKAGE_FILES)
    const resolved = await precheck('fetched-plugin', { fetch: registryStub(packument(bytes), bytes).fetch })
    const stub = registryStub(packument(bytes), bytes)
    const verified = await fetchVerifiedTarball(resolved, { fetch: stub.fetch })
    expect(verified.bytes.byteLength).toBe(bytes.byteLength)
    expect(stub.calls).toEqual([resolved.tarball])
  })
})
