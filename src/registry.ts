/**
 * Fetching a published package from an npm registry, and proving the bytes are
 * the ones the registry vouched for.
 *
 * This is the one module in the tool that opens a socket, and it exists behind
 * one explicit flag. A network fetch is not execution — nothing here installs,
 * unpacks to disk, or runs a lifecycle script — but it is a side effect the
 * tool's other two modes do not have, so it is never reached implicitly: a
 * directory or tarball scan cannot get here, because neither imports this
 * module.
 *
 * The order of operations is the security property. The packument is read
 * first, which is ~3 KB and already answers `hasInstallScript`, the install
 * lifecycle scripts, and whether the package declares `dsh.bundle` — a
 * pre-check that needs no tarball at all. Only then is the tarball fetched, and
 * its `dist.integrity` hash is verified **before** any byte of it reaches the
 * tar parser. A hash mismatch is a refusal, not a warning: the whole point of
 * the mode is that the analysed bytes are the published bytes.
 * @module dsh-plugin-inspector/registry
 */

import { createHash, type BinaryLike } from 'node:crypto'
import { INSTALL_LIFECYCLE_SCRIPTS } from './knowledge.ts'
import { MAX_TOTAL_BYTES } from './source.ts'

/** The public npm registry, used when no other is named. */
export const DEFAULT_REGISTRY = 'https://registry.npmjs.org'

/** Largest packument the tool will read. A version document is a few kilobytes. */
export const MAX_METADATA_BYTES = 4 * 1024 * 1024

/**
 * Largest compressed tarball the tool will download. The decompressed stream is
 * capped separately, and lower, by the tar reader.
 */
export const MAX_TARBALL_BYTES = MAX_TOTAL_BYTES

/** Hash algorithms accepted in a Subresource Integrity string, weakest last. */
const SRI_ALGORITHMS: ReadonlySet<string> = new Set(['sha512', 'sha384', 'sha256'])

/**
 * npm package names, as the registry accepts them. Validated because the name
 * is interpolated into a URL: `../` in a package name is a request for a
 * different endpoint, and a `http://…` "name" is a request to a different host.
 */
const PACKAGE_NAME = /^(?:@[a-z0-9~][a-z0-9-._~]*\/)?[a-z0-9~][a-z0-9-._~]*$/

/** Versions and dist-tags, as they may appear after the `@` in a spec. */
const VERSION_OR_TAG = /^[A-Za-z0-9][A-Za-z0-9-._+]*$/

/** Thrown when a package cannot be resolved, fetched, or verified. */
export class RegistryError extends Error {}

/** One `<name>` or `<name>@<version>` argument, split. */
export interface PackageSpec {
  readonly name: string
  /** A version or dist-tag, or `null` to mean the `latest` tag. */
  readonly version: string | null
}

/**
 * What the packument says, before anything is downloaded. Every field here
 * costs one small request and no tarball.
 */
export interface ResolvedPackage {
  readonly name: string
  readonly version: string
  readonly tarball: string
  /** The registry's own SRI string, e.g. `sha512-…`, or `null` on old packages. */
  readonly integrity: string | null
  /** The legacy SHA-1 digest, the only check available when `integrity` is absent. */
  readonly shasum: string | null
  /** The registry's own flag, which is set when npm would run an install script. */
  readonly hasInstallScript: boolean
  /** Install lifecycle script names the manifest declares. */
  readonly lifecycleScripts: readonly string[]
  /** The `dsh.bundle.patch` value, which is what makes a package a mounted layer. */
  readonly bundlePatch: string | null
  /** Bytes of metadata read to learn all of the above. */
  readonly metadataBytes: number
}

/** How a fetched tarball was verified. */
export interface VerifiedTarball {
  readonly bytes: Buffer
  /** The algorithm the digest was taken with, e.g. `sha512`. */
  readonly algorithm: string
  /** The digest that matched, in the registry's own encoding. */
  readonly digest: string
}

/** Where to fetch from. */
export interface RegistryOptions {
  /** Registry base URL, without a trailing slash. Defaults to {@link DEFAULT_REGISTRY}. */
  readonly registry?: string
  /** Injected for tests; defaults to the global `fetch`. */
  readonly fetch?: typeof globalThis.fetch
}

/**
 * Split a `<name>` or `<name>@<version>` argument.
 *
 * The `@` that starts a scope is not a separator, so `@scope/name` has no
 * version and `@scope/name@1.2.3` has one.
 * @param spec - the argument as typed.
 * @returns the package name and the requested version, if any.
 * @throws RegistryError when the name or version is not one the registry accepts.
 */
export function parseSpec(spec: string): PackageSpec {
  const separator = spec.lastIndexOf('@')
  const split = separator > 0
  const name = split ? spec.slice(0, separator) : spec
  const version = split ? spec.slice(separator + 1) : null
  if (!PACKAGE_NAME.test(name)) throw new RegistryError(`not an npm package name: ${spec}`)
  if (version !== null && !VERSION_OR_TAG.test(version)) {
    throw new RegistryError(`not a version or dist-tag: ${version}`)
  }
  return { name, version }
}

/**
 * Read one response body under a ceiling, without materialising more than the
 * ceiling allows. A registry that streams forever is a hang, and a hang in a
 * gate is a denial of service.
 * @param response - the fetch response.
 * @param limit - the ceiling in bytes.
 * @param what - what is being read, for the error message.
 * @returns the body.
 * @throws RegistryError when the body passes the ceiling.
 */
async function readCapped(response: Response, limit: number, what: string): Promise<Buffer> {
  const body = response.body
  if (body === null) return Buffer.alloc(0)
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of body as unknown as AsyncIterable<Uint8Array>) {
    total += chunk.byteLength
    if (total > limit) throw new RegistryError(`${what} is larger than ${limit} bytes`)
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks)
}

/**
 * GET a URL, failing loud on anything but a 2xx.
 * @param url - the absolute URL.
 * @param accept - the Accept header.
 * @param options - registry options carrying the fetch implementation.
 * @returns the response.
 * @throws RegistryError on a transport failure or a non-2xx status.
 */
async function get(url: string, accept: string, options: RegistryOptions): Promise<Response> {
  const call = options.fetch ?? globalThis.fetch
  let response: Response
  try {
    response = await call(url, { headers: { accept, 'user-agent': 'dsh-plugin-inspector' } })
  } catch (error) {
    throw new RegistryError(`cannot reach ${url}: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!response.ok) throw new RegistryError(`${url} returned HTTP ${response.status}`)
  return response
}

/**
 * Read the packument for one version, which is the pre-check.
 * @param spec - the package name and requested version.
 * @param options - where to fetch from.
 * @returns everything the metadata says, including the tarball URL and its hash.
 * @throws RegistryError when the package or version does not resolve, or when
 * the document does not carry a tarball URL on the registry's own origin.
 */
export async function resolvePackage(spec: PackageSpec, options: RegistryOptions = {}): Promise<ResolvedPackage> {
  const registry = (options.registry ?? DEFAULT_REGISTRY).replace(/\/+$/, '')
  const url = `${registry}/${spec.name}/${encodeURIComponent(spec.version ?? 'latest')}`
  const response = await get(url, 'application/json', options)
  const body = await readCapped(response, MAX_METADATA_BYTES, 'package metadata')
  let document: unknown
  try {
    document = JSON.parse(body.toString('utf8'))
  } catch (error) {
    /* v8 ignore next -- JSON.parse rejects text only with a SyntaxError. */
    throw new RegistryError(`${url} did not return JSON: ${error instanceof Error ? error.message : String(error)}`)
  }
  const record = asRecord(document)
  const dist = asRecord(record.dist)
  const tarball = typeof dist.tarball === 'string' ? dist.tarball : null
  if (tarball === null) throw new RegistryError(`${url} carries no dist.tarball`)
  assertSameOrigin(tarball, registry)
  const scripts = asRecord(record.scripts)
  const dsh = asRecord(record.dsh)
  const bundle = asRecord(dsh.bundle)
  return {
    name: typeof record.name === 'string' ? record.name : spec.name,
    version: typeof record.version === 'string' ? record.version : (spec.version ?? 'latest'),
    tarball,
    integrity: typeof dist.integrity === 'string' ? dist.integrity : null,
    shasum: typeof dist.shasum === 'string' ? dist.shasum : null,
    hasInstallScript: record.hasInstallScript === true,
    lifecycleScripts: INSTALL_LIFECYCLE_SCRIPTS.filter(name => typeof scripts[name] === 'string'),
    bundlePatch: typeof bundle.patch === 'string' ? bundle.patch : null,
    metadataBytes: body.byteLength,
  }
}

/**
 * Narrow an unknown JSON value to a record, so a hostile document's `dist: 7`
 * reads as "no fields" rather than throwing somewhere further down.
 * @param value - the parsed JSON value.
 * @returns the value as a record, or an empty one.
 */
function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

/**
 * Refuse a tarball URL that points somewhere other than the registry that
 * described it.
 *
 * The integrity hash comes from the same document as the URL, so a hostile
 * registry can always make the two agree — this does not defend against that.
 * What it does refuse is a single doctored packument on an honest registry
 * pointing the download at a host of the attacker's choosing, which would make
 * the tool fetch an arbitrary URL on the user's behalf.
 * @param tarball - the declared tarball URL.
 * @param registry - the registry base URL.
 * @throws RegistryError when the origins differ or the URL is not http(s).
 */
function assertSameOrigin(tarball: string, registry: string): void {
  let url: URL
  let base: URL
  try {
    url = new URL(tarball)
    base = new URL(registry)
  } catch {
    throw new RegistryError(`dist.tarball is not a URL: ${tarball}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new RegistryError(`dist.tarball is not an http(s) URL: ${tarball}`)
  }
  if (url.origin !== base.origin) {
    throw new RegistryError(`dist.tarball ${tarball} is not on the registry's origin ${base.origin}`)
  }
}

/**
 * Check downloaded bytes against what the registry published.
 *
 * `dist.integrity` is preferred and is a real check. `dist.shasum` is SHA-1 and
 * is accepted only when there is no `integrity` field at all, which happens on
 * packages published before npm 5; it is recorded in the report as the weaker
 * check it is. No digest at all is a refusal, because "verified" would then be
 * a claim the tool cannot make.
 * @param bytes - the downloaded tarball.
 * @param resolved - what the packument said about it.
 * @returns the algorithm and digest that matched.
 * @throws RegistryError on a mismatch, an unusable digest, or no digest at all.
 */
export function verifyIntegrity(bytes: Buffer, resolved: ResolvedPackage): VerifiedTarball {
  if (resolved.integrity !== null) {
    // An `integrity` field may carry several space-separated digests. One
    // matching digest in a recognised algorithm is the check; an unrecognised
    // algorithm is not silently ignored, it just is not a match.
    for (const entry of resolved.integrity.trim().split(/\s+/)) {
      const dash = entry.indexOf('-')
      const algorithm = dash < 0 ? '' : entry.slice(0, dash)
      if (!SRI_ALGORITHMS.has(algorithm)) continue
      const expected = entry.slice(dash + 1)
      const actual = digest(algorithm, bytes, 'base64')
      if (actual !== expected) {
        throw new RegistryError(
          `integrity check failed for ${resolved.name}@${resolved.version}: `
          + `registry published ${algorithm}-${expected}, downloaded bytes are ${algorithm}-${actual}`,
        )
      }
      return { bytes, algorithm, digest: entry }
    }
    throw new RegistryError(
      `no usable digest in dist.integrity for ${resolved.name}@${resolved.version}: ${resolved.integrity}`,
    )
  }
  if (resolved.shasum !== null) {
    const actual = digest('sha1', bytes, 'hex')
    if (actual !== resolved.shasum) {
      throw new RegistryError(
        `shasum check failed for ${resolved.name}@${resolved.version}: `
        + `registry published sha1-${resolved.shasum}, downloaded bytes are sha1-${actual}`,
      )
    }
    return { bytes, algorithm: 'sha1', digest: `sha1-${actual}` }
  }
  throw new RegistryError(
    `${resolved.name}@${resolved.version} carries neither dist.integrity nor dist.shasum, so the download cannot be verified`,
  )
}

/**
 * Hash a buffer.
 * @param algorithm - the hash algorithm.
 * @param bytes - the input.
 * @param encoding - how to render the digest.
 * @returns the digest.
 */
function digest(algorithm: string, bytes: BinaryLike, encoding: 'base64' | 'hex'): string {
  return createHash(algorithm).update(bytes).digest(encoding)
}

/**
 * Download a resolved package's tarball and verify it before returning it.
 *
 * Nothing parses the bytes on the way in — they are counted against a ceiling
 * and hashed, and a failed hash throws before any caller can see them.
 * @param resolved - the packument reading for the version to fetch.
 * @param options - where to fetch from.
 * @returns the verified tarball, in memory.
 * @throws RegistryError on a transport failure, an oversized body, or a hash mismatch.
 */
export async function fetchVerifiedTarball(
  resolved: ResolvedPackage, options: RegistryOptions = {},
): Promise<VerifiedTarball> {
  const response = await get(resolved.tarball, 'application/octet-stream', options)
  const bytes = await readCapped(response, MAX_TARBALL_BYTES, `tarball ${resolved.tarball}`)
  return verifyIntegrity(bytes, resolved)
}
