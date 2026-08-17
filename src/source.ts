/**
 * Reading the package under analysis without installing, building, or running
 * any part of it.
 *
 * A directory is walked directly. A tarball is decoded **entirely in memory** —
 * nothing is ever written to disk. That is a safety property, not an
 * optimisation: it makes tar path traversal (`../../.ssh/authorized_keys`)
 * structurally impossible rather than something a filter has to catch, and it
 * lets a test assert that analysing a hostile tarball touched no file.
 *
 * Every cap is enforced *while* bytes arrive, not after. A tar entry is
 * abandoned the moment its running total passes {@link MAX_FILE_BYTES}, so a
 * 27 MB tarball holding a 6 GB member costs 27 MB of decompression and no
 * memory at all. Enforcing a cap on an already-materialised buffer is not a
 * cap.
 *
 * Symbolic links are recorded and never followed, for the same reason: a link
 * pointing outside the package is not part of the package.
 * @module dsh-plugin-inspector/source
 */

import { createReadStream, openSync, readdirSync, readFileSync, readSync, closeSync, statSync, type Dirent, type Stats } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { PassThrough, Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { createGunzip } from 'node:zlib'
import { Parser } from 'tar'
import type { SkippedFile } from './model.ts'
import { publishSet, TARBALL_PUBLISH_SET, type PublishBasis, type PublishSet } from './publish.ts'

/** Largest single file the analyzer will hold in memory. */
export const MAX_FILE_BYTES = 4 * 1024 * 1024

/** Largest total payload the analyzer will hold in memory. */
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024

/** Largest number of files the analyzer will consider. */
export const MAX_ENTRIES = 10_000

/**
 * Decompressed tar bytes one tarball may produce before the read is abandoned.
 *
 * Eight times the in-memory ceiling. A plugin tarball is never this large, and
 * one that is has already answered the only question worth asking about it.
 */
export const MAX_STREAM_BYTES = 8 * MAX_TOTAL_BYTES

/** The resource ceilings one read runs under. */
export interface ReadLimits {
  readonly maxFileBytes: number
  readonly maxTotalBytes: number
  readonly maxEntries: number
  /** Decompressed tar bytes one tarball may produce before the read is abandoned. */
  readonly maxStreamBytes: number
}

/** The shipping ceilings. Tests substitute smaller ones to exercise each cap. */
export const DEFAULT_LIMITS: ReadLimits = {
  maxFileBytes: MAX_FILE_BYTES,
  maxTotalBytes: MAX_TOTAL_BYTES,
  maxEntries: MAX_ENTRIES,
  maxStreamBytes: MAX_STREAM_BYTES,
}

/** Directories never descended into: not shipped, and not the package's own code. */
const SKIPPED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules', '.git', '.pnpm-store', '.yarn', 'coverage', '.nyc_output',
])

/** Thrown when the target cannot be read at all, which is exit code 2, not a finding. */
export class SourceError extends Error {}

/**
 * Where the analysed bytes came from. `registry` is a tarball too — the same
 * in-memory decoding, over bytes fetched by `--from-npm` instead of read from
 * disk — and is kept distinct so a report says which one it was.
 */
export type SourceKind = 'directory' | 'tarball' | 'registry'

/** The analysed package, decoded into memory. */
export interface PluginSource {
  readonly kind: SourceKind
  /** The target as the user gave it, resolved to an absolute path. */
  readonly path: string
  /** Package-relative POSIX path to UTF-8 text, for every readable text file. */
  readonly files: ReadonlyMap<string, string>
  /** Files deliberately not read, each with the reason. Feeds Tier C. */
  readonly skipped: readonly SkippedFile[]
  readonly bytesRead: number
  /** How the set of analysed files was decided. */
  readonly publishBasis: PublishBasis
  /** Working-tree files npm would not publish, and which were therefore not read. */
  readonly unpublishedFiles: number
}

/** Accumulator shared by both readers so the caps behave identically. */
interface Collector {
  readonly files: Map<string, string>
  readonly skipped: SkippedFile[]
  readonly limits: ReadLimits
  bytes: number
  entries: number
  unpublished: number
}

/**
 * Whether a buffer looks like binary content. A NUL byte in the first 8 KiB is
 * the same cheap test `grep` and `git` use, and it is enough here: the point is
 * only to avoid parsing bytes that are not source.
 * @param buffer - the file content.
 * @returns true when the file should be treated as opaque.
 */
function isBinary(buffer: Buffer): boolean {
  return buffer.subarray(0, 8192).includes(0)
}

/**
 * Charge one file against the entry count.
 * @param collector - the shared accumulator.
 * @param path - package-relative POSIX path.
 * @returns true when the analyzer may go on to read it.
 */
function countEntry(collector: Collector, path: string): boolean {
  if (collector.entries >= collector.limits.maxEntries) {
    collector.skipped.push({ path, reason: 'entry-cap' })
    return false
  }
  collector.entries += 1
  return true
}

/**
 * Record one already-read file against the size caps, storing its text when it
 * is readable.
 * @param collector - the shared accumulator.
 * @param path - package-relative POSIX path.
 * @param buffer - the file content.
 */
function store(collector: Collector, path: string, buffer: Buffer): void {
  /* v8 ignore next 4 -- both callers check the size before reading; this is the same ceiling held at the last point that could still allocate. */
  if (buffer.byteLength > collector.limits.maxFileBytes) {
    collector.skipped.push({ path, reason: 'size-cap' })
    return
  }
  if (collector.bytes + buffer.byteLength > collector.limits.maxTotalBytes) {
    collector.skipped.push({ path, reason: 'total-cap' })
    return
  }
  if (isBinary(buffer)) {
    collector.skipped.push({ path, reason: 'binary' })
    return
  }
  collector.bytes += buffer.byteLength
  collector.files.set(path, buffer.toString('utf8'))
}

/**
 * Walk a directory tree, never following symlinks, never descending into build
 * or dependency directories, and reading only what the package would publish.
 * @param root - absolute package root.
 * @param directory - absolute directory currently being read.
 * @param collector - the shared accumulator.
 * @param published - the publish-set membership test.
 */
function walkDirectory(root: string, directory: string, collector: Collector, published: PublishSet): void {
  let entries: Dirent[]
  try {
    entries = readdirSync(directory, { withFileTypes: true })
  } catch {
    collector.skipped.push({ path: toPackagePath(root, directory), reason: 'unreadable' })
    return
  }
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const absolute = join(directory, entry.name)
    const path = toPackagePath(root, absolute)
    if (entry.isSymbolicLink()) {
      if (published.includes(path)) collector.skipped.push({ path, reason: 'unreadable' })
      continue
    }
    if (entry.isDirectory()) {
      if (SKIPPED_DIRECTORIES.has(entry.name)) continue
      walkDirectory(root, absolute, collector, published)
      continue
    }
    if (!entry.isFile()) continue
    if (!published.includes(path)) {
      collector.unpublished += 1
      continue
    }
    if (!countEntry(collector, path)) continue
    try {
      // Size first, then read. `readFileSync` on an oversized file materialises
      // it before any cap can reject it, which is the same mistake on the
      // directory path that the tar reader had on the tarball path.
      if (statSync(absolute).size > collector.limits.maxFileBytes) {
        collector.skipped.push({ path, reason: 'size-cap' })
        continue
      }
      store(collector, path, readFileSync(absolute))
    } catch {
      collector.skipped.push({ path, reason: 'unreadable' })
    }
  }
}

/**
 * Convert an absolute path inside the package to the POSIX package-relative
 * form every report and finding uses.
 * @param root - absolute package root.
 * @param absolute - absolute path inside it.
 * @returns the package-relative POSIX path.
 */
function toPackagePath(root: string, absolute: string): string {
  return relative(root, absolute).split(sep).join(posix.sep)
}

/**
 * Drop the tarball's single leading directory, which npm always sets to
 * `package/`, so tarball paths and directory paths are directly comparable, and
 * reject anything that still climbs out afterwards. Nothing is written from a
 * tar entry, but a finding whose `file` reads `../../../../etc/passwd` claims a
 * location the package does not have.
 * @param entryPath - the raw tar entry path.
 * @returns the package-relative path, or `undefined` when there is none.
 */
function stripRoot(entryPath: string): string | undefined {
  const normalized = entryPath.replace(/^\.\//, '')
  const slash = normalized.indexOf('/')
  if (slash < 0) return undefined
  const remainder = normalized.slice(slash + 1)
  /* v8 ignore next -- an entry name ending in `/` is a directory entry, which the parser never hands to this. */
  if (remainder === '') return undefined
  const segments: string[] = []
  for (const segment of remainder.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      if (segments.length === 0) return undefined
      segments.pop()
      continue
    }
    segments.push(segment)
  }
  return segments.length === 0 ? undefined : segments.join('/')
}

/**
 * A stage that fails the pipeline once the decompressed stream passes a
 * ceiling. Nothing downstream keeps the bytes, but *producing* eight gigabytes
 * from a 28 MB file still costs the time to inflate them, and a CI job that
 * hangs for a minute on a hostile input is a denial of service with extra
 * steps.
 * @param limit - the ceiling in bytes.
 * @returns the counting stage.
 */
function byteCeiling(limit: number): Transform {
  let total = 0
  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      total += chunk.byteLength
      if (total > limit) {
        callback(new SourceError(`decompresses to more than ${limit} bytes`))
        return
      }
      callback(null, chunk)
    },
  })
}

/**
 * Whether a file begins with the gzip magic number, so a plain `.tar` is read
 * as one rather than failing in the inflater.
 * @param file - absolute path.
 * @returns true when the file is gzipped.
 */
function isGzip(file: string): boolean {
  const handle = openSync(file, 'r')
  try {
    const header = Buffer.alloc(2)
    readSync(handle, header, 0, 2, 0)
    return header[0] === 0x1f && header[1] === 0x8b
  } finally {
    closeSync(handle)
  }
}

/**
 * Decode an npm tarball into memory. The tar reader is only ever a `Parser`;
 * no extraction call exists in this module, so there is no code path that can
 * write a file.
 *
 * The pipeline is assembled by hand rather than through `tar.list({ file })`
 * because that convenience path applies no backpressure between the inflater
 * and the parser: the inflater runs ahead, and a tarball holding one very large
 * member materialises gigabytes of it whatever the entry consumer does. A
 * `stream.pipeline` of Node streams paces the inflater against the parser, and
 * measured on the same 28 MB probe it holds the process at 96 MB instead of
 * 4 GB.
 *
 * Errors thrown from the entry callbacks reach an EventEmitter, not the
 * `await`, so every one of them is captured here and rethrown on the awaited
 * path — an emitter-thrown `RangeError` that escapes becomes an uncaught
 * exception and a raw stack trace on a user's terminal.
 * @param bytes - the arriving tar stream, gzipped or not.
 * @param gzipped - whether to inflate before parsing.
 * @param collector - the shared accumulator.
 */
async function readTarStream(bytes: Readable, gzipped: boolean, collector: Collector): Promise<void> {
  const pending: Promise<void>[] = []
  let failure: unknown = null
  const parser = new Parser({
    onReadEntry: (entry) => {
      if (entry.type !== 'File') {
        entry.resume()
        return
      }
      const path = stripRoot(String(entry.path))
      if (path === undefined) {
        collector.skipped.push({ path: String(entry.path), reason: 'unreadable' })
        entry.resume()
        return
      }
      if (!countEntry(collector, path)) {
        entry.resume()
        return
      }
      pending.push(new Promise<void>((done) => {
        let chunks: Buffer[] = []
        let size = 0
        let abandoned: SkippedFile['reason'] | null = null
        const abandon = (reason: SkippedFile['reason']): void => {
          abandoned = reason
          chunks = []
          entry.resume()
        }
        entry.on('data', (chunk: Buffer) => {
          if (abandoned !== null) return
          size += chunk.byteLength
          if (size > collector.limits.maxFileBytes) return abandon('size-cap')
          if (collector.bytes + size > collector.limits.maxTotalBytes) return abandon('total-cap')
          chunks.push(chunk)
        })
        entry.on('end', () => {
          try {
            if (abandoned === null) store(collector, path, Buffer.concat(chunks))
            else collector.skipped.push({ path, reason: abandoned })
          } catch (error) {
            failure ??= error
          }
          chunks = []
          done()
        })
      }))
    },
  })
  const inflate = gzipped ? createGunzip() : new PassThrough()
  await pipeline(bytes, inflate, byteCeiling(collector.limits.maxStreamBytes), parser)
  await Promise.all(pending)
  if (failure !== null) throw failure
}

/**
 * Read the `files`, `main`, and ignore rules a working tree publishes under,
 * without trusting the manifest to be well formed — a hostile `package.json`
 * whose `files` is a number must not stop the analysis.
 *
 * A manifest that is missing or is not JSON produces no rules rather than an
 * error. Diagnosing that is `parseManifest`'s job and it says something more
 * useful than this function could; failing here would replace "package.json is
 * not valid JSON, at position 4" with "this is not an npm package".
 * @param root - absolute package root.
 * @returns the publish-set membership test.
 */
function directoryPublishSet(root: string): PublishSet {
  let manifest: unknown
  try {
    manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  } catch {
    manifest = {}
  }
  const record = typeof manifest === 'object' && manifest !== null && !Array.isArray(manifest)
    ? manifest as Record<string, unknown>
    : {}
  const files = record.files
  const main = record.main
  return publishSet({
    files: Array.isArray(files) ? files.filter((entry): entry is string => typeof entry === 'string') : null,
    main: typeof main === 'string' ? main : null,
    npmignore: readOptional(join(root, '.npmignore')),
    gitignore: readOptional(join(root, '.gitignore')),
  })
}

/**
 * Read a file that may not exist.
 * @param path - absolute path.
 * @returns the text, or `null`.
 */
function readOptional(path: string): string | null {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    // Absent, a directory, or unreadable: all three mean "no rules from here".
    return null
  }
}

/**
 * Read the package under analysis.
 * @param target - a plugin directory, or a `.tgz` / `.tar.gz` npm tarball.
 * @param limits - resource ceilings; defaults to {@link DEFAULT_LIMITS}.
 * @returns the decoded package.
 * @throws SourceError when the target does not exist, is not a readable
 * tarball, or holds no `package.json`.
 */
export async function loadSource(target: string, limits: ReadLimits = DEFAULT_LIMITS): Promise<PluginSource> {
  const path = resolve(target)
  let stats: Stats
  try {
    stats = statSync(path)
  } catch {
    throw new SourceError(`cannot read target: ${path}`)
  }
  const collector: Collector = { files: new Map(), skipped: [], limits, bytes: 0, entries: 0, unpublished: 0 }
  const kind = stats.isDirectory() ? 'directory' : 'tarball'
  let published: PublishSet
  if (kind === 'directory') {
    published = directoryPublishSet(path)
    walkDirectory(path, path, collector, published)
  } else {
    published = TARBALL_PUBLISH_SET
    await decodeTar(createReadStream(path), isGzip(path), collector, path)
  }
  return finish(kind, path, collector, published)
}

/**
 * Decode an npm tarball held in memory, for bytes that never touched the disk.
 *
 * The only caller is the `--from-npm` path, which fetches a tarball and
 * verifies its `dist.integrity` hash before handing the buffer here. Reading it
 * goes through the same `Parser` as the on-disk path, so the "no extraction,
 * ever" property covers both.
 * @param bytes - the complete tarball, gzipped or not.
 * @param label - what to report as the target path, e.g. `npm:pkg@1.2.3`.
 * @param limits - resource ceilings; defaults to {@link DEFAULT_LIMITS}.
 * @returns the decoded package.
 * @throws SourceError when the buffer is not a readable npm tarball.
 */
export async function loadTarballBuffer(
  bytes: Buffer, label: string, limits: ReadLimits = DEFAULT_LIMITS,
): Promise<PluginSource> {
  const collector: Collector = { files: new Map(), skipped: [], limits, bytes: 0, entries: 0, unpublished: 0 }
  const gzipped = bytes[0] === 0x1f && bytes[1] === 0x8b
  await decodeTar(Readable.from(bytes), gzipped, collector, label)
  return finish('registry', label, collector, TARBALL_PUBLISH_SET)
}

/**
 * Run the tar pipeline and turn every failure into a `SourceError` naming the
 * target, so a caller can tell "this is not a tarball" from a crash.
 * @param bytes - the arriving tar stream.
 * @param gzipped - whether to inflate before parsing.
 * @param collector - the shared accumulator.
 * @param label - the target as it should appear in an error message.
 */
async function decodeTar(bytes: Readable, gzipped: boolean, collector: Collector, label: string): Promise<void> {
  try {
    await readTarStream(bytes, gzipped, collector)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new SourceError(`cannot read tarball ${label}: ${detail}`)
  }
  if (collector.entries === 0) {
    throw new SourceError(`${label} holds no tar entries — this is not a readable npm tarball`)
  }
}

/**
 * Assemble the decoded package, refusing a target that holds no manifest.
 * @param kind - where the bytes came from.
 * @param path - the target as it should appear in the report.
 * @param collector - the shared accumulator.
 * @param published - the publish-set membership test that was used.
 * @returns the decoded package.
 */
function finish(kind: SourceKind, path: string, collector: Collector, published: PublishSet): PluginSource {
  if (!collector.files.has('package.json')) {
    throw new SourceError(`no readable package.json in ${path} — this is not an npm package`)
  }
  return {
    kind,
    path,
    files: collector.files,
    skipped: collector.skipped,
    bytesRead: collector.bytes,
    publishBasis: published.basis,
    unpublishedFiles: collector.unpublished,
  }
}
