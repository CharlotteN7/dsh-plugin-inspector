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
 * Symbolic links are recorded and never followed, for the same reason: a link
 * pointing outside the package is not part of the package.
 * @module dsh-plugin-inspector/source
 */

import { readdirSync, readFileSync, statSync, type Dirent, type Stats } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { list } from 'tar'
import type { SkippedFile } from './model.ts'

/** Largest single file the analyzer will hold in memory. */
export const MAX_FILE_BYTES = 4 * 1024 * 1024

/** Largest total payload the analyzer will hold in memory. */
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024

/** Largest number of files the analyzer will consider. */
export const MAX_ENTRIES = 10_000

/** Directories never descended into: not shipped, and not the package's own code. */
const SKIPPED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules', '.git', '.pnpm-store', '.yarn', 'coverage', '.nyc_output',
])

/** Thrown when the target cannot be read at all, which is exit code 2, not a finding. */
export class SourceError extends Error {}

/** The analysed package, decoded into memory. */
export interface PluginSource {
  readonly kind: 'directory' | 'tarball'
  /** The target as the user gave it, resolved to an absolute path. */
  readonly path: string
  /** Package-relative POSIX path to UTF-8 text, for every readable text file. */
  readonly files: ReadonlyMap<string, string>
  /** Files deliberately not read, each with the reason. Feeds Tier C. */
  readonly skipped: readonly SkippedFile[]
  readonly bytesRead: number
}

/** Accumulator shared by both readers so the caps behave identically. */
interface Collector {
  readonly files: Map<string, string>
  readonly skipped: SkippedFile[]
  bytes: number
  entries: number
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
 * Record one file against the caps, storing its text when it is readable.
 * @param collector - the shared accumulator.
 * @param path - package-relative POSIX path.
 * @param buffer - the file content.
 */
function accept(collector: Collector, path: string, buffer: Buffer): void {
  if (collector.entries >= MAX_ENTRIES) {
    collector.skipped.push({ path, reason: 'entry-cap' })
    return
  }
  collector.entries += 1
  if (buffer.byteLength > MAX_FILE_BYTES) {
    collector.skipped.push({ path, reason: 'size-cap' })
    return
  }
  if (collector.bytes + buffer.byteLength > MAX_TOTAL_BYTES) {
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
 * Walk a directory tree, never following symlinks and never descending into
 * build or dependency directories.
 * @param root - absolute package root.
 * @param directory - absolute directory currently being read.
 * @param collector - the shared accumulator.
 */
function walkDirectory(root: string, directory: string, collector: Collector): void {
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
      collector.skipped.push({ path, reason: 'unreadable' })
      continue
    }
    if (entry.isDirectory()) {
      if (SKIPPED_DIRECTORIES.has(entry.name)) continue
      walkDirectory(root, absolute, collector)
      continue
    }
    if (!entry.isFile()) continue
    try {
      accept(collector, path, readFileSync(absolute))
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
 * `package/`, so tarball paths and directory paths are directly comparable.
 * @param entryPath - the raw tar entry path.
 * @returns the package-relative path, or `undefined` when nothing remains.
 */
function stripRoot(entryPath: string): string | undefined {
  const normalized = entryPath.replace(/^\.\//, '')
  const slash = normalized.indexOf('/')
  if (slash < 0) return undefined
  const remainder = normalized.slice(slash + 1)
  return remainder === '' ? undefined : remainder
}

/**
 * Decode an npm tarball into memory. The tar reader is only ever asked to
 * *list* entries; no extraction call exists in this module, so there is no
 * code path that can write a file.
 * @param file - absolute path to the `.tgz`.
 * @param collector - the shared accumulator.
 */
async function readTarball(file: string, collector: Collector): Promise<void> {
  const pending: Promise<void>[] = []
  await list({
    file,
    onReadEntry: (entry) => {
      if (entry.type !== 'File') return
      const path = stripRoot(String(entry.path))
      if (path === undefined) return
      const chunks: Buffer[] = []
      pending.push(new Promise<void>((done) => {
        entry.on('data', (chunk: Buffer) => chunks.push(chunk))
        entry.on('end', () => {
          accept(collector, path, Buffer.concat(chunks))
          done()
        })
      }))
    },
  })
  await Promise.all(pending)
}

/**
 * Read the package under analysis.
 * @param target - a plugin directory, or a `.tgz` / `.tar.gz` npm tarball.
 * @returns the decoded package.
 * @throws SourceError when the target does not exist or holds no `package.json`.
 */
export async function loadSource(target: string): Promise<PluginSource> {
  const path = resolve(target)
  let stats: Stats
  try {
    stats = statSync(path)
  } catch {
    throw new SourceError(`cannot read target: ${path}`)
  }
  const collector: Collector = { files: new Map(), skipped: [], bytes: 0, entries: 0 }
  const kind = stats.isDirectory() ? 'directory' : 'tarball'
  if (kind === 'directory') {
    walkDirectory(path, path, collector)
  } else {
    try {
      await readTarball(path, collector)
    } catch (error) {
      throw new SourceError(`cannot read tarball ${path}: ${String(error)}`)
    }
  }
  if (!collector.files.has('package.json')) {
    throw new SourceError(`no readable package.json in ${path} — this is not an npm package`)
  }
  return { kind, path, files: collector.files, skipped: collector.skipped, bytesRead: collector.bytes }
}
