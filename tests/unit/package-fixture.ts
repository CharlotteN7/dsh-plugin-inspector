/**
 * Building a package on disk from a literal, so a regression test states its
 * own input next to its assertion.
 *
 * The committed fixtures in `tests/fixtures/` are the catalogue: one hostile
 * package per detection story, meant to be read. These are the opposite — one
 * or two files pinning one behavior, where a whole fixture directory would put
 * the interesting line three files away from the test that cares about it.
 * @module tests/unit/package-fixture
 */

import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { create } from 'tar'

/** Directories made by this module, removed after each spec file finishes. */
const created: string[] = []

/**
 * Write a package to a fresh temporary directory.
 * @param files - package-relative POSIX path to file content.
 * @returns the absolute package root.
 */
export function createPackage(files: Readonly<Record<string, string>>): string {
  const root = mkdtempSync(join(tmpdir(), 'dsh-inspector-pkg-'))
  created.push(root)
  for (const [path, content] of Object.entries(files)) {
    const absolute = join(root, path)
    mkdirSync(dirname(absolute), { recursive: true })
    writeFileSync(absolute, content)
  }
  return root
}

/**
 * Add a symbolic link inside an existing package.
 * @param root - the package root.
 * @param path - package-relative link path.
 * @param target - the link's target, verbatim.
 */
export function addSymlink(root: string, path: string, target: string): void {
  const absolute = join(root, path)
  mkdirSync(dirname(absolute), { recursive: true })
  symlinkSync(target, absolute)
}

/**
 * Pack an exact list of package-relative paths into a tarball, with the
 * `package/` prefix npm always uses.
 *
 * The list is explicit on purpose. A pack helper that tars whatever is in the
 * directory cannot detect a directory reader that reads more than npm would
 * publish, because both sides then see the same files and parity holds by
 * construction.
 * @param root - the package root.
 * @param paths - the package-relative paths npm would publish, exactly.
 * @returns the absolute tarball path.
 */
export async function packExactly(root: string, paths: readonly string[]): Promise<string> {
  const file = join(mkdtempSync(join(tmpdir(), 'dsh-inspector-tgz-')), 'package.tgz')
  created.push(dirname(file))
  await create({ gzip: true, file, cwd: root, prefix: 'package' }, [...paths])
  return file
}

/**
 * Write an uncompressed tar holding exactly the entry names given, including
 * names no packing tool would produce.
 *
 * `tar.create` cannot be made to emit `package/../../etc/passwd`, because it
 * writes names for files that exist. An attacker's archive is written by hand,
 * so the test that the reader refuses one has to be written by hand too.
 * @param entries - entry name to file content.
 * @returns the absolute `.tar` path.
 */
export function packRawEntries(entries: Readonly<Record<string, string>>): string {
  const blocks: Buffer[] = []
  for (const [name, content] of Object.entries(entries)) {
    const body = Buffer.from(content, 'utf8')
    const header = Buffer.alloc(512, 0)
    header.write(name.slice(0, 100), 0, 'utf8')
    header.write('0000644\0', 100, 'utf8')
    header.write('0000000\0', 108, 'utf8')
    header.write('0000000\0', 116, 'utf8')
    header.write(`${body.length.toString(8).padStart(11, '0')}\0`, 124, 'utf8')
    header.write('00000000000\0', 136, 'utf8')
    header.write('        ', 148, 'utf8')
    header.write('0', 156, 'utf8')
    header.write('ustar\x0000', 257, 'utf8')
    let checksum = 0
    for (const byte of header) checksum += byte
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 'utf8')
    blocks.push(header, body, Buffer.alloc((512 - body.length % 512) % 512, 0))
  }
  blocks.push(Buffer.alloc(1024, 0))
  const file = join(mkdtempSync(join(tmpdir(), 'dsh-inspector-raw-')), 'raw.tar')
  created.push(dirname(file))
  writeFileSync(file, Buffer.concat(blocks))
  return file
}

/** Remove everything this module created. */
export function cleanupPackages(): void {
  for (const root of created.splice(0)) rmSync(root, { recursive: true, force: true })
}
