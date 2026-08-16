/**
 * `--from-npm` — inspecting a published package without installing it.
 *
 * This module is the only path in the tool that reaches a network, and it is
 * separate from `inspect.ts` on purpose: a directory or tarball scan cannot
 * arrive here, because nothing on that path imports this file. The steps are
 * fixed and their order is the guarantee:
 *
 * 1. read the version document (~3 KB) — which already answers
 *    `hasInstallScript`, the install lifecycle scripts, and `dsh.bundle`;
 * 2. download the tarball into memory;
 * 3. verify `dist.integrity` **before** anything parses a byte of it;
 * 4. decode in memory and analyse, exactly as the tarball path does.
 *
 * No subprocess, no disk write, no lifecycle script, and no `npm pack`.
 * @module dsh-plugin-inspector/npm
 */

import { analyze } from './inspect.ts'
import type { RegistryProvenance, Report } from './model.ts'
import {
  DEFAULT_REGISTRY,
  fetchVerifiedTarball,
  parseSpec,
  resolvePackage,
  type RegistryOptions,
  type ResolvedPackage,
} from './registry.ts'
import { loadTarballBuffer } from './source.ts'

/**
 * The metadata pre-check, which needs no tarball.
 *
 * A caller sweeping many packages can read this for each of them at a few
 * kilobytes apiece and decide which ones are worth downloading.
 * @param spec - `<name>` or `<name>@<version>`.
 * @param options - where to fetch from.
 * @returns what the version document says.
 * @throws RegistryError when the package or version does not resolve.
 */
export async function precheck(spec: string, options: RegistryOptions = {}): Promise<ResolvedPackage> {
  return resolvePackage(parseSpec(spec), options)
}

/**
 * Fetch a published package and inspect it in memory.
 * @param spec - `<name>` or `<name>@<version>`; no version means the `latest` tag.
 * @param options - where to fetch from.
 * @returns the complete report, carrying the registry provenance.
 * @throws RegistryError when the package cannot be resolved, fetched, or verified.
 * @throws SourceError or ManifestError when the fetched tarball is not a package.
 */
export async function inspectFromNpm(spec: string, options: RegistryOptions = {}): Promise<Report> {
  const resolved = await precheck(spec, options)
  const verified = await fetchVerifiedTarball(resolved, options)
  const provenance: RegistryProvenance = {
    spec,
    registry: (options.registry ?? DEFAULT_REGISTRY).replace(/\/+$/, ''),
    resolvedVersion: resolved.version,
    tarball: resolved.tarball,
    digest: verified.digest,
    algorithm: verified.algorithm,
    hasInstallScript: resolved.hasInstallScript,
    metadataBytes: resolved.metadataBytes,
    tarballBytes: verified.bytes.byteLength,
  }
  const source = await loadTarballBuffer(verified.bytes, `npm:${resolved.name}@${resolved.version}`)
  return analyze(source, provenance)
}
