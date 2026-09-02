/**
 * `--from-npm` — inspecting a published package without installing it.
 *
 * This module is the only path in the tool that reaches a network, and it is
 * separate from `inspect.ts` on purpose: a directory or tarball scan cannot
 * arrive here, because nothing on that path imports this file. The steps are
 * fixed and their order is the guarantee:
 *
 * 1. read the version document (~3 KB) — which already answers
 *    `hasInstallScript`, the install lifecycle scripts, `dsh.bundle`, and
 *    whether the registry holds a provenance attestation at all;
 * 2. download the tarball into memory;
 * 3. verify `dist.integrity` **before** anything parses a byte of it;
 * 4. read the provenance attestation, when step 1 said there is one, and check
 *    it against the bytes step 3 vouched for;
 * 5. decode in memory and analyse, exactly as the tarball path does.
 *
 * Step 4 is the only request this module makes that is not unconditional, and
 * it is skipped for every package the version document says has no attestation
 * — which on the measured corpus is 28 packages in 40. It never fails an
 * analysis: an endpoint that is down or a bundle that does not decode leaves
 * the provenance fact in state `unreadable`, which is a different answer from
 * `absent` and is printed as one.
 *
 * No subprocess, no disk write, no lifecycle script, and no `npm pack`.
 * @module dsh-plugin-inspector/npm
 */

import {
  provenanceAbsent,
  provenanceUnreadable,
  readProvenance,
  type ProvenanceFact,
} from './attestation.ts'
import { analyze } from './inspect.ts'
import type { RegistryProvenance, Report } from './model.ts'
import {
  attestationUrl,
  DEFAULT_REGISTRY,
  fetchAttestation,
  fetchVerifiedTarball,
  parseSpec,
  RegistryError,
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
 * Read the registry's provenance attestation for a resolved package, when it
 * has one, and check it against the bytes that were downloaded.
 *
 * Every failure on this path becomes a fact rather than a refusal. The tarball
 * has already been checked against `dist.integrity`, so the analysis is sound
 * whatever the attestation endpoint does, and turning a registry outage into
 * exit code 2 would make provenance a precondition for reading a package
 * instead of something reported about it.
 * @param resolved - the packument reading for the version.
 * @param registry - the registry base URL, without a trailing slash.
 * @param tarball - the verified tarball bytes.
 * @param options - where to fetch from.
 * @returns what the registry says about the build origin, and what was checked.
 */
async function readRegistryProvenance(
  resolved: ResolvedPackage, registry: string, tarball: Buffer, options: RegistryOptions,
): Promise<ProvenanceFact> {
  if (resolved.provenancePredicateType === null) return provenanceAbsent()
  let url: string
  try {
    url = attestationUrl(registry, resolved.name, resolved.version)
  } catch (error) {
    /* v8 ignore next -- `attestationUrl` refuses a name or version only with a RegistryError. */
    if (!(error instanceof RegistryError)) throw error
    return provenanceUnreadable(null, error.message)
  }
  let body: Buffer
  try {
    body = await fetchAttestation(url, options)
  } catch (error) {
    /* v8 ignore next -- `fetchAttestation` reports every refusal as a RegistryError. */
    if (!(error instanceof RegistryError)) throw error
    return provenanceUnreadable(url, error.message)
  }
  return readProvenance(body, { name: resolved.name, version: resolved.version, tarball, url })
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
  const registry = (options.registry ?? DEFAULT_REGISTRY).replace(/\/+$/, '')
  const attestation = await readRegistryProvenance(resolved, registry, verified.bytes, options)
  const provenance: RegistryProvenance = {
    spec,
    registry,
    resolvedVersion: resolved.version,
    tarball: resolved.tarball,
    digest: verified.digest,
    algorithm: verified.algorithm,
    hasInstallScript: resolved.hasInstallScript,
    metadataBytes: resolved.metadataBytes,
    tarballBytes: verified.bytes.byteLength,
  }
  const source = await loadTarballBuffer(verified.bytes, `npm:${resolved.name}@${resolved.version}`)
  return analyze(source, provenance, attestation)
}
