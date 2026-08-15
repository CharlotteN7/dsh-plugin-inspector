/**
 * The decoded package every check tier reads from.
 *
 * Parsing happens once, in `inspect.ts`, and each tier receives the result.
 * That keeps the tiers pure functions of already-parsed data — which is what
 * makes "no analysed code was executed" a property of one small module rather
 * than something every check has to be trusted about.
 * @module dsh-plugin-inspector/checks/input
 */

import type { PatchDocument, PatchParseError } from '../cordis-yaml.ts'
import type { PackageManifest } from '../manifest.ts'
import type { PluginSource } from '../source.ts'

/** A patch layer that could not be parsed. */
export interface PatchFailure {
  /** Package-relative path of the YAML file. */
  readonly file: string
  readonly error: PatchParseError
}

/** Everything the checks see. */
export interface CheckInput {
  readonly source: PluginSource
  readonly manifest: PackageManifest
  /** Every Cordis patch layer found in the package that parsed. */
  readonly patches: readonly PatchDocument[]
  readonly patchFailures: readonly PatchFailure[]
  /** Package-relative paths of shipped JavaScript and TypeScript source. */
  readonly sourceFiles: readonly string[]
  /** Package-relative paths of shipped skill and agent-instruction markdown. */
  readonly modelVisibleFiles: readonly string[]
}
