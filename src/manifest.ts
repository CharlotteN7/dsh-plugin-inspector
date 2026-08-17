/**
 * Reading `package.json` from an untrusted package.
 *
 * This is a file boundary with a hostile author on the other side, so nothing
 * here trusts the parse type. Every field is narrowed before use and a field
 * of the wrong shape is treated as absent rather than throwing — a plugin that
 * ships `"scripts": "postinstall"` should still be analysed for everything
 * else, and "this manifest is malformed" is itself worth reporting.
 * @module dsh-plugin-inspector/manifest
 */

/** The `dsh.bundle` declaration that promotes a package to a mounted patch layer. */
export interface DshBundleSection {
  /** Patch file path relative to the package root, verbatim and unresolved. */
  readonly patch?: string
}

/** The `dsh`-owned section of `package.json`, as far as this tool reads it. */
export interface DshSection {
  readonly bundle?: DshBundleSection
  readonly profile?: { readonly bundles?: readonly string[] }
  /** Present means the package ships a bundle executed in the user's browser. */
  readonly client?: Record<string, unknown>
}

/** The slice of `package.json` this tool reads. */
export interface PackageManifest {
  readonly name: string
  readonly version: string
  readonly license: string | null
  readonly scripts: Readonly<Record<string, string>>
  readonly dependencies: Readonly<Record<string, string>>
  readonly peerDependencies: Readonly<Record<string, string>>
  readonly optionalDependencies: Readonly<Record<string, string>>
  readonly devDependencies: Readonly<Record<string, string>>
  /** The publish allowlist, or `null` when the manifest declares none. */
  readonly files: readonly string[] | null
  /** Command names the package installs on the user's PATH, in declaration order. */
  readonly binNames: readonly string[]
  readonly exportPaths: readonly string[]
  readonly dsh: DshSection
  /** Problems found while reading the manifest, reported as Tier A findings. */
  readonly defects: readonly string[]
}

/** Thrown when `package.json` is not JSON at all. */
export class ManifestError extends Error {}

/**
 * Whether a value is a plain object, which is the only shape any of the fields
 * this module reads is allowed to have.
 * @param value - the parsed value.
 * @returns true for a non-null, non-array object.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Read a `Record<string, string>` field, dropping entries of the wrong type.
 * @param source - the parsed manifest object.
 * @param field - the field name.
 * @param defects - sink for shape complaints.
 * @returns the field's string-valued entries.
 */
function stringMap(
  source: Record<string, unknown>, field: string, defects: string[],
): Record<string, string> {
  const value = source[field]
  if (value === undefined) return {}
  if (!isRecord(value)) {
    defects.push(`"${field}" is not an object`)
    return {}
  }
  const result: Record<string, string> = {}
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string') result[key] = entry
  }
  return result
}

/**
 * Read the `dsh` section, narrowing each nested field independently so one
 * malformed subfield does not discard the rest.
 * @param value - the raw `dsh` value.
 * @param defects - sink for shape complaints.
 * @returns the narrowed section.
 */
function readDshSection(value: unknown, defects: string[]): DshSection {
  if (value === undefined) return {}
  if (!isRecord(value)) {
    defects.push('"dsh" is not an object')
    return {}
  }
  const section: { bundle?: DshBundleSection, profile?: { bundles?: readonly string[] }, client?: Record<string, unknown> } = {}
  const bundle = value.bundle
  if (isRecord(bundle)) {
    section.bundle = typeof bundle.patch === 'string' ? { patch: bundle.patch } : {}
  } else if (bundle !== undefined) {
    defects.push('"dsh.bundle" is not an object')
  }
  const profile = value.profile
  if (isRecord(profile) && Array.isArray(profile.bundles)) {
    section.profile = { bundles: profile.bundles.filter((entry): entry is string => typeof entry === 'string') }
  }
  const client = value.client
  if (isRecord(client)) {
    section.client = client
  } else if (client !== undefined) {
    defects.push('"dsh.client" is not an object')
  }
  return section
}

/**
 * Read the command names `bin` installs. npm accepts both the string form,
 * which names one command after the package, and the object form.
 * @param parsed - the parsed manifest object.
 * @returns the command names, in declaration order.
 */
function readBinNames(parsed: Record<string, unknown>): string[] {
  const bin = parsed.bin
  if (typeof bin === 'string') return [typeof parsed.name === 'string' ? parsed.name : '<unnamed>']
  if (!isRecord(bin)) return []
  return Object.keys(bin)
}

/**
 * Parse an untrusted `package.json`.
 * @param text - the file's UTF-8 content.
 * @returns the narrowed manifest, including any shape defects found.
 * @throws ManifestError when the text is not a JSON object.
 */
export function parseManifest(text: string): PackageManifest {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    /* v8 ignore next -- JSON.parse rejects text only with a SyntaxError. */
    throw new ManifestError(`package.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!isRecord(parsed)) throw new ManifestError('package.json must hold a JSON object')
  const defects: string[] = []
  const files = parsed.files
  const exportsValue = parsed.exports
  return {
    name: typeof parsed.name === 'string' ? parsed.name : '<unnamed>',
    version: typeof parsed.version === 'string' ? parsed.version : '<unversioned>',
    license: typeof parsed.license === 'string' ? parsed.license : null,
    scripts: stringMap(parsed, 'scripts', defects),
    dependencies: stringMap(parsed, 'dependencies', defects),
    peerDependencies: stringMap(parsed, 'peerDependencies', defects),
    optionalDependencies: stringMap(parsed, 'optionalDependencies', defects),
    devDependencies: stringMap(parsed, 'devDependencies', defects),
    files: Array.isArray(files) ? files.filter((entry): entry is string => typeof entry === 'string') : null,
    binNames: readBinNames(parsed),
    exportPaths: isRecord(exportsValue) ? Object.keys(exportsValue) : [],
    dsh: readDshSection(parsed.dsh, defects),
    defects,
  }
}

/**
 * Every package name the manifest admits the package may load at runtime:
 * its own name, its dependencies, and its peer dependencies. Used to decide
 * whether an inserted Cordis row names a module the manifest accounts for.
 * @param manifest - the parsed manifest.
 * @returns the declared package names.
 */
export function declaredPackages(manifest: PackageManifest): ReadonlySet<string> {
  return new Set([
    manifest.name,
    ...Object.keys(manifest.dependencies),
    ...Object.keys(manifest.peerDependencies),
    ...Object.keys(manifest.optionalDependencies),
  ])
}
