/**
 * Classifying the files inside an analysed package, and formatting excerpts of
 * them for evidence.
 * @module dsh-plugin-inspector/files
 */

/** Extensions the TypeScript parser is asked to read. */
const SOURCE_EXTENSIONS: readonly string[] = [
  '.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs',
]

/** Longest evidence excerpt kept in a finding. */
const SNIPPET_LIMIT = 160

/**
 * Whether a path is JavaScript or TypeScript source this tool will parse.
 * Declaration files are excluded: they carry types, never behavior.
 * @param path - package-relative path.
 * @returns true when the file should be parsed.
 */
export function isSourceFile(path: string): boolean {
  if (path.endsWith('.d.ts') || path.endsWith('.d.mts') || path.endsWith('.d.cts')) return false
  return SOURCE_EXTENSIONS.some(extension => path.endsWith(extension))
}

/**
 * Whether a path is markdown that can reach the model verbatim.
 *
 * The reach is conditional: a `SKILL.md` inside an npm
 * package is only discovered when the plugin registers it through
 * `ctx.skills`, when a patch row redirects a skill root into the package, or
 * when something copies it into the user's workspace. This predicate answers
 * "is this the kind of file that would reach the model if it were found", not
 * "will it be found".
 * @param path - package-relative POSIX path.
 * @returns true for skill and agent-instruction markdown.
 */
export function isModelVisibleText(path: string): boolean {
  const segments = path.split('/')
  /* v8 ignore next -- `split` returns at least one element for any string. */
  const base = segments.at(-1) ?? ''
  if (base === 'SKILL.md' || base === 'AGENTS.md' || base === 'CLAUDE.md') return true
  // The filesystem provider scans a skill root at depth 1: `<root>/<name>.md`
  // or `<root>/<name>/SKILL.md`. The bare `.md` form is only a skill when it
  // sits directly inside a directory named `skills`.
  return segments.length >= 2 && segments.at(-2) === 'skills' && base.endsWith('.md')
}

/**
 * Whether a path is a Cordis config file, using the harness's own naming
 * convention from `scripts/cordis-config-files.ts`.
 * @param path - package-relative POSIX path.
 * @returns true for a cordis YAML file.
 */
export function isCordisConfigFile(path: string): boolean {
  /* v8 ignore next -- `split` returns at least one element for any string. */
  const base = path.split('/').at(-1) ?? ''
  return /cordis/.test(base) && (base.endsWith('.yml') || base.endsWith('.yaml'))
}

/**
 * Resolve a manifest-declared path to the package-relative POSIX form used as
 * map keys, or report that it leaves the package.
 *
 * Only `..` escapes. An absolute path does **not**: the launcher resolves the
 * patch as `join(packageDir, declared)` (`packages/boot/app-boot/src/profile.ts`),
 * and `join` re-roots an absolute second argument *inside* the first, so
 * `join('/…/pkg', '/etc/passwd')` is `/…/pkg/etc/passwd`. A leading slash
 * therefore names a file the package does not ship, not a file outside it.
 * @param declared - the path exactly as the manifest declares it.
 * @returns the normalised package-relative path, or `null` when it escapes.
 */
export function normalizePackagePath(declared: string): string | null {
  const segments: string[] = []
  for (const segment of declared.replace(/^[a-zA-Z]:/, '').split(/[\\/]/)) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') {
      if (segments.length === 0) return null
      segments.pop()
      continue
    }
    segments.push(segment)
  }
  return segments.join('/')
}

/**
 * Render a value as JSON-like evidence without walking a graph as a tree.
 * A YAML anchor makes one node reachable by many paths, so `JSON.stringify` on
 * a patch row's `config` can be asked to serialise billions of nodes from a
 * few hundred bytes of input. This stops at a depth and a length instead.
 * @param value - the value to describe.
 * @param maxDepth - how far to descend before writing an ellipsis.
 * @param limit - the longest string to return.
 * @returns the bounded rendering.
 */
export function boundedJson(value: unknown, maxDepth = 4, limit = SNIPPET_LIMIT * 2): string {
  const seen = new WeakSet<object>()
  const render = (node: unknown, depth: number): string => {
    if (node === null || typeof node !== 'object') return JSON.stringify(node) ?? 'null'
    if (seen.has(node)) return '"…(repeated)"'
    if (depth >= maxDepth) return Array.isArray(node) ? '[…]' : '{…}'
    seen.add(node)
    if (Array.isArray(node)) return `[${node.slice(0, 8).map(item => render(item, depth + 1)).join(',')}]`
    const entries = Object.entries(node).slice(0, 16)
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${render(item, depth + 1)}`).join(',')}}`
  }
  const text = render(value, 0)
  return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`
}

/**
 * Reduce text to a single-line excerpt safe to print in a report.
 * @param text - the source text.
 * @param limit - maximum characters to keep.
 * @returns the collapsed, truncated excerpt.
 */
export function snippet(text: string, limit: number = SNIPPET_LIMIT): string {
  const collapsed = text.replace(/\s+/g, ' ').trim()
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 1)}…`
}

/**
 * Convert a character offset to a `line:column` locator, both 1-based.
 * @param text - the file text.
 * @param offset - the character offset.
 * @returns the locator.
 */
export function lineColumn(text: string, offset: number): string {
  const before = text.slice(0, offset)
  const line = before.split('\n').length
  const column = offset - (before.lastIndexOf('\n') + 1) + 1
  return `${line}:${column}`
}
