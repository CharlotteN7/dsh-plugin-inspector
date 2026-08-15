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
 * The reach is conditional and PLAN.md §6.1 says so: a `SKILL.md` inside an npm
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
  const base = path.split('/').at(-1) ?? ''
  return /cordis/.test(base) && (base.endsWith('.yml') || base.endsWith('.yaml'))
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
