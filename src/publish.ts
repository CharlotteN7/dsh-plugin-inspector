/**
 * Which files of a working tree npm would actually publish.
 *
 * A directory target is a repository checkout, and a repository holds far more
 * than the package: tests, fixtures, CI config, build scratch. None of that is
 * installed, none of it is mounted, and none of it can act on a user. Reporting
 * on it produces findings nobody can act on and buries the ones they can, so
 * the directory reader is scoped to the set npm would put in the tarball.
 *
 * The rules are npm's, transcribed from `npm-packlist`: the `files` allowlist
 * when the manifest declares one, otherwise `.npmignore` — or `.gitignore` when
 * there is no `.npmignore` — over everything else. A handful of files are
 * always published whatever the manifest says, and a handful are never
 * published whatever it says.
 * @module dsh-plugin-inspector/publish
 */

/** How the publish set was decided, reported so the user knows what was read. */
export type PublishBasis = 'files-allowlist' | 'ignore-rules' | 'tarball'

/** Files npm publishes at the package root regardless of `files` or ignore rules. */
const ALWAYS_PUBLISHED = /^(?:package\.json|npm-shrinkwrap\.json|(?:readme|licen[cs]e|changelog|notice)(?:\.[^/]*)?)$/i

/**
 * Patterns npm refuses to publish whatever the manifest says. Transcribed from
 * `npm-packlist`'s default rule list; the lockfiles and dotfiles are the ones
 * that actually show up in a plugin checkout.
 */
const NEVER_PUBLISHED: readonly string[] = [
  '**/.git/**', '**/.git', '**/.svn/**', '**/.hg/**', '**/CVS/**',
  '**/node_modules/**', '**/node_modules',
  '**/.npmrc', '**/.DS_Store', '**/._*', '**/*.orig', '**/.*.swp',
  'npm-debug.log', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  '.lock-wscript', 'build/config.gypi', '.npmignore', '.gitignore',
]

/** A path is published, or it is not. */
export interface PublishSet {
  readonly basis: PublishBasis
  /**
   * Whether npm would put this path in the tarball.
   * @param path - package-relative POSIX path.
   * @returns true when the file is published.
   */
  includes: (path: string) => boolean
}

/**
 * Match one glob segment list against one path segment list. Segment-wise with
 * a memo rather than a compiled regular expression: `files` comes from an
 * untrusted manifest, and a memoised walk cannot be made to backtrack.
 * @param pattern - the pattern's segments.
 * @param path - the path's segments.
 * @returns true when the pattern matches the whole path.
 */
function matchSegments(pattern: readonly string[], path: readonly string[]): boolean {
  const seen = new Set<number>()
  const step = (p: number, s: number): boolean => {
    const key = p * (path.length + 1) + s
    if (seen.has(key)) return false
    seen.add(key)
    if (p === pattern.length) return s === path.length
    if (pattern[p] === '**') {
      for (let index = s; index <= path.length; index += 1) {
        if (step(p + 1, index)) return true
      }
      return false
    }
    if (s === path.length) return false
    if (!matchSegment(pattern[p] ?? '', path[s] ?? '')) return false
    return step(p + 1, s + 1)
  }
  return step(0, 0)
}

/**
 * Match one glob segment, where `*` stops at a separator and `?` takes one
 * character.
 * @param pattern - the pattern segment.
 * @param name - the path segment.
 * @returns true when they match.
 */
function matchSegment(pattern: string, name: string): boolean {
  const source = [...pattern].map((character) => {
    if (character === '*') return '[^/]*'
    if (character === '?') return '[^/]'
    return character.replace(/[.*+?^${}()|[\]\\]/, '\\$&')
  }).join('')
  return new RegExp(`^${source}$`).test(name)
}

/**
 * Whether a glob matches a path.
 * @param pattern - the glob, package-relative and POSIX.
 * @param path - the path, package-relative and POSIX.
 * @returns true when the glob matches.
 */
export function globMatch(pattern: string, path: string): boolean {
  return matchSegments(pattern.split('/'), path.split('/'))
}

/**
 * Strip the leading `./` or `/` npm accepts on a `files` entry, both of which
 * mean "from the package root".
 * @param pattern - the raw manifest entry.
 * @returns the root-relative pattern.
 */
function normalizePattern(pattern: string): string {
  return pattern.replace(/^\.?\//, '').replace(/\/+$/, '')
}

/**
 * Whether one `files` entry covers a path. npm treats a bare directory name as
 * that whole subtree, so `"lib"` publishes everything under `lib/`.
 * @param pattern - a normalised `files` entry.
 * @param path - package-relative POSIX path.
 * @returns true when the entry publishes the path.
 */
function allowlistCovers(pattern: string, path: string): boolean {
  if (pattern === '') return false
  if (globMatch(pattern, path)) return true
  if (path.startsWith(`${pattern}/`)) return true
  return globMatch(`${pattern}/**`, path)
}

/**
 * One `.npmignore` / `.gitignore` line, in the form the matcher needs.
 */
interface IgnoreRule {
  readonly negated: boolean
  /** True when the rule may only match a directory or something inside one. */
  readonly directoryOnly: boolean
  /** Segments to match, already anchored or not. */
  readonly pattern: string
  /** True when the rule is pinned to the package root rather than any depth. */
  readonly anchored: boolean
}

/**
 * Parse ignore-file text into rules, using git's syntax: `#` comments, `!`
 * negation, a trailing `/` for directories only, and anchoring to the root as
 * soon as the pattern contains an interior separator.
 * @param text - the file's content, or `null` when there is no such file.
 * @returns the rules in declaration order.
 */
function parseIgnore(text: string): IgnoreRule[] {
  const rules: IgnoreRule[] = []
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '').trim()
    if (line === '' || line.startsWith('#')) continue
    const negated = line.startsWith('!')
    const body = negated ? line.slice(1) : line
    const directoryOnly = body.endsWith('/')
    const trimmed = body.replace(/\/+$/, '')
    const anchored = trimmed.startsWith('/') || trimmed.includes('/')
    rules.push({ negated, directoryOnly, anchored, pattern: trimmed.replace(/^\//, '') })
  }
  return rules
}

/**
 * Whether an ignore rule matches a path or any directory above it, which is how
 * git decides that `coverage/` hides `coverage/tmp/x.json`.
 * @param rule - the rule.
 * @param path - package-relative POSIX path.
 * @returns true when the rule applies.
 */
function ignoreMatches(rule: IgnoreRule, path: string): boolean {
  const segments = path.split('/')
  for (let end = 1; end <= segments.length; end += 1) {
    const prefix = segments.slice(0, end).join('/')
    // A directory-only rule cannot match the file itself, only a parent of it.
    if (rule.directoryOnly && end === segments.length) continue
    if (rule.anchored) {
      if (globMatch(rule.pattern, prefix)) return true
      continue
    }
    if (globMatch(rule.pattern, segments[end - 1] ?? '')) return true
  }
  return false
}

/** Everything the publish set needs from the working tree. */
export interface PublishInputs {
  /** The manifest's `files` array, or `null` when it declares none. */
  readonly files: readonly string[] | null
  /** `.npmignore` content, or `null` when the package has none. */
  readonly npmignore: string | null
  /** `.gitignore` content, or `null` when the package has none. */
  readonly gitignore: string | null
  /** The manifest's `main`, which npm publishes even outside the allowlist. */
  readonly main: string | null
}

/**
 * Build the publish set for a working tree.
 * @param inputs - the manifest fields and ignore files the decision needs.
 * @returns the membership test and the basis it used.
 */
export function publishSet(inputs: PublishInputs): PublishSet {
  const never = NEVER_PUBLISHED
  const main = inputs.main === null ? null : normalizePattern(inputs.main)

  if (inputs.files !== null) {
    const allow = inputs.files.filter(entry => !entry.startsWith('!')).map(normalizePattern)
    const deny = inputs.files.filter(entry => entry.startsWith('!')).map(entry => normalizePattern(entry.slice(1)))
    return {
      basis: 'files-allowlist',
      includes: (path) => {
        if (never.some(pattern => globMatch(pattern, path))) return false
        if (ALWAYS_PUBLISHED.test(path)) return true
        if (main !== null && path === main) return true
        if (deny.some(pattern => allowlistCovers(pattern, path))) return false
        return allow.some(pattern => allowlistCovers(pattern, path))
      },
    }
  }

  const text = inputs.npmignore ?? inputs.gitignore
  const rules = text === null ? [] : parseIgnore(text)
  return {
    basis: 'ignore-rules',
    includes: (path) => {
      if (never.some(pattern => globMatch(pattern, path))) return false
      if (ALWAYS_PUBLISHED.test(path)) return true
      if (main !== null && path === main) return true
      let ignored = false
      for (const rule of rules) {
        if (!ignoreMatches(rule, path)) continue
        ignored = !rule.negated
      }
      return !ignored
    },
  }
}

/** Every file is published: a tarball is already the publish set. */
export const TARBALL_PUBLISH_SET: PublishSet = { basis: 'tarball', includes: () => true }
