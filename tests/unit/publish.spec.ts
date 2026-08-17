/**
 * npm's own answer to "which of these files ship", which is the answer that
 * decides what a directory target means.
 * @module tests/unit/publish
 */

import { describe, expect, it } from 'vitest'
import { globMatch, publishSet, TARBALL_PUBLISH_SET, type PublishInputs } from '../../src/publish.ts'

/**
 * Build a publish set from partial inputs.
 * @param inputs - the fields under test.
 * @returns the membership test.
 */
function set(inputs: Partial<PublishInputs>) {
  return publishSet({ files: null, npmignore: null, gitignore: null, main: null, ...inputs })
}

describe('glob matching', () => {
  it('lets `**/` stand for no directories at all, as minimatch does', () => {
    expect(globMatch('lib/**/*.js', 'lib/index.js')).toBe(true)
    expect(globMatch('lib/**/*.js', 'lib/deep/nested/index.js')).toBe(true)
    expect(globMatch('lib/**/*.js', 'lib/index.ts')).toBe(false)
  })

  it('stops a single star at the separator', () => {
    expect(globMatch('lib/*.js', 'lib/index.js')).toBe(true)
    expect(globMatch('lib/*.js', 'lib/deep/index.js')).toBe(false)
  })

  it('takes exactly one character for `?`', () => {
    expect(globMatch('lib/index?.js', 'lib/index2.js')).toBe(true)
    expect(globMatch('lib/index?.js', 'lib/index.js')).toBe(false)
  })

  it('does not backtrack on a pattern written to make it', () => {
    // `files` comes from an untrusted manifest. Several `**` in a row give a
    // regular-expression matcher exponentially many ways to split the path; the
    // memo makes each (pattern, path) position pair cost one visit.
    const started = Date.now()
    expect(globMatch('**/**/**/**/**/**/**/**/**/**/*.js', 'a/b/c/d/e/f/g/h/i/j/k/l/index.ts')).toBe(false)
    expect(globMatch('**/**/**/*.js', 'a/b/c/index.js')).toBe(true)
    expect(Date.now() - started).toBeLessThan(1_000)
  })
})

describe('a `files` allowlist', () => {
  const published = set({ files: ['lib/**/*.js', 'cordis.patch.yml'], main: 'lib/index.js' })

  it('ships what it names and nothing else', () => {
    expect(published.includes('lib/index.js')).toBe(true)
    expect(published.includes('cordis.patch.yml')).toBe(true)
    expect(published.includes('tests/hostile/payload.js')).toBe(false)
    expect(published.includes('src/index.ts')).toBe(false)
  })

  it('ships the files npm ships whatever the allowlist says', () => {
    expect(published.includes('package.json')).toBe(true)
    expect(published.includes('README.md')).toBe(true)
    expect(published.includes('LICENSE')).toBe(true)
  })

  it('treats a bare directory name as the whole subtree', () => {
    expect(set({ files: ['lib'] }).includes('lib/deep/index.js')).toBe(true)
  })

  it('honours a `!` entry, which excludes from what the rest of the list allows', () => {
    const partial = set({ files: ['lib/**/*.js', '!lib/secret.js'] })
    expect(partial.includes('lib/index.js')).toBe(true)
    expect(partial.includes('lib/secret.js')).toBe(false)
  })

  it('ships `main` even when the allowlist does not name it, as npm does', () => {
    const elsewhere = set({ files: ['cordis.patch.yml'], main: './lib/index.js' })
    expect(elsewhere.includes('lib/index.js')).toBe(true)
    expect(elsewhere.includes('lib/other.js')).toBe(false)
  })

  it('publishes nothing for an entry that names no path', () => {
    expect(set({ files: ['/'] }).includes('lib/index.js')).toBe(false)
  })

  it('refuses what npm never publishes, even when the allowlist names it', () => {
    const greedy = set({ files: ['**'] })
    expect(greedy.includes('.npmrc')).toBe(false)
    expect(greedy.includes('node_modules/evil/index.js')).toBe(false)
    expect(greedy.includes('pnpm-lock.yaml')).toBe(false)
    expect(greedy.includes('lib/index.js')).toBe(true)
  })
})

describe('no `files` allowlist', () => {
  it('uses .npmignore when there is one', () => {
    const published = set({ npmignore: 'scratch/\n*.key\n', gitignore: 'lib/\n' })
    expect(published.includes('scratch/notes.md')).toBe(false)
    expect(published.includes('signing.key')).toBe(false)
    // .gitignore is not consulted at all once .npmignore exists, which is why
    // `lib/` in .gitignore does not hide the build here.
    expect(published.includes('lib/index.js')).toBe(true)
  })

  it('falls back to .gitignore, which is where a plugin loses its own build', () => {
    const published = set({ gitignore: 'node_modules/\n/lib/\ncoverage/\n' })
    expect(published.includes('lib/index.js')).toBe(false)
    expect(published.includes('src/index.ts')).toBe(true)
  })

  it('honours a negation, last rule winning', () => {
    const published = set({ gitignore: '*.md\n!docs/guide.md\n' })
    expect(published.includes('notes.md')).toBe(false)
    expect(published.includes('docs/other.md')).toBe(false)
    expect(published.includes('docs/guide.md')).toBe(true)
  })

  it('ships `main` even when an ignore rule would have dropped it', () => {
    expect(set({ npmignore: 'lib/\n', main: './lib/index.js' }).includes('lib/index.js')).toBe(true)
    expect(set({ npmignore: 'lib/\n', main: './lib/index.js' }).includes('lib/other.js')).toBe(false)
  })

  it('anchors a rule with a leading slash to the root', () => {
    const published = set({ gitignore: '/build/\n' })
    expect(published.includes('build/out.js')).toBe(false)
    expect(published.includes('packages/build/out.js')).toBe(true)
  })
})

describe('a tarball', () => {
  it('is already the publish set, so every entry in it was published', () => {
    expect(TARBALL_PUBLISH_SET.basis).toBe('tarball')
    expect(TARBALL_PUBLISH_SET.includes('lib/index.js')).toBe(true)
    expect(TARBALL_PUBLISH_SET.includes('anything/at/all')).toBe(true)
  })
})
