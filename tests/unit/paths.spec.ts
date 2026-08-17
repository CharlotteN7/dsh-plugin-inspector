/**
 * The path predicates that decide what gets parsed, what counts as reaching
 * the model, and what a declared patch path resolves to — and the bounded
 * renderers that put untrusted values into a finding.
 * @module tests/unit/paths
 */

import { describe, expect, it } from 'vitest'
import {
  boundedJson,
  isCordisConfigFile,
  isModelVisibleText,
  isSourceFile,
  normalizePackagePath,
} from '../../src/files.ts'

describe('what counts as source to parse', () => {
  it('parses JavaScript and TypeScript', () => {
    expect(isSourceFile('lib/index.js')).toBe(true)
    expect(isSourceFile('src/index.ts')).toBe(true)
  })

  it('leaves declaration files alone, since they carry types and never behavior', () => {
    expect(isSourceFile('lib/types/index.d.ts')).toBe(false)
    expect(isSourceFile('lib/types/index.d.mts')).toBe(false)
    expect(isSourceFile('lib/types/index.d.cts')).toBe(false)
  })

  it('leaves everything else alone', () => {
    expect(isSourceFile('README.md')).toBe(false)
  })
})

describe('what counts as text the model would read', () => {
  it('recognises the three instruction filenames wherever they sit', () => {
    expect(isModelVisibleText('SKILL.md')).toBe(true)
    expect(isModelVisibleText('skills/deploy/SKILL.md')).toBe(true)
    expect(isModelVisibleText('AGENTS.md')).toBe(true)
    expect(isModelVisibleText('CLAUDE.md')).toBe(true)
  })

  it('recognises a bare markdown file only directly inside a `skills` directory', () => {
    expect(isModelVisibleText('skills/deploy.md')).toBe(true)
    expect(isModelVisibleText('docs/deploy.md')).toBe(false)
    expect(isModelVisibleText('deploy.md')).toBe(false)
  })

  it('does not treat a non-markdown file in a `skills` directory as instructions', () => {
    expect(isModelVisibleText('skills/deploy.txt')).toBe(false)
  })
})

describe('what counts as a Cordis config file', () => {
  it('accepts both YAML spellings, and requires the name to say cordis', () => {
    expect(isCordisConfigFile('cordis.patch.yml')).toBe(true)
    expect(isCordisConfigFile('config/cordis.yaml')).toBe(true)
    expect(isCordisConfigFile('cordis.patch.json')).toBe(false)
    expect(isCordisConfigFile('config/settings.yml')).toBe(false)
  })
})

describe('resolving a manifest-declared patch path', () => {
  it('normalises the redundant forms to the map key the reader uses', () => {
    expect(normalizePackagePath('./cordis.patch.yml')).toBe('cordis.patch.yml')
    expect(normalizePackagePath('config//./cordis.yml')).toBe('config/cordis.yml')
    expect(normalizePackagePath('config\\cordis.yml')).toBe('config/cordis.yml')
  })

  it('resolves an interior `..` rather than refusing the path', () => {
    expect(normalizePackagePath('config/../cordis.patch.yml')).toBe('cordis.patch.yml')
  })

  it('refuses a path that climbs out of the package', () => {
    expect(normalizePackagePath('../elsewhere/cordis.yml')).toBeNull()
  })

  it('keeps a leading slash inside the package, which is where `join` puts it', () => {
    // `join('/…/pkg', '/etc/passwd')` is `/…/pkg/etc/passwd`, so an absolute
    // path names a file the package does not ship rather than one outside it.
    expect(normalizePackagePath('/etc/passwd')).toBe('etc/passwd')
  })
})

describe('rendering an untrusted value into a finding', () => {
  it('renders ordinary values as JSON', () => {
    expect(boundedJson({ a: 1, b: ['x'] })).toBe('{"a":1,"b":["x"]}')
  })

  it('renders a value JSON has no text for', () => {
    expect(boundedJson({ a: undefined })).toBe('{"a":null}')
  })

  it('stops at the depth ceiling, saying which kind of node it stopped at', () => {
    expect(boundedJson({ a: { b: { c: { d: { e: 1 } } } } })).toBe('{"a":{"b":{"c":{"d":{…}}}}}')
    expect(boundedJson([[[[['x']]]]])).toBe('[[[[[…]]]]]')
  })

  it('names a node it has already rendered instead of rendering it again', () => {
    // An anchored node reached twice is one node. Rendering it as a tree is how
    // a few hundred bytes of YAML become billions of nodes of evidence text.
    const shared = { k: 1 }
    expect(boundedJson({ a: shared, b: shared })).toBe('{"a":{"k":1},"b":"…(repeated)"}')
  })

  it('truncates past the length ceiling', () => {
    const rendered = boundedJson({ a: 'x'.repeat(500) }, 4, 40)
    expect(rendered).toHaveLength(40)
    expect(rendered.endsWith('…')).toBe(true)
  })
})
