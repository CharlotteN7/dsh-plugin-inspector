/**
 * What the inspector reports for each hostile fixture, and — the check that
 * keeps the tool usable — that a well-behaved plugin produces nothing at all.
 * @module tests/unit/detection
 */

import { describe, expect, it } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { fixture, onlyCheck, withCheck } from './fixtures.ts'

describe('a well-behaved plugin', () => {
  it('produces no findings, so the tool stays worth reading', async () => {
    const report = await inspect(fixture('benign-control'))
    expect(report.findings).toEqual([])
    expect(report.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0 })
  })

  it('still reports what the plugin does', async () => {
    const report = await inspect(fixture('benign-control'))
    expect(report.facts.packageName).toBe('dsh-plugin-fixture-benign')
    expect(report.facts.mountsAsBundle).toBe(true)
    expect(report.facts.insertedRows).toEqual([
      { id: 'fixture-benign', name: 'dsh-plugin-fixture-benign' },
    ])
    expect(report.facts.targetedRows).toEqual([])
    expect(report.analysis.integrity).toBe('complete')
  })
})

describe('a patch layer that disables a security row', () => {
  it('is a Tier A critical naming the row and what stops holding', async () => {
    const report = await inspect(fixture('disables-approval'))
    const finding = onlyCheck(report, 'A2')
    expect(finding.tier).toBe('A')
    expect(finding.severity).toBe('critical')
    expect(finding.confidence).toBe('certain')
    expect(finding.title).toContain('approval')
    expect(finding.detail).toContain('user approval prompts')
    expect(finding.evidence.file).toBe('cordis.patch.yml')
    expect(finding.evidence.path).toBe('[0].disabled')
  })

  it('records the targeted row as a fact even before any severity is assigned', async () => {
    const report = await inspect(fixture('disables-approval'))
    expect(report.facts.targetedRows).toEqual(['approval'])
  })
})

describe('a !!js expression that reaches the module system', () => {
  it('is a Tier A critical, classified without being evaluated', async () => {
    const report = await inspect(fixture('js-child-process'))
    const findings = withCheck(report, 'A6')
    const moduleAccess = findings.find(finding => finding.severity === 'critical')
    expect(moduleAccess?.title).toContain('reaches the module system')
    expect(moduleAccess?.evidence.snippet).toContain("require('child_process')")
    expect(moduleAccess?.evidence.path).toBe('[0].insert[0].config.hostId')
  })

  it('separates an inert process read from a module reach', async () => {
    const report = await inspect(fixture('js-child-process'))
    const severities = withCheck(report, 'A6').map(finding => finding.severity).sort()
    expect(severities).toEqual(['critical', 'low'])
  })
})

describe('an install lifecycle script', () => {
  it('names the script and the pnpm default that stands in front of it', async () => {
    const report = await inspect(fixture('postinstall-script'))
    const finding = onlyCheck(report, 'A1')
    expect(finding.title).toContain('postinstall')
    expect(finding.evidence.path).toBe('scripts.postinstall')
    // pnpm >= 10 blocks a dependency's lifecycle scripts until the package is
    // listed under allowBuilds, and the harness prints that instruction itself.
    // Asserting execution at the user's uid would be wrong about the outcome.
    expect(finding.severity).toBe('medium')
    expect(finding.detail).toContain('allowBuilds')
  })
})

describe('a credential read paired with a network call', () => {
  it('reports both halves and the pair', async () => {
    const report = await inspect(fixture('credential-exfil'))
    expect(onlyCheck(report, 'B6').title).toContain('DEEPSEEK_API_KEY')
    expect(onlyCheck(report, 'B7').title).toContain('fetch()')
    expect(onlyCheck(report, 'B8').severity).toBe('critical')
  })

  it('says the pair is a capability and not a proven dataflow', async () => {
    const report = await inspect(fixture('credential-exfil'))
    const pair = onlyCheck(report, 'B8')
    expect(pair.detail).toContain('capability, not a dataflow')
    expect(pair.detail).toContain('has NOT shown')
    expect(pair.bypass).not.toBeNull()
  })
})

describe('a shipped skill carrying injection text', () => {
  it('reports the file, the redirect that makes it reachable, and the phrasing', async () => {
    const report = await inspect(fixture('skill-injection'))
    expect(onlyCheck(report, 'A12').severity).toBe('low')
    expect(onlyCheck(report, 'A15').severity).toBe('high')
    const injections = withCheck(report, 'A21')
    expect(injections.length).toBeGreaterThanOrEqual(3)
    expect(injections.every(finding => finding.evidence.file.endsWith('SKILL.md'))).toBe(true)
  })

  it('names which heuristic fired so the reader can judge it', async () => {
    const report = await inspect(fixture('skill-injection'))
    const rules = withCheck(report, 'A21').map(finding => finding.detail)
    expect(rules.some(detail => detail.includes('override-prior-instructions'))).toBe(true)
    expect(rules.some(detail => detail.includes('conceal-from-user'))).toBe(true)
  })

  it('is Tier A, so a minified sibling file cannot lower its confidence', async () => {
    // The shipped markdown IS the prompt: there is no syntax between these
    // bytes and the model, so there is nothing for a Tier C degradation to
    // have made unreliable.
    const report = await inspect(fixture('skill-injection'))
    expect(withCheck(report, 'A21').every(finding => finding.tier === 'A')).toBe(true)
    expect(withCheck(report, 'A21').every(finding => finding.confidence === 'certain')).toBe(true)
  })
})

describe('an MCP stdio row', () => {
  it('is a Tier A critical naming the command it would spawn', async () => {
    const report = await inspect(fixture('mcp-stdio'))
    const finding = onlyCheck(report, 'A10')
    expect(finding.severity).toBe('critical')
    expect(finding.title).toContain('/usr/local/bin/memory-server')
    expect(finding.detail).toContain('ctx.subprocess')
  })
})

describe('a `!js` single-bang tag', () => {
  it('reports that the layer has never loaded anywhere, without crashing', async () => {
    const report = await inspect(fixture('bad-tag'))
    const finding = onlyCheck(report, 'A8')
    expect(finding.severity).toBe('medium')
    expect(finding.detail).toContain('never been loaded')
  })
})

describe('a dsh.bundle.patch path that leaves the package', () => {
  it('is a Tier A critical and the path is not followed', async () => {
    const report = await inspect(fixture('patch-traversal'))
    const finding = onlyCheck(report, 'A14')
    expect(finding.severity).toBe('critical')
    expect(finding.detail).toContain('did not follow the path')
    expect(report.facts.filesRead).toBe(1)
  })
})

describe('an obfuscated package', () => {
  it('reports that it could not be read, and marks every negative unreliable', async () => {
    const report = await inspect(fixture('obfuscated'))
    expect(report.analysis.integrity).toBe('degraded')
    expect(report.analysis.negativesReliable).toBe(false)
    expect(report.analysis.degradedBy).toEqual(['C1', 'C2'])
  })

  it('does not count shipping build output as an unreadable package', async () => {
    // C3 is still reported — the build cannot be checked against a source that
    // is not there. It says nothing about whether the parse succeeded, and
    // shipping only `lib` is what publishing a package looks like, so letting
    // it set `negativesReliable: false` would mark every ordinary tarball
    // degraded and empty the word of meaning.
    const report = await inspect(fixture('obfuscated'))
    expect(withCheck(report, 'C3')).toHaveLength(1)
    expect(report.analysis.degradedBy).not.toContain('C3')
  })

  it('downgrades Tier B confidence rather than dropping the finding', async () => {
    const report = await inspect(fixture('obfuscated'))
    const network = onlyCheck(report, 'B7')
    expect(network.confidence).toBe('moderate')
  })

  it('does not catch the seam replacement the fixture hides, which is the point', async () => {
    const report = await inspect(fixture('obfuscated'))
    expect(withCheck(report, 'B1')).toEqual([])
  })
})

describe('every finding', () => {
  const packages = [
    'benign-control', 'disables-approval', 'js-child-process', 'postinstall-script',
    'credential-exfil', 'skill-injection', 'mcp-stdio', 'obfuscated', 'bad-tag', 'patch-traversal',
  ]

  it('carries a bypass for Tier B and Tier C, and none for Tier A', async () => {
    for (const name of packages) {
      const report = await inspect(fixture(name))
      for (const finding of report.findings) {
        if (finding.tier === 'A') expect(finding.bypass, `${name} ${finding.checkId}`).toBeNull()
        else expect(finding.bypass, `${name} ${finding.checkId}`).not.toBeNull()
      }
    }
  })

  it('ranks most severe first', async () => {
    const report = await inspect(fixture('skill-injection'))
    const order = report.findings.map(finding => finding.severity)
    expect(order).toEqual([...order].sort((a, b) => {
      const rank = { critical: 4, high: 3, medium: 2, low: 1 }
      return rank[b] - rank[a]
    }))
  })
})
