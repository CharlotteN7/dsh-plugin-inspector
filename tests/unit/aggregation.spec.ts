/**
 * A finding is per package, not per syntax site.
 *
 * The 0.1 report emitted one finding per matched node, so three import-shape
 * checks produced 81 % of every finding across the published ecosystem and a
 * package importing `node:fs` from eleven files buried whatever else it did
 * under eleven identical lines. These cases pin the collapse and, just as
 * importantly, pin what the collapse must not merge.
 * @module tests/unit/aggregation
 */

import { afterAll, describe, expect, it } from 'vitest'
import { inspect } from '../../src/inspect.ts'
import { aggregateFindings, MAX_EXAMPLES, type Evidence, type Finding } from '../../src/model.ts'
import { renderHuman } from '../../src/report.ts'
import { cleanupPackages, createPackage } from './package-fixture.ts'
import { onlyCheck, withCheck } from './fixtures.ts'

afterAll(cleanupPackages)

/** Five modules, each importing the same two node builtins. */
const REPEATED_IMPORTS = {
  'package.json': JSON.stringify({ name: 'repeats', version: '1.0.0', files: ['lib/**/*.js'] }),
  'lib/a.js': 'import { readFile } from "node:fs"\nexport const a = readFile\n',
  'lib/b.js': 'import { writeFile } from "node:fs"\nexport const b = writeFile\n',
  'lib/c.js': 'import fs from "node:fs"\nexport const c = fs\n',
  'lib/d.js': 'import { stat } from "node:fs"\nexport const d = stat\n',
  'lib/e.js': 'import { spawn } from "node:child_process"\nexport const e = spawn\n',
}

describe('the same module imported from several files', () => {
  it('is one finding carrying the count and the first sites', async () => {
    const report = await inspect(createPackage(REPEATED_IMPORTS))
    const filesystem = onlyCheck(report, 'B13')
    expect(filesystem.subject).toBe('node:fs')
    expect(filesystem.occurrences).toBe(4)
    expect(filesystem.examples).toHaveLength(MAX_EXAMPLES)
    expect(filesystem.examples.map(example => example.file)).toEqual(['lib/a.js', 'lib/b.js', 'lib/c.js'])
    expect(filesystem.evidence).toEqual(filesystem.examples[0])
  })

  it('says how many sites it did not list, rather than listing three and stopping', async () => {
    const report = await inspect(createPackage(REPEATED_IMPORTS))
    const text = renderHuman(report, false)
    expect(text).toContain('(×4)')
    expect(text).toContain('… and 1 more site(s)')
  })

  it('keeps a different module a different finding', async () => {
    const report = await inspect(createPackage(REPEATED_IMPORTS))
    const process = onlyCheck(report, 'B9')
    expect(process.subject).toBe('node:child_process')
    expect(process.occurrences).toBe(1)
    expect(process.title).toContain('node:child_process')
  })

  it('does not merge two modules that one check reports on', async () => {
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'both', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'import "node:child_process"\nimport "node:worker_threads"\nimport "node:vm"\n',
    }))
    const subjects = withCheck(report, 'B9').map(finding => finding.subject).sort()
    expect(subjects).toEqual(['node:child_process', 'node:vm', 'node:worker_threads'])
    expect(withCheck(report, 'B9').every(finding => finding.occurrences === 1)).toBe(true)
  })

  it('counts a module imported under both its bare and its `node:` name separately', async () => {
    // `fs` and `node:fs` resolve to the same module, but the finding quotes the
    // specifier the package wrote, so merging them would make the title wrong
    // for half the sites it claims.
    const report = await inspect(createPackage({
      'package.json': JSON.stringify({ name: 'prefixes', version: '1.0.0', files: ['lib/**/*.js'] }),
      'lib/index.js': 'import "fs"\nimport "node:fs"\nimport "node:fs/promises"\n',
    }))
    expect(withCheck(report, 'B13').map(finding => finding.subject).sort())
      .toEqual(['fs', 'node:fs', 'node:fs/promises'])
  })
})

describe('aggregation itself', () => {
  /**
   * A finding with one site.
   * @param checkId - the check id.
   * @param subject - the subject.
   * @param file - the site's file.
   * @returns the finding.
   */
  function one(checkId: string, subject: string, file: string): Finding {
    const evidence: Evidence = { file, path: '1:1' }
    return {
      checkId,
      name: 'test',
      tier: 'B',
      severity: 'medium',
      confidence: 'high',
      subject,
      title: `${checkId} ${subject}`,
      detail: 'detail',
      evidence,
      examples: [evidence],
      occurrences: 1,
      bypass: null,
    }
  }

  it('groups by check and subject together, never by either alone', () => {
    const aggregated = aggregateFindings([
      one('B13', 'node:fs', 'a.js'),
      one('B13', 'node:fs', 'b.js'),
      one('B13', 'node:fs/promises', 'c.js'),
      one('B9', 'node:fs', 'd.js'),
    ])
    expect(aggregated.map(finding => `${finding.checkId}/${finding.subject}=${finding.occurrences}`))
      .toEqual(['B13/node:fs=2', 'B13/node:fs/promises=1', 'B9/node:fs=1'])
  })

  it('keeps the first occurrence\'s prose, so the finding reads about the site it shows', () => {
    const first = one('B13', 'node:fs', 'first.js')
    const aggregated = aggregateFindings([first, one('B13', 'node:fs', 'second.js')])
    expect(aggregated[0]?.title).toBe(first.title)
    expect(aggregated[0]?.evidence).toEqual(first.evidence)
  })

  it('caps the example list while still counting every site', () => {
    const many = Array.from({ length: 40 }, (_, index) => one('B7', 'node:https', `f${index}.js`))
    const aggregated = aggregateFindings(many, 2)
    expect(aggregated[0]?.occurrences).toBe(40)
    expect(aggregated[0]?.examples).toHaveLength(2)
  })

  it('is a no-op on findings that share no group', () => {
    const distinct = [one('A1', 'postinstall', 'package.json'), one('A1', 'prepare', 'package.json')]
    expect(aggregateFindings(distinct)).toHaveLength(2)
  })
})
