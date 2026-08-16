/**
 * The calibration bar, held against the recorded ecosystem measurement.
 *
 * `tests/ecosystem-baseline.json` is what `scripts/ecosystem-sweep.ts --record`
 * wrote, and it is the number the README quotes. These cases read it offline
 * and assert the properties that decide whether the tool can be a gate. They do
 * not fetch anything: the sweep needs the network, this file needs the sweep's
 * output, and CI stays network-free.
 *
 * What they cannot do is notice that the ecosystem moved. That is
 * `--check`'s job, on a schedule, against a fresh run. What they do catch is a
 * baseline regenerated with worse numbers, or a bar quietly loosened to fit
 * one.
 * @module tests/unit/calibration
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import type { Severity } from '../../src/model.ts'

/** One check's contribution to the measurement. */
interface CheckStats {
  readonly findings: number
  readonly packages: number
  readonly worst: Readonly<Record<Severity, number>>
}

/** The recorded measurement. */
interface Baseline {
  readonly measuredOn: string
  readonly sample: string
  readonly corpusSize: number
  readonly scanned: number
  readonly findings: number
  readonly severities: Readonly<Record<Severity, number>>
  readonly withHighOrCritical: number
  readonly medianFindingsPerPackage: number
  readonly checks: Readonly<Record<string, CheckStats>>
  readonly bar: { readonly maxCriticalShareOfCorpus: number }
  readonly packages: readonly { readonly name: string, readonly version: string }[]
}

/** One pinned corpus entry. */
interface Corpus {
  readonly packages: readonly { readonly name: string, readonly version: string }[]
}

/**
 * Read a checked-in JSON file.
 * @param relative - path relative to this file.
 * @returns the parsed document.
 */
function load<T>(relative: string): T {
  return JSON.parse(readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8')) as T
}

const baseline = load<Baseline>('../ecosystem-baseline.json')
const corpus = load<Corpus>('../../scripts/ecosystem-corpus.json')

describe('the recorded ecosystem measurement', () => {
  it('describes the corpus that is checked in, so a stale baseline is not quoted', () => {
    expect(baseline.scanned).toBe(corpus.packages.length)
    expect(baseline.packages.map(entry => `${entry.name}@${entry.version}`))
      .toEqual(corpus.packages.map(entry => `${entry.name}@${entry.version}`))
    expect(baseline.sample).toMatch(/most-starred/)
  })

  it('keeps `critical` rare enough to mean something', () => {
    // The whole release exists because 252 criticals across 40 legitimate
    // packages meant the word had stopped carrying information.
    expect(baseline.severities.critical).toBeLessThanOrEqual(3)
    // And rare is not the same as absent: the one package that disables three
    // sandbox rows is exactly what a critical is for.
    expect(baseline.checks.A2?.worst.critical).toBe(1)
  })

  it('holds every check under the bar for how often a `critical` may fire', () => {
    expect(baseline.bar.maxCriticalShareOfCorpus).toBeLessThanOrEqual(0.1)
    const over = Object.entries(baseline.checks)
      .filter(([, stats]) => stats.worst.critical / baseline.scanned > baseline.bar.maxCriticalShareOfCorpus)
      .map(([check, stats]) => `${check} on ${Math.round(stats.worst.critical * 100 / baseline.scanned)}%`)
    expect(over).toEqual([])
  })

  it('keeps the report short enough to read', () => {
    // 1,420 findings over 40 packages, a median of 10.5 each, was a list nobody
    // reads to the end of — which is the same as reporting nothing.
    expect(baseline.findings).toBeLessThanOrEqual(295)
    expect(baseline.medianFindingsPerPackage).toBeLessThanOrEqual(6)
  })

  it('records how many packages a default gate would still stop', () => {
    // Published as measured, not as hoped: this is still a majority, and the
    // README says so rather than quoting the critical number alone.
    expect(baseline.withHighOrCritical).toBeLessThanOrEqual(21)
    expect(baseline.withHighOrCritical / baseline.scanned).toBeGreaterThan(0.5)
  })
})
