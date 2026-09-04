/**
 * The invariants the harness ground-truth tables have to hold whatever release
 * they describe.
 *
 * These cases cannot tell whether the tables are *correct* against a harness —
 * that needs the published packages, and `scripts/harness-sync.ts` does it with
 * a network. What they catch is the edit that drops a row while re-syncing, and
 * the subset entry that is not in its parent set and therefore silently never
 * fires: `SECURITY_SEAM_KEYS` is only ever consulted for a key that already
 * matched `SEAM_KEYS`, so a misspelling there removes a `critical` and changes
 * nothing else a reader would notice.
 * @module tests/unit/knowledge
 */

import { describe, expect, it } from 'vitest'
import {
  CORE_ROWS,
  CORE_ROW_IDS,
  DECISION_EVENTS,
  HARNESS_REFERENCE,
  SEAM_KEYS,
  SECURITY_ROW_IDS,
  SECURITY_SEAM_KEYS,
  WATERFALL_EVENTS,
} from '../../src/knowledge.ts'

describe('the transcribed harness tables', () => {
  it('holds the row and seam counts the named release was verified at', () => {
    // Re-verified against 0.1.2-rc.1 by `scripts/harness-sync.ts`, which reads
    // the published bundle patches and api-catalog. Changing a count here is
    // how a re-sync announces itself.
    expect(HARNESS_REFERENCE).toBe('0.1.2-rc.1')
    expect(CORE_ROWS.size).toBe(147)
    expect(SEAM_KEYS.size).toBe(68)
    expect(WATERFALL_EVENTS.size).toBe(14)
  })

  it('names a module for every row, so A4 has a guard to compare against', () => {
    const unnamed = [...CORE_ROWS].filter(([, row]) => row.module === '' || row.bundles.length === 0)
    expect(unnamed).toEqual([])
  })

  it.each([
    ['every security row is a core row', SECURITY_ROW_IDS.keys(), CORE_ROW_IDS],
    ['every security seam is a seam key', SECURITY_SEAM_KEYS, SEAM_KEYS],
    ['every decision event is a waterfall event', DECISION_EVENTS, WATERFALL_EVENTS],
  ])('%s, or the subset entry never fires', (_what, subset, parent) => {
    expect([...subset].filter(entry => !parent.has(entry))).toEqual([])
  })
})
