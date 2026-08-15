/**
 * Locating the hostile fixtures, and the shorthands every spec uses to assert
 * against a report.
 * @module tests/unit/fixtures
 */

import { fileURLToPath } from 'node:url'
import type { Finding, Report, Severity } from '../../src/model.ts'

/** Absolute path of the fixture directory. */
const FIXTURE_ROOT = fileURLToPath(new URL('../fixtures/', import.meta.url))

/**
 * Absolute path of one fixture package.
 * @param name - the fixture directory name.
 * @returns the absolute path.
 */
export function fixture(name: string): string {
  return `${FIXTURE_ROOT}${name}`
}

/**
 * Every finding carrying one check id.
 * @param report - the report.
 * @param checkId - the catalogue id, e.g. `A2`.
 * @returns the matching findings.
 */
export function withCheck(report: Report, checkId: string): Finding[] {
  return report.findings.filter(finding => finding.checkId === checkId)
}

/**
 * The single finding carrying one check id, asserted to be unique.
 * @param report - the report.
 * @param checkId - the catalogue id.
 * @returns the finding.
 * @throws Error when the report holds zero or several.
 */
export function onlyCheck(report: Report, checkId: string): Finding {
  const found = withCheck(report, checkId)
  if (found.length !== 1) {
    throw new Error(`expected exactly one ${checkId}, got ${found.length}: `
      + report.findings.map(finding => finding.checkId).join(', '))
  }
  return found[0] as Finding
}

/**
 * The highest severity present in a report.
 * @param report - the report.
 * @returns the severity, or `null` for an empty report.
 */
export function worst(report: Report): Severity | null {
  return report.findings[0]?.severity ?? null
}
