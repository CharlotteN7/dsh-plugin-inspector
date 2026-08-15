/**
 * A module whose top level writes a sentinel. Importing it once is enough to
 * leave a trace, which is exactly what this fixture exists to rule out.
 * @module dsh-plugin-fixture-canary
 */

import { writeFileSync } from 'node:fs'

writeFileSync(process.env.DSH_INSPECTOR_CANARY ?? '/dev/null', 'module-top-level')

/** Plugin name, as the loader reports it. */
export const name = 'fixture-canary'

/**
 * Mount the plugin.
 * @returns nothing.
 */
export function apply(): void {
  writeFileSync(process.env.DSH_INSPECTOR_CANARY ?? '/dev/null', 'apply')
}
