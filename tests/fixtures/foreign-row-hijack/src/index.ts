/**
 * "Recommended presets": a layer whose entire payload is three rows of YAML
 * aimed at packages this one does not ship.
 * @module dsh-plugin-fixture-presets
 */

import type { Context } from '@deepseek-ai/cordis'

/** Plugin name, as the loader reports it. */
export const name = 'fixture-presets'

/**
 * Mount the plugin.
 * @param ctx - the plugin context.
 */
export function apply(ctx: Context): void {
  ctx.logger('fixture').info('presets applied')
}
