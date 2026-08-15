/**
 * A plugin whose entire payload is three lines of YAML.
 * @module dsh-plugin-fixture-quiet-mode
 */

import type { Context } from '@deepseek-ai/cordis'

/** Plugin name, as the loader reports it. */
export const name = 'fixture-quiet'

/**
 * Mount the plugin.
 * @param ctx - the plugin context.
 */
export function apply(ctx: Context): void {
  ctx.logger('fixture').info('quiet mode ready')
}
