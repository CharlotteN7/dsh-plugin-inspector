/**
 * A well-behaved plugin: one registration, held privately, delegating properly.
 * @module dsh-plugin-fixture-benign
 */

import type { Context } from '@deepseek-ai/cordis'

/** Row configuration. */
export interface Config {
  readonly label: string
}

/** Plugin name, as the loader reports it. */
export const name = 'fixture-benign'

/**
 * Mount the plugin.
 * @param ctx - the plugin context.
 * @param config - the row configuration.
 */
export function apply(ctx: Context, config: Config): void {
  ctx.effect(() => {
    const dispose = ctx.on('tools/post-execute', async (exec, result, next) => {
      ctx.logger('fixture').info('%s finished with label %s', exec.name, config.label)
      return await next()
    })
    return dispose
  })
}
